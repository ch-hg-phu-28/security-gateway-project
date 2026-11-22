-- ============================================================================
-- security_check.lua  -  Core Inspection Engine (Mục 3.4) + Active Defense (3.6)
--
-- Chạy ở pha access_by_lua (trước proxy_pass). Luồng xử lý:
--   1. Bóc tách request (utils.extract_request)
--   2. [Tùy chọn] Kiểm tra IP đã bị khóa tạm thời chưa
--   3. Module 1: SQL Injection     -> Signature-based matching (Regex)
--   4. Module 2: API Injection     -> JSON Schema / Whitelist validation
--   5. Vi phạm  -> ghi log JSON + trả 403 + ngx.exit()  (backend không hề biết)
--      Hợp lệ   -> return, nginx tiếp tục chạy proxy_pass
-- ============================================================================
local utils = require "utils"
local cjson = require "cjson.safe"

-- ----------------------------------------------------------------------------
-- CẤU HÌNH
-- ----------------------------------------------------------------------------
local CONFIG = {
    -- true : bật thêm 2 luật "thô" theo đúng đề cương: dấu nháy đơn ' và dấu ;
    --        (bắt được cả payload thăm dò như q=' nhưng dễ False Positive: O'Brien)
    -- false: chỉ dùng các luật ngữ cảnh SQL (ít False Positive hơn)
    STRICT_MODE = true,

    -- Active Defense mở rộng: tự khóa IP nếu vi phạm >= BLOCK_THRESHOLD lần trong
    -- WINDOW giây, khóa BAN_SECONDS giây. MẶC ĐỊNH TẮT để không tự khóa máy bạn
    -- khi demo / load test từ cùng một IP.
    AUTO_BLOCK      = false,
    BLOCK_THRESHOLD = 5,
    WINDOW          = 60,
    BAN_SECONDS     = 300,

    -- Rate Limiting & Throttling chống brute-force / spam API (theo IP, cửa sổ cố định).
    -- MẶC ĐỊNH TẮT để không cản trở load test. Bật: RATE_LIMIT = true.
    RATE_LIMIT  = false,
    RATE_MAX    = 100,    -- tối đa 100 request ...
    RATE_WINDOW = 10,     -- ... trong 10 giây cho mỗi IP

    MAX_SCAN_LEN = 16384,   -- chỉ quét tối đa 16KB / mỗi giá trị (chống tốn CPU)
}

-- ----------------------------------------------------------------------------
-- MODULE 1 - SQL INJECTION: tập luật Regex (PCRE, chạy trên chuỗi đã chuẩn hóa)
-- Thứ tự: luật cụ thể trước, luật "thô" sau cùng -> log ghi đúng loại tấn công nhất
-- ----------------------------------------------------------------------------
local SQLI_RULES = {
    { name = "UNION_SELECT",
      re   = [[\bunion(?:\s+all|\s+distinct)?\s+select\b]] },

    { name = "BOOLEAN_TAUTOLOGY",   -- ' OR '1'='1 | 1 OR 1=1 | AND 2>1
      re   = [[\b(?:or|and)\s+['"(]*\d+['")]*\s*(?:=|<>|!=|<|>|like)\s*['"(]*\d+]] },

    { name = "STRING_TAUTOLOGY",    -- ' OR 'a'='a | ' OR ''='
      re   = [[\b(?:or|and)\s+['"]\w*['"]\s*=\s*['"]\w*]] },

    { name = "STACKED_QUERY",       -- ; DROP TABLE users;--
      re   = [[;\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec|shutdown|attach|pragma)\b]] },

    { name = "TIME_BASED_BLIND",    -- sleep(5), benchmark(...), randomblob (SQLite), waitfor delay
      re   = [[\b(?:sleep|benchmark|pg_sleep|randomblob|load_extension)\s*\(|\bwaitfor\s+delay\b]] },

    { name = "SCHEMA_PROBING",
      re   = [[\b(?:sqlite_master|sqlite_version|information_schema|pg_catalog|sysobjects)\b|\bpragma\s+\w+]] },

    { name = "DESTRUCTIVE_STATEMENT",
      re   = [[\b(?:drop|truncate|alter)\s+(?:table|database|index|view)\b|\bdelete\s+from\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b]] },

    { name = "SQL_COMMENT",         -- admin'--   |   1 -- x   |   /* ... */
      re   = [[--(?:\s|$)|'\s*(?:--|#)|/\*|\*/]] },

    { name = "ORDER_BY_PROBING",    -- ' ORDER BY 5 --
      re   = [[\border\s+by\s+\d+]] },

    { name = "SELECT_FROM",
      re   = [[\bselect\b.{1,200}?\bfrom\b]], strict_only = true },

    -- Hai luật "thô" theo đề cương (chỉ bật khi STRICT_MODE = true)
    { name = "SINGLE_QUOTE", re = [[']], strict_only = true },
    { name = "SEMICOLON",    re = [[;]], strict_only = true },
}

-- Quét danh sách item đã bóc tách. Trả về thông tin vi phạm đầu tiên hoặc nil.
local function check_sqli(ctx)
    for _, item in ipairs(ctx.items) do
        local value = item.value
        if #value > CONFIG.MAX_SCAN_LEN then value = value:sub(1, CONFIG.MAX_SCAN_LEN) end
        local norm = utils.normalize(value)

        -- Header chuẩn chứa ; ' nên chỉ áp luật ngữ cảnh SQL cho header
        local is_header = (item.source == "header")

        for _, rule in ipairs(SQLI_RULES) do
            local skip = rule.strict_only and (not CONFIG.STRICT_MODE or is_header)
            if not skip then
                local m = ngx.re.match(norm, rule.re, "ijo")
                if m then
                    return {
                        attack_type = "SQL_INJECTION",
                        rule        = rule.name,
                        location    = item.source .. ":" .. item.name,
                        payload     = norm,
                    }
                end
            end
        end
    end
    return nil
end

-- ----------------------------------------------------------------------------
-- MODULE 1b - COMMAND INJECTION / PATH TRAVERSAL ("Parameter Filtering" trong đề tài)
-- Thuộc nhóm API_INJECTION. Chạy TRƯỚC module SQLi để payload dạng "; cat /etc/passwd"
-- được phân loại đúng là Command Injection (luật SEMICOLON thô của SQLi sẽ bắt nó trước nếu chạy sau).
-- ----------------------------------------------------------------------------
local CMD_WORDS = "cat|ls|rm|wget|curl|bash|sh|nc|ncat|ping|whoami|id|uname|chmod|chown|python3?|perl|php|nslookup|powershell|cmd|telnet|ifconfig"
local CMDI_RULES = {
    { name = "CMD_SUBSTITUTION", re = [[\$\(|`[^`]+`]] },
    { name = "CMD_CHAINING",     re = [[(?:;|&&|\|\||\|)\s*(?:]] .. CMD_WORDS .. [[)\b]] },
    { name = "PATH_TRAVERSAL",   re = [[(?:\.\./|\.\.\\)|/etc/(?:passwd|shadow|hosts)\b|\bc:\\windows]] },
    { name = "SHELLSHOCK",       re = [[\(\)\s*\{\s*:?;?\s*\}?]], header_only = true },
}

local function check_cmdi(ctx)
    for _, item in ipairs(ctx.items) do
        local value = item.value
        if #value > CONFIG.MAX_SCAN_LEN then value = value:sub(1, CONFIG.MAX_SCAN_LEN) end
        local norm = utils.normalize(value)
        local is_header = (item.source == "header")
        for _, rule in ipairs(CMDI_RULES) do
            if (not rule.header_only) or is_header then
                if ngx.re.match(norm, rule.re, "ijo") then
                    return {
                        attack_type = "API_INJECTION",
                        rule        = rule.name,
                        location    = item.source .. ":" .. item.name,
                        payload     = norm,
                        reason      = "command injection / path traversal pattern (" .. rule.name .. ")",
                    }
                end
            end
        end
    end
    return nil
end

-- ----------------------------------------------------------------------------
-- MODULE 2 - API INJECTION / MASS ASSIGNMENT: Whitelist Schema theo endpoint
-- ----------------------------------------------------------------------------
-- Trường nhạy cảm KHÔNG BAO GIỜ được client gửi lên (so khớp không phân biệt hoa/thường,
-- ở mọi cấp lồng nhau của JSON)
local FORBIDDEN_FIELDS = {
    is_admin = true, isadmin = true, admin = true, role = true, roles = true,
    permissions = true, permission = true, privilege = true, privileges = true,
    is_superuser = true, is_staff = true, user_type = true, scope = true,
}

local SCHEMAS = {
    ["POST /api/update-profile"] = {
        body = {
            additional_properties = false,   -- cấm mọi trường không có trong danh sách
            fields = {
                username = { type = "string",  required = true, max_len = 50,
                             pattern = [[^[A-Za-z0-9_.\-]+$]] },
                email    = { type = "string",  max_len = 100,
                             pattern = [[^[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+$]] },
                age      = { type = "integer", min = 0, max = 150 },
            },
        },
    },
    ["GET /api/search"] = {
        args = {
            q = { type = "string", max_len = 100 },   -- ?q=a&q=b (HTTP Parameter Pollution) bị bắt
        },
    },
}

local function lua_type_of(v)
    local t = type(v)
    if t == "userdata" then return "null" end           -- cjson.null
    if t == "table" then
        return (#v > 0 or next(v) == nil) and "array" or "object"
    end
    return t
end

local function type_ok(expected, v)
    local t = lua_type_of(v)
    if expected == "integer" then return t == "number" and math.floor(v) == v end
    if expected == "number"  then return t == "number" end
    return t == expected                                 -- string | boolean
end

-- Kiểm tra một giá trị theo định nghĩa trường. Trả về chuỗi lý do nếu sai.
local function validate_field(name, rule, v)
    if not type_ok(rule.type, v) then
        return string.format("field '%s' must be %s, got %s", name, rule.type, lua_type_of(v))
    end
    if rule.type == "string" then
        if rule.max_len and #v > rule.max_len then
            return string.format("field '%s' exceeds max length %d", name, rule.max_len)
        end
        if rule.pattern and not ngx.re.match(v, rule.pattern, "jo") then
            return string.format("field '%s' has invalid format", name)
        end
    elseif rule.type == "integer" or rule.type == "number" then
        if (rule.min and v < rule.min) or (rule.max and v > rule.max) then
            return string.format("field '%s' out of range", name)
        end
    end
    return nil
end

-- Tìm trường cấm ở mọi cấp của JSON
local function find_forbidden(node, path)
    if type(node) ~= "table" then return nil end
    for k, v in pairs(node) do
        local key = tostring(k)
        if FORBIDDEN_FIELDS[key:lower()] then
            return key, path .. "." .. key
        end
        local fk, fp = find_forbidden(v, path .. "." .. key)
        if fk then return fk, fp end
    end
    return nil
end

local function api_violation(reason, payload, location, rule)
    return { attack_type = "API_INJECTION", rule = rule, location = location,
             payload = payload, reason = reason }
end

local function check_api(ctx)
    local schema = SCHEMAS[ctx.method .. " " .. ctx.path]
    if not schema then return nil end                    -- endpoint chưa khai báo schema -> bỏ qua

    local raw = ctx.body_raw or ctx.uri

    -- (a) Kiểm tra query args
    if schema.args then
        for name, rule in pairs(schema.args) do
            local v = ctx.args[name]
            if v ~= nil then
                local reason = validate_field(name, rule, v == true and "" or v)
                if type(v) == "table" then
                    reason = string.format("param '%s' repeated (parameter pollution)", name)
                end
                if reason then
                    return api_violation(reason, ctx.uri, "args:" .. name, "ARG_SCHEMA_VIOLATION")
                end
            end
        end
    end

    -- (b) Kiểm tra JSON body
    if schema.body then
        if ctx.json_error then
            return api_violation("malformed JSON body", raw, "body", "MALFORMED_JSON")
        end
        if lua_type_of(ctx.json) ~= "object" then
            return api_violation("JSON object body required", raw, "body", "BODY_NOT_OBJECT")
        end

        -- Mass Assignment: trường nhạy cảm bị gài thêm
        local fk, fpath = find_forbidden(ctx.json, "$")
        if fk then
            return api_violation("forbidden field '" .. fk .. "' (mass assignment)",
                                 raw, "body:" .. fpath, "MASS_ASSIGNMENT")
        end

        local fields = schema.body.fields

        -- Trường lạ, không có trong whitelist
        if schema.body.additional_properties == false then
            for k in pairs(ctx.json) do
                if not fields[tostring(k)] then
                    return api_violation("unexpected field '" .. tostring(k) .. "'",
                                         raw, "body:$." .. tostring(k), "UNEXPECTED_FIELD")
                end
            end
        end

        -- Trường bắt buộc + kiểu dữ liệu (Type Confusion)
        for name, rule in pairs(fields) do
            local v = ctx.json[name]
            if v == nil then
                if rule.required then
                    return api_violation("missing required field '" .. name .. "'",
                                         raw, "body:$." .. name, "MISSING_FIELD")
                end
            else
                local reason = validate_field(name, rule, v)
                if reason then
                    return api_violation(reason, raw, "body:$." .. name, "TYPE_CONFUSION")
                end
            end
        end
    end

    return nil
end

-- ----------------------------------------------------------------------------
-- ACTIVE DEFENSE mở rộng: đếm vi phạm theo IP và tự khóa (dùng lua_shared_dict)
-- ----------------------------------------------------------------------------
local function is_ip_banned(ip)
    local banned = ngx.shared.sec_blocklist
    return banned and banned:get(ip) or false
end

local function register_violation(ip)
    if not CONFIG.AUTO_BLOCK then return end
    local counter, banned = ngx.shared.sec_counter, ngx.shared.sec_blocklist
    if not (counter and banned) then return end
    local n = counter:incr(ip, 1, 0, CONFIG.WINDOW)
    if n and n >= CONFIG.BLOCK_THRESHOLD then
        banned:set(ip, true, CONFIG.BAN_SECONDS)
        counter:delete(ip)
        ngx.log(ngx.WARN, "[SECURITY_ALERT] IP auto-banned: ", ip)
    end
end

-- ----------------------------------------------------------------------------
-- RATE LIMITING: đếm request theo IP trong cửa sổ WINDOW giây (lua_shared_dict)
-- ----------------------------------------------------------------------------
local function rate_limited(ip)
    if not CONFIG.RATE_LIMIT then return false end
    local counter = ngx.shared.sec_counter
    if not counter then return false end
    local n = counter:incr("rl:" .. ip, 1, 0, CONFIG.RATE_WINDOW)
    -- trả về: (bị giới hạn?, có phải lần vượt đầu tiên trong cửa sổ?) - chỉ ghi log lần đầu để không tràn file log
    return n ~= nil and n > CONFIG.RATE_MAX, n == CONFIG.RATE_MAX + 1
end

-- ----------------------------------------------------------------------------
-- THỰC THI
-- ----------------------------------------------------------------------------
local t0 = os.clock()   -- đồng hồ CPU, độ phân giải micro giây (ngx.now() chỉ tới mili giây)

local ctx = utils.extract_request()

-- Rate limit (rẻ nhất nên kiểm tra đầu tiên)
local limited, first_hit = rate_limited(ctx.client_ip)
if limited then
    if first_hit then
        utils.log_alert({
            client_ip = ctx.client_ip, method = ctx.method, uri = ctx.uri,
            attack_type = "RATE_LIMIT", rule = "RATE_LIMIT", location = "client_ip",
            payload = string.format("> %d requests / %ds", CONFIG.RATE_MAX, CONFIG.RATE_WINDOW),
        })
    end
    return utils.block("RATE_LIMIT", "too many requests, slow down", 429, "RATE_LIMIT")
end

-- 0. IP đang bị khóa
if CONFIG.AUTO_BLOCK and is_ip_banned(ctx.client_ip) then
    utils.log_alert({
        client_ip = ctx.client_ip, method = ctx.method, uri = ctx.uri,
        attack_type = "IP_BANNED", rule = "AUTO_BLOCK", location = "client_ip",
        payload = ctx.client_ip,
    })
    return utils.block("IP_BANNED", "client IP temporarily banned after repeated violations", nil, "AUTO_BLOCK")
end

-- 1. Command Injection  ->  2. SQL Injection  ->  3. API Injection / Mass Assignment
local violation = check_cmdi(ctx) or check_sqli(ctx) or check_api(ctx)

ngx.ctx.inspect_us = (os.clock() - t0) * 1000000   -- thời gian kiểm tra (micro giây), xuất ra header

if violation then
    utils.log_alert({
        client_ip   = ctx.client_ip,
        method      = ctx.method,
        uri         = ctx.uri,
        attack_type = violation.attack_type,
        rule        = violation.rule,
        location    = violation.location,
        payload     = violation.payload,
    })
    register_violation(ctx.client_ip)
    return utils.block(violation.attack_type, violation.reason or ("matched rule " .. violation.rule), nil, violation.rule)
end

-- Sạch: kết thúc hàm, nginx chạy tiếp proxy_pass

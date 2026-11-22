-- ============================================================================
-- utils.lua  -  Hàm phụ trợ cho Security Gateway (Mục 3.4)
--   * Bóc tách dữ liệu đầu vào: URL args, HTTP headers, Request body
--   * Giải mã URL (URL decode) + chuẩn hóa chuỗi để chống né bộ lọc
--   * Ghi nhật ký JSON (JSON Logging) cho Active Defense
-- ============================================================================
local cjson = require "cjson.safe"   -- bản "safe": decode lỗi trả nil thay vì ném exception
-- Không escape dấu "/" thành "\/" để log JSON dễ đọc (hàm này có trong cjson của OpenResty)
if cjson.encode_escape_forward_slash then cjson.encode_escape_forward_slash(false) end

local _M = {}

-- Đường dẫn file log cảnh báo (được mount ra host qua docker-compose)
_M.ALERT_LOG_FILE = "/var/log/security/security_alerts.json"

-- ---------------------------------------------------------------------------
-- 1. URL DECODE
--    Hacker thường mã hóa payload: %27 = ', %20 = khoảng trắng, + = khoảng trắng,
--    thậm chí mã hóa 2 lần (%2527 -> %27 -> '). Vì vậy ta giải mã lặp tới khi ổn định.
-- ---------------------------------------------------------------------------
local function decode_once(s)
    s = s:gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    return s
end

function _M.url_decode(s, max_rounds)
    if type(s) ~= "string" then return s end
    max_rounds = max_rounds or 3
    for _ = 1, max_rounds do
        local decoded = decode_once(s)
        if decoded == s then break end   -- đã sạch, không còn gì để giải mã
        s = decoded
    end
    return s
end

-- ---------------------------------------------------------------------------
-- 2. CHUẨN HÓA (normalize) trước khi chạy Regex
--    - URL decode nhiều lớp
--    - Xóa byte NULL
--    - Biến comment inline  /**/  thành khoảng trắng (UNION/**/SELECT)
--    - Gộp mọi chuỗi khoảng trắng/tab/xuống dòng thành 1 dấu cách
-- ---------------------------------------------------------------------------
function _M.normalize(s)
    if type(s) ~= "string" then return "" end
    s = _M.url_decode(s)
    s = s:gsub("%z", "")
    s = s:gsub("/%*.-%*/", " ")
    s = s:gsub("%s+", " ")
    return s
end

-- ---------------------------------------------------------------------------
-- 3. BÓC TÁCH DỮ LIỆU ĐẦU VÀO
-- ---------------------------------------------------------------------------

-- Đọc Request Body. ngx.req.get_body_data() trả nil nếu body quá lớn bị nginx
-- ghi ra file tạm -> khi đó đọc lại từ file (giới hạn 1MB để an toàn).
local function read_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body then return body end

    local path = ngx.req.get_body_file()
    if path then
        local f = io.open(path, "rb")
        if f then
            body = f:read(1024 * 1024)
            f:close()
            return body
        end
    end
    return nil
end

-- Làm phẳng một bảng args/form thành danh sách { source, name, value }
-- Một tham số lặp (?q=a&q=b) trong OpenResty là table; tham số không có giá trị (?q) là true.
local function collect(source, tbl, out)
    for name, value in pairs(tbl) do
        if type(value) == "table" then
            for _, v in ipairs(value) do
                if type(v) == "string" then
                    out[#out + 1] = { source = source, name = name, value = v }
                end
            end
        elseif type(value) == "string" then
            out[#out + 1] = { source = source, name = name, value = value }
        end
    end
end

-- Duyệt đệ quy cây JSON, thu thập CẢ key lẫn value kiểu chuỗi (hacker có thể
-- giấu payload trong tên trường hoặc trong object lồng nhau).
local function walk_json(node, path, out)
    local t = type(node)
    if t == "table" then
        for k, v in pairs(node) do
            local key = tostring(k)
            out[#out + 1] = { source = "body.key", name = path, value = key }
            walk_json(v, path .. "." .. key, out)
        end
    elseif t == "string" then
        out[#out + 1] = { source = "body", name = path, value = node }
    end
end

-- Các header có thể bị nhồi payload. Không quét toàn bộ header vì header chuẩn
-- (Accept: text/html;q=0.9 ...) chứa ; và = sẽ gây False Positive.
local INSPECTED_HEADERS = {
    ["user-agent"] = true, ["referer"] = true, ["cookie"] = true,
    ["x-forwarded-for"] = true, ["x-api-key"] = true, ["x-real-ip"] = true,
    ["authorization"] = true,
}

-- Hàm chính: gom mọi thứ vào một cấu trúc duy nhất.
-- Trả về:
--   ctx.method, ctx.uri, ctx.path, ctx.client_ip
--   ctx.args        : bảng args gốc (cho schema check)
--   ctx.body_raw    : chuỗi body gốc (hoặc nil)
--   ctx.json        : bảng JSON đã parse (nếu body là JSON hợp lệ)
--   ctx.json_error  : true nếu body trông như JSON nhưng không parse được
--   ctx.items       : danh sách phẳng { source, name, value } để chạy Regex
function _M.extract_request()
    local ctx = {
        method    = ngx.req.get_method(),
        uri       = ngx.var.request_uri,
        path      = ngx.var.uri,
        client_ip = ngx.var.remote_addr,
        items     = {},
    }

    -- (a) Tham số URL
    local args = ngx.req.get_uri_args(100)
    ctx.args = args
    collect("args", args, ctx.items)
    -- thêm cả TÊN tham số (key) vào danh sách quét
    for name in pairs(args) do
        ctx.items[#ctx.items + 1] = { source = "args.key", name = name, value = name }
    end

    -- (b) HTTP Headers
    local headers = ngx.req.get_headers(100)
    ctx.headers = headers
    for name, value in pairs(headers) do
        if INSPECTED_HEADERS[name:lower()] then
            if type(value) == "table" then value = table.concat(value, ",") end
            ctx.items[#ctx.items + 1] = { source = "header", name = name, value = tostring(value) }
        end
    end

    -- (c) Request Body
    local m = ctx.method
    if m == "POST" or m == "PUT" or m == "PATCH" or m == "DELETE" then
        local body = read_body()
        ctx.body_raw = body
        if body and #body > 0 then
            local ctype = (headers["content-type"] or ""):lower()
            local looks_json = ctype:find("json", 1, true) or body:match("^%s*[%[{]")

            if looks_json then
                local parsed = cjson.decode(body)
                if parsed ~= nil then
                    ctx.json = parsed
                    walk_json(parsed, "$", ctx.items)
                else
                    ctx.json_error = true
                    -- JSON hỏng: vẫn quét thô toàn bộ body để không lọt payload
                    ctx.items[#ctx.items + 1] = { source = "body", name = "$raw", value = body }
                end
            elseif ctype:find("x-www-form-urlencoded", 1, true) then
                local form = ngx.decode_args(body, 100)
                collect("body", form, ctx.items)
                for name in pairs(form) do
                    ctx.items[#ctx.items + 1] = { source = "body.key", name = name, value = name }
                end
            else
                ctx.items[#ctx.items + 1] = { source = "body", name = "$raw", value = body }
            end
        end
    end

    return ctx
end

-- ---------------------------------------------------------------------------
-- 4. JSON LOGGING
-- ---------------------------------------------------------------------------
local function truncate(s, n)
    s = tostring(s or "")
    if #s > n then return s:sub(1, n) .. "...(truncated)" end
    return s
end

-- Ghi 1 dòng JSON vào file log + ngx.log (hiện trong `docker logs`)
function _M.log_alert(entry)
    entry.timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time())
    entry.payload   = truncate(entry.payload, 500)
    entry.action    = entry.action or "BLOCKED"

    local line = cjson.encode(entry)

    -- (1) hiện ngay trong log Docker: dùng cho ảnh chụp minh chứng mục 3.7 / 3.8
    ngx.log(ngx.WARN, "[SECURITY_ALERT] ", line)

    -- (2) ghi file JSON (mỗi dòng 1 bản ghi - định dạng JSON Lines) cho Dashboard
    local f, err = io.open(_M.ALERT_LOG_FILE, "a")
    if f then
        f:write(line, "\n")
        f:close()
    else
        ngx.log(ngx.ERR, "cannot open alert log: ", err)
    end
end

-- Trả về JSON 403 (hoặc 429 khi rate limit) chuẩn cho client và ngắt luồng xử lý (không chạy xuống proxy_pass)
function _M.block(attack_type, reason, status, rule)
    status = status or ngx.HTTP_FORBIDDEN
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["X-Blocked-By"] = "Security-Gateway"
    ngx.say(cjson.encode({
        status      = "blocked",
        code        = status,
        error       = (status == 429) and "Too Many Requests" or "Forbidden",
        attack_type = attack_type,
        rule        = rule,
        message     = "Request blocked by Security Gateway",
        reason      = reason,
        request_id  = ngx.var.request_id,
    }))
    return ngx.exit(status)
end

return _M

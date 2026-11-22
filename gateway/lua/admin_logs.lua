-- ============================================================================
-- admin_logs.lua - API đọc log cảnh báo cho Admin Dashboard (Mục 3.6 - nâng cao)
--   GET  /admin/logs?limit=50   -> JSON: thống kê + các bản ghi mới nhất (mới -> cũ)
--   POST /admin/logs/clear      -> xóa log (dùng để reset trước khi demo)
-- ============================================================================
local cjson = require "cjson.safe"
local utils = require "utils"

ngx.header["Content-Type"] = "application/json; charset=utf-8"
ngx.header["Cache-Control"] = "no-store"

local LOG_FILE = utils.ALERT_LOG_FILE

if ngx.var.uri == "/admin/logs/clear" then
    if ngx.req.get_method() ~= "POST" then
        ngx.status = 405
        return ngx.say(cjson.encode({ error = "use POST" }))
    end
    local f = io.open(LOG_FILE, "w")
    if f then f:close() end
    return ngx.say(cjson.encode({ status = "cleared" }))
end

local limit = tonumber(ngx.var.arg_limit) or 50
if limit < 1 then limit = 1 elseif limit > 500 then limit = 500 end

local events, stats = {}, { total = 0, SQL_INJECTION = 0, API_INJECTION = 0, IP_BANNED = 0, RATE_LIMIT = 0 }

local f = io.open(LOG_FILE, "r")
if f then
    -- Chỉ đọc tối đa 512KB cuối file để dashboard luôn nhanh
    local size = f:seek("end")
    local start = size > 524288 and (size - 524288) or 0
    f:seek("set", start)
    local data = f:read("*a") or ""
    f:close()

    for line in data:gmatch("[^\r\n]+") do
        local ev = cjson.decode(line)       -- dòng cắt dở ở đầu đoạn đọc sẽ decode lỗi -> bỏ qua
        if type(ev) == "table" then
            events[#events + 1] = ev
            stats.total = stats.total + 1
            if stats[ev.attack_type] ~= nil then stats[ev.attack_type] = stats[ev.attack_type] + 1 end
        end
    end
end

-- Đảo thứ tự: mới nhất lên đầu, cắt theo limit
local out = {}
for i = #events, math.max(1, #events - limit + 1), -1 do
    out[#out + 1] = events[i]
end

ngx.say(cjson.encode({ stats = stats, events = out }))

# Security Gateway – phát hiện & ngăn chặn SQL Injection / API Injection

> **Mới bắt đầu?** Đọc [`HUONG_DAN_DEMO.md`](HUONG_DAN_DEMO.md): chạy demo tuần tự, cách dùng từng bộ test, hướng dẫn Postman và danh sách ảnh minh chứng cho báo cáo.

Reverse Proxy **OpenResty (Nginx + LuaJIT)** đứng trước backend **FastAPI + SQLite** (cố ý có lỗ hổng).
Mọi request phải qua bộ lọc Lua (Deep Packet Inspection) trước khi `proxy_pass`.

```
Client/Hacker ──► [ Gateway :80 ]──(sạch)──► [ Backend FastAPI :5000 ] ──► SQLite
                       │ access_by_lua: security_check.lua
                       ├─(độc hại)──► 403 JSON + ghi security_alerts.json
                       └─ /admin/dashboard  (theo dõi cảnh báo thời gian thực)
```

## Cấu trúc thư mục
```
security-gateway-project/
├── docker-compose.yml
├── backend/                  app.py (2 endpoint có lỗ hổng + /api/health), Dockerfile, requirements.txt, database.db
├── gateway/
│   ├── Dockerfile
│   ├── conf/nginx.conf       Reverse proxy + access_by_lua_file + admin routes
│   ├── lua/
│   │   ├── utils.lua            bóc tách args/headers/body, URL decode, chuẩn hóa, JSON logging, block()
│   │   ├── security_check.lua   module SQLi (Regex) + module API Injection (whitelist schema) + Active Defense
│   │   └── admin_logs.lua       API đọc log cho dashboard
│   ├── html/dashboard.html   giao diện theo dõi cảnh báo
│   └── logs/                 security_alerts.json (JSON Lines) xuất hiện ở đây
└── tests/
    ├── attack_demo.sh        kịch bản demo 3 trạng thái bằng cURL
    ├── attack_tests.py       bộ payload (SQLi, Command Injection, API Injection) → bảng Detection rate / False Positive
    ├── rate_limit_test.py    kiểm thử Rate Limiting (429)
    ├── load_test.py          đo RPS + độ trễ (không cần cài thêm thư viện)
    ├── locustfile.py         đo tải bằng Locust (thay cho wrk)
    ├── postman_collection.json  Postman: 43 request có assert tự động (kèm SecurityGateway.postman_environment.json)
    └── Dockerfile            container "Attacker Lab"
```

## 1. Chạy hệ thống
```bash
docker compose up --build
```
| Địa chỉ | Chức năng |
|---|---|
| `http://localhost:80`  | Security Gateway (đi qua bộ lọc) |
| `http://localhost:5000`| Backend trực tiếp (chỉ để demo "không có Gateway") |
| `http://localhost/admin/dashboard` | Dashboard cảnh báo real-time (tự làm mới mỗi 2 s) |
| `http://localhost/admin/logs` | API JSON của dashboard |

Sửa file `.lua` / `nginx.conf` xong chỉ cần: `docker compose restart gateway` (đã mount volume, không cần build lại).

Các lệnh Docker thường dùng:
```bash
docker compose up -d --build        # chạy nền
docker compose ps                   # trạng thái container
docker compose logs -f              # xem log (gateway in [SECURITY_ALERT], backend in [EXECUTING SQL])
docker compose down                 # tắt;  thêm -v để xóa luôn CSDL SQLite (reset dữ liệu demo)

# Scale backend (Gateway chia tải round-robin giữa các bản sao; chạy lại `docker compose restart gateway` nếu thêm bản sao sau)
docker compose up -d --build --scale backend=3

# Attacker Lab: chạy bộ kiểm thử từ BÊN TRONG mạng Docker
docker compose --profile lab run --rm attacker
```
Tầng cơ sở dữ liệu là SQLite (file `/data/database.db` trong volume `sqlite-data`, có 3 bảng `users`, `products`, `articles`). Sau Trạng thái 1 của demo,
dữ liệu bị sửa (user bị nâng quyền) → chạy `docker compose down -v` rồi `up` lại để reset.

## 2. Kiểm thử & chụp ảnh minh chứng (Mục 3.7, 3.8)
```bash
bash tests/attack_demo.sh 1     # Trạng thái 1: tấn công thẳng backend  -> lộ dữ liệu / nâng quyền
bash tests/attack_demo.sh 2     # Trạng thái 2: cùng payload qua gateway -> 403 Forbidden
docker logs security_gateway    # chỉ thấy [SECURITY_ALERT] {...}
docker compose logs backend     # KHÔNG còn dòng [EXECUTING SQL] của request bị chặn
```
Postman: `GET http://localhost/api/search?q=' OR '1'='1` và `POST http://localhost/api/update-profile` với body JSON
`{"username":"chauhoangphu","is_admin":true}` (Content-Type: application/json).

Bảng kết quả cho báo cáo (Detection rate, False Positive):
```bash
pip install requests
python tests/attack_tests.py --no-backend      # --no-backend: không tấn công thật vào DB của backend
```

## 3. Cơ chế phát hiện
**SQL Injection** (`security_check.lua`) – quét tham số URL, tên tham số, JSON body (cả key lẫn value, mọi cấp lồng), form body, và các header
User-Agent/Referer/Cookie/X-Forwarded-For/…; trước khi so Regex, chuỗi được **URL-decode tối đa 3 lớp**, xóa NULL, đổi `/**/` thành khoảng trắng.
Các luật: `UNION_SELECT`, `BOOLEAN_TAUTOLOGY`, `STRING_TAUTOLOGY`, `STACKED_QUERY`, `TIME_BASED_BLIND`, `SCHEMA_PROBING`, `DESTRUCTIVE_STATEMENT`,
`SQL_COMMENT`, `ORDER_BY_PROBING`, và (khi `STRICT_MODE=true`) `SELECT_FROM`, `SINGLE_QUOTE`, `SEMICOLON`.

**Command Injection / Path Traversal** ("Parameter Filtering" của đề tài, tính vào nhóm `API_INJECTION`): `CMD_CHAINING` (`; cat`, `&& whoami`, `| ls`),
`CMD_SUBSTITUTION` (`$(...)`, `` `...` ``), `PATH_TRAVERSAL` (`../`, `/etc/passwd`), `SHELLSHOCK` (header).

**Rate Limiting** – đếm request theo IP trong cửa sổ cố định, vượt ngưỡng trả **429** (chỉ ghi log lần vượt đầu tiên mỗi cửa sổ). Mặc định tắt.

**API Injection / Mass Assignment** – whitelist schema theo `METHOD + path` (bảng `SCHEMAS`):
trường cấm (`is_admin`, `role`, … ở mọi cấp), trường lạ, thiếu trường bắt buộc, sai kiểu (Type Confusion), sai định dạng, JSON hỏng,
tham số lặp (HTTP Parameter Pollution). Thêm endpoint mới = thêm 1 mục vào `SCHEMAS`.

**Cấu hình** (đầu file `security_check.lua`):
| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `STRICT_MODE` | `true` | Bật thêm luật dấu `'` và `;` đúng đề cương. Bắt được cả `q='` nhưng gây False Positive (O'Brien). `false` = ít FP hơn, bỏ lọt payload thăm dò chỉ có dấu nháy. |
| `RATE_LIMIT` | `false` | Bật giới hạn tốc độ: `RATE_MAX` request / `RATE_WINDOW` giây cho mỗi IP (mặc định 100 / 10 s). Test: `python tests/rate_limit_test.py`. |
| `AUTO_BLOCK` | `false` | Tự khóa IP khi vi phạm ≥ `BLOCK_THRESHOLD` lần / `WINDOW` giây (khóa `BAN_SECONDS` giây). Để tắt khi demo/load test từ cùng một máy. |

## 4. Active Defense & Logging
- Vi phạm → `ngx.status = 403`, JSON `{"status":"blocked","attack_type":...,"reason":...}`, rồi `ngx.exit(403)` → **không chạy xuống `proxy_pass`**.
- Mỗi lần chặn ghi 1 dòng JSON (`timestamp, client_ip, method, uri, attack_type, rule, location, payload, action`) vào
  `gateway/logs/security_alerts.json` và `ngx.log` (hiện trong `docker logs`).

## 5. Đo hiệu năng (Mục 4.1)
Tắt log truy cập khi benchmark để không bị nhiễu: trong `nginx.conf` đổi `access_log /dev/stdout;` thành `access_log off;` rồi `docker compose restart gateway`.
```bash
# Cách 1: wrk (khuyến nghị)
wrk -t2 -c10 -d15s --latency http://localhost:5000/api/health   # trực tiếp backend
wrk -t2 -c10 -d15s --latency http://localhost/api/health        # qua gateway

# Cách 2: script Python (chỉ cần Python 3)
python tests/load_test.py -n 5000 -c 10
python tests/load_test.py -n 5000 -c 10 --path "/api/search?q=phu"
```
Mỗi response qua gateway có header **`X-Inspection-Time-Us`** = thời gian riêng của bộ lọc Lua (micro giây) – dùng làm số liệu chính chứng minh "< 5 ms".
Để tách riêng chi phí proxy và chi phí Lua, đo thêm lần thứ ba với dòng `access_by_lua_file` được comment lại.
Lưu ý: nên giữ số kết nối thấp (c = 1–10); backend Python 1 tiến trình bão hòa rất sớm, khi đó độ trễ đo được chủ yếu là thời gian xếp hàng ở backend chứ không phải overhead của gateway.

## 6. Ẩn backend khi triển khai thật
Trong `docker-compose.yml`, xóa mục `ports: - "5000:5000"` của service `backend`: backend chỉ còn truy cập được từ gateway qua mạng Docker nội bộ.
(Giữ lại khi demo Trạng thái 1.)

## 7. Các quyết định thiết kế (chốt các điểm chưa thống nhất giữa các tài liệu)
| # | Vấn đề | Quyết định trong dự án |
|---|---|---|
| 1 | Backend "ẩn hoàn toàn" nhưng demo lại tấn công cổng 5000 | Giữ `5000:5000` trong compose **chỉ để demo/đo tải**; khi triển khai thật xóa dòng này (mục 6). Trong báo cáo nêu rõ đây là cổng dành cho thực nghiệm đối chứng. |
| 2 | Phạm vi lõi / nâng cao | **Lõi:** Reverse Proxy, SQLi Regex, Whitelist Schema, 403 + JSON log, Dashboard. **Nâng cao đã làm:** tự khóa IP bằng `lua_shared_dict` (mặc định tắt). **Chưa làm (hướng phát triển):** libinjection, Redis, iptables, Grafana+Loki, Traefik. |
| 3 | Dashboard | Tự viết `/admin/dashboard` + `/admin/logs` đọc file JSON (không dùng Grafana+Loki) – nhẹ, không thêm container. |
| 4 | "JSON Schema" hay "Whitelist Schema" | Cài đặt là **Whitelist Schema viết tay bằng Lua + cjson** (bảng `SCHEMAS`), không dùng thư viện JSON Schema chuẩn. Báo cáo nên mô tả đúng như vậy. |
| 5 | False Positive của `'` và `;` | Có cờ `STRICT_MODE`; `attack_tests.py` có nhóm request sạch + nhóm chuỗi dễ nhầm (O'Brien) để đo và nêu ở mục 4.2. |
| 6 | Số liệu "< 5 ms" | Phải tự đo (mục 5); header `X-Inspection-Time-Us` cho số liệu riêng của Lua. |

## 8. Bảng theo dõi tiến độ
| Hạng mục | Mục BC | Mã nguồn | Việc còn lại của bạn |
|---|---|---|---|
| Cấu hình Lua trong nginx.conf | 3.3 | Xong | Chụp ảnh file cấu hình |
| utils.lua + security_check.lua | 3.4 | Xong | Chụp ảnh mã nguồn |
| app.py có lỗ hổng + giải thích | 3.5 | Xong | Chụp ảnh `app.py` |
| Active Defense + JSON Logging + Dashboard | 3.6 | Xong | Chụp Dashboard |
| Test & ảnh chứng minh SQLi | 3.7 | Script sẵn | `attack_demo.sh 1` / `2`, chụp 403 + docker logs |
| Test & ảnh chứng minh API Injection | 3.8 | Script sẵn | Như trên, chụp log `API_INJECTION` |
| Đo tải & độ trễ (5000 vs 80) | 4.1 | Script sẵn | Chạy trên máy bạn, điền bảng |
| Ưu/nhược điểm, hướng phát triển, TLTK | 4.2, 4.3 | – | Đã có bản nháp trong báo cáo; đọc lại và chỉnh |
| Chương 1, 2, 3.1, 3.2 | – | – | Đã có bản nháp; chỉnh theo yêu cầu của khoa |

## 9. Đối chiếu yêu cầu của đề tài với mã nguồn
| Yêu cầu (tài liệu nguồn) | Trạng thái | Nằm ở đâu |
|---|---|---|
| Reverse Proxy OpenResty, mọi request qua cổng 80 (Đề tài, Roadmap GĐ1) | Xong | `gateway/conf/nginx.conf` |
| `lua_package_path` + `access_by_lua_file` trước `proxy_pass` (URGENT mục 1) | Xong | `nginx.conf` |
| Bóc tách URL args, Headers, Body JSON/Form (Roadmap GĐ2, URGENT mục 2) | Xong | `utils.lua` |
| URL Decode chống `%27` (URGENT mục 2) | Xong (giải mã tới 3 lớp) | `utils.lua` |
| SQLi bằng Regex: UNION SELECT, OR 1=1, `'`, `--`, `;`, sleep (Roadmap GĐ3) | Xong | `security_check.lua` |
| API Injection / Mass Assignment bằng cjson + whitelist, kiểu dữ liệu, định dạng email (GĐ3) | Xong | `security_check.lua` (`SCHEMAS`) |
| Parameter Filtering: Command Injection (Đề tài, khối B) | Xong (bổ sung) | `security_check.lua` (`CMDI_RULES`) |
| Rate Limiting & Throttling (Đề tài, khối B) | Xong (bổ sung, mặc định tắt) | `security_check.lua` |
| Chặn 403 + JSON + `ngx.exit` (URGENT mục 3) | Xong | `utils.block()` |
| Log JSON: timestamp, IP, method, uri, attack_type, payload (URGENT mục 3) | Xong | `utils.log_alert()` |
| Dashboard `/admin/logs` realtime (Roadmap GĐ4) | Xong | `admin_logs.lua`, `dashboard.html` |
| Active Defense: tự khóa IP khi vượt ngưỡng (Đề tài, khối C) | Xong (Nginx deny-list bằng `lua_shared_dict`, mặc định tắt) | `security_check.lua` |
| Backend có lỗ hổng cố ý, bảng users/products/articles (Roadmap GĐ1) | Xong (bổ sung 2 bảng) | `backend/app.py` |
| Docker Compose gateway + backend + database, mạng bridge (Roadmap GĐ1) | Xong (DB = SQLite trong volume) | `docker-compose.yml` |
| `docker compose up --scale backend=3` (Đề tài) | Xong (bổ sung: bỏ `container_name`, dải cổng 5000-5010) | `docker-compose.yml` |
| Attacker Lab / Postman / cURL / script Python (Tổng quan, Tools) | Xong (bổ sung container `attacker` + Postman collection) | `tests/` |
| wrk hoặc locust (Tools) | Xong | README mục 5, `locustfile.py`, `load_test.py` |
| Kịch bản demo 3 trạng thái | Xong | `tests/attack_demo.sh` |
| 2 phiên bản endpoint: trực tiếp vs sau Gateway (Đề tài, khối D) | Xong | cổng 5000 (trực tiếp) và cổng 80 (qua Gateway) |
| **Chưa làm – tùy chọn "nếu còn thời gian":** libinjection, Redis Rate Limiting, iptables, Grafana + Loki, Traefik, HTTPS/TLS (cổng 443), BOLA, tự sinh schema từ OpenAPI | – | Nêu trong báo cáo mục 4.3 (hướng phát triển) |
| **Việc của bạn:** chụp ảnh minh chứng, đo hiệu năng trên máy bạn, vẽ sơ đồ | – | README mục 2, 5, 8 |

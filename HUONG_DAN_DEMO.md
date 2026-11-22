# Hướng dẫn chạy demo và sử dụng các bộ test

Áp dụng cho Windows + Docker Desktop. Mở **PowerShell** (hoặc Terminal của VS Code) tại thư mục dự án, ví dụ `D:\security-gateway-project`.
Trong PowerShell hãy gõ `curl.exe` (không phải `curl`, vì `curl` là bí danh của một lệnh khác).

---

## PHẦN A. Chạy demo tuần tự (kịch bản khoảng 10 phút)

### Bước 0. Khởi động sạch
```powershell
docker compose down -v --remove-orphans     # -v: xóa dữ liệu SQLite cũ -> về trạng thái ban đầu
docker compose up -d --build
docker compose ps                            # gateway (80) và backend (5000) phải ở trạng thái running
```
Mở sẵn 3 thứ để chiếu: (1) trình duyệt tại `http://localhost/admin/dashboard`, (2) cửa sổ log `docker compose logs -f`, (3) Postman.

### Bước 1. Request sạch đi qua Gateway
```powershell
curl.exe -i "http://localhost/api/search?q=phu"
```
Kỳ vọng: `200 OK`, có header `X-Protected-By` và `X-Inspection-Time-Us` (thời gian riêng của bộ lọc Lua, đơn vị micro giây).
Ý nghĩa: Gateway không cản trở người dùng hợp lệ.

### Bước 2. Trạng thái 1 – tấn công thẳng vào Backend (cổng 5000, không có Gateway)
```powershell
curl.exe -G "http://localhost:5000/api/search" --data-urlencode "q=' UNION SELECT 1,name,sql,0 FROM sqlite_master --"
curl.exe -X POST "http://localhost:5000/api/update-profile" -H "Content-Type: application/json" -d "{\"username\":\"chauhoangphu\",\"email\":\"hack@evil.com\",\"is_admin\":true}"
curl.exe "http://localhost:5000/api/search?q=chauhoangphu"
docker compose logs --tail 5 backend
```
Kỳ vọng: lộ toàn bộ cấu trúc bảng (`CREATE TABLE ...`); user `chauhoangphu` bị nâng `is_admin = true`; log backend có dòng `[EXECUTING SQL]` chứa payload.
Ý nghĩa: chứng minh ứng dụng gốc có lỗ hổng. Bước này **làm thay đổi dữ liệu** nên demo xong cần reset (Bước 0).

### Bước 3. Trạng thái 2 – gửi đúng payload đó qua Gateway (cổng 80)
```powershell
curl.exe -i -G "http://localhost/api/search" --data-urlencode "q=' OR '1'='1"
curl.exe -i -X POST "http://localhost/api/update-profile" -H "Content-Type: application/json" -d "{\"username\":\"chauhoangphu\",\"email\":\"hack@evil.com\",\"is_admin\":true}"
docker compose logs --tail 5 gateway     # có dòng [SECURITY_ALERT] {...JSON...}
docker compose logs --tail 5 backend     # KHÔNG có dòng [EXECUTING SQL] mới
```
Kỳ vọng: `403 Forbidden` + JSON có `attack_type` (`SQL_INJECTION` hoặc `API_INJECTION`), `rule`, `reason`. Dashboard xuất hiện thêm dòng cảnh báo (nhấp nháy). File `gateway\logs\security_alerts.json` có thêm bản ghi.
Ý nghĩa: request độc hại bị chặn tại biên, backend không hề nhận được.

### Bước 4. Các kỹ thuật né tránh vẫn bị chặn (chọn 2–3 ví dụ)
```powershell
curl.exe -i -G "http://localhost/api/search" --data-urlencode "q=1' UNION/**/SELECT/**/1,2,3,4--"      # chèn comment
curl.exe -i "http://localhost/api/search?q=%2527%2520OR%2520%25271%2527%253D%25271"                      # mã hóa URL 2 lớp
curl.exe -i -G "http://localhost/api/search" --data-urlencode "q=x; cat /etc/passwd"                    # Command Injection
```

### Bước 5. Đo hiệu năng
```powershell
python tests\load_test.py -n 3000 -c 10
```
Ghi lại bảng RPS và độ trễ trung bình của hai chế độ. Thời gian riêng của Lua lấy từ header `X-Inspection-Time-Us` (xem Postman request 0.1).

### Bước 6 (tùy chọn). Rate Limiting
Đổi `RATE_LIMIT = true` trong `gateway\lua\security_check.lua`, chạy `docker compose restart gateway`, rồi `python tests\rate_limit_test.py` (100 request đầu qua, sau đó 429). Xong nhớ đặt lại `false`.

---

## PHẦN B. Các bộ test hoạt động thế nào

| Bộ test | Lệnh | Làm gì | Khi nào dùng |
|---|---|---|---|
| `attack_demo.sh` | `bash tests/attack_demo.sh 1` / `2` | Chạy các lệnh cURL của Trạng thái 1 và 2, in ra kết quả | Demo nhanh bằng dòng lệnh (cần Git Bash hoặc WSL) |
| `attack_tests.py` | `python tests\attack_tests.py --no-backend` | Gửi ~26 payload tấn công và ~18 request sạch qua Gateway, in bảng kết quả và **Detection rate / False Positive** | Lấy số liệu cho báo cáo (mục 3.7, 3.8, 4.2). `--no-backend` để không sửa dữ liệu backend |
| `attacker` (Docker) | `docker compose --profile lab run --rm attacker` | Chạy `attack_tests.py` từ **bên trong** mạng Docker (gọi `http://gateway`, `http://backend:5000`) | Khi không muốn cài Python trên máy |
| `load_test.py` | `python tests\load_test.py -n 3000 -c 10` | Bắn request sạch vào backend (5000) rồi vào Gateway (80), so sánh RPS, độ trễ trung bình, P95, P99 | Mục 4.1 |
| `locustfile.py` | `locust -f tests\locustfile.py --host http://localhost` | Đo tải bằng giao diện web Locust (`http://localhost:8089`) | Thay `wrk` nếu thích giao diện |
| `rate_limit_test.py` | `python tests\rate_limit_test.py` | Gửi 150 request liên tiếp, đếm số 200 và 429 | Kiểm thử Rate Limiting |
| Postman | xem Phần C | Từng request riêng lẻ, có assert tự động | Xem chi tiết từng thao tác, chụp ảnh |

Cách đọc kết quả `attack_tests.py`: mỗi dòng là một payload, cột `backend` là mã trạng thái khi gửi thẳng (200 nghĩa là bị khai thác), cột `gateway` là mã khi qua Gateway (403 là bị chặn).
Cuối bảng có `Detection rate` (tỷ lệ payload bị chặn) và `FP rate` (tỷ lệ request sạch bị chặn nhầm).

---

## PHẦN C. Dùng Postman để xem thao tác chi tiết

### C1. Nhập dữ liệu
1. Postman → **Import** → kéo thả hai file trong thư mục `tests\`: `postman_collection.json` và `SecurityGateway.postman_environment.json`.
2. Góc trên bên phải, chọn môi trường **SecurityGateway - Local Docker** (có hai biến: `gateway = http://localhost`, `backend = http://localhost:5000`).

### C2. Cấu trúc collection (chạy theo thứ tự 0 → 5)
| Thư mục | Nội dung | Kỳ vọng |
|---|---|---|
| 0. Kiểm tra hệ thống | health của Gateway, Backend, trang Dashboard | 200 |
| 1. TRẠNG THÁI 1 | Tấn công trực tiếp backend (5 request). **Sửa dữ liệu thật** | 200, dữ liệu bị lộ, user bị nâng quyền |
| 2. TRẠNG THÁI 2 | Cùng payload qua Gateway: 2A SQLi (11), 2B Command Injection (4), 2C API Injection (12) | 403 + `attack_type` + `rule` |
| 3. Request SẠCH | Tìm kiếm thường, tiếng Việt, cập nhật profile hợp lệ | 200 |
| 4. Hạn chế đã biết | `O'Brien`, `hello; world` | 403 (False Positive có chủ đích, minh họa mục 4.2) |
| 5. Log & Dashboard | Gọi `/admin/logs` | Có bản ghi mới nhất |
| 6. Rate Limiting | Spam request | 200 rồi 429 (chỉ khi đã bật) |

### C3. Thao tác từng request
1. Chọn request → **Send**.
2. Xem **Body** (JSON phản hồi), **Headers** (tìm `X-Blocked-By`, `X-Protected-By`, `X-Inspection-Time-Us`) và tab **Test Results** (các dấu tích xanh/đỏ).
3. Xem chính xác request đã gửi đi: menu **View → Show Postman Console** (hoặc `Ctrl+Alt+C`) hiển thị URL sau khi mã hóa, header, body.
4. Tab **Docs** hoặc mô tả của từng request có ghi mục đích và ảnh nào cần chụp cho báo cáo.

### C4. Chạy cả collection bằng Runner
Chuột phải collection → **Run collection** → tick các thư mục cần chạy → **Run**. Kết quả tổng hợp số request và số assertion pass/fail.
- Chạy **0, 2, 3, 5** để có bộ kết quả không làm đổi dữ liệu.
- Thư mục 6: đặt `Iterations = 120`, `Delay = 0` sau khi bật `RATE_LIMIT`.
- Thư mục 4 sẽ FAIL nếu bạn tắt `STRICT_MODE` (vì khi đó không còn chặn nhầm). Đó là kết quả đúng.

### C5. Chạy bằng dòng lệnh (Newman, tùy chọn)
```powershell
npm install -g newman
newman run tests\postman_collection.json -e tests\SecurityGateway.postman_environment.json
```
Bản trong hướng dẫn này đã được chạy thử: 43 request, 161 assertion, 0 lỗi.

---

## PHẦN D. Danh sách ảnh minh chứng cho báo cáo

| Mục báo cáo | Chụp gì | Lấy ở đâu |
|---|---|---|
| 3.3, 3.4 | File `nginx.conf`, `utils.lua`, `security_check.lua` | VS Code |
| 3.5 | `backend\app.py` (hai endpoint có lỗ hổng) | VS Code |
| 3.6 | Dashboard có các dòng cảnh báo; file `security_alerts.json` | Trình duyệt, VS Code |
| 3.7 | Request 1.1/1.2 (trực tiếp backend, 200); request 2A.1 (Gateway, 403); log gateway có `[SECURITY_ALERT]`; log backend không có `[EXECUTING SQL]` mới | Postman, Docker Desktop |
| 3.8 | Request 1.4 (backend chấp nhận); request 2C.1 (Gateway, 403); log `API_INJECTION` | Postman, Docker Desktop |
| 4.1 | Bảng kết quả `load_test.py`; header `X-Inspection-Time-Us` ở request 0.1 | Terminal, Postman |
| 4.2 | Bảng `attack_tests.py` (Detection rate, FP); thư mục 4 | Terminal, Postman |

---

## PHẦN E. Xử lý sự cố
| Hiện tượng | Cách xử lý |
|---|---|
| `port is already allocated` hoặc `container name already in use` | `docker compose down --remove-orphans`, nếu còn: `docker rm -f target_backend security_gateway` |
| Gateway trả `502 Bad Gateway` | Backend chưa lên hoặc đang khởi động lại. `docker compose ps` rồi `docker compose logs backend` |
| Dashboard không hiện gì / `403` khi mở `/admin/dashboard` | Chỉ cho phép IP nội bộ. Truy cập bằng `http://localhost` trên chính máy chạy Docker |
| Sửa file `.lua` nhưng không thấy thay đổi | `docker compose restart gateway` |
| Sửa `app.py` nhưng không thấy thay đổi | `docker compose up -d --build` (backend được đóng gói vào image) |
| Thư mục 1 trong Postman chạy lần hai cho kết quả khác | Dữ liệu đã bị sửa ở lần trước. Reset bằng Bước 0 |
| Mọi request bị `429` | `RATE_LIMIT` đang bật, đợi 10 giây hoặc đặt lại `false` rồi restart gateway |
| `curl` trong PowerShell báo lỗi lạ | Dùng `curl.exe` thay cho `curl` |

#!/usr/bin/env python3
"""
attack_tests.py - Bộ kiểm thử đối chứng cho Security Gateway (Mục 3.7, 3.8)

Gửi cùng một tập payload tới 2 địa chỉ:
    - BACKEND trực tiếp (cổng 5000)   -> chứng minh lỗ hổng tồn tại
    - GATEWAY (cổng 80)               -> chứng minh gateway chặn được (HTTP 403)
Đồng thời gửi tập request SẠCH để đo False Positive.

Chạy:   pip install requests
        python tests/attack_tests.py
        python tests/attack_tests.py --gateway http://localhost --backend http://localhost:5000
"""
import argparse, json, sys
import requests

# --------------------------------------------------------------------------
# DATASET (theo Module_Dataset.docx, mục 3: OWASP Top 10 / OWASP API Security)
# --------------------------------------------------------------------------
SQLI_PAYLOADS = [
    # (tên mẫu, payload)
    ("Mẫu 1  - Bẻ gãy logic xác thực",   "' OR '1'='1"),
    ("Mẫu 1b - Tautology số",            "1' OR 1=1 --"),
    ("Mẫu 2  - UNION trích xuất dữ liệu", "1' UNION SELECT null, username, password FROM users --"),
    ("Mẫu 2b - UNION lộ schema",         "' UNION SELECT 1,name,sql,0 FROM sqlite_master --"),
    ("Mẫu 3  - Comment cắt câu lệnh",    "admin' --"),
    ("Mẫu 3b - Stacked query",           "x'; DROP TABLE users;--"),
    ("Time-based blind (SQLite)",        "1' AND 1=randomblob(300000000) --"),
    ("Thăm dò lỗi (dấu nháy đơn)",       "'"),
    # --- biến thể né tránh (evasion) ---
    ("Evasion: UNION/**/SELECT",         "1' UNION/**/SELECT/**/1,2,3,4--"),
    ("Evasion: chữ hoa/thường",          "' UnIoN SeLeCt 1,2,3,4 --"),
    ("Evasion: mã hóa 2 lớp (%2527)",    "%27 OR %271%27=%271"),
]

# Command Injection / Path Traversal (Parameter Filtering) - gửi qua tham số q
CMDI_PAYLOADS = [
    ("Command chaining: ; cat /etc/passwd", "x; cat /etc/passwd"),
    ("Command chaining: && whoami",         "x && whoami"),
    ("Command chaining: | ls",              "x | ls -la"),
    ("Command substitution: $(id)",         "$(id)"),
    ("Command substitution: `uname -a`",    "`uname -a`"),
    ("Path traversal: ../../etc/passwd",    "../../etc/passwd"),
    ("Path traversal mã hóa %2e%2e%2f",     "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
]

def api_injection_cases():
    # (tên mẫu, JSON body gửi lên /api/update-profile)
    return [
        ("Mẫu 1  - Leo thang đặc quyền (role + is_admin)",
         {"username": "phu", "role": "administrator", "is_admin": True}),
        ("Mass assignment: chỉ is_admin",
         {"username": "chauhoangphu", "email": "a@b.com", "is_admin": True}),
        ("Mass assignment: is_admin lồng nhau",
         {"username": "phu", "profile": {"IsAdmin": 1}}),
        ("Mẫu 2  - Type Confusion (age là chuỗi)",
         {"username": "phu", "age": "20; DROP TABLE users"}),
        ("Type Confusion: age là object",
         {"username": "phu", "age": {"$gt": 0}}),
        ("Trường lạ ngoài whitelist",
         {"username": "phu", "debug": "true"}),
        ("Thiếu trường bắt buộc",
         {"email": "a@b.com"}),
        ("SQLi trong giá trị JSON",
         {"username": "admin' OR '1'='1", "email": "a@b.com"}),
    ]

BENIGN_SEARCH = ["cat", "id", "bash scripting", "c++ & python", "a | b", "phu", "chauhoangphu", "nguyen", "admin", "hutech", "Nguyễn Thành", "john doe", "a.b-c_d", "123", ""]
BENIGN_PROFILES = [
    {"username": "chauhoangphu", "email": "phu@hutech.edu.vn"},
    {"username": "nguyenthanhphi", "email": "phi@gmail.com", "age": 21},
    {"username": "demo_user-01"},
]
# Văn bản hợp lệ nhưng có thể làm Regex nhầm (để minh họa False Positive - mục 4.2)
FP_PRONE = [
    ("Tên có dấu nháy: O'Brien", "O'Brien"),
    ("Văn bản có dấu chấm phẩy", "hello; world"),
]

def get(session, base, q):
    return session.get(base + "/api/search", params={"q": q}, timeout=10)

def post(session, base, body):
    return session.post(base + "/api/update-profile", json=body, timeout=10)

def short(r):
    try:
        t = r.text.replace("\n", " ")
    except Exception:
        t = ""
    return t[:70]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://localhost")
    ap.add_argument("--backend", default="http://localhost:5000")
    ap.add_argument("--no-backend", action="store_true", help="bỏ qua tấn công trực tiếp backend (tránh sửa DB thật)")
    a = ap.parse_args()
    s = requests.Session()

    rows = []   # (nhóm, tên, backend_status, gateway_status)
    def line(group, name, b, g):
        rows.append((group, name, b, g))
        print(f"{group:<8} {name:<50} backend={b!s:<5} gateway={g!s:<5}")

    print("=" * 100); print("A. SQL INJECTION  (GET /api/search?q=...)"); print("=" * 100)
    for name, p in SQLI_PAYLOADS:
        b = "-" if a.no_backend else get(s, a.backend, p).status_code
        g = get(s, a.gateway, p).status_code
        line("SQLi", name, b, g)

    print(); print("=" * 100); print("A2. COMMAND INJECTION / PATH TRAVERSAL  (GET /api/search?q=...)"); print("=" * 100)
    for name, p in CMDI_PAYLOADS:
        b = "-" if a.no_backend else get(s, a.backend, p).status_code
        g = get(s, a.gateway, p).status_code
        line("CMDi", name, b, g)

    print(); print("=" * 100); print("B. API INJECTION / MASS ASSIGNMENT  (POST /api/update-profile)"); print("=" * 100)
    for name, body in api_injection_cases():
        b = "-" if a.no_backend else post(s, a.backend, body).status_code
        g = post(s, a.gateway, body).status_code
        line("API", name, b, g)

    print(); print("=" * 100); print("C. REQUEST SẠCH (kỳ vọng 200 - nếu 403 là False Positive)"); print("=" * 100)
    for q in BENIGN_SEARCH:
        line("CLEAN", f"GET q={q!r}", "-", get(s, a.gateway, q).status_code)
    for body in BENIGN_PROFILES:
        line("CLEAN", "POST " + json.dumps(body, ensure_ascii=False)[:42], "-", post(s, a.gateway, body).status_code)

    print(); print("=" * 100); print("D. CHUỖI HỢP LỆ DỄ GÂY FALSE POSITIVE (minh họa hạn chế - mục 4.2)"); print("=" * 100)
    for name, q in FP_PRONE:
        line("FP?", name, "-", get(s, a.gateway, q).status_code)

    # ---------------- Tổng kết ----------------
    atk = [r for r in rows if r[0] in ("SQLi", "CMDi", "API")]
    clean = [r for r in rows if r[0] == "CLEAN"]
    blocked = sum(1 for r in atk if r[3] == 403)
    fp = sum(1 for r in clean if r[3] == 403)
    print(); print("=" * 100); print("TỔNG KẾT"); print("=" * 100)
    print(f"Số payload tấn công          : {len(atk)}")
    print(f"Bị Gateway chặn (403)        : {blocked}  -> Detection rate = {blocked/len(atk)*100:.1f}%")
    print(f"Request sạch                 : {len(clean)}")
    print(f"Bị chặn nhầm (False Positive): {fp}  -> FP rate = {fp/len(clean)*100:.1f}%")
    missed = [r for r in atk if r[3] != 403]
    if missed:
        print("\nPayload LỌT qua gateway:")
        for r in missed: print("  -", r[1], "->", r[3])
    return 0

if __name__ == "__main__":
    sys.exit(main())

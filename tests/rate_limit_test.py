#!/usr/bin/env python3
"""
rate_limit_test.py - Kiểm thử Rate Limiting chống brute-force (đề tài: Rate Limiting & Throttling)

Bước chuẩn bị: trong gateway/lua/security_check.lua đặt  RATE_LIMIT = true  (RATE_MAX/RATE_WINDOW tùy chọn),
rồi `docker compose restart gateway`. Sau khi test nhớ đặt lại false để không ảnh hưởng load test.

Chạy:  python tests/rate_limit_test.py [--url http://localhost] [-n 150]
Kỳ vọng: những request đầu trả 200, sau khi vượt RATE_MAX trong RATE_WINDOW giây trả 429.
"""
import argparse, collections
import requests

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://localhost")
ap.add_argument("-n", type=int, default=150)
a = ap.parse_args()

s = requests.Session()
codes = collections.Counter()
first_429 = None
for i in range(1, a.n + 1):
    c = s.get(a.url + "/api/search", params={"q": "phu"}, timeout=10).status_code
    codes[c] += 1
    if c == 429 and first_429 is None:
        first_429 = i
print("Phân bố mã trạng thái:", dict(codes))
print("Request đầu tiên bị 429:", first_429 if first_429 else "không có (Rate Limit đang tắt?)")

#!/usr/bin/env python3
"""
load_test.py - Đo RPS và độ trễ (Mục 4.1). Chỉ dùng thư viện chuẩn Python (asyncio).

So sánh 2 chế độ với cùng số request SẠCH:
    - Trực tiếp Backend  (cổng 5000)
    - Qua Security Gateway (cổng 80)
Mỗi "kết nối" giữ keep-alive (giống trình duyệt/wrk), gửi HTTP/1.1 thô để overhead phía client thấp nhất.

Chạy:  python tests/load_test.py                      # mặc định 3000 request, 50 kết nối
       python tests/load_test.py -n 5000 -c 100 --path "/api/search?q=phu"
"""
import argparse, asyncio, statistics, time
from urllib.parse import urlparse


async def worker(host, port, path, n_req, lat, errors):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n").encode()
    reader, writer = await asyncio.open_connection(host, port)
    for _ in range(n_req):
        if writer.is_closing():                      # server đã đóng keep-alive -> mở lại kết nối
            reader, writer = await asyncio.open_connection(host, port)
        t0 = time.perf_counter()
        try:
            writer.write(req)
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            status = int(head.split(b" ", 2)[1])
            clen = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":")[1])
            if clen:
                await reader.readexactly(clen)
            else:
                # chunked / không có content-length: đọc tới hết chunk cuối
                body = await reader.readuntil(b"0\r\n\r\n") if b"chunked" in head.lower() else b""
            if status != 200:
                errors.append(status)
            if b"connection: close" in head.lower():   # nginx đóng kết nối sau N request
                writer.close()
        except Exception as e:                       # noqa
            errors.append(str(e))
            return
        lat.append((time.perf_counter() - t0) * 1000)
    writer.close()


async def run(url, total, conns):
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    per = total // conns
    lat, errors = [], []
    # khởi động nóng 200 request
    await asyncio.gather(*[worker(host, port, path, 4, [], []) for _ in range(50)])
    t0 = time.perf_counter()
    await asyncio.gather(*[worker(host, port, path, per, lat, errors) for _ in range(conns)])
    dur = time.perf_counter() - t0
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]
    return dict(requests=len(lat), errors=len(errors), seconds=dur, rps=len(lat) / dur,
                avg=statistics.mean(lat), p50=pct(.50), p95=pct(.95), p99=pct(.99))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:5000")
    ap.add_argument("--gateway", default="http://localhost")
    ap.add_argument("--path", default="/api/health")
    ap.add_argument("-n", "--requests", type=int, default=3000)
    ap.add_argument("-c", "--connections", type=int, default=50)
    ap.add_argument("--rounds", type=int, default=3, help="số lượt lặp, lấy trung bình")
    a = ap.parse_args()

    res = {}
    for name, base in (("Backend trực tiếp (:5000)", a.backend), ("Qua Gateway (:80)", a.gateway)):
        runs = [asyncio.run(run(base + a.path, a.requests, a.connections)) for _ in range(a.rounds)]
        res[name] = {k: statistics.mean(r[k] for r in runs) for k in runs[0]}

    print(f"\nPath: {a.path} | {a.requests} request x {a.rounds} lượt | {a.connections} kết nối đồng thời\n")
    print(f"{'Chế độ':<28}{'RPS':>10}{'Avg (ms)':>11}{'P50':>9}{'P95':>9}{'P99':>9}{'Lỗi':>6}")
    print("-" * 82)
    for name, r in res.items():
        print(f"{name:<28}{r['rps']:>10.0f}{r['avg']:>11.2f}{r['p50']:>9.2f}{r['p95']:>9.2f}{r['p99']:>9.2f}{r['errors']:>6.0f}")
    b, g = list(res.values())
    print("-" * 82)
    print(f"Độ trễ chèn thêm bởi Gateway (avg): {g['avg'] - b['avg']:+.2f} ms   "
          f"| RPS thay đổi: {(g['rps'] / b['rps'] - 1) * 100:+.1f}%")


if __name__ == "__main__":
    main()

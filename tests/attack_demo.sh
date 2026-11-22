#!/usr/bin/env bash
# =============================================================================
# attack_demo.sh - Kịch bản demo 3 bước (Mục 3.7, 3.8 + bảo vệ trước Hội đồng)
#   Dùng: bash tests/attack_demo.sh            # chạy tất cả
#         bash tests/attack_demo.sh 1|2|3      # chạy riêng từng trạng thái
# Biến môi trường: GATEWAY (mặc định http://localhost)  BACKEND (mặc định http://localhost:5000)
# Windows: chạy trong Git Bash hoặc WSL.
# =============================================================================
GATEWAY="${GATEWAY:-http://localhost}"
BACKEND="${BACKEND:-http://localhost:5000}"
SQLI="' OR '1'='1"
UNION="' UNION SELECT 1,name,sql,0 FROM sqlite_master --"
MASS='{"username":"chauhoangphu","email":"hack@evil.com","is_admin":true}'

hr() { printf '\n\033[1;36m==== %s ====\033[0m\n' "$1"; }
show() { printf '\033[0;33m$ %s\033[0m\n' "$*"; }

state1() {
  hr "TRẠNG THÁI 1: Tấn công TRỰC TIẾP Backend ($BACKEND) - không có Gateway"
  show "curl -G $BACKEND/api/search --data-urlencode \"q=$UNION\""
  curl -s -G "$BACKEND/api/search" --data-urlencode "q=$UNION" | python3 -m json.tool 2>/dev/null || true
  echo
  show "curl -X POST $BACKEND/api/update-profile -d '$MASS'"
  curl -s -X POST "$BACKEND/api/update-profile" -H 'Content-Type: application/json' -d "$MASS"; echo
  echo "-> Kiểm tra: user 'chauhoangphu' đã bị nâng quyền is_admin = true"
  curl -s -G "$BACKEND/api/search" --data-urlencode "q=chauhoangphu"; echo
}

state2() {
  hr "TRẠNG THÁI 2: Gửi lại CHÍNH các payload đó qua Security Gateway ($GATEWAY)"
  show "curl -i -G $GATEWAY/api/search --data-urlencode \"q=$SQLI\"     # Mục 3.7"
  curl -i -s -G "$GATEWAY/api/search" --data-urlencode "q=$SQLI"; echo
  show "curl -i -G $GATEWAY/api/search --data-urlencode \"q=$UNION\""
  curl -i -s -G "$GATEWAY/api/search" --data-urlencode "q=$UNION"; echo
  show "curl -i -X POST $GATEWAY/api/update-profile -d '$MASS'   # Mục 3.8"
  curl -i -s -X POST "$GATEWAY/api/update-profile" -H 'Content-Type: application/json' -d "$MASS"; echo
  hr "Request SẠCH vẫn đi qua bình thường (kỳ vọng 200)"
  show "curl -i -G $GATEWAY/api/search --data-urlencode \"q=phu\""
  curl -i -s -G "$GATEWAY/api/search" --data-urlencode "q=phu"; echo
  echo
  echo "-> Mở Dashboard: $GATEWAY/admin/dashboard   |   Xem log Docker: docker logs security_gateway"
  echo "-> Backend KHÔNG còn dòng [EXECUTING SQL] cho các request bị chặn: docker compose logs backend"
}

state3() {
  hr "TRẠNG THÁI 3: Hiệu năng (xem README mục 5)"
  python3 "$(dirname "$0")/load_test.py" --backend "$BACKEND" --gateway "$GATEWAY"
}

case "${1:-all}" in
  1) state1;; 2) state2;; 3) state3;;
  *) state1; state2;;
esac

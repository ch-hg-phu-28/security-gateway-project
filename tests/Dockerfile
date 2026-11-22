# "Attacker Lab": container chạy bộ kiểm thử từ BÊN TRONG mạng Docker (gọi gateway / backend theo tên service)
FROM python:3.11-slim
RUN pip install --no-cache-dir requests
WORKDIR /tests
CMD ["python", "attack_tests.py", "--gateway", "http://gateway", "--backend", "http://backend:5000"]

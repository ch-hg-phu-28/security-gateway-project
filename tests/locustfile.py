"""
locustfile.py - Đo tải bằng Locust (thay thế wrk).   pip install locust
Chạy giao diện web:  locust -f tests/locustfile.py --host http://localhost         (mở http://localhost:8089)
Chạy không giao diện: locust -f tests/locustfile.py --host http://localhost --headless -u 20 -r 10 -t 30s
So sánh: lặp lại với --host http://localhost:5000 (trực tiếp backend).
"""
from locust import HttpUser, task, between


class CleanTraffic(HttpUser):
    wait_time = between(0.001, 0.01)

    @task(3)
    def health(self):
        self.client.get("/api/health")

    @task(2)
    def search(self):
        self.client.get("/api/search", params={"q": "phu"})

    @task(1)
    def update_profile(self):
        self.client.post("/api/update-profile",
                         json={"username": "chauhoangphu", "email": "phu@hutech.edu.vn"})

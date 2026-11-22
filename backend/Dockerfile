# Sử dụng Python image chính thức, bản nhẹ (slim)
FROM python:3.11-slim

# Thiết lập thư mục làm việc bên trong container
WORKDIR /app

# Copy file danh sách thư viện vào container
COPY requirements.txt .

# Cài đặt các thư viện Python cần thiết
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn ứng dụng (app.py, v.v.) vào container
COPY . .

# Mở cổng 5000 để ứng dụng lắng nghe kết nối
EXPOSE 5000

# Lệnh để khởi chạy ứng dụng FastAPI bằng Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
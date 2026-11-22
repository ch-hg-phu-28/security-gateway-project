from fastapi import FastAPI, Request
import os
import sqlite3

# Đường dẫn CSDL: mặc định database.db; trong Docker Compose được trỏ tới volume /data để dữ liệu bền vững
DB_PATH = os.getenv("DB_PATH", "database.db")

app = FastAPI()

# Hàm khởi tạo database SQLite với cột is_admin (hoặc role)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Tạo bảng users có thêm cột is_admin
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT,
            is_admin BOOLEAN DEFAULT 0
        )
    """)
    # Thêm dữ liệu mẫu nếu bảng trống
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, email, is_admin) VALUES ('admin', 'admin@hutech.edu.vn', 1)")
        cursor.execute("INSERT INTO users (username, email, is_admin) VALUES ('chauhoangphu', 'chauhoangphu@hutech.edu.vn', 0)")
        cursor.execute("INSERT INTO users (username, email, is_admin) VALUES ('nguyenthanhphi', 'nguyenthanhphi@gmail.com', 0)")
    # Bảng products và articles (theo RoadMap: users, products, articles) - làm "mồi" cho kịch bản UNION SELECT
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            author TEXT
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO products (name, price) VALUES ('Laptop HUTECH Edition', 15000000)")
        cursor.execute("INSERT INTO products (name, price) VALUES ('Ban phim co', 850000)")
        cursor.execute("INSERT INTO products (name, price) VALUES ('Chuot khong day', 320000)")
    cursor.execute("SELECT COUNT(*) FROM articles")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO articles (title, content, author) VALUES ('Chao mung', 'Bai viet mau dau tien', 'admin')")
        cursor.execute("INSERT INTO articles (title, content, author) VALUES ('Noi bo: ke hoach bao mat', 'Tai lieu noi bo - khong cong khai', 'admin')")
    conn.commit()
    conn.close()

init_db()

# 1. API Tìm kiếm (Dính lỗi SQLi và ĐÃ HIỂN THỊ CỘT is_admin)
@app.get("/api/search")
def search_users(q: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Lỗ hổng SQLi cố ý nối chuỗi trực tiếp
    query = f"SELECT id, username, email, is_admin FROM users WHERE username LIKE '%{q}%' OR '{q}'='1'"
    print(f"[EXECUTING SQL]: {query}")
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        users = []
        for row in rows:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "is_admin": bool(row[3]) # Hiển thị rõ quyền admin hay không
            })
        conn.close()
        return {"status": "success", "data": users}
    except Exception as e:
        conn.close()
        return {"status": "error", "message": str(e)}

# 2. API Cập nhật profile (Dính lỗi Mass Assignment / API Injection)
@app.post("/api/update-profile")
async def update_profile(request: Request):
    body = await request.json()
    username = body.get("username")
    email = body.get("email")
    
    # Lỗ hổng: Chấp nhận mọi trường dữ liệu truyền lên từ body, kể cả is_admin do hacker tự bịa ra
    is_admin = body.get("is_admin", 0) 
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Thực hiện update thẳng vào database theo username
    cursor.execute("""
        UPDATE users 
        SET email = ?, is_admin = ? 
        WHERE username = ?
    """, (email, 1 if is_admin == True or is_admin == "TRUE" or is_admin == 1 else 0, username))
    
    conn.commit()
    conn.close()
    
    return {
        "status": "success", 
        "message": "Profile updated successfully",
        "updated_data": body
    }

# 3. Endpoint nhẹ, KHÔNG có lỗ hổng - dùng để đo độ trễ thuần của Gateway (Mục 4.1)
@app.get("/api/health")
def health():
    return {"status": "ok"}

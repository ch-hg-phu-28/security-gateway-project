# Image chính thức của OpenResty (đã tích hợp sẵn Nginx, LuaJIT và lua-cjson)
FROM openresty/openresty:alpine

# Xóa cấu hình mặc định
RUN rm -f /usr/local/openresty/nginx/conf/nginx.conf

# Thư mục chứa mã Lua, giao diện admin và log cảnh báo
RUN mkdir -p /usr/local/openresty/nginx/lua \
             /usr/local/openresty/nginx/admin_html \
             /var/log/security

# Đóng gói sẵn cấu hình + mã nguồn (docker-compose vẫn mount đè bằng volume để sửa code không cần build lại)
COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/            /usr/local/openresty/nginx/lua/
COPY html/           /usr/local/openresty/nginx/admin_html/

EXPOSE 80

# Chạy foreground
CMD ["openresty", "-g", "daemon off;"]

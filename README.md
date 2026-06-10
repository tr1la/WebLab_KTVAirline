# KTVAirline - Hệ Thống Quản Lý Hàng Không

## Tổng Quan
KTVAirline là hệ thống quản lý hàng không được xây dựng bằng Spring Boot và React. Hệ thống cung cấp các chức năng toàn diện để quản lý hoạt động hàng không, bao gồm đặt vé, quản lý người dùng và các tính năng quản trị.

## Công Nghệ Sử Dụng
### Backend
- Java 17
- Spring Boot 3.1.3
- Spring Security (Bảo mật)
- Spring Data JPA (Quản lý dữ liệu)
- Cơ sở dữ liệu MySQL
- Xác thực JWT
- Tài liệu API với Swagger/OpenAPI
- Kiểm thử với JUnit
- Xử lý Excel với Apache POI
- Dịch vụ gửi email với Jakarta Mail

### Frontend
- React
- JavaScript/TypeScript
- Node.js
- NPM/Yarn

## Tính Năng Chính
- Xác thực và phân quyền người dùng
- Quản lý chuyến bay
- Hệ thống đặt vé
- Quản lý thông tin người dùng
- Bảng điều khiển quản trị
- Thông báo qua email
- Tạo báo cáo

## Yêu Cầu Hệ Thống
- Java Development Kit (JDK) 17 trở lên
- Node.js 14+ và npm/yarn
- MySQL 8.0+
- Maven 3.6+

## Hướng Dẫn Cài Đặt

### Cài Đặt Backend
1. Clone dự án:
   ```bash
   git clone [đường-dẫn-repository]
   ```

2. Cấu hình cơ sở dữ liệu MySQL:
   - Tạo cơ sở dữ liệu mới tên 'test01'
   - Cập nhật thông tin đăng nhập cơ sở dữ liệu trong file `src/main/resources/application.properties`

3. Build và chạy backend:
   ```bash
   mvn clean install
   mvn spring-boot:run
   ```

### Cài Đặt Frontend
1. Di chuyển đến thư mục frontend:
   ```bash
   cd frontend
   ```

2. Cài đặt các thư viện phụ thuộc:
   ```bash
   npm install
   # hoặc
   yarn install
   ```

3. Khởi chạy ứng dụng frontend:
   ```bash
   npm run dev
   # hoặc
   yarn start
   ```

## Tài Liệu API
Tài liệu API được cung cấp thông qua giao diện Swagger UI tại địa chỉ:
```
http://localhost:8080/swagger-ui.html
```

## Kiểm Thử
Để chạy các bài kiểm thử:
```bash
mvn test
```

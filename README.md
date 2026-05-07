# Website quản lý thông tin của các hệ thống theo quy trình DevOps dựa trên SBOM (Software Bill of Materials)

[![HUST](https://img.shields.io/badge/University-HUST-red.svg)](https://www.hust.edu.vn/)
[![DevOps](https://img.shields.io/badge/Process-DevOps-blue.svg)]()
[![Security](https://img.shields.io/badge/Security-Supply--Chain-green.svg)]()

> **Đồ án Nghiên cứu Tốt nghiệp 1 (GR1)**

> **Đề tài:** Xây dựng Website quản lý thông tin của các hệ thống theo quy trình DevOps dựa trên SBOM.

> **Sinh viên thực hiện:** Nguyễn Nhật Minh - 20235781

> **Giáo viên hướng dẫn:** TS. Vũ Thị Hương Giang

---

## Giới thiệu

Trong bối cảnh tấn công chuỗi cung ứng phần mềm (Software Supply Chain Attacks) ngày càng phức tạp, việc nắm rõ "thành phần" bên trong một sản phẩm phần mềm là rất quan trọng. Dự án này tập trung xây dựng một nền tảng quản lý tập trung dựa trên **SBOM (Software Bill of Materials)**.

Hệ thống cho phép các kỹ sư DevOps và Security Manager theo dõi, phân tích và quản lý toàn bộ thư viện, phụ thuộc (dependencies) và các lỗ hổng bảo mật liên quan trong suốt vòng đời phát triển phần mềm (SDLC).

## Tính năng chính

- **Import SBOM:** Hỗ trợ tải lên và phân tích các chuẩn phổ biến: **CycloneDX** và **SPDX** (định dạng JSON/XML).
- **Inventory Management:** Liệt kê đầy đủ danh mục các thành phần, phiên bản, và giấy phép (licenses).
- **Vulnerability Scanning:** Tự động đối chiếu các thành phần với cơ sở dữ liệu lỗ hổng (CVE) để đưa ra cảnh báo bảo mật.
- **Dashboard:** Trực quan hóa mức độ rủi ro của toàn bộ hệ thống dưới dạng biểu đồ.
- **DevOps Integration:** Cung cấp API để tích hợp trực tiếp vào pipeline CI/CD (Jenkins, GitHub Actions).

## Công nghệ sử dụng

### Backend

- **Ngôn ngữ:** Node.js (Express)
- **Cơ sở dữ liệu:** PostgreSQL (Lưu trữ quan hệ giữa các thành phần)
- **Phân tích SBOM:** Thư viện trích xuất dữ liệu tùy chỉnh cho CycloneDX/SPDX.

### Frontend

- **Framework:** React.js / Next.js
- **UI Library:** Tailwind CSS & Shadcn/UI
- **Charts:** Recharts / Chart.js

### Công cụ hỗ trợ (DevOps Tools)

- **SBOM Generation:** Syft, Trivy
- **Containerization:** Docker & Docker Compose

## Kiến trúc hệ thống

```text
[Source Code/Images] --> [CI/CD Pipeline] --> [SBOM Generator (Syft/Trivy)]
                                                    |
                                                    v
[User Interface] <--> [REST API Server] <--> [SBOM Parser Module]
                            |                       |
                    [PostgreSQL DB] <------> [Vulnerability DB (NVD/GitHub)]
```

## Yêu cầu hệ thống (Prerequisites)

- **Node.js**: Phiên bản 18.x trở lên
- **PostgreSQL**: Phiên bản 14.x trở lên
- **Docker & Docker Compose** (Khuyến khích nếu muốn thiết lập nhanh qua Container)

## Hướng dẫn cài đặt (Installation)

1. **Clone repository:**

   ```bash
   git clone https://github.com/your-username/SBOM-Management.git
   cd SBOM-Management
   ```

2. **Cài đặt thư viện (Dependencies):**
   - Dành cho Backend:
     ```bash
     cd backend
     npm install
     ```
   - Dành cho Frontend:
     ```bash
     cd frontend
     npm install
     ```

3. **Thiết lập biến môi trường (Environment Variables):**
   - Copy file `.env.example` thành `.env` trong cả 2 thư mục `backend` và `frontend`.
   - Cập nhật thông tin kết nối cơ sở dữ liệu PostgreSQL trong `.env` của backend.

4. **Khởi chạy ứng dụng:**
   - Khởi động Backend:
     ```bash
     npm run dev
     ```
   - Khởi động Frontend:
     ```bash
     npm run dev
     ```

## Hướng dẫn sử dụng (Usage)

- Truy cập giao diện web của ứng dụng.
- Tại trang Dashboard, chọn **Upload SBOM** để tải lên file SBOM định dạng JSON hoặc XML (SPDX/CycloneDX).
- Theo dõi màn hình danh sách các thành phần (Inventory) và các rủi ro bảo mật (Vulnerabilities).
- _Tích hợp CI/CD_: Mở tài liệu API (Swagger UI) để lấy endpoint upload SBOM phục vụ tự động hóa trong pipeline.

## Cấu trúc thư mục (Project Structure)

```text
SBOM-Management/
├── backend/                 # Máy chủ REST API (Node.js/Express)
│   ├── src/
│   │   ├── controllers/     # Xử lý logic của các request và response
│   │   ├── models/          # Định nghĩa cấu trúc dữ liệu mapping với PostgreSQL
│   │   ├── routes/          # Khai báo các endpoint API (Upload, Inventory, Vulnerabilities)
│   │   ├── services/        # Xử lý business logic (như phân tích file SBOM)
│   │   └── utils/           # Các hàm hỗ trợ, tiện ích dùng chung
│   ├── .env.example         # Mẫu khai báo biến môi trường cho backend
│   └── package.json         # Khai báo dependencies của backend
├── frontend/                # Giao diện Web (React.js/Next.js)
│   ├── src/
│   │   ├── app/ (hoặc pages) # Tổ chức định tuyến (Routing) màn hình
│   │   ├── components/      # Các UI component có thể tái sử dụng (Biểu đồ, Bảng, Nút bấm...)
│   │   ├── hooks/           # Các custom React hooks
│   │   └── lib/             # Cấu hình API client, thư viện ngoài
│   ├── .env.example         # Mẫu khai báo biến môi trường cho frontend
│   └── package.json         # Khai báo dependencies của frontend
├── docs/                    # Tài liệu thiết kế hệ thống, cấu trúc database & API doc
├── docker-compose.yml       # File cấu hình đóng gói toàn bộ hệ thống (DB, Backend, Frontend)
└── README.md                # File hướng dẫn chung của dự án
```

## Tài liệu tham khảo

- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)

## Đóng góp & Bản quyền (License)

- Dự án thuộc Đồ án Nghiên cứu Tốt nghiệp (HUST).
- MIT License.

## Liên hệ

- **Sinh viên:** Nguyễn Nhật Minh
- **Email:** [minh.nn235781@sis.hust.edu.vn](mailto:minh.nn235781@sis.hust.edu.vn)
- **GitHub:** [Minh20235781](https://github.com/Minh20235781)

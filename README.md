# Công cụ website quản lý thông tin hệ thống theo quy trình DevOps dựa trên SBOM (Software Bill of Materials)

[![HUST](https://img.shields.io/badge/University-HUST-red.svg)](https://www.hust.edu.vn/)
[![DevOps](https://img.shields.io/badge/Process-DevSecOps-blue.svg)]()
[![Security](https://img.shields.io/badge/Security-Supply_Chain-green.svg)]()

> **Đồ án Nghiên cứu Tốt nghiệp 1 (GR1)**
>
> **Đề tài:** Xây dựng nền tảng quản lý thông tin hệ thống theo quy trình DevOps dựa trên SBOM (Software Bill of Materials).
>
> **Sinh viên thực hiện:** Nguyễn Nhật Minh - 20235781 | **Giảng viên hướng dẫn:** TS. Vũ Thị Hương Giang

---

## Giới thiệu

Trong kỷ nguyên chuyển đổi số, an ninh chuỗi cung ứng phần mềm trở nên cấp thiết hơn bao giờ hết. **S-Track** là nền tảng quản lý tập trung thông tin hệ thống, đóng vai trò như một "Hộ chiếu linh kiện" cho phần mềm. Bằng cách ứng dụng tiêu chuẩn SBOM, hệ thống cho phép tự động hóa việc theo dõi các thành phần mã nguồn mở, phụ thuộc bắc cầu và rủi ro an ninh trong suốt vòng đời DevSecOps.

**Mục tiêu cốt lõi:**

- **Minh bạch hóa:** Nắm rõ mọi thư viện đang vận hành trong hệ thống.
- **Tự động hóa:** Trích xuất và phân tích dữ liệu trực tiếp từ Pipeline CI/CD.
- **Kiểm soát biến động:** Phát hiện sự thay đổi thành phần giữa các phiên bản Build (Drift Analysis).

## 🛠 Thuật toán Cốt lõi

Hệ thống không chỉ là công cụ lưu trữ mà còn thực hiện các xử lý logic chuyên sâu:

- **Thuật toán Duyệt và Trực quan hóa Đồ thị phụ thuộc:** Sử dụng DFS/BFS để chuyển đổi dữ liệu `cyclonedx.json` thành cấu trúc cây đa tầng, hỗ trợ truy vết nguồn gốc (Provenance).
- **Thuật toán Phân tích sai lệch (Drift Analysis):** So sánh bản chụp (Snapshot) SBOM giữa các lần Build dựa trên khóa định danh PURL để phát hiện các thư viện bị thêm/sửa/xóa hoặc hạ cấp phiên bản trái phép.

## Kiến trúc Hệ thống

Nền tảng được thiết kế theo mô hình 3 lớp đồng bộ:

```text
[ Developer ] --(git push)--> [ GitHub Actions / Pipeline ]
                                       |
                                [ SBOM Generation ] --(Syft/Trivy Scanners)
                                       |
                                 (POST .json)
                                       v
[ Dashboard ] <------------> [ API Aggregator ] <--------> [ PostgreSQL ]
(React/Consumer)             (NodeJS/Express)            (Normalized Schema)
      ^                             |                            |
      |                      [ Parser Module ] <---(Vulnerability Data)---
```

## Tính năng chính

- **SBOM Aggregator:** Tiếp nhận tự động dữ liệu từ Pipeline hoặc Upload thủ công (Hỗ trợ CycloneDX 1.5, SPDX 2.3).
- **Inventory Management:** Quản lý chi tiết linh kiện: Supplier, Version, PURL, License, Support Level.
- **Security Insights:** Tự động ánh xạ CVE và hiển thị biểu đồ mức độ nghiêm trọng của lỗ hổng.
- **Dependency Tree:** Trực quan hóa mối quan hệ phụ thuộc đa tầng (Transitive Dependencies).
- **Compliance Tracking:** Theo dõi tính tuân thủ giấy phép mã nguồn mở và vòng đời sản phẩm.

## Công nghệ sử dụng

| Thành phần     | Công nghệ                                         |
| :------------- | :------------------------------------------------ |
| **Frontend**   | ReactJS, TypeScript, Vite, Tailwind CSS, Recharts |
| **Backend**    | Node.js (Express), TypeScript, Multer             |
| **Database**   | PostgreSQL (Relational Mapping cho SBOM Metadata) |
| **DevOps**     | Docker, Docker Compose, GitHub Actions            |
| **SBOM Tools** | Syft (Generator), Grype/Trivy (Vulnerability DB)  |

## Cấu trúc Mã nguồn

```text
SBOM-Management/
├── backend/                  # Lớp Trung tâm (Aggregator Server)
│   ├── src/
│   │   ├── models/           # Schema PostgreSQL (Metadata, Component, Vulnerability...)
│   │   ├── services/         # Logic Parser & Thuật toán Drift Analysis
│   │   └── index.ts          # API Endpoints cho DevOps Integration
├── frontend/                 # Lớp Hiển thị (Consumer Dashboard)
│   ├── src/
│   │   ├── components/       # ComponentTable, DependencyTree, RiskCharts
│   │   └── types/            # Strict Type definitions cho chuẩn SBOM
├── .github/workflows/        # Cấu hình CI/CD tự động trích xuất SBOM
├── docker-compose.yml        # Đóng gói và triển khai hệ thống
└── README.md                 # Tài liệu mô tả dự án
```

## Cài đặt & Khởi chạy

**Khởi động môi trường (Docker):**

```bash
docker-compose up -d
```

**Cài đặt thủ công (Nếu không dùng Docker):**

- **Backend:**
  ```bash
  cd backend && npm install && npm run dev
  ```
- **Frontend:**
  ```bash
  cd frontend && npm install && npm run dev
  ```

_Lưu ý: Cấu hình tệp `.env` dựa trên `.env.example` để kết nối với cơ sở dữ liệu PostgreSQL._

## Tài liệu tham khảo

- SPDX (ISO/IEC 5962:2021)
- CycloneDX v1.5 Specification
- BOMs Away! A Comprehensive Study of Bills of Materials (ICSE 2024)

---

**Bản quyền:** Dự án phục vụ mục đích học thuật tại Đại học Bách khoa Hà Nội (HUST).

**Liên hệ:**

- Sinh viên: Nguyễn Nhật Minh
- Email: [minh.nn235781@sis.hust.edu.vn](mailto:minh.nn235781@sis.hust.edu.vn)
- GitHub: [Minh20235781](https://github.com/Minh20235781)

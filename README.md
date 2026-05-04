# 🛡️ SBOM Management System for DevOps Workflow

[![Project Status: GR1 - Research & Prototype](https://img.shields.io/badge/Project_Status-GR1-blue.svg)](https://github.com/nhatminh-hust/sbom-management)
[![HUST - School of ICT](https://img.shields.io/badge/HUST-SoICT-red.svg)](https://soict.hust.edu.vn/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📌 Tổng quan đề tài

**Tên đề tài:** Xây dựng Website quản lý thông tin của các hệ thống theo quy trình DevOps dựa trên SBOM.  
**Sinh viên thực hiện:** Nguyễn Nhật Minh  
**Giảng viên hướng dẫn:** TS. Vũ Thị Hương Giang  
**Đơn vị:** Bộ môn Công nghệ Phần mềm - Đại học Bách Khoa Hà Nội.

Trong bối cảnh an toàn chuỗi cung ứng phần mềm (Software Supply Chain Security) trở nên cấp thiết, dự án này tập trung vào việc quản lý tập trung và phân tích các **Software Bill of Materials (SBOM)**. Hệ thống giúp các đội ngũ DevOps theo dõi toàn bộ thành phần, thư viện và lỗ hổng bảo mật trong quy trình phát triển phần mềm một cách tự động và minh bạch.

---

## ✨ Tính năng chính (GR1)

- [x] **SBOM Parser:** Hỗ trợ đọc và phân tích định dạng chuẩn `CycloneDX` và `SPDX` (JSON/XML).
- [x] **Inventory Management:** Quản lý danh mục linh kiện phần mềm, phiên bản và giấy phép (licenses).
- [x] **Vulnerability Tracking:** Tích hợp tra cứu dữ liệu lỗ hổng bảo mật (CVE) từ các nguồn dữ liệu tin cậy.
- [x] **DevOps Integration:** Hỗ trợ nhận dữ liệu từ các công cụ quét tự động trong pipeline CI/CD (Syft, Trivy).
- [ ] **Security Dashboard:** Trực quan hóa mức độ rủi ro của toàn bộ hệ thống (Đang phát triển).

---

## 🛠️ Công nghệ sử dụng

### Backend

- **Language:** Node.js (Express) / Python (FastAPI)
- **Database:** PostgreSQL (Lưu trữ quan hệ giữa các components)
- **SBOM Tools:** Syft, Trivy (Dùng để trích xuất dữ liệu mẫu)

### Frontend

- **Framework:** React.js / Next.js
- **UI Library:** Tailwind CSS, Shadcn/UI
- **Visualization:** Recharts / D3.js (Biểu đồ thống kê rủi ro)

### DevOps & Tools

- **Containerization:** Docker, Docker Compose
- **Standard:** CycloneDX v1.5, SPDX v2.3

---

## 📂 Cấu trúc thư mục

```text
├── src/
│   ├── backend/          # Source code xử lý logic, API và Parser
│   ├── frontend/         # Giao diện người dùng (Dashboard, Table View)
│   └── database/         # Scripts khởi tạo Schema và Migration
├── docs/                 # Tài liệu phân tích thiết kế (R4.1)
├── data/                 # Dataset mẫu (SBOM JSON/XML files)
├── tools/                # Scripts tích hợp (CI/CD integration scripts)
└── README.md             # Tài liệu hướng dẫn dự án
```

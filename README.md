# SBOM Management

Nền tảng quản lý và kiểm chứng SBOM cho quy trình DevSecOps, tập trung vào việc phân tích dependency, sinh SBOM, lưu metadata/component/dependency và kiểm chứng SBOM với mã nguồn thật.

> Đồ án Nghiên cứu Tốt nghiệp 1  
> Đề tài: Xây dựng nền tảng quản lý thông tin hệ thống theo quy trình DevOps dựa trên SBOM.  
> Sinh viên thực hiện: Nguyễn Nhật Minh - 20235781  
> Giảng viên hướng dẫn: TS. Vũ Thị Hương Giang

## Phạm Vi Hiện Tại

Phiên bản hiện tại chỉ xử lý:

- Application type: Web Application
- Repo scope: Single Repository
- Source input: một GitHub repository thật
- SBOM format chính: CycloneDX JSON

Multi-repo và microservice nhiều repository hiện chỉ là hướng mở rộng, không khẳng định là chức năng đã hỗ trợ trong phiên bản này.

## Tính Năng Chính

- Quản lý hệ thống/project và SBOM đã upload hoặc generate.
- Phân tích GitHub repository bằng Syft để sinh CycloneDX SBOM.
- Tự động phát hiện dependency files như `package.json`, `pom.xml`, `requirements.txt`, `composer.json`, `Gemfile`, `go.mod`.
- Lưu metadata, component, dependency, vulnerability và snapshot SBOM vào PostgreSQL.
- Hiển thị dependency graph theo component/package và quan hệ phụ thuộc.
- Pipeline demo cho CI/CD SBOM: tạo task, tạo pipeline, nhập GitHub Repo URL, chạy pipeline và xem snapshot.
- Kiểm chứng SBOM với source thật:
  - Chọn repository thật.
  - Tải file SBOM CycloneDX JSON từ máy lên.
  - Phân tích lại source repository.
  - So sánh source với SBOM upload.
  - Báo cáo `MATCHED`, `MISSING_IN_SBOM`, `EXTRA_IN_SBOM`, `VERSION_MISMATCH`, Trust Score và Trust Level.
- Demo SBOM lỗi:
  - Xóa component khỏi SBOM upload.
  - Thêm component giả hoặc component bất kỳ.
  - Sửa version component.
  - Verify lại để chứng minh hệ thống phát hiện sai lệch.

## Kiến Trúc

```text
Frontend React/Vite
        |
        v
Backend Express/TypeScript
        |
        +-- PostgreSQL
        +-- Git clone/update source repository
        +-- Syft CycloneDX generation
        +-- SBOM parser and verification services
```

Các service chính trong backend:

- `RepositoryCatalogService`: lấy danh sách repository web thật đã lưu trong hệ thống.
- `SourceCloneService`: clone hoặc cập nhật source repository.
- `DependencyFileDetectorService`: phát hiện file dependency.
- `SbomGenerationService`: chạy Syft và sinh CycloneDX JSON.
- `MetadataInferenceService`: suy luận tác giả, dịch vụ, lifecycle phase từ source.
- `DependencyGraphService`: dựng dependency graph từ SBOM.
- `SbomVerificationService`: phân tích lại source và so sánh với SBOM.
- `FaultySbomDemoService`: tạo SBOM lỗi để demo.
- `TestReportService`: sinh báo cáo kiểm thử và evidence.

## Công Nghệ

| Thành phần | Công nghệ |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, Recharts, lucide-react |
| Backend | Node.js, Express, TypeScript |
| Database | PostgreSQL |
| SBOM generator | Syft |
| Vulnerability scanner | Grype, nếu được cài đặt |
| Source control | Git |

## Yêu Cầu Môi Trường

- Node.js
- PostgreSQL
- Git
- Syft
- Grype, tùy chọn nếu cần scan vulnerability

Kiểm tra nhanh:

```bash
git --version
syft version
node --version
npm --version
```

## Cấu Trúc Dự Án

```text
SBOM-Management/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   ├── controllers/
│   │   ├── routes/
│   │   ├── services/
│   │   └── index.ts
│   ├── sbom.sql
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── types/
│   │   ├── api.ts
│   │   └── App.tsx
│   └── package.json
└── README.md
```

## Cấu Hình Database

Tạo database PostgreSQL, ví dụ:

```sql
CREATE DATABASE sbom_db;
```

Trong `backend/.env`, cấu hình:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=sbom_db
PORT=5000
```

Backend có hàm tự tạo/migrate các bảng chính khi khởi động. Nếu muốn tạo schema thủ công, chạy file:

```text
backend/sbom.sql
```

Lưu ý nếu gặp lỗi PostgreSQL `no schema has been selected to create in`, chạy trước:

```sql
CREATE SCHEMA IF NOT EXISTS public;
SET search_path TO public;
```

## Cài Đặt Và Chạy

Cài dependencies backend:

```bash
cd backend
npm install
```

Chạy backend:

```bash
npm run dev
```

Backend mặc định chạy tại:

```text
http://localhost:5000
```

Cài dependencies frontend:

```bash
cd frontend
npm install
```

Chạy frontend:

```bash
npm run dev
```

Frontend mặc định chạy tại:

```text
http://localhost:5173
```

## Kiểm Tra Build

Backend:

```bash
cd backend
npm run build
```

Frontend:

```bash
cd frontend
npm run build
```

Chạy test thuật toán mẫu:

```bash
cd backend
npm test
```

## Demo Trang Kiểm Chứng SBOM

Flow chính:

1. Mở trang `Kiểm chứng SBOM`.
2. Chọn một repository web thật trong danh sách.
3. Tải file SBOM CycloneDX JSON tương ứng từ máy lên, ví dụ file đã generate trước đó.
4. Bấm `Analyze Source`.
   - Backend clone hoặc update repository thật.
   - Phát hiện dependency files.
   - Chạy Syft để phân tích source.
   - Dựng metadata, component, dependency và graph.
5. Bấm `Verify SBOM`.
   - Backend phân tích lại source thật.
   - So sánh source components với SBOM upload.
   - Trả về matched, missing, extra, version mismatch và Trust Score.
6. Xem `Báo cáo kiểm chứng` và `Báo cáo kiểm thử`.

Demo phát hiện lỗi:

1. Sau khi upload SBOM, dùng các thao tác trong card `SBOM tải lên từ máy`:
   - `Xóa khỏi SBOM`
   - `Sửa version`
   - `Thêm vào SBOM`
2. Bấm `Verify SBOM` để kiểm chứng bản SBOM đã chỉnh.
3. Hoặc bấm `Create Faulty SBOM Demo` để hệ thống tự tạo bản lỗi gồm:
   - Xóa một component thật.
   - Thêm `fake-lib-demo@9.9.9`.
   - Sửa version một component thật.
4. Bấm `Verify Faulty SBOM`.
5. Kiểm tra báo cáo có `MISSING_IN_SBOM`, `EXTRA_IN_SBOM`, `VERSION_MISMATCH` và Trust Score giảm.

Trust Score được tính theo công thức:

```text
matchedExactCount / (sourceComponentCount + extraInSbomCount) * 100
```

Phân loại:

- High trust: 90-100%
- Medium: 70-89%
- Low: 50-69%
- Untrusted: dưới 50%

## Demo Trang Upload Repository GitHub

Flow:

1. Nhập GitHub Repository URL.
2. Bấm `Phân tích SBOM`.
3. Xem kết quả phân tích và metadata do công cụ suy luận:
   - Tác giả
   - Dịch vụ
   - Giai đoạn vòng đời DevOps
4. Bấm `Confirm Analysis`.
5. Bấm `Generate SBOM`.
6. Tải file SBOM CycloneDX JSON về máy để lưu lại.
7. Sau một thời gian, có thể dùng lại chính file này ở trang `Kiểm chứng SBOM` để so sánh với source repository hiện tại.

## Demo Trang Pipeline

Flow:

1. Chọn project.
2. Tạo task phát triển nếu cần.
3. Tạo pipeline:
   - Nhập pipeline name.
   - Nhập branch.
   - Chọn provider.
   - Chọn trigger.
   - Nhập GitHub Repo URL.
4. Chọn pipeline vừa tạo.
5. Bấm `Run Pipeline`.
6. Xem pipeline runs, snapshot, change log và dependency graph.

## API Chính

SBOM:

- `POST /api/sboms/upload`
- `POST /api/sboms/analyze-repo`
- `POST /api/sboms/generate`
- `GET /api/sboms`
- `GET /api/sboms/:id/components`
- `GET /api/sboms/:id/dependencies`

Validation scenarios:

- `GET /api/validation-scenarios`
- `POST /api/validation-scenarios/:scenarioId/analyze`
- `POST /api/validation-scenarios/runs/:runId/confirm`
- `POST /api/validation-scenarios/runs/:runId/generate`
- `POST /api/validation-scenarios/runs/:runId/faulty`
- `POST /api/validation-scenarios/runs/:runId/verify`
- `POST /api/validation-scenarios/runs/:runId/verify-uploaded`
- `GET /api/validation-scenarios/runs/:runId/report`

Incremental SBOM:

- `POST /api/projects/:projectId/sbom/incremental-generate`
- `POST /api/projects/:projectId/sbom/auto-generate`
- `GET /api/projects/:projectId/sbom/snapshots`
- `GET /api/sbom/snapshots/:snapshotId/changes`
- `GET /api/sbom/snapshots/:snapshotId/graph`
- `GET /api/sbom/snapshots/:snapshotId/export`

Pipeline:

- `GET /api/projects/:projectId/tasks`
- `POST /api/projects/:projectId/tasks`
- `GET /api/projects/:projectId/pipelines`
- `POST /api/projects/:projectId/pipelines`
- `POST /api/pipelines/:pipelineId/run`
- `GET /api/pipelines/:pipelineId/runs`
- `GET /api/pipeline-runs/:runId`

## Repository Web Dùng Cho Demo

Trang kiểm chứng làm việc với repository GitHub thật đã có trong hệ thống. Các ví dụ phù hợp phạm vi Web Application + Single Repository:

- Spring PetClinic
- Ghost CMS
- NodeBB
- BookStack
- Discourse
- Gitea
- Flasky
- RealWorld React
- RealWorld Vue
- OWASP Juice Shop

## Lưu Ý Và Hạn Chế

- Không fake số liệu phân tích. Component count, dependency count và graph phụ thuộc kết quả Syft chạy thực tế.
- Nếu Git clone hoặc Syft thất bại, UI sẽ hiển thị lỗi tương ứng.
- Phiên bản hiện tại chưa hỗ trợ kiểm chứng multi-repo như một hệ thống microservice nhiều repository.
- File SBOM upload nên là CycloneDX JSON có trường `components`.
- Kết quả dependency graph phụ thuộc dữ liệu `dependencies` có trong SBOM.

## Tài Liệu Tham Khảo

- CycloneDX Specification
- SPDX Specification
- Syft Documentation
- Grype Documentation
- OWASP Software Component Verification Standard

## Liên Hệ

- Sinh viên: Nguyễn Nhật Minh
- Email: [minh.nn235781@sis.hust.edu.vn](mailto:minh.nn235781@sis.hust.edu.vn)
- GitHub: [Minh20235781](https://github.com/Minh20235781)

import type { AuditLogItem, MonitoringAlert, MonitoringStatus } from '../types/management';

export const mockAuditLogs: AuditLogItem[] = [
  { id: 'audit-1', timestamp: '2026-06-21T09:24:00+07:00', actor: 'Developer', action: 'VERIFY', target: 'SBOM gần nhất', result: 'SUCCESS', detail: 'Đối chiếu thành phần và dependency với mã nguồn.' },
  { id: 'audit-2', timestamp: '2026-06-21T09:12:00+07:00', actor: 'GitHub Actions', action: 'GENERATE', target: 'main', result: 'SUCCESS', detail: 'Sinh CycloneDX SBOM từ pipeline.' },
  { id: 'audit-3', timestamp: '2026-06-20T16:40:00+07:00', actor: 'Auditor', action: 'IMPORT', target: 'sbom.cdx.json', result: 'SUCCESS', detail: 'Import SBOM để phân tích.' },
];

export const mockMonitoringStatuses: MonitoringStatus[] = [
  { id: 'api', service: 'API server', status: 'ONLINE', detail: 'Sẵn sàng nhận yêu cầu', checkedAt: new Date().toISOString() },
  { id: 'database', service: 'Database', status: 'ONLINE', detail: 'Kết nối PostgreSQL ổn định', checkedAt: new Date().toISOString() },
  { id: 'generator', service: 'SBOM generator', status: 'ONLINE', detail: 'Syft đã được cấu hình', checkedAt: new Date().toISOString() },
  { id: 'scanner', service: 'Vulnerability scanner', status: 'WARNING', detail: 'Cần cập nhật vulnerability database định kỳ', checkedAt: new Date().toISOString() },
];

export const mockMonitoringAlerts: MonitoringAlert[] = [
  { id: 'alert-1', timestamp: '2026-06-21T09:25:00+07:00', repository: 'SBOM-Management', type: 'Vulnerability', severity: 'WARNING', message: 'Phát hiện thành phần cần kiểm tra bản vá.', status: 'NEW' },
  { id: 'alert-2', timestamp: '2026-06-20T16:42:00+07:00', repository: 'SBOM-Management', type: 'SBOM validation', severity: 'INFO', message: 'SBOM đã được đối chiếu với dependency manifest.', status: 'RESOLVED' },
];

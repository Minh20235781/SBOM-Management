import { useMemo, useState } from 'react';
import { Activity, Clock3, FileSearch, GitFork, Search, ShieldAlert } from 'lucide-react';
import type { BackendVulnerability, Dependency, SBOMComponent, SBOMMetadata } from '../types/sbom';
import type { AuditLogItem, ComplianceCheck, ComponentItem, DependencyItem, MonitoringAlert, MonitoringStatus, VulnerabilityItem } from '../types/management';
import { mockAuditLogs, mockMonitoringAlerts, mockMonitoringStatuses } from '../data/managementData';

type SbomDataProps = { components: SBOMComponent[]; dependencies: Dependency[]; vulnerabilities: BackendVulnerability[]; metadata: SBOMMetadata | null; selectedVulnerabilityId?: number | null };

const card = 'rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900';
const input = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none focus:border-blue-400 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200';

const Header = ({ title, description }: { title: string; description: string }) => (
  <div className="border-b border-slate-200 pb-5 dark:border-slate-800">
    <h2 className="text-2xl font-bold text-slate-900 dark:text-white">{title}</h2>
    <p className="mt-2 max-w-4xl text-sm text-slate-500 dark:text-slate-400">{description}</p>
  </div>
);

const Stats = ({ items }: { items: Array<{ label: string; value: string | number; tone?: string }> }) => (
  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
    {items.map(item => <div key={item.label} className={card}><p className="text-xs font-bold uppercase tracking-wide text-slate-400">{item.label}</p><p className={`mt-2 text-3xl font-bold ${item.tone || 'text-slate-900 dark:text-white'}`}>{item.value}</p></div>)}
  </div>
);

const Badge = ({ value }: { value: string }) => {
  const normalized = value.toUpperCase();
  const cls = normalized.includes('CRITICAL') || normalized.includes('FAIL') || normalized.includes('ERROR')
    ? 'border-red-200 bg-red-50 text-red-700'
    : normalized.includes('HIGH') || normalized.includes('WARNING') || normalized.includes('OPEN')
      ? 'border-amber-200 bg-amber-50 text-amber-700'
      : normalized.includes('PASS') || normalized.includes('SUCCESS') || normalized.includes('ONLINE') || normalized.includes('VERIFIED') || normalized.includes('RESOLVED')
        ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
        : 'border-blue-200 bg-blue-50 text-blue-700';
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${cls}`}>{value.replaceAll('_', ' ')}</span>;
};

const Empty = ({ text }: { text: string }) => <div className="py-12 text-center text-sm text-slate-400"><FileSearch className="mx-auto mb-3 h-9 w-9 opacity-40" />{text}</div>;

const ecosystemOf = (purl?: string) => purl?.match(/^pkg:([^/]+)/)?.[1] || 'unknown';
const licenseOf = (licenses?: string) => {
  if (!licenses) return '';
  try { const parsed = JSON.parse(licenses); return Array.isArray(parsed) ? parsed.map(item => item?.license?.id || item?.license?.name || item?.id || item?.name).filter(Boolean).join(', ') : licenses; } catch { return licenses; }
};

const componentItems = (components: SBOMComponent[], vulnerabilities: BackendVulnerability[]): ComponentItem[] => {
  const severityByRef = new Map(vulnerabilities.map(v => [v.affected_component_ref || '', String(v.severity || '').toUpperCase()]));
  return components.map(component => ({
    id: component.component_id,
    name: component.name,
    version: component.version,
    purl: component.purl,
    license: licenseOf(component.licenses),
    supplier: component.supplier_name,
    ecosystem: ecosystemOf(component.purl),
    riskLevel: (severityByRef.get(component.component_id) || 'LOW') as ComponentItem['riskLevel'],
  }));
};

export const ComponentsPage = ({ components, vulnerabilities }: SbomDataProps) => {
  const [query, setQuery] = useState('');
  const [ecosystem, setEcosystem] = useState('ALL');
  const items = useMemo(() => componentItems(components, vulnerabilities), [components, vulnerabilities]);
  const ecosystems = [...new Set(items.map(item => item.ecosystem))];
  const filtered = items.filter(item => item.name.toLowerCase().includes(query.toLowerCase()) && (ecosystem === 'ALL' || item.ecosystem === ecosystem));
  return <div className="space-y-6"><Header title="Thành phần" description="Theo dõi các thư viện, package và thành phần phần mềm được phát hiện từ SBOM." />
    <Stats items={[{ label: 'Tổng thành phần', value: items.length }, { label: 'Có license', value: items.filter(i => i.license).length }, { label: 'Thiếu version', value: items.filter(i => !i.version).length, tone: 'text-amber-600' }, { label: 'Có rủi ro', value: items.filter(i => i.riskLevel !== 'LOW').length, tone: 'text-red-600' }]} />
    <section className={card}><div className="mb-4 flex flex-col gap-3 sm:flex-row"><label className="relative flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" /><input className={`${input} w-full pl-9`} value={query} onChange={e => setQuery(e.target.value)} placeholder="Tìm theo tên component" /></label><select className={input} value={ecosystem} onChange={e => setEcosystem(e.target.value)}><option value="ALL">Mọi ecosystem</option>{ecosystems.map(value => <option key={value}>{value}</option>)}</select></div>
      <div className="max-h-[480px] overflow-auto"><table className="w-full min-w-[1100px] table-fixed text-left text-sm"><thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-slate-500 shadow-sm dark:bg-slate-800"><tr><th className="w-[190px] px-4 py-3">Component</th><th className="w-[120px] px-4 py-3">Version</th><th className="w-[420px] px-4 py-3">PURL</th><th className="w-[140px] px-4 py-3">License</th><th className="w-[150px] px-4 py-3">Supplier</th><th className="w-[100px] px-4 py-3">Risk</th></tr></thead><tbody className="divide-y divide-slate-100">{filtered.map(item => <tr key={item.id}><td className="truncate px-4 py-3 font-semibold text-slate-800" title={item.name}>{item.name}</td><td className="truncate px-4 py-3" title={item.version || '-'}>{item.version || '-'}</td><td className="px-4 py-3 text-xs"><p className="truncate font-mono" title={item.purl || '-'}>{item.purl || '-'}</p></td><td className="truncate px-4 py-3" title={item.license || '-'}>{item.license || '-'}</td><td className="truncate px-4 py-3" title={item.supplier || '-'}>{item.supplier || '-'}</td><td className="px-4 py-3"><Badge value={item.riskLevel} /></td></tr>)}</tbody></table>{filtered.length === 0 && <Empty text="Chưa có thành phần phù hợp. Hãy tải lên hoặc chọn một SBOM." />}</div>
    </section></div>;
};

export const DependenciesPage = ({ components, dependencies }: SbomDataProps) => {
  const names = new Map(components.map(c => [c.component_id, c.name]));
  const items: DependencyItem[] = dependencies.map(dep => ({ id: String(dep.dependency_id), source: names.get(dep.component_ref) || dep.component_ref, target: names.get(dep.depends_on_ref) || dep.depends_on_ref, type: 'DIRECT', scope: 'UNKNOWN', status: names.has(dep.component_ref) && names.has(dep.depends_on_ref) ? 'VERIFIED' : 'MISSING_INFO' }));
  return <div className="space-y-6"><Header title="Phụ thuộc" description="Phân tích quan hệ phụ thuộc trực tiếp và gián tiếp giữa các thành phần phần mềm." /><Stats items={[{ label: 'Tổng dependency', value: items.length }, { label: 'Trực tiếp', value: items.filter(i => i.type === 'DIRECT').length }, { label: 'Gián tiếp', value: items.filter(i => i.type === 'TRANSITIVE').length }, { label: 'Thiếu thông tin', value: items.filter(i => i.status === 'MISSING_INFO').length, tone: 'text-amber-600' }]} />
    <section className={card}><div className="mb-4 flex items-center gap-2"><GitFork className="h-5 w-5 text-blue-500" /><h3 className="font-bold">Dependency graph</h3></div><p className="text-sm text-slate-500">Biểu đồ phụ thuộc chi tiết được hiển thị trong trang Tải lên và Lịch sử phiên bản. Bảng dưới đây cung cấp quan hệ đã chuẩn hóa.</p></section>
    <section className={card}><div className="max-h-[480px] overflow-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-slate-500 shadow-sm dark:bg-slate-800"><tr>{['Component gốc','Phụ thuộc vào','Loại','Scope','Trạng thái'].map(h => <th key={h} className="px-4 py-3">{h}</th>)}</tr></thead><tbody className="divide-y divide-slate-100">{items.map(item => <tr key={item.id}><td className="px-4 py-3 font-semibold">{item.source}</td><td className="px-4 py-3">{item.target}</td><td className="px-4 py-3">{item.type}</td><td className="px-4 py-3">{item.scope}</td><td className="px-4 py-3"><Badge value={item.status} /></td></tr>)}</tbody></table>{items.length === 0 && <Empty text="Chưa có quan hệ phụ thuộc trong SBOM đang chọn." />}</div></section></div>;
};

export const VulnerabilitiesPage = ({ components, vulnerabilities, selectedVulnerabilityId }: SbomDataProps) => {
  const [severity, setSeverity] = useState('ALL');
  const names = new Map(components.map(c => [c.component_id, c.name]));
  const items: VulnerabilityItem[] = vulnerabilities.map(v => ({ id: v.cve_id || v.vulnerability || String(v.vuln_id), component: v.name || names.get(v.affected_component_ref || '') || 'Unknown', affectedVersion: v.installed || undefined, severity: String(v.severity || 'UNKNOWN').toUpperCase() as VulnerabilityItem['severity'], cvssScore: v.epss ? Number(v.epss) : undefined, description: v.description || undefined, recommendation: v.fixed_in ? `Nâng cấp lên ${v.fixed_in}` : 'Theo dõi advisory và áp dụng bản vá phù hợp.', status: 'OPEN' }));
  const selectedVulnerability = vulnerabilities.find(item => item.vuln_id === selectedVulnerabilityId);
  const filtered = severity === 'ALL' ? items : items.filter(item => item.severity === severity);
  return <div className="space-y-6"><Header title="Lỗ hổng" description="Theo dõi CVE, mức độ nghiêm trọng và trạng thái xử lý lỗ hổng trong các thành phần phần mềm." /><Stats items={[{ label: 'Tổng lỗ hổng', value: items.length }, { label: 'Critical', value: items.filter(i => i.severity === 'CRITICAL').length, tone: 'text-red-700' }, { label: 'High', value: items.filter(i => i.severity === 'HIGH').length, tone: 'text-orange-600' }, { label: 'Medium / Low', value: items.filter(i => ['MEDIUM','LOW'].includes(i.severity)).length, tone: 'text-amber-600' }]} />
    {selectedVulnerability && <section className="rounded-xl border border-blue-200 bg-blue-50 p-5 shadow-sm dark:border-blue-900 dark:bg-blue-950/30"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-xs font-bold uppercase tracking-wide text-blue-500">Chi tiết lỗ hổng được chọn</p><h3 className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-white">{selectedVulnerability.cve_id || selectedVulnerability.vulnerability}</h3><p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{selectedVulnerability.description || 'Chưa có mô tả chi tiết cho lỗ hổng này.'}</p></div><Badge value={selectedVulnerability.severity || 'UNKNOWN'} /></div><div className="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4"><div><p className="text-xs text-slate-400">Component</p><p className="font-semibold">{selectedVulnerability.name || '-'}</p></div><div><p className="text-xs text-slate-400">Phiên bản</p><p className="font-semibold">{selectedVulnerability.installed || '-'}</p></div><div><p className="text-xs text-slate-400">Bản vá</p><p className="font-semibold">{selectedVulnerability.fixed_in || 'Chưa có'}</p></div><div><p className="text-xs text-slate-400">EPSS</p><p className="font-semibold">{selectedVulnerability.epss == null ? '-' : `${(Number(selectedVulnerability.epss) * 100).toFixed(1)}%`}</p></div></div></section>}
    <section className={card}><select className={`${input} mb-4`} value={severity} onChange={e => setSeverity(e.target.value)}><option value="ALL">Mọi severity</option>{['CRITICAL','HIGH','MEDIUM','LOW'].map(v => <option key={v}>{v}</option>)}</select><div className="max-h-[480px] overflow-auto"><table className="w-full min-w-[920px] text-left text-sm"><thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-slate-500 shadow-sm dark:bg-slate-800"><tr>{['CVE','Component','Version','Severity','Score','Khuyến nghị','Trạng thái'].map(h => <th key={h} className="px-4 py-3">{h}</th>)}</tr></thead><tbody className="divide-y divide-slate-100">{filtered.map(item => <tr key={item.id} className={selectedVulnerability && item.id === (selectedVulnerability.cve_id || selectedVulnerability.vulnerability || String(selectedVulnerability.vuln_id)) ? 'bg-blue-50' : ''}><td className="px-4 py-3 font-mono font-semibold">{item.id}</td><td className="px-4 py-3">{item.component}</td><td className="px-4 py-3">{item.affectedVersion || '-'}</td><td className="px-4 py-3"><Badge value={item.severity} /></td><td className="px-4 py-3">{item.cvssScore ?? '-'}</td><td className="max-w-sm px-4 py-3">{item.recommendation}</td><td className="px-4 py-3"><Badge value={item.status} /></td></tr>)}</tbody></table>{filtered.length === 0 && <Empty text="Không có lỗ hổng phù hợp với bộ lọc." />}</div></section></div>;
};

const complianceChecks = ({ metadata, components, dependencies }: SbomDataProps): ComplianceCheck[] => {
  const has = (condition: boolean, id: string, criterion: string, recommendation: string, warning = false): ComplianceCheck => ({ id, criterion, status: condition ? 'PASS' : warning ? 'WARNING' : 'FAIL', impact: condition ? 'LOW' : warning ? 'MEDIUM' : 'HIGH', recommendation: condition ? 'Không cần xử lý.' : recommendation });
  return [
    has(Boolean(metadata), 'metadata', 'Có metadata SBOM', 'Bổ sung metadata cho tài liệu SBOM.'),
    has(Boolean(metadata?.authors || metadata?.tool_components), 'author', 'Có thông tin author/tool', 'Khai báo tác giả hoặc công cụ sinh SBOM.', true),
    has(Boolean(metadata?.created_timestamp), 'timestamp', 'Có timestamp', 'Bổ sung thời gian tạo SBOM.'),
    has(components.length > 0 && components.every(c => Boolean(c.name)), 'name', 'Component có name', 'Bổ sung tên cho mọi component.'),
    has(components.length > 0 && components.every(c => Boolean(c.version)), 'version', 'Component có version', 'Bổ sung version cho component.', true),
    has(components.length > 0 && components.every(c => Boolean(c.licenses)), 'license', 'Component có license', 'Khai báo license SPDX.', true),
    has(components.length > 0 && components.every(c => Boolean(c.purl || c.cpe)), 'identity', 'Component có PURL/CPE', 'Bổ sung định danh PURL hoặc CPE.', true),
    has(dependencies.length > 0, 'dependency', 'Dependency relationship đầy đủ', 'Bổ sung cây phụ thuộc.', true),
  ];
};

export const CompliancePage = (props: SbomDataProps) => {
  const checks = complianceChecks(props); const pass = checks.filter(c => c.status === 'PASS').length; const score = Math.round(pass / checks.length * 100);
  return <div className="space-y-6"><Header title="Tuân thủ" description="Đánh giá mức độ đáp ứng của SBOM theo các tiêu chí định dạng, giấy phép và thông tin bắt buộc." /><Stats items={[{ label: 'Điểm tổng quan', value: `${score}%`, tone: score >= 75 ? 'text-emerald-600' : 'text-amber-600' }, { label: 'Đạt', value: pass, tone: 'text-emerald-600' }, { label: 'Cảnh báo', value: checks.filter(c => c.status === 'WARNING').length, tone: 'text-amber-600' }, { label: 'Lỗi', value: checks.filter(c => c.status === 'FAIL').length, tone: 'text-red-600' }]} /><section className={card}><div className="space-y-3">{checks.map(check => <div key={check.id} className="flex flex-col justify-between gap-3 rounded-lg border border-slate-100 p-4 sm:flex-row sm:items-center"><div><p className="font-semibold text-slate-800">{check.criterion}</p><p className="mt-1 text-xs text-slate-500">{check.recommendation}</p></div><div className="flex gap-2"><Badge value={check.impact} /><Badge value={check.status} /></div></div>)}</div></section></div>;
};

export const AuditPage = () => {
  const [action, setAction] = useState('ALL');
  const logs: AuditLogItem[] = mockAuditLogs.filter(log => action === 'ALL' || log.action === action).sort((a,b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  return <div className="space-y-6"><Header title="Kiểm toán" description="Ghi nhận lịch sử thao tác, phân tích và thay đổi liên quan đến SBOM." /><Stats items={[{ label: 'Tổng sự kiện', value: mockAuditLogs.length }, { label: 'Import SBOM', value: mockAuditLogs.filter(l => l.action === 'IMPORT').length }, { label: 'Sinh SBOM', value: mockAuditLogs.filter(l => l.action === 'GENERATE').length }, { label: 'Xác minh', value: mockAuditLogs.filter(l => l.action === 'VERIFY').length }]} /><section className={card}><select className={`${input} mb-4`} value={action} onChange={e => setAction(e.target.value)}><option value="ALL">Mọi hành động</option>{['IMPORT','GENERATE','VERIFY','UPDATE'].map(v => <option key={v}>{v}</option>)}</select><div className="space-y-3">{logs.map(log => <div key={log.id} className="grid gap-3 rounded-lg border border-slate-100 p-4 sm:grid-cols-[170px_120px_1fr_auto]"><div className="text-xs text-slate-500"><Clock3 className="mr-1 inline h-3.5 w-3.5" />{new Date(log.timestamp).toLocaleString('vi-VN')}</div><div className="font-semibold text-slate-700">{log.actor}</div><div><p className="font-semibold text-slate-800">{log.action} · {log.target}</p><p className="mt-1 text-xs text-slate-500">{log.detail}</p></div><Badge value={log.result} /></div>)}{logs.length === 0 && <Empty text="Chưa có nhật ký kiểm toán phù hợp." />}</div></section></div>;
};

export const MonitoringPage = () => {
  const statuses: MonitoringStatus[] = mockMonitoringStatuses; const alerts: MonitoringAlert[] = mockMonitoringAlerts;
  return <div className="space-y-6"><Header title="Giám sát" description="Theo dõi trạng thái pipeline, repository, SBOM và cảnh báo bảo mật theo thời gian." /><Stats items={[{ label: 'Dịch vụ online', value: statuses.filter(s => s.status === 'ONLINE').length, tone: 'text-emerald-600' }, { label: 'Cảnh báo hệ thống', value: statuses.filter(s => s.status !== 'ONLINE').length, tone: 'text-amber-600' }, { label: 'Repo cần kiểm tra', value: new Set(alerts.filter(a => a.status !== 'RESOLVED').map(a => a.repository)).size }, { label: 'Cảnh báo mới', value: alerts.filter(a => a.status === 'NEW').length, tone: 'text-red-600' }]} />
    <section className={card}><h3 className="mb-4 flex items-center gap-2 font-bold"><Activity className="h-5 w-5 text-blue-500" />Trạng thái hệ thống</h3><div className="grid gap-3 sm:grid-cols-2">{statuses.map(status => <div key={status.id} className="rounded-lg border border-slate-100 p-4"><div className="flex items-center justify-between gap-2"><p className="font-semibold text-slate-800">{status.service}</p><Badge value={status.status} /></div><p className="mt-2 text-xs text-slate-500">{status.detail}</p></div>)}</div></section>
    <section className={card}><h3 className="mb-4 flex items-center gap-2 font-bold"><ShieldAlert className="h-5 w-5 text-red-500" />Cảnh báo gần đây</h3><div className="space-y-3">{alerts.map(alert => <div key={alert.id} className="grid gap-3 rounded-lg border border-slate-100 p-4 md:grid-cols-[150px_180px_1fr_auto]"><span className="text-xs text-slate-500">{new Date(alert.timestamp).toLocaleString('vi-VN')}</span><span className="font-semibold text-slate-700">{alert.repository}</span><div><p className="font-semibold text-slate-800">{alert.type}</p><p className="mt-1 text-xs text-slate-500">{alert.message}</p></div><div className="flex gap-2"><Badge value={alert.severity} /><Badge value={alert.status} /></div></div>)}</div></section></div>;
};

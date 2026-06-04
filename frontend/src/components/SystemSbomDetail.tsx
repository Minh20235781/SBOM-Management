import React, { useEffect, useState } from 'react';
import { ArrowLeft, Box, Info, ListTree, ShieldAlert } from 'lucide-react';
import ComponentTable from './ComponentTable';
import SbomParsedDependencyGraph from './SbomParsedDependencyGraph';
import { type BackendVulnerability, type Dependency, type SBOMComponent, type SBOMMetadata } from '../types/sbom';

const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://localhost:5000';

type SystemRecord = {
  system_id: number;
  name: string;
};

type Props = {
  system: SystemRecord;
  onBack: () => void;
};

const formatMetadataValue = (value?: string | null) => {
  if (!value) return '-';
  const normalized = value.trim();
  return normalized && normalized.toUpperCase() !== 'N/A' ? normalized : '-';
};

const SystemSbomDetail: React.FC<Props> = ({ system, onBack }) => {
  const [metadata, setMetadata] = useState<SBOMMetadata | null>(null);
  const [components, setComponents] = useState<SBOMComponent[]>([]);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<BackendVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const detailRes = await fetch(`${API_BASE}/api/systems/${system.system_id}/detail`);
        const detail = await detailRes.json();
        if (!detailRes.ok) throw new Error(detail.error || detail.message || 'Failed to load system detail');
        const latestSbomId = detail.sboms?.[0]?.sbom_id;
        if (!latestSbomId) throw new Error('He thong nay chua co SBOM nao duoc gan.');

        const [metaRes, compRes, depRes, vulnRes] = await Promise.all([
          fetch(`${API_BASE}/api/sboms/${encodeURIComponent(latestSbomId)}`),
          fetch(`${API_BASE}/api/sboms/${encodeURIComponent(latestSbomId)}/components`),
          fetch(`${API_BASE}/api/sboms/${encodeURIComponent(latestSbomId)}/dependencies`),
          fetch(`${API_BASE}/api/sboms/${encodeURIComponent(latestSbomId)}/vulnerabilities`),
        ]);

        const [metaData, compData, depData, vulnData] = await Promise.all([
          metaRes.json(),
          compRes.json(),
          depRes.json(),
          vulnRes.json(),
        ]);
        if (cancelled) return;

        setMetadata(metaData);
        setComponents(Array.isArray(compData) ? compData : []);
        setDependencies(Array.isArray(depData) ? depData : []);
        setVulnerabilities(Array.isArray(vulnData) ? vulnData : []);
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Khong the tai du lieu SBOM');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => { cancelled = true; };
  }, [system.system_id]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-50"
          >
            <ArrowLeft className="h-4 w-4" />
            Quay lại danh sách
          </button>
          <h2 className="mt-4 text-xl font-bold text-slate-800">Chi tiết hệ thống: {system.name}</h2>
        </div>
      </div>

      {loading && <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Đang tải dữ liệu SBOM...</div>}
      {error && <div className="rounded-xl border border-rose-100 bg-rose-50 p-5 text-rose-700">{error}</div>}

      {!loading && !error && (
        <>
          {metadata && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100">
                <h3 className="font-bold text-slate-800 flex items-center gap-2">
                  <Info className="w-4 h-4 text-indigo-500" /> Thông tin chung
                </h3>
              </div>
              <div className="p-6 bg-slate-50/50 grid grid-cols-1 md:grid-cols-2 gap-y-4 gap-x-8">
                <div>
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">SBOM ID</p>
                  <p className="text-sm font-medium text-slate-800 truncate" title={metadata.sbom_id}>{metadata.sbom_id}</p>
                </div>
                <div>
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Thời gian tạo</p>
                  <p className="text-sm font-medium text-slate-800">{new Date(metadata.created_timestamp).toLocaleString('vi-VN')}</p>
                </div>
                <div className="md:col-span-2">
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Tác giả</p>
                  <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.authors)}</p>
                </div>
                <div className="md:col-span-2">
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Công cụ tạo</p>
                  <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.tool_components)}</p>
                </div>
                <div>
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Dịch vụ</p>
                  <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.tool_services)}</p>
                </div>
                <div>
                  <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Giai đoạn vòng đời</p>
                  <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.lifecycle_phase)}</p>
                </div>
              </div>
            </div>
          )}

          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100">
              <h3 className="font-bold text-slate-800 flex items-center gap-2">
                <Box className="w-4 h-4 text-purple-500" /> Danh mục thành phần
              </h3>
            </div>
            <div className="p-6 bg-slate-50/50">
              <div className="bg-white border border-slate-200 rounded-lg overflow-auto max-h-[420px]">
                <ComponentTable components={components} />
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100">
              <h3 className="font-bold text-slate-800 flex items-center gap-2">
                <ListTree className="w-4 h-4 text-emerald-500" /> Cây phụ thuộc
              </h3>
            </div>
            <div className="p-6 bg-slate-50/50">
              <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <SbomParsedDependencyGraph
                  projectName={system.name}
                  sbomId={metadata?.sbom_id}
                  components={components}
                  dependencies={dependencies}
                  vulnerabilities={vulnerabilities}
                />
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100">
              <h3 className="font-bold text-slate-800 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-500" /> Các lỗ hổng đã phát hiện
              </h3>
            </div>
            <div className="p-6 bg-slate-50/50">
              <div className="bg-white border border-slate-200 rounded-lg overflow-auto max-h-[420px]">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="sticky top-0 bg-white z-10 shadow-sm">
                    <tr className="text-slate-500 text-xs uppercase tracking-wider font-semibold border-b border-slate-200">
                      <th className="px-6 py-4 font-medium">STT</th>
                      <th className="px-6 py-4 font-medium">Name</th>
                      <th className="px-6 py-4 font-medium">Installed</th>
                      <th className="px-6 py-4 font-medium">Fixed in</th>
                      <th className="px-6 py-4 font-medium">Type</th>
                      <th className="px-6 py-4 font-medium">Vulnerability</th>
                      <th className="px-6 py-4 font-medium">Severity</th>
                      <th className="px-6 py-4 font-medium">EPSS</th>
                      <th className="px-6 py-4 font-medium">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {vulnerabilities.length === 0 ? (
                      <tr><td colSpan={9} className="px-6 py-12 text-center text-slate-500 bg-slate-50/50">Không tìm thấy lỗ hổng nào.</td></tr>
                    ) : vulnerabilities.map((vuln, idx) => (
                      <tr key={vuln.vuln_id || idx} className="hover:bg-slate-50/50">
                        <td className="px-6 py-4 font-mono text-slate-700">{idx + 1}</td>
                        <td className="px-6 py-4 font-medium text-slate-700">{vuln.name || 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.installed || 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.fixed_in || 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.package_type || 'N/A'}</td>
                        <td className="px-6 py-4 font-mono text-slate-600 font-medium">{vuln.vulnerability || vuln.cve_id || 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.severity || 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.epss ? `${(Number(vuln.epss) * 100).toFixed(1)}%` : 'N/A'}</td>
                        <td className="px-6 py-4 text-slate-700">{vuln.risk || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default SystemSbomDetail;

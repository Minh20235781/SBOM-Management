/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect } from 'react';
import Systems from './components/Systems';
import SBOMUpload from './components/SBOMUpload';
import ComponentTable from './components/ComponentTable';
import DependencyTree from './components/DependencyTree';
import Dashboard from './components/Dashboard';
import { type SBOMComponent, type BackendVulnerability, type Dependency, type SBOMMetadata } from './types/sbom';
import { 
  Search, Database, LayoutDashboard, Box, ShieldAlert, 
  Activity, ListTree, History, ShieldCheck, FileKey, 
  GitMerge, Server, Layers, UploadCloud, Info 
} from 'lucide-react';

function App() {
  const [components, setComponents] = useState<SBOMComponent[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<BackendVulnerability[]>([]);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [metadata, setMetadata] = useState<SBOMMetadata | null>(null);
  const [systems, setSystems] = useState<any[]>([]);
  const [activeMenu, setActiveMenu] = useState<string>('dashboard');

  const handleUploadSuccess = async (rawData: unknown) => {
    try {
      let uploadBody: any = rawData;
      // If caller provided { sbom, systemName }
      if (rawData && typeof rawData === 'object' && (rawData as any).sbom) {
        const payload = rawData as any;
        uploadBody = { sbom: payload.sbom };
        if (payload.systemName) {
          // Create or get system
          const sysRes = await fetch('http://localhost:5000/api/systems', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: payload.systemName })
          });
          const sysData = await sysRes.json();
          uploadBody.system_id = sysData.system_id || sysData.systemId || sysData.id;
        }
      }

      const response = await fetch('http://localhost:5000/api/sboms/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(uploadBody)
      });
      const data = await response.json();
      
      if (data.success) {
        const sbomId = data.sbomId;
        // Fetch metadata
        const metaRes = await fetch(`http://localhost:5000/api/sboms/${sbomId}`);
        const metaData = await metaRes.json();
        setMetadata(metaData);

        // Fetch components
        const compRes = await fetch(`http://localhost:5000/api/sboms/${sbomId}/components`);
        const compData = await compRes.json();
        setComponents(compData);

        // Fetch dependencies
        const depRes = await fetch(`http://localhost:5000/api/sboms/${sbomId}/dependencies`);
        const depData = await depRes.json();
        setDependencies(depData);
        
        // Fetch vulnerabilities
        const vulnRes = await fetch(`http://localhost:5000/api/sboms/${sbomId}/vulnerabilities`);
        const vulnData = await vulnRes.json();

        const mappedVulns = vulnData.map((v: any) => ({
          vuln_id: v.vuln_id,
          sbom_id: v.sbom_id,
          name: v.name,
          installed: v.installed,
          fixed_in: v.fixed_in,
          package_type: v.package_type,
          vulnerability: v.vulnerability || v.cve_id,
          severity: v.severity,
          epss: typeof v.epss === 'number' ? v.epss : (v.epss ? Number(v.epss) : null),
          risk: v.risk,
          cve_id: v.cve_id,
          description: v.description,
          affected_component_ref: v.affected_component_ref,
        }));
        
        // Sắp xếp lỗ hổng ưu tiên cao (Critical, High) lên đầu
        const severityOrder: Record<string, number> = {
          'critical': 4,
          'high': 3,
          'medium': 2,
          'low': 1,
          'info': 0,
          'unknown': -1
        };
        
        mappedVulns.sort((a: any, b: any) => {
          const sA = (a.severity || 'unknown').toLowerCase();
          const sB = (b.severity || 'unknown').toLowerCase();
          return (severityOrder[sB] || -1) - (severityOrder[sA] || -1);
        });

        setVulnerabilities(mappedVulns);
        // Refresh systems list in case upload created a new system
        try { await fetchSystems(); } catch { /* ignore */ }
        
      } else {
        alert("Upload failed: " + (data.error || data.message || " Unknown error"));
      }
    } catch (e) {
      console.error(e);
      alert("Error calling backend API");
    }
  };

  const fetchSystems = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/systems');
      if (!res.ok) throw new Error('Failed to fetch systems');
      const list = await res.json();
      setSystems(list);
    } catch (e) {
      console.error('Failed to load systems', e);
    }
  };

  // Load systems on mount
  useEffect(() => { fetchSystems(); }, []);

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col hidden md:flex shrink-0">
        <div className="h-16 flex items-center px-6 border-b border-slate-200 shrink-0">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-1.5 rounded-lg shadow-sm shadow-blue-200">
              <LayoutDashboard className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-sm leading-tight text-slate-800">SBOM Management</h1>
              <p className="text-[9px] text-slate-400 uppercase tracking-widest font-bold mt-0.5">Enterprise Platform</p>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto py-6 px-3 space-y-8 select-none">
          {/* Menu Nhóm Tổng Quan */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Tổng quan</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('dashboard')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'dashboard' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <LayoutDashboard className={`w-4 h-4 ${activeMenu === 'dashboard' ? 'text-blue-600' : 'text-slate-400'}`} /> Dashboard
              </button>
              <button 
                onClick={() => setActiveMenu('system')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'system' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <Server className={`w-4 h-4 ${activeMenu === 'system' ? 'text-blue-600' : 'text-slate-400'}`} /> Hệ thống
              </button>
            </nav>
          </div>

          {/* Menu Nhóm SBOM */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">SBOM</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('upload')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'upload' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <UploadCloud className={`w-4 h-4 ${activeMenu === 'upload' ? 'text-blue-600' : 'text-slate-400'}`} /> Tải lên
              </button>
              <button 
                onClick={() => setActiveMenu('components')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'components' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <Layers className={`w-4 h-4 ${activeMenu === 'components' ? 'text-blue-600' : 'text-slate-400'}`} /> Thành phần
              </button>
              <button 
                onClick={() => setActiveMenu('dependencies')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'dependencies' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <ListTree className={`w-4 h-4 ${activeMenu === 'dependencies' ? 'text-blue-600' : 'text-slate-400'}`} /> Phụ thuộc
              </button>
              <button 
                onClick={() => setActiveMenu('history')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'history' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <History className={`w-4 h-4 ${activeMenu === 'history' ? 'text-blue-600' : 'text-slate-400'}`} /> Lịch sử phiên bản
              </button>
            </nav>
          </div>

          {/* Menu Nhóm Bảo Mật */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Bảo mật</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('cve')}
                className={`w-full flex justify-between items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'cve' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <div className="flex items-center gap-3">
                  <ShieldAlert className={`w-4 h-4 ${activeMenu === 'cve' ? 'text-blue-600' : 'text-red-400'}`} /> Lỗ hổng (CVE)
                </div>
                {vulnerabilities.length > 0 && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-50 text-red-600 border border-red-100">{vulnerabilities.length}</span>
                )}
              </button>
              <button 
                onClick={() => setActiveMenu('compliance')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'compliance' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <ShieldCheck className={`w-4 h-4 ${activeMenu === 'compliance' ? 'text-blue-600' : 'text-slate-400'}`} /> Tuân thủ
              </button>
              <button 
                onClick={() => setActiveMenu('audit')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'audit' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <FileKey className={`w-4 h-4 ${activeMenu === 'audit' ? 'text-blue-600' : 'text-slate-400'}`} /> Kiểm toán
              </button>
            </nav>
          </div>

          {/* Menu Nhóm CI/CD */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">CI/CD</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('pipeline')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'pipeline' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <GitMerge className={`w-4 h-4 ${activeMenu === 'pipeline' ? 'text-blue-600' : 'text-slate-400'}`} /> Pipeline
              </button>
              <button 
                onClick={() => setActiveMenu('monitoring')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${activeMenu === 'monitoring' ? 'text-blue-700 bg-blue-50/80' : 'text-slate-600 hover:bg-slate-50'}`}
              >
                <Activity className={`w-4 h-4 ${activeMenu === 'monitoring' ? 'text-blue-600' : 'text-slate-400'}`} /> Giám sát
              </button>
            </nav>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8 shrink-0">
          <div className="flex-1 max-w-xl relative">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input 
              type="text" 
              placeholder="Tìm kiếm hệ thống, CVE, pipeline..." 
              className="w-full bg-slate-50 border border-slate-200 rounded-full py-2 pl-10 pr-4 text-sm focus:bg-white focus:ring-2 focus:ring-blue-100 focus:border-blue-300 outline-none transition-all placeholder:text-slate-400" 
            />
          </div>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-sm font-semibold text-emerald-600">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Live
            </div>
            <div className="flex items-center gap-3 py-2 border-l border-slate-200 pl-6">
              <div className="w-9 h-9 rounded-full bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-700 font-bold text-sm shadow-sm opacity-90">
                NM
              </div>
              <div className="text-sm">
                <p className="font-bold text-slate-700 leading-none">Nguyễn Minh</p>
                <p className="text-[11px] text-slate-500 mt-1 font-medium">Developer</p>
              </div>
            </div>
          </div>
        </header>

        {/* Content Scrollable area */}
        <div className="flex-1 overflow-auto bg-[#fafafa] p-8">
          
          <div className="max-w-7xl mx-auto space-y-6">

            {activeMenu === 'dashboard' && <Dashboard />}

            {activeMenu === 'upload' && (
              <>
                {/* Khối 1: Tải lên SBOM & Thống kê */}
                <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8">
                  <div className="flex-1 w-full max-w-xl">
                    <h3 className="font-bold text-slate-800 mb-4 border-b border-slate-100 pb-3 flex items-center gap-2 text-sm">
                      <Database className="w-4 h-4 text-blue-500" /> Tải lên SBOM
                    </h3>
                    <SBOMUpload onUploadSuccess={handleUploadSuccess} />
                  </div>
                  
                  <div className="flex gap-4 shrink-0 mt-4 lg:mt-0">
                    <div className="px-6 py-4 bg-blue-50/50 rounded-xl border border-blue-100 shadow-sm text-center min-w-[130px]">
                      <p className="text-xs font-bold uppercase text-slate-500 mb-1 tracking-wider">Thành phần</p>
                      <p className="text-3xl font-bold text-blue-600">{components.length}</p>
                    </div>
                    <div className="px-6 py-4 bg-amber-50/50 rounded-xl border border-amber-100 shadow-sm text-center min-w-[130px]">
                      <p className="text-xs font-bold uppercase text-slate-500 mb-1 tracking-wider">Lỗ hổng (CVE)</p>
                      <p className="text-3xl font-bold text-amber-500">{vulnerabilities.length}</p>
                    </div>
                  </div>
                </div>
            </div>

            {/* Khối Metadata (Thông tin cơ bản) */}
            {metadata && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
                <div className="px-6 py-5 border-b border-slate-100">
                    <h3 className="font-bold text-slate-800 flex items-center gap-2">
                        <Info className="w-4 h-4 text-indigo-500" /> Thông tin chung
                    </h3>
                </div>
                <div className="p-6 bg-slate-50/50 grid grid-cols-1 md:grid-cols-2 gap-y-4 gap-x-8">
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Mã định danh (SBOM ID)</p>
                    <p className="text-sm font-medium text-slate-800 truncate" title={metadata.sbom_id}>{metadata.sbom_id}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Thời gian tạo</p>
                    <p className="text-sm font-medium text-slate-800">{new Date(metadata.created_timestamp).toLocaleString('vi-VN')}</p>
                  </div>
                  <div className="md:col-span-2">
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Tác giả</p>
                    <p className="text-sm font-medium text-slate-800">{metadata.authors}</p>
                  </div>
                  <div className="md:col-span-2">
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Công cụ tạo (Tools)</p>
                    <p className="text-sm font-medium text-slate-800">{metadata.tool_components}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Dịch vụ (Services)</p>
                    <p className="text-sm font-medium text-slate-800">{metadata.tool_services}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Giai đoạn Vòng đời</p>
                    <p className="text-sm font-medium text-slate-800">{metadata.lifecycle_phase}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Khối 2: Danh mục thành phần (Ngay bên dưới) */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
                <div className="px-6 py-5 border-b border-slate-100">
                    <h3 className="font-bold text-slate-800 flex items-center gap-2">
                        <Box className="w-4 h-4 text-purple-500" /> Danh mục thành phần
                    </h3>
                </div>
                <div className="p-6 bg-slate-50/50">
                  <div className="bg-white border border-slate-200 rounded-lg overflow-auto max-h-[400px]">
                    {components.length > 0 ? (
                      <ComponentTable components={components} />
                    ) : (
                      <div className="flex flex-col items-center justify-center p-16 text-slate-400">
                        <Box className="w-12 h-12 mb-3 opacity-20 text-slate-500" />
                        <p className="text-sm font-medium">Chưa có dữ liệu SBOM thực tế. Vui lòng tải lên SBOM.</p>
                      </div>
                    )}
                  </div>
                </div>
            </div>

            {/* Khối Cây Phụ Thuộc */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
                <div className="px-6 py-5 border-b border-slate-100">
                    <h3 className="font-bold text-slate-800 flex items-center gap-2">
                        <ListTree className="w-4 h-4 text-emerald-500" /> Cây phụ thuộc
                    </h3>
                </div>
                <div className="p-6 bg-slate-50/50">
                  <div className="bg-white border border-slate-200 rounded-lg overflow-auto max-h-[400px]">
                    <DependencyTree dependencies={dependencies} components={components} />
                  </div>
                </div>
            </div>

            {/* Khối Lỗ hổng */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100 flex justify-between items-center">
                <h3 className="font-bold text-slate-800 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-500" /> Lỗ hổng ưu tiên cao
                </h3>
              </div>
              <div className="p-6 bg-slate-50/50">
                <div className="bg-white border border-slate-200 rounded-lg overflow-auto max-h-[400px]">
                  <table className="w-full text-left text-sm whitespace-nowrap">
                    <thead className="sticky top-0 bg-white z-10 shadow-sm">
                      <tr className="text-slate-500 text-xs uppercase tracking-wider font-semibold border-b border-slate-200">
                        <th className="px-6 py-4 font-medium">STT</th>
                        <th className="px-6 py-4 font-medium">NAME</th>
                        <th className="px-6 py-4 font-medium">INSTALLED</th>
                        <th className="px-6 py-4 font-medium">FIXED IN</th>
                        <th className="px-6 py-4 font-medium">TYPE</th>
                        <th className="px-6 py-4 font-medium">VULNERABILITY</th>
                        <th className="px-6 py-4 font-medium">SEVERITY</th>
                        <th className="px-6 py-4 font-medium">EPSS</th>
                        <th className="px-6 py-4 font-medium">RISK</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {vulnerabilities.length > 0 ? (
                        vulnerabilities.map((vuln, idx) => {
                          const severity = vuln.severity || 'unknown';
                          let severityColor = "bg-slate-50 text-slate-700 border-slate-200";
                          let severityText = severity;
                          if (severity.toLowerCase() === 'critical') { severityColor = "text-red-700 bg-red-50 border-red-100"; severityText="Nghiêm trọng"; }
                          else if (severity.toLowerCase() === 'high') { severityColor = "text-amber-700 bg-amber-50 border-amber-100"; severityText="Cao"; }
                          else if (severity.toLowerCase() === 'medium') { severityColor = "text-blue-700 bg-blue-50 border-blue-100"; severityText="Trung bình"; }
                          else if (severity.toLowerCase() === 'low') { severityColor = "text-emerald-700 bg-emerald-50 border-emerald-100"; severityText="Thấp"; }

                          const epssText = vuln.epss !== null && vuln.epss !== undefined
                            ? `${(vuln.epss * 100).toFixed(1)}%`
                            : 'N/A';

                            return (
                            <tr key={vuln.vuln_id || idx} className="hover:bg-slate-50/50 transition-colors">
                              <td className="px-6 py-4 font-mono text-slate-700">{idx + 1}</td>
                              <td className="px-6 py-4 font-medium text-slate-700">{vuln.name || 'N/A'}</td>
                              <td className="px-6 py-4 text-slate-700">{vuln.installed || 'N/A'}</td>
                              <td className="px-6 py-4 text-slate-700">{vuln.fixed_in || 'N/A'}</td>
                              <td className="px-6 py-4 text-slate-700">{vuln.package_type || 'N/A'}</td>
                              <td className="px-6 py-4 font-mono text-slate-600 font-medium">{vuln.vulnerability || vuln.cve_id || 'N/A'}</td>
                              <td className="px-6 py-4">
                                <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${severityColor}`}>
                                  {severityText}
                                </span>
                              </td>
                              <td className="px-6 py-4 text-slate-700">{epssText}</td>
                              <td className="px-6 py-4 text-slate-700">{vuln.risk || 'N/A'}</td>
                            </tr>
                          );
                        })
                      ) : (
                        <tr>
                          <td colSpan={9} className="px-6 py-12 text-center text-slate-500 bg-slate-50/50">
                            <ShieldAlert className="w-10 h-10 mx-auto mb-3 text-slate-300 opacity-60" />
                            <p className="font-medium text-slate-600">Không tìm thấy lỗ hổng nào trong SBOM cục bộ</p>
                            <p className="text-xs text-slate-400 mt-1">File an toàn hoặc công cụ chưa đính kèm dữ liệu quét.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            </>
            )}

            {activeMenu === 'system' && (
              // Lazy-load Systems component to keep App simple
              <Systems systems={systems} refresh={fetchSystems} />
            )}

            {activeMenu !== 'dashboard' && activeMenu !== 'upload' && activeMenu !== 'system' && (
              <div className="flex flex-col items-center justify-center p-20 text-slate-400 bg-white border border-slate-200 rounded-xl shadow-sm">
                <Activity className="w-16 h-16 mb-4 opacity-20" />
                <p className="text-lg font-medium text-slate-600">Đang phát triển tính năng này</p>
                <p className="text-sm mt-2">Vui lòng chọn Dashboard hoặc mục Tải lên để xem trước.</p>
              </div>
            )}

          </div>
        </div>
      </main>
    </div>
  );
}

export default App;

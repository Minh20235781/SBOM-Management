/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect } from 'react';
import Systems from './components/Systems';
import SBOMUpload, { createDefaultSBOMUploadSession, type SBOMUploadSession } from './components/SBOMUpload';
import ComponentTable from './components/ComponentTable';
import SbomParsedDependencyGraph from './components/SbomParsedDependencyGraph';
import Dashboard from './components/Dashboard';
import SbomSnapshots from './components/SbomSnapshots';
import SystemSbomDetail from './components/SystemSbomDetail';
import DeveloperCicd from './components/DeveloperCicd';
import SbomValidationScenarios from './components/SbomValidationScenarios';
import GlobalSearch from './components/GlobalSearch';
import { AuditPage, CompliancePage, ComponentsPage, DependenciesPage, VulnerabilitiesPage } from './components/ManagementPages';
import PipelineMonitoring from './components/PipelineMonitoring';
import { API_BASE } from './api';
import { type SBOMComponent, type BackendVulnerability, type CicdPipeline, type Dependency, type SBOMMetadata } from './types/sbom';
import { 
  Database, LayoutDashboard, Box, ShieldAlert, 
  Activity, ListTree, History, ShieldCheck, FileKey, 
  GitMerge, Server, Layers, UploadCloud, Info,
  PanelLeftClose, PanelLeftOpen, TestTube2, Moon, Sun
} from 'lucide-react';

function App() {
  const [components, setComponents] = useState<SBOMComponent[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<BackendVulnerability[]>([]);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [metadata, setMetadata] = useState<SBOMMetadata | null>(null);
  const [systems, setSystems] = useState<any[]>([]);
  const [activeMenu, setActiveMenu] = useState<string>('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem('sbom-theme') === 'dark');
  const [sbomUploadSession, setSbomUploadSession] = useState<SBOMUploadSession>(() => createDefaultSBOMUploadSession());
  const [selectedSystemDetail, setSelectedSystemDetail] = useState<any | null>(null);
  const [searchPipelines, setSearchPipelines] = useState<CicdPipeline[]>([]);
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState<number | null>(null);
  const [selectedPipelineTarget, setSelectedPipelineTarget] = useState<CicdPipeline | null>(null);
  const [pipelineNavigationVersion, setPipelineNavigationVersion] = useState(0);

  const formatMetadataValue = (value?: string | null) => {
    if (!value) return '-';
    const normalized = value.trim();
    return normalized && normalized.toUpperCase() !== 'N/A' ? normalized : '-';
  };

  const sidebarItemClass = (active: boolean) =>
    `w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
      active
        ? 'text-blue-700 bg-blue-50/80 dark:bg-blue-950/50 dark:text-blue-200'
        : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'
    }`;

  const sidebarSplitItemClass = (active: boolean) =>
    `w-full flex justify-between items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
      active
        ? 'text-blue-700 bg-blue-50/80 dark:bg-blue-950/50 dark:text-blue-200'
        : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'
    }`;

  const sidebarIconClass = (active: boolean, inactiveClass = 'text-slate-400') =>
    `w-4 h-4 ${active ? 'text-blue-600 dark:text-blue-300' : `${inactiveClass} dark:text-slate-500`}`;

  const loadGeneratedSbomData = async (sbomId: string) => {
    const metaRes = await fetch(`${API_BASE}/sboms/${sbomId}`);
    const metaData = await metaRes.json();
    setMetadata(metaData);

    const compRes = await fetch(`${API_BASE}/sboms/${sbomId}/components`);
    const compData = await compRes.json();
    setComponents(compData);

    const depRes = await fetch(`${API_BASE}/sboms/${sbomId}/dependencies`);
    const depData = await depRes.json();
    setDependencies(depData);

    const vulnRes = await fetch(`${API_BASE}/sboms/${sbomId}/vulnerabilities`);
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
    try { await fetchSystems(); } catch { /* ignore */ }
  };

  const handleUploadSuccess = async (rawData: unknown) => {
    try {
      if (rawData && typeof rawData === 'object' && (rawData as any).success && (rawData as any).sbomId && !(rawData as any).sbom) {
        await loadGeneratedSbomData(String((rawData as any).sbomId));
        return;
      }

      let uploadBody: any = rawData;
      // If caller provided { sbom, systemName }
      if (rawData && typeof rawData === 'object' && (rawData as any).sbom) {
        const payload = rawData as any;
        uploadBody = { sbom: payload.sbom, systemName: payload.systemName, repoUrl: payload.repoUrl };
        if (payload.systemName) {
          // Create or get system
          const sysRes = await fetch(`${API_BASE}/systems`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: payload.systemName })
          });
          if (!sysRes.ok) {
            const errData = await sysRes.json().catch(() => ({}));
            throw new Error(errData.error || errData.message || 'Không thể tạo hệ thống');
          }
          const sysData = await sysRes.json();
          uploadBody.system_id = sysData.system_id || sysData.systemId || sysData.id;
        }
      }

      const response = await fetch(`${API_BASE}/sboms/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(uploadBody)
      });
      const data = await response.json();
      
      if (data.success) {
        const sbomId = data.sbomId;
        // Fetch metadata
        const metaRes = await fetch(`${API_BASE}/sboms/${sbomId}`);
        const metaData = await metaRes.json();
        setMetadata(metaData);

        // Fetch components
        const compRes = await fetch(`${API_BASE}/sboms/${sbomId}/components`);
        const compData = await compRes.json();
        setComponents(compData);

        // Fetch dependencies
        const depRes = await fetch(`${API_BASE}/sboms/${sbomId}/dependencies`);
        const depData = await depRes.json();
        setDependencies(depData);
        
        // Fetch vulnerabilities
        const vulnRes = await fetch(`${API_BASE}/sboms/${sbomId}/vulnerabilities`);
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
      const res = await fetch(`${API_BASE}/systems`);
      if (!res.ok) throw new Error('Failed to fetch systems');
      const list = await res.json();
      setSystems(list);
    } catch (e) {
      console.error('Failed to load systems', e);
    }
  };

  // Load systems on mount
  useEffect(() => { fetchSystems(); }, []);

  useEffect(() => {
    let cancelled = false;
    const loadSearchPipelines = async () => {
      const responses = await Promise.all(systems.map(async system => {
        try {
          const response = await fetch(`${API_BASE}/projects/${system.system_id}/pipelines`);
          if (!response.ok) return [];
          const data = await response.json();
          return Array.isArray(data) ? data : [];
        } catch {
          return [];
        }
      }));
      if (!cancelled) setSearchPipelines(responses.flat());
    };
    loadSearchPipelines();
    return () => { cancelled = true; };
  }, [systems]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('sbom-theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  return (
    <div className={`flex h-screen bg-slate-50 text-slate-900 font-sans overflow-hidden dark:bg-slate-950 dark:text-slate-100 ${darkMode ? 'dark' : ''}`}>
      {/* Sidebar */}
      {!sidebarCollapsed && <aside className="w-64 bg-white border-r border-slate-200 flex flex-col hidden md:flex shrink-0 dark:bg-slate-900 dark:border-slate-800">
        <div className="h-16 flex items-center px-6 border-b border-slate-200 shrink-0 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-1.5 rounded-lg shadow-sm shadow-blue-200">
              <LayoutDashboard className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-sm leading-tight text-slate-800 dark:text-slate-100">SBOM Management</h1>
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
                className={sidebarItemClass(activeMenu === 'dashboard')}
              >
                <LayoutDashboard className={sidebarIconClass(activeMenu === 'dashboard')} /> Dashboard
              </button>
              <button 
                onClick={() => setActiveMenu('system')}
                className={sidebarItemClass(activeMenu === 'system')}
              >
                <Server className={sidebarIconClass(activeMenu === 'system')} /> Hệ thống
              </button>
            </nav>
          </div>

          {/* Menu Nhóm SBOM */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">SBOM</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('upload')}
                className={sidebarItemClass(activeMenu === 'upload')}
              >
                <UploadCloud className={sidebarIconClass(activeMenu === 'upload')} /> Tải lên
              </button>
              <button 
                onClick={() => setActiveMenu('components')}
                className={sidebarSplitItemClass(activeMenu === 'components')}
              >
                <div className="flex items-center gap-3">
                  <Layers className={sidebarIconClass(activeMenu === 'components')} /> Thành phần
                </div>
                {components.length > 0 && (
                  <span className="rounded-full border border-purple-100 bg-purple-50 px-1.5 py-0.5 text-[10px] font-bold text-purple-600 dark:border-purple-900 dark:bg-purple-950/50 dark:text-purple-300">{components.length}</span>
                )}
              </button>
              <button 
                onClick={() => setActiveMenu('dependencies')}
                className={sidebarSplitItemClass(activeMenu === 'dependencies')}
              >
                <div className="flex items-center gap-3">
                  <ListTree className={sidebarIconClass(activeMenu === 'dependencies')} /> Phụ thuộc
                </div>
                {dependencies.length > 0 && (
                  <span className="rounded-full border border-emerald-100 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-bold text-emerald-600 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300">{dependencies.length}</span>
                )}
              </button>
              <button 
                onClick={() => setActiveMenu('validation-scenarios')}
                className={sidebarItemClass(activeMenu === 'validation-scenarios')}
              >
                <TestTube2 className={sidebarIconClass(activeMenu === 'validation-scenarios')} /> Kiểm chứng
              </button>
              <button 
                onClick={() => setActiveMenu('history')}
                className={sidebarItemClass(activeMenu === 'history')}
              >
                <History className={sidebarIconClass(activeMenu === 'history')} /> Lịch sử phiên bản
              </button>
            </nav>
          </div>

          {/* Menu Nhóm Bảo Mật */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Bảo mật</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('cve')}
                className={sidebarSplitItemClass(activeMenu === 'cve')}
              >
                <div className="flex items-center gap-3">
                  <ShieldAlert className={sidebarIconClass(activeMenu === 'cve', 'text-red-400')} /> Lỗ hổng (CVE)
                </div>
                {vulnerabilities.length > 0 && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-50 text-red-600 border border-red-100">{vulnerabilities.length}</span>
                )}
              </button>
              <button 
                onClick={() => setActiveMenu('compliance')}
                className={sidebarItemClass(activeMenu === 'compliance')}
              >
                <ShieldCheck className={sidebarIconClass(activeMenu === 'compliance')} /> Tuân thủ
              </button>
              <button 
                onClick={() => setActiveMenu('audit')}
                className={sidebarItemClass(activeMenu === 'audit')}
              >
                <FileKey className={sidebarIconClass(activeMenu === 'audit')} /> Kiểm toán
              </button>
            </nav>
          </div>

          {/* Menu Nhóm CI/CD */}
          <div>
            <p className="px-3 text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">CI/CD</p>
            <nav className="space-y-1">
              <button 
                onClick={() => setActiveMenu('pipeline')}
                className={sidebarItemClass(activeMenu === 'pipeline')}
              >
                <GitMerge className={sidebarIconClass(activeMenu === 'pipeline')} /> Pipeline
              </button>
              <button 
                onClick={() => setActiveMenu('monitoring')}
                className={sidebarItemClass(activeMenu === 'monitoring')}
              >
                <Activity className={sidebarIconClass(activeMenu === 'monitoring')} /> Giám sát
              </button>
            </nav>
          </div>
        </div>
      </aside>}

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8 shrink-0 dark:bg-slate-900 dark:border-slate-800">
          <button
            type="button"
            onClick={() => setSidebarCollapsed(value => !value)}
            title={sidebarCollapsed ? 'Mo sidebar' : 'An sidebar'}
            className="hidden md:inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 hover:bg-slate-50 hover:text-slate-800 transition mr-3 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white"
          >
            {sidebarCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>
          <div className="min-w-0 flex-1">
            <GlobalSearch
              systems={systems}
              vulnerabilities={vulnerabilities}
              pipelines={searchPipelines}
              onSelectSystem={system => {
                setSelectedSystemDetail(system);
                setActiveMenu('system-detail');
              }}
              onSelectVulnerability={vulnerability => {
                setSelectedVulnerabilityId(vulnerability.vuln_id);
                setActiveMenu('cve');
              }}
              onSelectPipeline={pipeline => {
                setSelectedPipelineTarget(pipeline);
                setPipelineNavigationVersion(version => version + 1);
                setActiveMenu('pipeline');
              }}
            />
          </div>
          <div className="flex items-center gap-6">
            <button
              type="button"
              onClick={() => setDarkMode(value => !value)}
              title={darkMode ? 'Chuyen sang giao dien sang' : 'Chuyen sang giao dien toi'}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition hover:bg-slate-50 hover:text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white"
            >
              {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <div className="flex items-center gap-2 text-sm font-semibold text-emerald-600">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Live
            </div>
            <div className="flex items-center gap-3 py-2 border-l border-slate-200 pl-6 dark:border-slate-700">
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
        <div className="flex-1 overflow-auto bg-[#fafafa] p-8 dark:bg-slate-950">
          
          <div className={`${activeMenu === 'history' || activeMenu === 'pipeline' ? 'max-w-none' : 'max-w-7xl'} mx-auto space-y-6`}>

            {activeMenu === 'dashboard' && <Dashboard />}

            {activeMenu === 'upload' && (
              <>
                {/* Khối 1: Tải lên SBOM & Thống kê */}
                <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                  <div className="w-full">
                    <h3 className="font-bold text-slate-800 mb-4 border-b border-slate-100 pb-3 flex items-center gap-2 text-sm">
                      <Database className="w-4 h-4 text-blue-500" /> Tải lên SBOM
                    </h3>
                    <SBOMUpload
                      onUploadSuccess={handleUploadSuccess}
                      session={sbomUploadSession}
                      onSessionChange={setSbomUploadSession}
                    />
                  </div>
                  
                  <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="px-6 py-4 bg-blue-50/50 rounded-xl border border-blue-100 shadow-sm text-center">
                      <p className="text-xs font-bold uppercase text-slate-500 mb-1 tracking-wider">Thành phần</p>
                      <p className="text-3xl font-bold text-blue-600">{components.length}</p>
                    </div>
                    <div className="px-6 py-4 bg-amber-50/50 rounded-xl border border-amber-100 shadow-sm text-center">
                      <p className="text-xs font-bold uppercase text-slate-500 mb-1 tracking-wider">Lỗ hổng (CVE)</p>
                      <p className="text-3xl font-bold text-amber-500">{vulnerabilities.length}</p>
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
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Tác giả</p>
                    <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.authors)}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Công cụ tạo (Tools)</p>
                    <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.tool_components)}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Dịch vụ (Services)</p>
                    <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.tool_services)}</p>
                  </div>
                  <div>
                    <p className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-1">Giai đoạn Vòng đời</p>
                    <p className="text-sm font-medium text-slate-800">{formatMetadataValue(metadata.lifecycle_phase)}</p>
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
                  <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                    <SbomParsedDependencyGraph
                      projectName={metadata?.sbom_id || 'Uploaded SBOM'}
                      sbomId={metadata?.sbom_id}
                      components={components}
                      dependencies={dependencies}
                      vulnerabilities={vulnerabilities}
                    />
                  </div>
                </div>
            </div>

            {/* Khối Lỗ hổng */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-5 border-b border-slate-100 flex justify-between items-center">
                <h3 className="font-bold text-slate-800 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-500" /> Các lỗ hổng đã phát hiện
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
              <Systems
                systems={systems}
                refresh={fetchSystems}
                onViewDetail={(system) => {
                  setSelectedSystemDetail(system);
                  setActiveMenu('system-detail');
                }}
              />
            )}

            {activeMenu === 'system-detail' && selectedSystemDetail && (
              <SystemSbomDetail
                system={selectedSystemDetail}
                onBack={() => {
                  setSelectedSystemDetail(null);
                  setActiveMenu('system');
                }}
              />
            )}

            {activeMenu === 'history' && (
              <SbomSnapshots systems={systems} />
            )}

            {activeMenu === 'validation-scenarios' && (
              <SbomValidationScenarios />
            )}

            {activeMenu === 'pipeline' && (
              <DeveloperCicd
                key={`pipeline-${selectedPipelineTarget?.pipeline_id || 'default'}-${pipelineNavigationVersion}`}
                systems={systems}
                refreshSystems={fetchSystems}
                initialProjectId={selectedPipelineTarget?.project_id}
                initialPipelineId={selectedPipelineTarget?.pipeline_id}
              />
            )}

            {activeMenu === 'components' && <ComponentsPage components={components} dependencies={dependencies} vulnerabilities={vulnerabilities} metadata={metadata} />}
            {activeMenu === 'dependencies' && <DependenciesPage components={components} dependencies={dependencies} vulnerabilities={vulnerabilities} metadata={metadata} />}
            {activeMenu === 'cve' && <VulnerabilitiesPage components={components} dependencies={dependencies} vulnerabilities={vulnerabilities} metadata={metadata} selectedVulnerabilityId={selectedVulnerabilityId} />}
            {activeMenu === 'compliance' && <CompliancePage components={components} dependencies={dependencies} vulnerabilities={vulnerabilities} metadata={metadata} />}
            {activeMenu === 'audit' && <AuditPage />}
            {activeMenu === 'monitoring' && <PipelineMonitoring systems={systems} onOpenPipeline={pipeline => { setSelectedPipelineTarget(pipeline); setPipelineNavigationVersion(version => version + 1); setActiveMenu('pipeline'); }} />}

          </div>
        </div>
      </main>
    </div>
  );
}

export default App;

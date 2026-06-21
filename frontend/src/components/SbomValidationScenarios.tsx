import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, CheckCircle2, Circle, ExternalLink, FileCode2,
  Network, Package, Play, RefreshCw, Search, ShieldCheck,
} from 'lucide-react';
import { API_BASE_URL } from '../api';
import SbomDependencyGraph from './SbomDependencyGraph';
import type { SbomGraphResponse } from '../types/sbom';

type Repo = {
  id: string; projectName: string; githubUrl: string; applicationType: string;
  repoScope: string; architectureType: string; techStack: string[];
  packageManager: string[]; dependencyFiles: string[]; description: string;
  sbomStatus: string;
  latestSbomId?: string | null; sourceCommit?: string | null; analyzedAt?: string | null;
};
type Analysis = {
  runId: string; projectName: string; githubUrl: string; sourceCommit: string;
  shortCommit: string; branch: string; commitTimestamp: string; analyzedAt: string;
  dependencyFiles: Array<{ path: string; name: string; sizeBytes: number }>;
  componentCount: number; dependencyCount: number; ecosystems: string[];
  analysisDurationMs: number; toolInfo: string; confirmed?: boolean;
  components: Array<{ name: string; version?: string | null; type: string; purl?: string | null }>;
  inferredMetadata?: Record<string, { value: string | string[]; source: string; confidence: string; reason?: string }>;
  workflowScenario: 'SERVICE_HAS_SBOM' | 'SERVICE_WITHOUT_SBOM';
  repositorySbom: {
    detected: boolean; usableForVerification: boolean;
    selectedFile?: { path: string; format: string; sizeBytes: number; componentCount: number; sourceCommit?: string | null } | null;
    files: Array<{ path: string; format: string; sizeBytes: number; parseable: boolean; componentCount: number }>;
  };
};
type Graph = {
  nodes: Array<{ id: string; label: string; type: string; ecosystem: string }>;
  edges: Array<{ id: string; source: string; target: string }>;
  summary: { nodeCount: number; edgeCount: number };
};
type Verification = {
  status: 'PASS' | 'FAIL'; trustScore: number; trustLevel: string;
  matchedCount: number; missingCount: number; extraCount: number; versionMismatchCount: number;
  sourceComponentCount: number; sbomComponentCount: number;
  MATCHED: string[]; MISSING_IN_SBOM: string[]; EXTRA_IN_SBOM: string[];
  VERSION_MISMATCH: Array<{ component: string; sourceVersion?: string; sbomVersion?: string; ecosystem: string }>;
  sbomSourceCommit?: string | null; currentCommit?: string | null; verifiedAt?: string;
  sourceChangedSinceGeneration?: boolean; recommendation?: string;
};

const api = (path: string) => `${API_BASE_URL}${path}`;
const errorMessage = async (response: Response) => {
  const body = await response.json().catch(() => ({}));
  const prefix: Record<string, string> = {
    SOURCE_CLONE_FAILED: 'Không thể tải source repository',
    SYFT_ANALYSIS_FAILED: 'Syft phân tích thất bại',
    DEPENDENCY_FILES_NOT_FOUND: 'Không tìm thấy dependency file được hỗ trợ',
    CURRENT_SBOM_NOT_FOUND: 'Repository chưa có SBOM đang lưu',
  };
  return `${prefix[body.code] || 'Thao tác thất bại'}: ${body.message || response.statusText}`;
};
const formatTime = (value?: string | null) => value ? new Date(value).toLocaleString('vi-VN') : '—';
const short = (value?: string | null) => value ? value.slice(0, 8) : '—';
const statusClass = (status: string) => status.includes('Chưa')
  ? 'border-slate-200 bg-slate-50 text-slate-700'
  : status.includes('Đã') ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
    : 'border-amber-200 bg-amber-50 text-amber-800';

const toVisualGraph = (graph: Graph | null): SbomGraphResponse | null => {
  if (!graph) return null;
  const depthById = new Map<string, number>();
  const incoming = new Set(graph.edges.map(edge => edge.target));
  const roots = graph.nodes.filter(node => !incoming.has(node.id));
  roots.forEach(node => depthById.set(node.id, 0));
  for (let pass = 0; pass < graph.nodes.length; pass += 1) {
    graph.edges.forEach(edge => {
      const sourceDepth = depthById.get(edge.source);
      if (sourceDepth !== undefined && depthById.get(edge.target) === undefined) depthById.set(edge.target, sourceDepth + 1);
    });
  }
  const rowsByDepth = new Map<number, number>();
  const nodes = graph.nodes.map(node => {
    const depth = depthById.get(node.id) ?? 1;
    const row = rowsByDepth.get(depth) || 0;
    rowsByDepth.set(depth, row + 1);
    return {
      ...node,
      type: node.type === 'PROJECT' ? 'PROJECT' as const : 'COMPONENT' as const,
      vulnerabilityCount: 0,
      riskLevel: 'LOW' as const,
      depth,
      x: depth * 330,
      y: row * 120,
    };
  });
  return {
    snapshotId: 'validation-analysis',
    nodes,
    edges: graph.edges.map(edge => ({ ...edge, relationship: 'DEPENDS_ON' as const, isTransitive: false })),
    summary: { ...graph.summary, maxDepth: Math.max(0, ...nodes.map(node => node.depth)), cycleDetected: false, criticalCount: 0, highCount: 0 },
  };
};

export default function SbomValidationScenarios() {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [query, setQuery] = useState('');
  const [scenario, setScenario] = useState<1 | 2>(1);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [generated, setGenerated] = useState(false);
  const [graphSearch, setGraphSearch] = useState('');
  const [graphDepth, setGraphDepth] = useState(5);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const analysisRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<HTMLDivElement>(null);

  const selected = repos.find(repo => repo.id === selectedId) || null;
  const filtered = useMemo(() => repos.filter(repo => `${repo.projectName} ${repo.techStack.join(' ')}`.toLowerCase().includes(query.toLowerCase())), [repos, query]);
  const visualGraph = useMemo(() => {
    const base = toVisualGraph(graph);
    if (!base) return null;
    const needle = graphSearch.trim().toLowerCase();
    const nodes = base.nodes.filter(node => node.depth <= graphDepth
      && (!needle || `${node.label} ${node.ecosystem} ${node.version || ''}`.toLowerCase().includes(needle))
      && (!onlyVulnerable || node.vulnerabilityCount > 0));
    const nodeIds = new Set(nodes.map(node => node.id));
    const edges = base.edges.filter(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target));
    return { ...base, nodes, edges, summary: { ...base.summary, nodeCount: nodes.length, edgeCount: edges.length } };
  }, [graph, graphSearch, graphDepth, onlyVulnerable]);

  const loadCatalog = async () => {
    try {
      const response = await fetch(api('/api/validation-scenarios'));
      if (!response.ok) throw new Error(await errorMessage(response));
      const data = await response.json();
      setRepos(data.repositories || []);
    } catch (error) { setError(error instanceof Error ? error.message : 'Không tải được repository catalog.'); }
  };
  // Catalog loading is the external synchronization owned by this page.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { void loadCatalog(); }, []);

  const run = async (name: string, operation: () => Promise<void>) => {
    setBusy(name); setError(''); setNotice('');
    try { await operation(); } catch (error) { setError(error instanceof Error ? error.message : 'Thao tác thất bại.'); }
    finally { setBusy(''); }
  };
  const post = async (path: string) => {
    const response = await fetch(api(path), { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    if (!response.ok) throw new Error(await errorMessage(response));
    return response.json();
  };
  const analyze = () => selected && run('analyze', async () => {
    const data = await post(`/api/validation-scenarios/${selected.id}/analyze`);
    setAnalysis(data.analysis); setGraph(data.graph); setVerification(null);
    const hasRepositorySbom = data.analysis.repositorySbom?.usableForVerification;
    setScenario(hasRepositorySbom ? 2 : 1);
    setNotice(hasRepositorySbom
      ? `Đã nhận diện SBOM ${data.analysis.repositorySbom.selectedFile.path} ngay trong repository. Flow đã chuyển sang Verify Current SBOM.`
      : `Repository không chứa SBOM dùng được. Flow đã chuyển sang tạo SBOM mới tại commit ${data.analysis.shortCommit}.`);
  });
  const confirm = () => analysis && run('confirm', async () => {
    await post(`/api/validation-scenarios/runs/${analysis.runId}/confirm`);
    setAnalysis({ ...analysis, confirmed: true }); setNotice('Kết quả phân tích đã được xác nhận.');
  });
  const generate = () => analysis && run('generate', async () => {
    await post(`/api/validation-scenarios/runs/${analysis.runId}/generate`);
    setGenerated(true);
    setNotice(`Đã generate và lưu CycloneDX SBOM gắn với commit ${analysis.shortCommit}.`);
    await loadCatalog();
  });
  const verifyCurrent = () => selected && run('verify', async () => {
    const data = await post(analysis?.repositorySbom?.usableForVerification
      ? `/api/validation-scenarios/runs/${analysis.runId}/verify`
      : `/api/validation-scenarios/${selected.id}/verify-current`);
    setVerification(data.verificationReport);
    setNotice(data.verificationReport.recommendation || 'Verify hoàn tất.');
    await loadCatalog();
  });

  const steps = scenario === 1
    ? [
      ['1', 'Chọn repository', Boolean(selected)], ['2', 'Analyze Source', Boolean(analysis)],
      ['3', 'Xác nhận phân tích', Boolean(analysis?.confirmed)], ['4', 'Generate & lưu SBOM', generated],
    ]
    : [
      ['1', 'Analyze & nhận diện SBOM', Boolean(analysis?.repositorySbom?.usableForVerification)], ['2', 'Verify Current SBOM', Boolean(verification)],
      ['3', 'Đọc Trust Score', Boolean(verification)], ['4', 'Regenerate nếu cần', verification?.status === 'PASS'],
    ];

  return (
    <div className="space-y-6">
      <header className="rounded-2xl border border-blue-100 bg-gradient-to-br from-white to-blue-50 p-6 text-slate-900 shadow-sm dark:border-slate-700 dark:from-slate-950 dark:to-slate-900 dark:text-white">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div><p className="text-xs font-bold uppercase tracking-[.18em] text-blue-600 dark:text-blue-300">Repository-first SBOM workflow</p>
            <h1 className="mt-2 text-2xl font-bold">SBOM Validation Scenarios</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">SBOM luôn thuộc về source code của một Web Application trong một GitHub repository. Phiên bản này chưa hỗ trợ multi-repo hoặc microservice nhiều repository.</p>
          </div>
          <div className="flex gap-2"><span className="rounded-full bg-blue-100 px-3 py-1.5 text-xs font-bold text-blue-700 dark:bg-blue-500/15 dark:text-blue-200">Web Application</span><span className="rounded-full bg-emerald-100 px-3 py-1.5 text-xs font-bold text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-200">Single Repository</span></div>
        </div>
      </header>

      <div className="grid gap-3 md:grid-cols-2">
        {([1, 2] as const).map(id => <button key={id} onClick={() => { setScenario(id); setVerification(null); }} className={`rounded-xl border p-4 text-left transition ${scenario === id ? 'border-blue-500 bg-blue-50 ring-2 ring-blue-100' : 'border-slate-200 bg-white hover:border-slate-300'}`}>
          <p className="text-xs font-bold uppercase text-blue-600">Kịch bản {id}</p><p className="mt-1 font-bold text-slate-900">{id === 1 ? 'Service mới chưa có SBOM' : 'Service đã có SBOM, source vừa cập nhật'}</p>
          <p className="mt-1 text-sm text-slate-500">{id === 1 ? 'Phân tích source → xác nhận → generate CycloneDX.' : 'Lấy SBOM đang lưu → phân tích lại source → Trust Score.'}</p>
        </button>)}
      </div>

      {(error || notice) && <div className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${error ? 'border-rose-200 bg-rose-50 text-rose-800' : 'border-emerald-200 bg-emerald-50 text-emerald-800'}`}>{error ? <AlertTriangle className="h-5 w-5 shrink-0" /> : <CheckCircle2 className="h-5 w-5 shrink-0" />}<pre className="whitespace-pre-wrap font-sans">{error || notice}</pre></div>}

      <div className="grid gap-6 xl:grid-cols-[390px_1fr]">
        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 p-4"><h2 className="font-bold text-slate-900">Repository thật ({repos.length})</h2><div className="relative mt-3"><Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Tìm theo tên hoặc tech stack" className="w-full rounded-lg border border-slate-200 py-2 pl-9 pr-3 text-sm outline-none focus:border-blue-400" /></div></div>
          <div className="max-h-[620px] divide-y divide-slate-100 overflow-auto">{filtered.map(repo => <button key={repo.id} onClick={() => { setSelectedId(repo.id); setAnalysis(null); setGraph(null); setVerification(null); setGenerated(false); }} className={`w-full p-4 text-left transition ${selectedId === repo.id ? 'bg-blue-50' : 'hover:bg-slate-50'}`}>
            <div className="flex items-start justify-between gap-3"><div><p className="font-bold text-slate-900">{repo.projectName}</p><p className="mt-1 text-xs text-slate-500">{repo.techStack.join(' · ')}</p></div><span className={`shrink-0 rounded-full border px-2 py-1 text-[10px] font-bold ${statusClass(repo.sbomStatus)}`}>{repo.sbomStatus}</span></div>
            <p className="mt-2 truncate text-xs text-blue-600">{repo.githubUrl}</p>
          </button>)}</div>
        </section>

        <div className="space-y-5">
          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            {selected ? <><div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div><p className="text-xs font-bold uppercase text-slate-400">Repository đang chọn</p><h2 className="mt-1 text-xl font-bold text-slate-900">{selected.projectName}</h2><a href={selected.githubUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1 text-sm text-blue-600 hover:underline">{selected.githubUrl}<ExternalLink className="h-3.5 w-3.5" /></a></div><span className={`rounded-full border px-3 py-1.5 text-xs font-bold ${statusClass(selected.sbomStatus)}`}>{selected.sbomStatus}</span></div>
              <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[['Kiến trúc', selected.architectureType], ['Package manager', selected.packageManager.join(', ')], ['SBOM source commit', short(selected.sourceCommit)], ['Generated / analyzed', formatTime(selected.analyzedAt)]].map(([label, value]) => <div key={label} className="rounded-lg bg-slate-50 p-3"><p className="text-[11px] font-bold uppercase text-slate-400">{label}</p><p className="mt-1 text-sm font-semibold text-slate-800">{value}</p></div>)}</div>
            </> : <p className="text-sm text-slate-500">Chọn repository để bắt đầu.</p>}
          </section>

          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="font-bold text-slate-900">Tiến trình demo</h3><div className="mt-4 grid gap-2 lg:grid-cols-4">{steps.map(([number, label, done]) => <div key={label as string} className={`rounded-lg border p-3 ${done ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200 bg-slate-50'}`}><div className="flex items-center gap-2">{done ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <Circle className="h-4 w-4 text-slate-400" />}<span className="text-xs font-bold text-slate-500">BƯỚC {number as string}</span></div><p className="mt-2 text-sm font-semibold text-slate-800">{label as string}</p></div>)}</div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button onClick={analyze} disabled={!selected || !!busy} className="btn-primary"><Play className="h-4 w-4" />{busy === 'analyze' ? 'Đang clone, dò SBOM & phân tích...' : 'Analyze Source'}</button>
              {scenario === 1 ? <>
                <button onClick={() => analysisRef.current?.scrollIntoView({ behavior: 'smooth' })} disabled={!analysis} className="btn-secondary"><FileCode2 className="h-4 w-4" />View Detected Dependencies</button>
                <button onClick={() => graphRef.current?.scrollIntoView({ behavior: 'smooth' })} disabled={!graph} className="btn-secondary"><Network className="h-4 w-4" />View Dependency Graph</button>
                <button onClick={confirm} disabled={!analysis || analysis.confirmed || !!busy} className="btn-secondary"><ShieldCheck className="h-4 w-4" />Confirm Analysis</button>
                <button onClick={generate} disabled={!analysis?.confirmed || !!busy} className="btn-primary"><Package className="h-4 w-4" />Generate SBOM</button>
              </> : <>
                <button onClick={verifyCurrent} disabled={(!analysis?.repositorySbom?.usableForVerification && !selected?.latestSbomId) || !!busy} className="btn-primary"><ShieldCheck className="h-4 w-4" />{busy === 'verify' ? 'Đang đối chiếu SBOM với source...' : 'Verify Current SBOM'}</button>
                <button onClick={confirm} disabled={!analysis || analysis.confirmed || !!busy} className="btn-secondary"><ShieldCheck className="h-4 w-4" />Confirm New Analysis</button>
                <button onClick={generate} disabled={!analysis?.confirmed || verification?.status === 'PASS' || !!busy} className="btn-secondary"><RefreshCw className="h-4 w-4" />Regenerate SBOM</button>
              </>}
            </div>
          </section>
        </div>
      </div>

      {analysis && <div ref={analysisRef} className="space-y-5 scroll-mt-5">
        <section className={`rounded-xl border p-5 shadow-sm ${analysis.repositorySbom.usableForVerification ? 'border-emerald-200 bg-emerald-50' : 'border-blue-200 bg-blue-50'}`}>
          <div className="flex items-start gap-3">{analysis.repositorySbom.usableForVerification ? <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" /> : <Package className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />}<div>
            <h3 className="font-bold text-slate-900">{analysis.repositorySbom.usableForVerification ? 'Đã nhận diện SBOM có sẵn trong repository' : 'Repository chưa chứa SBOM có thể kiểm chứng'}</h3>
            {analysis.repositorySbom.selectedFile ? <p className="mt-1 text-sm text-slate-700"><span className="font-mono font-semibold">{analysis.repositorySbom.selectedFile.path}</span> · {analysis.repositorySbom.selectedFile.format} · {analysis.repositorySbom.selectedFile.componentCount} components. Công cụ sẽ dùng chính file này để verify.</p> : <p className="mt-1 text-sm text-slate-700">Đã quét source tree nhưng không tìm thấy CycloneDX/SPDX JSON hợp lệ; hãy xác nhận phân tích rồi generate SBOM mới.</p>}
            {analysis.repositorySbom.files.length > 1 && <p className="mt-2 text-xs text-slate-600">Các candidate phát hiện: {analysis.repositorySbom.files.map(file => file.path).join(', ')}</p>}
          </div></div>
        </section>
        <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[['Components', analysis.componentCount], ['Dependencies', analysis.dependencyCount], ['Dependency files', analysis.dependencyFiles.length], ['Commit', analysis.shortCommit]].map(([label, value]) => <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"><p className="text-xs font-bold uppercase text-slate-400">{label}</p><p className="mt-2 text-2xl font-bold text-slate-900">{value}</p></div>)}</section>
        <section className="grid gap-5 xl:grid-cols-2"><div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="font-bold text-slate-900">Source evidence</h3><dl className="mt-4 grid grid-cols-[130px_1fr] gap-3 text-sm"><dt className="text-slate-500">Repository</dt><dd className="break-all font-medium">{analysis.githubUrl}</dd><dt className="text-slate-500">Commit</dt><dd className="font-mono">{analysis.sourceCommit}</dd><dt className="text-slate-500">Branch</dt><dd>{analysis.branch}</dd><dt className="text-slate-500">Analyzed at</dt><dd>{formatTime(analysis.analyzedAt)}</dd><dt className="text-slate-500">Analyzer</dt><dd>{analysis.toolInfo}</dd></dl></div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="font-bold text-slate-900">Metadata tự suy luận</h3><div className="mt-4 space-y-3">{Object.entries(analysis.inferredMetadata || {}).map(([name, field]) => <div key={name} className="rounded-lg bg-slate-50 p-3"><div className="flex justify-between"><p className="text-xs font-bold uppercase text-slate-500">{name}</p><span className="text-[10px] font-bold text-blue-600">{field.confidence}</span></div><p className="mt-1 text-sm font-semibold">{Array.isArray(field.value) ? field.value.join(', ') : field.value}</p><p className="mt-1 text-xs text-slate-500">Nguồn: {field.source}</p></div>)}</div></div></section>
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="font-bold text-slate-900">Dependency files phát hiện</h3><div className="mt-4 overflow-auto"><table className="w-full text-sm"><thead><tr className="border-b bg-slate-50 text-left text-xs uppercase text-slate-500"><th className="p-3">File</th><th className="p-3">Path</th><th className="p-3 text-right">Bytes</th></tr></thead><tbody>{analysis.dependencyFiles.map(file => <tr key={file.path} className="border-b border-slate-100"><td className="p-3 font-mono font-semibold">{file.name}</td><td className="p-3 font-mono text-xs text-slate-600">{file.path}</td><td className="p-3 text-right">{file.sizeBytes.toLocaleString()}</td></tr>)}</tbody></table></div></section>
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="font-bold text-slate-900">Component table</h3><div className="mt-4 max-h-96 overflow-auto"><table className="w-full text-sm"><thead className="sticky top-0 bg-slate-50"><tr className="text-left text-xs uppercase text-slate-500"><th className="p-3">Name</th><th className="p-3">Version</th><th className="p-3">Type</th><th className="p-3">PURL</th></tr></thead><tbody>{analysis.components.map((component, index) => <tr key={`${component.purl}-${index}`} className="border-t border-slate-100"><td className="p-3 font-semibold">{component.name}</td><td className="p-3">{component.version || '—'}</td><td className="p-3">{component.type}</td><td className="max-w-md truncate p-3 font-mono text-xs text-slate-500">{component.purl || '—'}</td></tr>)}</tbody></table></div></section>
      </div>}

      <section ref={graphRef} className="scroll-mt-5 rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><div className="mb-4 flex items-center justify-between"><div><h3 className="font-bold text-slate-900">Dependency graph</h3><p className="mt-1 text-sm text-slate-500">Cùng bộ visualize, zoom, search và node detail như các trang SBOM khác.</p></div>{graph && <span className="text-xs font-bold text-slate-500">{graph.summary.nodeCount} nodes · {graph.summary.edgeCount} edges</span>}</div><SbomDependencyGraph graph={visualGraph} search={graphSearch} depth={graphDepth} onlyVulnerable={onlyVulnerable} onSearchChange={setGraphSearch} onDepthChange={setGraphDepth} onOnlyVulnerableChange={setOnlyVulnerable} /></section>

      {verification && <section className={`rounded-xl border p-5 shadow-sm ${verification.status === 'PASS' ? 'border-emerald-200 bg-emerald-50/40' : 'border-amber-200 bg-amber-50/50'}`}>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div><p className="text-xs font-bold uppercase text-slate-500">Verify report</p><h3 className="mt-1 text-xl font-bold text-slate-900">{verification.recommendation || (verification.status === 'PASS' ? 'SBOM is up-to-date' : 'SBOM needs update')}</h3><p className="mt-2 text-sm text-slate-600">Repo: {selected?.githubUrl} · verified {formatTime(verification.verifiedAt)}</p></div><div className="rounded-xl bg-white px-6 py-3 text-center shadow-sm"><p className="text-xs font-bold uppercase text-slate-500">Trust Score</p><p className="text-3xl font-black text-slate-900">{verification.trustScore}%</p><p className="text-xs text-slate-500">{verification.trustLevel}</p></div></div>
        {verification.sourceChangedSinceGeneration && <div className="mt-4 flex gap-2 rounded-lg border border-amber-200 bg-amber-100 p-3 text-sm font-semibold text-amber-900"><AlertTriangle className="h-5 w-5 shrink-0" />Source code may have changed since SBOM generation. SBOM commit {short(verification.sbomSourceCommit)}, current commit {short(verification.currentCommit)}.</div>}
        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">{[['MATCHED', verification.matchedCount], ['MISSING_IN_SBOM', verification.missingCount], ['EXTRA_IN_SBOM', verification.extraCount], ['VERSION_MISMATCH', verification.versionMismatchCount]].map(([label, value]) => <div key={label} className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-[11px] font-bold text-slate-500">{label}</p><p className="mt-1 text-2xl font-bold text-slate-900">{value}</p></div>)}</div>
        <div className="mt-4 grid gap-3 lg:grid-cols-3"><pre className="max-h-56 overflow-auto rounded-lg bg-white p-3 text-xs text-emerald-800">MATCHED\n{verification.MATCHED.slice(0, 40).join('\n') || '—'}</pre><pre className="max-h-56 overflow-auto rounded-lg bg-white p-3 text-xs text-rose-800">MISSING_IN_SBOM\n{verification.MISSING_IN_SBOM.join('\n') || '—'}</pre><pre className="max-h-56 overflow-auto rounded-lg bg-white p-3 text-xs text-amber-800">EXTRA_IN_SBOM\n{verification.EXTRA_IN_SBOM.join('\n') || '—'}\n\nVERSION_MISMATCH\n{verification.VERSION_MISMATCH.map(item => `${item.ecosystem}:${item.component} ${item.sbomVersion || '—'} → ${item.sourceVersion || '—'}`).join('\n') || '—'}</pre></div>
      </section>}
    </div>
  );
}

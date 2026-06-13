import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  FileJson,
  GitBranch,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  TestTube2,
  TriangleAlert,
} from 'lucide-react';
import { API_BASE_URL } from '../api';

const API_BASE = API_BASE_URL;

type ScenarioRepo = {
  id: string;
  projectName: string;
  githubUrl: string;
  applicationType: 'Web Application';
  repoScope: 'Single Repository';
  architectureType: string;
  techStack: string[];
  packageManager: string[];
  dependencyFiles: string[];
  description: string;
  supportStatus: string;
};

type Analysis = {
  runId: string;
  projectName: string;
  githubUrl: string;
  applicationType: string;
  repoScope: string;
  architectureType: string;
  dependencyFiles: Array<{ path: string; name: string; sizeBytes: number }>;
  dependencyFileCount: number;
  componentCount: number;
  dependencyCount: number;
  ecosystems: string[];
  analysisDurationMs: number;
  sbomSizeBytes: number;
  sbomId: string;
  sbomPath: string;
  toolInfo: string;
  createdTimestamp: string;
  confirmed?: boolean;
};

type Graph = {
  nodes: Array<{ id: string; label: string; type: string; ecosystem: string }>;
  edges: Array<{ id: string; source: string; target: string; relationship: string }>;
  summary: { nodeCount: number; edgeCount: number };
};

type VerificationReport = {
  status: 'PASS' | 'FAIL';
  trustLevel: string;
  trustScore: number;
  matchedCount: number;
  missingCount: number;
  extraCount: number;
  versionMismatchCount: number;
  sourceComponentCount: number;
  sbomComponentCount: number;
  MATCHED: string[];
  MISSING_IN_SBOM: string[];
  EXTRA_IN_SBOM: string[];
  VERSION_MISMATCH: Array<{ component: string; sourceVersion?: string | null; sbomVersion?: string | null; ecosystem: string }>;
};

type TestReport = {
  testCaseId: string;
  name: string;
  scope: string;
  applicationType: string;
  repoScope: string;
  architectureType: string;
  inputRepo: string;
  preconditions: string[];
  steps: string[];
  expectedResult: string;
  actualResult: string;
  result: 'PASS' | 'FAIL';
  evidence: Record<string, unknown>;
};

type StepAction = {
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  loading?: boolean;
  primary?: boolean;
  warning?: boolean;
  helper?: string;
};

type StepGroup = {
  title: string;
  description: string;
  actions: StepAction[];
};

const badge = 'inline-flex items-center rounded-md border px-2 py-1 text-xs font-semibold';
const scopeBadge = `${badge} border-blue-100 bg-blue-50 text-blue-700`;
const repoBadge = `${badge} border-emerald-100 bg-emerald-50 text-emerald-700`;
const mutedBadge = `${badge} border-slate-200 bg-slate-50 text-slate-600`;

const applicationTypeLabels: Record<string, string> = {
  'Web Application': 'Ứng dụng web',
};

const repoScopeLabels: Record<string, string> = {
  'Single Repository': 'Một kho lưu trữ',
};

const supportStatusLabels: Record<string, string> = {
  'Supported for SBOM validation demo': 'Sẵn sàng cho demo kiểm chứng',
};

const architectureLabels: Record<string, string> = {
  'Monolithic Spring Boot web application': 'Ứng dụng web Spring Boot nguyên khối',
  'Node.js CMS web application': 'Ứng dụng web CMS Node.js',
  'Node.js forum web application': 'Ứng dụng web diễn đàn Node.js',
  'Laravel monolithic web application': 'Ứng dụng web Laravel nguyên khối',
  'Rails web application': 'Ứng dụng web Rails',
  'Go web application': 'Ứng dụng web Go',
  'Flask monolithic web application': 'Ứng dụng web Flask nguyên khối',
  'Single-page React web application': 'Ứng dụng web React một trang',
  'Single-page Vue web application': 'Ứng dụng web Vue một trang',
  'Node.js/Angular web application': 'Ứng dụng web Node.js/Angular',
};

const descriptionLabels: Record<string, string> = {
  'Reference Spring Boot web application used for PetClinic demos.': 'Ứng dụng web Spring Boot tham chiếu dùng cho demo PetClinic.',
  'Open-source publishing and CMS platform.': 'Nền tảng xuất bản và CMS mã nguồn mở.',
  'Modern web forum software built on Node.js.': 'Phần mềm diễn đàn web hiện đại xây dựng trên Node.js.',
  'Documentation and wiki web application.': 'Ứng dụng web tài liệu và wiki.',
  'Open-source discussion platform.': 'Nền tảng thảo luận mã nguồn mở.',
  'Self-hosted Git service web application.': 'Ứng dụng web dịch vụ Git tự lưu trữ.',
  'Example Flask web application from Flask Web Development.': 'Ví dụ ứng dụng web Flask từ Flask Web Development.',
  'RealWorld frontend implementation using React and Redux.': 'Triển khai frontend RealWorld bằng React và Redux.',
  'RealWorld frontend implementation using Vue.': 'Triển khai frontend RealWorld bằng Vue.',
  'Intentionally vulnerable web application for security training.': 'Ứng dụng web cố ý có lỗ hổng để huấn luyện bảo mật.',
};

const reportTextLabels: Record<string, string> = {
  'SBOM validation demo for real Web Application source code in one GitHub repository.': 'Demo kiểm chứng SBOM cho mã nguồn ứng dụng web thực tế trong một kho GitHub.',
  'Git is available on backend host.': 'Git có sẵn trên máy chủ backend.',
  'Syft is available on backend host.': 'Syft có sẵn trên máy chủ backend.',
  'Repository is public and cloneable.': 'Kho lưu trữ công khai và có thể sao chép.',
  'Current version supports Web Application + Single Repository only.': 'Phiên bản hiện tại chỉ hỗ trợ Ứng dụng web + Một kho lưu trữ.',
  'Select the real GitHub repository from SBOM Validation Scenarios.': 'Chọn kho GitHub thực tế từ trang Kiểm chứng SBOM.',
  'Clone or update the selected Single Repository source.': 'Sao chép hoặc cập nhật mã nguồn của kho đã chọn.',
  'Detect dependency files in the source tree.': 'Phát hiện các file phụ thuộc trong cây mã nguồn.',
  'Run Syft and parse CycloneDX JSON.': 'Chạy Syft và phân tích JSON CycloneDX.',
  'Persist metadata, components, and dependency relationships.': 'Lưu metadata, thành phần và quan hệ phụ thuộc.',
  'Confirm analysis before generating downloadable SBOM.': 'Xác nhận phân tích trước khi tạo SBOM có thể tải xuống.',
  'Verify the SBOM by regenerating source analysis and comparing components.': 'Kiểm chứng SBOM bằng cách phân tích lại source thật và so sánh thành phần.',
  'SBOM is generated from the real repository and verification reports MATCHED, MISSING_IN_SBOM, EXTRA_IN_SBOM, VERSION_MISMATCH, counts, and Trust Score.': 'SBOM được tạo từ kho thật và báo cáo kiểm chứng hiển thị MATCHED, MISSING_IN_SBOM, EXTRA_IN_SBOM, VERSION_MISMATCH, số lượng và Trust Score.',
  'Verification has not been run yet.': 'Chưa chạy kiểm chứng.',
};

const translateTestReportName = (value: string) => {
  const prefix = 'Validate CycloneDX SBOM against real repository ';
  return value.startsWith(prefix) ? `Kiểm chứng SBOM CycloneDX với kho thật ${value.slice(prefix.length)}` : value;
};

const translateText = (value: string) =>
  reportTextLabels[value]
  || descriptionLabels[value]
  || architectureLabels[value]
  || supportStatusLabels[value]
  || applicationTypeLabels[value]
  || repoScopeLabels[value]
  || value;

const translateActualResult = (value: string) => {
  const prefix = 'Verification finished with ';
  return value.startsWith(prefix) ? `Kiểm chứng hoàn tất với ${value.slice(prefix.length)}` : translateText(value);
};

const translateApplicationType = (value: string) => applicationTypeLabels[value] || value;
const translateRepoScope = (value: string) => repoScopeLabels[value] || value;
const translateSupportStatus = (value: string) => supportStatusLabels[value] || value;
const translateArchitecture = (value: string) => architectureLabels[value] || value;
const translateDescription = (value: string) => descriptionLabels[value] || value;
const translateTrustLevel = (value: string) =>
  value === 'High trust' ? 'Tin cậy cao'
    : value === 'Medium' ? 'Trung bình'
      : value === 'Low' ? 'Thấp'
        : value === 'Untrusted' ? 'Không tin cậy'
          : value;
const translateStatus = (value: string) => (value === 'PASS' ? 'ĐẠT' : value === 'FAIL' ? 'KHÔNG ĐẠT' : value);

const formatBytes = (bytes?: number) => {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
};

const formatEvidenceValue = (value: unknown) =>
  value === null || value === undefined || value === '' ? '-' : String(value);

const downloadJson = (fileName: string, value: unknown) => {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
};

const actionButtonClass = (action: StepAction) => {
  if (action.primary) return 'bg-blue-600 text-white border-blue-600 hover:bg-blue-700 disabled:hover:bg-blue-600';
  if (action.warning) return 'bg-amber-50 text-amber-800 border-amber-200 hover:bg-amber-100 disabled:hover:bg-amber-50';
  return 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 disabled:hover:bg-white';
};

const MiniGraph: React.FC<{ graph: Graph | null }> = ({ graph }) => {
  const nodes = (graph?.nodes || []).slice(0, 28);
  const edges = (graph?.edges || []).filter(edge =>
    nodes.some(node => node.id === edge.source) && nodes.some(node => node.id === edge.target)
  ).slice(0, 42);
  const positions = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, index) => {
      const col = index % 4;
      const row = Math.floor(index / 4);
      map.set(node.id, { x: 90 + col * 220, y: 70 + row * 86 });
    });
    return map;
  }, [nodes]);

  if (!graph) {
    return (
      <div className="flex min-h-[280px] flex-col items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50/80 px-6 py-10 text-center">
        <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-white text-slate-400 shadow-sm">
          <Network className="h-6 w-6" />
        </div>
        <h4 className="text-sm font-bold text-slate-800">Chưa có dữ liệu đồ thị</h4>
        <p className="mt-1 max-w-md text-sm text-slate-500">
          Hãy chọn repository và chạy Phân tích nguồn trước.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-auto rounded-lg border border-slate-200 bg-slate-50">
      <svg width={960} height={Math.max(420, Math.ceil(nodes.length / 4) * 96 + 80)} className="block">
        <defs>
          <marker id="scenario-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto">
            <path d="M0,0 L0,7 L7,3.5 z" fill="#64748b" />
          </marker>
        </defs>
        {edges.map(edge => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return null;
          return (
            <line
              key={edge.id}
              x1={source.x + 150}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="#94a3b8"
              strokeWidth={1.2}
              markerEnd="url(#scenario-arrow)"
              opacity={0.65}
            />
          );
        })}
        {nodes.map(node => {
          const position = positions.get(node.id);
          if (!position) return null;
          return (
            <g key={node.id} transform={`translate(${position.x}, ${position.y - 28})`}>
              <rect width={168} height={56} rx={8} fill={node.type === 'PROJECT' ? '#0f172a' : '#ffffff'} stroke="#cbd5e1" />
              <text x={12} y={22} className={node.type === 'PROJECT' ? 'fill-white text-xs font-semibold' : 'fill-slate-800 text-xs font-semibold'}>
                {node.label.length > 22 ? `${node.label.slice(0, 21)}...` : node.label}
              </text>
              <text x={12} y={42} className={node.type === 'PROJECT' ? 'fill-slate-300 text-[10px]' : 'fill-slate-500 text-[10px]'}>
                {node.ecosystem}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};

const StepGroupCard: React.FC<{ index: number; group: StepGroup }> = ({ index, group }) => (
  <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
    <div className="flex items-start gap-3">
      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-900 text-xs font-bold text-white">
        {index + 1}
      </div>
      <div className="min-w-0 flex-1">
        <h4 className="text-sm font-bold text-slate-900">{group.title}</h4>
        <p className="mt-1 text-xs leading-5 text-slate-500">{group.description}</p>
      </div>
    </div>
    <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
      {group.actions.map(action => (
        <div key={action.label}>
          <button
            type="button"
            onClick={action.onClick}
            disabled={action.disabled || action.loading}
            title={action.disabled ? action.helper : action.label}
            className={`inline-flex min-h-10 w-full items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-45 ${actionButtonClass(action)}`}
          >
            {action.loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : action.icon}
            <span className="truncate">{action.label}</span>
          </button>
          {action.disabled && action.helper && (
            <p className="mt-1.5 text-xs leading-4 text-slate-400">{action.helper}</p>
          )}
        </div>
      ))}
    </div>
  </section>
);

const SbomValidationScenarios: React.FC = () => {
  const [repositories, setRepositories] = useState<ScenarioRepo[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState('');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [generatedSbom, setGeneratedSbom] = useState<any | null>(null);
  const [verification, setVerification] = useState<VerificationReport | null>(null);
  const [testReport, setTestReport] = useState<TestReport | null>(null);
  const [faultyInfo, setFaultyInfo] = useState<any | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const analysisSectionRef = useRef<HTMLElement | null>(null);
  const graphSectionRef = useRef<HTMLElement | null>(null);
  const selectedRepo = repositories.find(repo => repo.id === selectedRepoId) || repositories[0];

  const loadCatalog = async () => {
    setCatalogLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/validation-scenarios`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || data.message || 'Không thể tải danh sách repository đã lưu.');
      setRepositories(data.repositories || []);
      if (data.repositories?.[0]?.id && !selectedRepoId) setSelectedRepoId(data.repositories[0].id);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Không thể tải danh sách repository đã lưu.');
    } finally {
      setCatalogLoading(false);
    }
  };

  useEffect(() => {
    loadCatalog();
  }, []);

  const runAction = async (action: string, fn: () => Promise<void>) => {
    setLoadingAction(action);
    setError(null);
    try {
      await fn();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Thao tác thất bại.');
    } finally {
      setLoadingAction(null);
    }
  };

  const selectRepo = (repoId: string) => {
    setSelectedRepoId(repoId);
    setAnalysis(null);
    setGraph(null);
    setGeneratedSbom(null);
    setVerification(null);
    setTestReport(null);
    setFaultyInfo(null);
  };

  const analyze = () => runAction('Analyze Source', async () => {
    if (!selectedRepoId) return;
    setAnalysis(null);
    setGraph(null);
    setGeneratedSbom(null);
    setVerification(null);
    setTestReport(null);
    setFaultyInfo(null);
    const res = await fetch(`${API_BASE}/api/validation-scenarios/${selectedRepoId}/analyze`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Phân tích nguồn thất bại.');
    setAnalysis(data.analysis);
    setGraph(data.graph);
  });

  const confirm = () => runAction('Confirm Analysis', async () => {
    if (!analysis?.runId) return;
    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/confirm`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Xác nhận phân tích thất bại.');
    setAnalysis(current => current ? { ...current, confirmed: true } : current);
  });

  const generate = () => runAction('Generate SBOM', async () => {
    if (!analysis?.runId) return;
    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/generate`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Tạo SBOM thất bại.');
    setGeneratedSbom(data);
  });

  const createFaulty = () => runAction('Create Faulty SBOM Demo', async () => {
    if (!analysis?.runId) return;
    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/faulty`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Tạo SBOM lỗi cho bản demo thất bại.');
    setFaultyInfo(data);
  });

  const verify = (useFaulty: boolean) => runAction(useFaulty ? 'Verify Faulty SBOM' : 'Verify SBOM', async () => {
    if (!analysis?.runId) return;
    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ useFaulty }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Kiểm chứng SBOM thất bại.');
    setVerification(data.verificationReport);
    setTestReport(data.testReport);
  });

  const loadReport = () => runAction('View Test Report', async () => {
    if (!analysis?.runId) return;
    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/report`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Xem báo cáo kiểm thử thất bại.');
    setTestReport(data);
  });

  const stepGroups: StepGroup[] = [
    {
      title: 'Phân tích nguồn',
      description: 'Clone repository thật, phát hiện file phụ thuộc và chạy Syft để tạo dữ liệu phân tích.',
      actions: [{
        label: 'Analyze Source',
        icon: <Play className="h-4 w-4" />,
        onClick: analyze,
        disabled: !selectedRepo || Boolean(loadingAction),
        loading: loadingAction === 'Analyze Source',
        primary: true,
        helper: !selectedRepo ? 'Hãy chọn repository trước.' : 'Đang có thao tác khác chạy.',
      }],
    },
    {
      title: 'Kiểm tra kết quả phân tích',
      description: 'Xem file phụ thuộc đã phát hiện và đồ thị quan hệ package sau khi phân tích.',
      actions: [
        {
          label: 'View Dependencies',
          icon: <GitBranch className="h-4 w-4" />,
          onClick: () => analysisSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
          disabled: !analysis,
          helper: 'Chưa phân tích nên chưa có danh sách phụ thuộc.',
        },
        {
          label: 'View Dependency Graph',
          icon: <Network className="h-4 w-4" />,
          onClick: () => graphSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
          disabled: !graph,
          helper: 'Chưa phân tích nên chưa có dữ liệu đồ thị.',
        },
      ],
    },
    {
      title: 'Xác nhận và tạo SBOM',
      description: 'Người dùng xác nhận kết quả phân tích trước, sau đó mới được tạo SBOM để xem hoặc tải xuống.',
      actions: [
        {
          label: 'Confirm Analysis',
          icon: <CheckCircle2 className="h-4 w-4" />,
          onClick: confirm,
          disabled: !analysis || analysis.confirmed || Boolean(loadingAction),
          loading: loadingAction === 'Confirm Analysis',
          primary: Boolean(analysis && !analysis.confirmed),
          helper: !analysis ? 'Cần chạy Phân tích nguồn trước.' : analysis.confirmed ? 'Kết quả phân tích đã được xác nhận.' : 'Đang có thao tác khác chạy.',
        },
        {
          label: 'Generate SBOM',
          icon: <FileJson className="h-4 w-4" />,
          onClick: generate,
          disabled: !analysis?.confirmed || Boolean(loadingAction),
          loading: loadingAction === 'Generate SBOM',
          primary: Boolean(analysis?.confirmed && !generatedSbom),
          helper: !analysis?.confirmed ? 'Cần Confirm Analysis trước khi tạo SBOM.' : 'Đang có thao tác khác chạy.',
        },
      ],
    },
    {
      title: 'Kiểm chứng SBOM',
      description: 'So sánh SBOM với source thật; có thể tạo SBOM lỗi để demo missing, extra và version mismatch.',
      actions: [
        {
          label: 'Create Faulty SBOM Demo',
          icon: <TriangleAlert className="h-4 w-4" />,
          onClick: createFaulty,
          disabled: !generatedSbom || Boolean(loadingAction),
          loading: loadingAction === 'Create Faulty SBOM Demo',
          warning: true,
          helper: !generatedSbom ? 'Cần Generate SBOM trước.' : 'Đang có thao tác khác chạy.',
        },
        {
          label: 'Verify SBOM',
          icon: <ShieldCheck className="h-4 w-4" />,
          onClick: () => verify(false),
          disabled: !generatedSbom || Boolean(loadingAction),
          loading: loadingAction === 'Verify SBOM',
          primary: Boolean(generatedSbom),
          helper: !generatedSbom ? 'Cần Generate SBOM trước.' : 'Đang có thao tác khác chạy.',
        },
        {
          label: 'Verify Faulty SBOM',
          icon: <TriangleAlert className="h-4 w-4" />,
          onClick: () => verify(true),
          disabled: !faultyInfo || Boolean(loadingAction),
          loading: loadingAction === 'Verify Faulty SBOM',
          warning: true,
          helper: !faultyInfo ? 'Cần Create Faulty SBOM Demo trước.' : 'Đang có thao tác khác chạy.',
        },
      ],
    },
    {
      title: 'Báo cáo',
      description: 'Mở báo cáo test case và evidence của lần chạy demo hiện tại.',
      actions: [{
        label: 'View Test Report',
        icon: <TestTube2 className="h-4 w-4" />,
        onClick: loadReport,
        disabled: !analysis || Boolean(loadingAction),
        loading: loadingAction === 'View Test Report',
        helper: !analysis ? 'Cần chạy Phân tích nguồn trước.' : 'Đang có thao tác khác chạy.',
      }],
    },
  ];

  return (
    <div className="space-y-6">
      <header className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="max-w-4xl">
            <p className="text-xs font-bold uppercase tracking-wide text-blue-600">Demo kiểm chứng trên dữ liệu thật</p>
            <h2 className="mt-1 text-2xl font-bold text-slate-900">Kiểm chứng SBOM</h2>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              Phạm vi hiện tại chỉ xử lý repository GitHub thật của ứng dụng web trong một kho lưu trữ. Multi-repo và microservice nhiều repo là hướng mở rộng, không phải hỗ trợ của phiên bản demo này.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <span className={scopeBadge}>Ứng dụng web</span>
            <span className={repoBadge}>Một kho lưu trữ</span>
          </div>
        </div>
      </header>

      {error && (
        <div className="flex flex-col gap-3 rounded-lg border border-rose-100 bg-rose-50 px-4 py-3 text-sm text-rose-700 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-2">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="leading-5">{error}</p>
          </div>
          <button
            type="button"
            onClick={loadCatalog}
            className="inline-flex items-center justify-center gap-2 rounded-md border border-rose-200 bg-white px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Thử lại
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.85fr)]">
        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-col gap-2 border-b border-slate-100 px-5 py-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Danh sách repository kiểm thử</h3>
              <p className="mt-1 text-sm text-slate-500">Repository được lấy từ các dự án đã lưu trong hệ thống và có URL nguồn.</p>
            </div>
            <span className={mutedBadge}>{repositories.length || 0} repo</span>
          </div>

          <div className="hidden overflow-auto lg:block">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Repository</th>
                  <th className="px-4 py-3">Kiến trúc</th>
                  <th className="px-4 py-3">Stack</th>
                  <th className="px-4 py-3">File phụ thuộc</th>
                  <th className="px-4 py-3 text-right">Hành động</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {catalogLoading ? (
                  <tr><td colSpan={5} className="px-4 py-10 text-center text-slate-500">Đang tải danh sách repository...</td></tr>
                ) : repositories.length === 0 ? (
                  <tr><td colSpan={5} className="px-4 py-10 text-center text-slate-500">Chưa có repository nào. Hãy tạo pipeline cho dự án và nhập URL repository trước.</td></tr>
                ) : repositories.map(repo => {
                  const selected = selectedRepoId === repo.id;
                  return (
                    <tr key={repo.id} className={selected ? 'bg-blue-50/40' : 'hover:bg-slate-50'}>
                      <td className="px-4 py-4">
                        <div className="min-w-0">
                          <p className="font-semibold text-slate-900">{repo.projectName}</p>
                          <a href={repo.githubUrl} target="_blank" rel="noreferrer" className="mt-0.5 block truncate text-xs text-blue-600 hover:underline">
                            {repo.githubUrl}
                          </a>
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            <span className={scopeBadge}>{translateApplicationType(repo.applicationType)}</span>
                            <span className={repoBadge}>{translateRepoScope(repo.repoScope)}</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4 text-slate-700">{translateArchitecture(repo.architectureType)}</td>
                      <td className="px-4 py-4 text-slate-600">{repo.techStack.slice(0, 4).join(', ')}</td>
                      <td className="px-4 py-4 font-mono text-xs text-slate-600">{repo.dependencyFiles.join(', ')}</td>
                      <td className="px-4 py-4 text-right">
                        <button
                          type="button"
                          onClick={() => selectRepo(repo.id)}
                          className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold transition ${selected ? 'border-blue-200 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'}`}
                        >
                          <Eye className="h-4 w-4" />
                          {selected ? 'Đang chọn' : 'Chọn'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="grid grid-cols-1 gap-3 p-4 lg:hidden">
            {catalogLoading ? (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500">Đang tải danh sách repository...</div>
            ) : repositories.length === 0 ? (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500">Chưa có repository nào. Hãy tạo pipeline cho dự án và nhập URL repository trước.</div>
            ) : repositories.map(repo => {
              const selected = selectedRepoId === repo.id;
              return (
                <article key={repo.id} className={`rounded-lg border p-4 ${selected ? 'border-blue-200 bg-blue-50/50' : 'border-slate-200 bg-white'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h4 className="font-bold text-slate-900">{repo.projectName}</h4>
                      <a href={repo.githubUrl} target="_blank" rel="noreferrer" className="mt-1 block truncate text-xs text-blue-600">
                        {repo.githubUrl}
                      </a>
                    </div>
                    <button
                      type="button"
                      onClick={() => selectRepo(repo.id)}
                      className={`shrink-0 rounded-md border px-3 py-1.5 text-xs font-semibold ${selected ? 'border-blue-200 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-700'}`}
                    >
                      {selected ? 'Đang chọn' : 'Chọn'}
                    </button>
                  </div>
                  <p className="mt-3 text-sm text-slate-600">{translateArchitecture(repo.architectureType)}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <span className={scopeBadge}>{translateApplicationType(repo.applicationType)}</span>
                    <span className={repoBadge}>{translateRepoScope(repo.repoScope)}</span>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        <aside className="space-y-4">
          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-xs font-bold uppercase tracking-wide text-slate-400">Kho lưu trữ đang chọn</p>
            {selectedRepo ? (
              <div className="mt-3 space-y-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-900">{selectedRepo.projectName}</h3>
                  <a href={selectedRepo.githubUrl} target="_blank" rel="noreferrer" className="mt-1 block break-all text-sm text-blue-600 hover:underline">
                    {selectedRepo.githubUrl}
                  </a>
                  <p className="mt-2 text-sm leading-6 text-slate-600">{translateDescription(selectedRepo.description)}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <span className={scopeBadge}>{translateApplicationType(selectedRepo.applicationType)}</span>
                  <span className={repoBadge}>{translateRepoScope(selectedRepo.repoScope)}</span>
                  <span className="rounded-md border border-emerald-100 bg-emerald-50 px-2 py-1 text-xs font-semibold text-emerald-700">
                    {translateSupportStatus(selectedRepo.supportStatus)}
                  </span>
                </div>
                <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-3 text-sm">
                  <dt className="font-semibold text-slate-500">Kiến trúc</dt>
                  <dd className="text-slate-800">{translateArchitecture(selectedRepo.architectureType)}</dd>
                  <dt className="font-semibold text-slate-500">Công nghệ</dt>
                  <dd className="text-slate-800">{selectedRepo.techStack.join(', ')}</dd>
                  <dt className="font-semibold text-slate-500">Gói</dt>
                  <dd className="text-slate-800">{selectedRepo.packageManager.join(', ')}</dd>
                  <dt className="font-semibold text-slate-500">File</dt>
                  <dd className="font-mono text-xs leading-5 text-slate-700">{selectedRepo.dependencyFiles.join(', ')}</dd>
                </dl>
              </div>
            ) : (
              <div className="mt-4 rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500">
                Chọn một repository để bắt đầu demo.
              </div>
            )}
          </section>

          <section className="space-y-3">
            {stepGroups.map((group, index) => (
              <StepGroupCard key={group.title} index={index} group={group} />
            ))}
          </section>
        </aside>
      </div>

      {analysis && (
        <section ref={analysisSectionRef} className="space-y-4 scroll-mt-6">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            {[
              ['Thành phần', analysis.componentCount],
              ['Phụ thuộc', analysis.dependencyCount],
              ['File phụ thuộc', analysis.dependencyFileCount],
              ['Kích thước SBOM', formatBytes(analysis.sbomSizeBytes)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</p>
                <p className="mt-2 text-2xl font-bold text-slate-900">{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <h3 className="font-bold text-slate-900">Kết quả phân tích</h3>
              <dl className="mt-4 grid grid-cols-[150px_1fr] gap-3 text-sm">
                <dt className="font-semibold text-slate-500">Repository</dt><dd className="break-all text-slate-800">{analysis.githubUrl}</dd>
                <dt className="font-semibold text-slate-500">Ứng dụng</dt><dd><span className={scopeBadge}>{translateApplicationType(analysis.applicationType)}</span></dd>
                <dt className="font-semibold text-slate-500">Kho</dt><dd><span className={repoBadge}>{translateRepoScope(analysis.repoScope)}</span></dd>
                <dt className="font-semibold text-slate-500">Kiến trúc</dt><dd>{translateArchitecture(analysis.architectureType)}</dd>
                <dt className="font-semibold text-slate-500">Ecosystem</dt><dd>{analysis.ecosystems.join(', ') || '-'}</dd>
                <dt className="font-semibold text-slate-500">Thời gian</dt><dd>{analysis.analysisDurationMs} ms</dd>
                <dt className="font-semibold text-slate-500">Tool</dt><dd>{analysis.toolInfo}</dd>
                <dt className="font-semibold text-slate-500">Timestamp</dt><dd>{new Date(analysis.createdTimestamp).toLocaleString('vi-VN')}</dd>
                <dt className="font-semibold text-slate-500">SBOM path</dt><dd className="break-all">{analysis.sbomPath}</dd>
              </dl>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <h3 className="font-bold text-slate-900">File phụ thuộc đã phát hiện</h3>
              <div className="mt-4 max-h-80 overflow-auto rounded-lg border border-slate-200">
                <table className="w-full text-sm">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                    <tr><th className="px-3 py-2 text-left">File</th><th className="px-3 py-2 text-left">Đường dẫn</th><th className="px-3 py-2 text-right">Size</th></tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {analysis.dependencyFiles.map(file => (
                      <tr key={file.path}>
                        <td className="px-3 py-2 font-mono text-xs">{file.name}</td>
                        <td className="px-3 py-2 font-mono text-xs text-slate-600">{file.path}</td>
                        <td className="px-3 py-2 text-right">{formatBytes(file.sizeBytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>
      )}

      <section ref={graphSectionRef} className="scroll-mt-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="font-bold text-slate-900">Đồ thị phụ thuộc</h3>
            <p className="mt-1 text-sm text-slate-500">Node là component/package, edge là quan hệ phụ thuộc.</p>
          </div>
          <span className="text-sm text-slate-500">{graph ? `${graph.summary.nodeCount} nodes / ${graph.summary.edgeCount} edges` : 'Chưa có dữ liệu'}</span>
        </div>
        <MiniGraph graph={graph} />
      </section>

      {generatedSbom && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h3 className="font-bold text-slate-900">SBOM đã tạo</h3>
              <p className="text-sm text-slate-500">Metadata, Components, Dependencies, Tool info và Created timestamp lấy từ CycloneDX JSON.</p>
            </div>
            <button onClick={() => downloadJson(`${selectedRepo?.id || 'repo'}-sbom.json`, generatedSbom.sbom)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">
              <Download className="h-4 w-4" /> Tải SBOM
            </button>
          </div>
          <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-4">
            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Components</p><p className="text-xl font-bold">{generatedSbom.components.length}</p></div>
            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Dependencies</p><p className="text-xl font-bold">{generatedSbom.dependencies.length}</p></div>
            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Tool</p><p className="text-sm font-semibold">{generatedSbom.toolInfo}</p></div>
            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Created</p><p className="text-sm font-semibold">{new Date(generatedSbom.createdTimestamp).toLocaleString('vi-VN')}</p></div>
          </div>
        </section>
      )}

      {faultyInfo && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-5 text-sm text-amber-900">
          Đã tạo SBOM lỗi: xóa {faultyInfo.changes?.removedComponent || '-'}, thêm {faultyInfo.changes?.addedComponent}, sửa version {faultyInfo.changes?.versionMutatedComponent || '-'}.
        </div>
      )}

      {verification && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="font-bold text-slate-900">Báo cáo kiểm chứng</h3>
          <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-6">
            {[
              ['Trust Score', `${verification.trustScore}%`],
              ['Trust Level', translateTrustLevel(verification.trustLevel)],
              ['MATCHED', verification.matchedCount],
              ['MISSING', verification.missingCount],
              ['EXTRA', verification.extraCount],
              ['VERSION', verification.versionMismatchCount],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <p className="text-xs font-bold text-slate-500">{label}</p>
                <p className="mt-1 text-lg font-bold text-slate-900">{value}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <pre className="max-h-56 overflow-auto rounded-lg bg-emerald-50 p-3 text-xs text-emerald-900">MATCHED{"\n"}{verification.MATCHED.slice(0, 30).join('\n')}</pre>
            <pre className="max-h-56 overflow-auto rounded-lg bg-rose-50 p-3 text-xs text-rose-900">MISSING_IN_SBOM{"\n"}{verification.MISSING_IN_SBOM.join('\n')}</pre>
            <pre className="max-h-56 overflow-auto rounded-lg bg-amber-50 p-3 text-xs text-amber-900">EXTRA_IN_SBOM{"\n"}{verification.EXTRA_IN_SBOM.join('\n')}{"\n\n"}VERSION_MISMATCH{"\n"}{verification.VERSION_MISMATCH.map(item => `${item.ecosystem}:${item.component} source=${item.sourceVersion || '-'} sbom=${item.sbomVersion || '-'}`).join('\n')}</pre>
          </div>
        </section>
      )}

      {testReport && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-slate-900">Báo cáo kiểm thử</h3>
            <span className={`${badge} ${testReport.result === 'PASS' ? 'border-emerald-100 bg-emerald-50 text-emerald-700' : 'border-rose-100 bg-rose-50 text-rose-700'}`}>{translateStatus(testReport.result)}</span>
          </div>
          <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
            {[
              ['Test case ID', testReport.testCaseId],
              ['Name', translateTestReportName(testReport.name)],
              ['Scope', translateText(testReport.scope)],
              ['Application type', translateApplicationType(testReport.applicationType)],
              ['Repo scope', translateRepoScope(testReport.repoScope)],
              ['Architecture', translateArchitecture(testReport.architectureType)],
              ['Input repo', testReport.inputRepo],
              ['Actual result', translateActualResult(testReport.actualResult)],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0 rounded-lg border border-slate-100 bg-slate-50/70 p-3">
                <p className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</p>
                <p className="mt-1 break-words text-sm font-medium leading-5 text-slate-900">{value}</p>
              </div>
            ))}
            <div className="min-w-0 rounded-lg border border-slate-100 bg-slate-50/70 p-3 lg:col-span-2">
              <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Expected result</p>
              <p className="mt-1 text-sm leading-5 text-slate-900">{translateText(testReport.expectedResult)}</p>
            </div>
          </div>

          <div className="mt-4 rounded-lg border border-slate-100 bg-white p-3">
            <p className="mb-3 text-xs font-bold uppercase tracking-wide text-slate-500">Evidence</p>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                ['Components', formatEvidenceValue(testReport.evidence.componentCount)],
                ['Dependencies', formatEvidenceValue(testReport.evidence.dependencyCount)],
                ['Files', formatEvidenceValue(testReport.evidence.dependencyFileCount)],
                ['Trust score', formatEvidenceValue(testReport.evidence.trustScore)],
                ['Graph nodes', formatEvidenceValue(testReport.evidence.graphNodes)],
                ['Graph edges', formatEvidenceValue(testReport.evidence.graphEdges)],
              ].map(([label, value]) => (
                <div key={label} className="rounded-md bg-slate-50 px-3 py-2">
                  <p className="text-[11px] font-semibold uppercase text-slate-400">{label}</p>
                  <p className="mt-1 text-lg font-bold text-slate-900">{value}</p>
                </div>
              ))}
            </div>
            <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-slate-600 lg:grid-cols-2">
              <p className="min-w-0 truncate rounded-md bg-slate-50 px-3 py-2" title={formatEvidenceValue(testReport.evidence.sbomPath)}>
                SBOM: {formatEvidenceValue(testReport.evidence.sbomPath)}
              </p>
              <p className="min-w-0 truncate rounded-md bg-slate-50 px-3 py-2" title={formatEvidenceValue(testReport.evidence.generatedTimestamp)}>
                Generated: {formatEvidenceValue(testReport.evidence.generatedTimestamp)}
              </p>
            </div>
          </div>
        </section>
      )}
    </div>
  );
};

export default SbomValidationScenarios;

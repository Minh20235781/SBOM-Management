import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  Download,
  Eye,
  FileJson,
  GitBranch,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  TestTube2,
} from 'lucide-react';
import { API_BASE_URL } from '../api';
import SbomDependencyGraph from './SbomDependencyGraph';
import { type SbomGraphResponse } from '../types/sbom';

const API_BASE = API_BASE_URL;

type ScenarioRepo = {
  id: string;
  systemId?: number;
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
  inferredMetadata?: InferredMetadata | null;
  confirmed?: boolean;
};

type InferredField = {
  value: string | string[];
  source: string;
  confidence: 'high' | 'medium' | 'low';
  reason?: string;
  suggestions?: string[];
};

type InferredMetadata = {
  authors: InferredField;
  services: InferredField;
  lifecyclePhase: InferredField;
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

type UploadedSbom = {
  fileName: string;
  sbom: any;
  componentCount: number;
  dependencyCount: number;
  changes: string[];
};

type MutationCounts = {
  add: number;
  remove: number;
  version: number;
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

const formatInferredValue = (field?: InferredField) => {
  if (!field) return 'Không phát hiện được từ mã nguồn';
  return Array.isArray(field.value) ? field.value.join(', ') : field.value;
};

const confidenceClass = (confidence?: string) => {
  if (confidence === 'high') return 'border-emerald-100 bg-emerald-50 text-emerald-700';
  if (confidence === 'medium') return 'border-blue-100 bg-blue-50 text-blue-700';
  return 'border-amber-100 bg-amber-50 text-amber-700';
};

const formatEvidenceValue = (value: unknown) =>
  value === null || value === undefined || value === '' ? '-' : String(value);

const escapeHtml = (value: unknown) =>
  formatEvidenceValue(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');


const formatUiError = (value: string) => {
  const normalized = value.replace(/\r/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  if (/Filename too long|unable to create file|checkout failed/i.test(normalized)) {
    return [
      'Git da clone repository nhung checkout that bai vi duong dan file qua dai tren Windows.',
      'Ung dung da bat core.longpaths cho cac lan clone tiep theo. Neu van gap loi, hay bat long paths trong Windows hoac chon repository co path ngan hon.',
    ].join('\n');
  }
  return normalized.length > 1200 ? `${normalized.slice(0, 1200)}\n...` : normalized;
};


const countDependencyEdges = (sbom: any) =>
  (Array.isArray(sbom?.dependencies) ? sbom.dependencies : [])
    .reduce((sum: number, dep: any) => sum + (Array.isArray(dep?.dependsOn) ? dep.dependsOn.length : 0), 0);

const buildUploadedSbomState = (fileName: string, sbom: any, changes: string[] = []): UploadedSbom => ({
  fileName,
  sbom,
  componentCount: Array.isArray(sbom?.components) ? sbom.components.length : 0,
  dependencyCount: countDependencyEdges(sbom),
  changes,
});

const clampMutationCount = (value: number) => Math.max(0, Math.min(100, Number.isFinite(value) ? Math.floor(value) : 0));

const componentRef = (component: any) =>
  String(component?.['bom-ref'] || component?.purl || component?.name || '').trim();

const componentLabel = (component: any) =>
  String(component?.name || component?.purl || component?.['bom-ref'] || 'unknown-component');

const pickRandomItems = <T,>(items: T[], count: number) => {
  const pool = [...items];
  const result: T[] = [];
  const limit = Math.min(count, pool.length);
  while (result.length < limit) {
    const index = Math.floor(Math.random() * pool.length);
    result.push(pool.splice(index, 1)[0]);
  }
  return result;
};

const mutateUploadedSbom = (uploadedSbom: UploadedSbom, counts: MutationCounts) => {
  const sbom = JSON.parse(JSON.stringify(uploadedSbom.sbom || {}));
  const components = Array.isArray(sbom.components) ? sbom.components : [];
  sbom.components = components;

  const changes: string[] = [];
  const removeTargets = pickRandomItems(components, clampMutationCount(counts.remove));
  const removedRefs = new Set(removeTargets.map(componentRef).filter(Boolean));
  if (removeTargets.length > 0) {
    sbom.components = components.filter((component: any) => !removeTargets.includes(component));
    for (const component of removeTargets) {
      changes.push(`Xóa component ${componentLabel(component)}`);
    }
    if (Array.isArray(sbom.dependencies)) {
      sbom.dependencies = sbom.dependencies
        .filter((dep: any) => !removedRefs.has(String(dep?.ref || '')))
        .map((dep: any) => ({
          ...dep,
          dependsOn: Array.isArray(dep?.dependsOn)
            ? dep.dependsOn.filter((ref: string) => !removedRefs.has(String(ref)))
            : dep?.dependsOn,
        }));
    }
  }

  const versionTargets = pickRandomItems<any>(sbom.components || [], clampMutationCount(counts.version));
  for (const component of versionTargets) {
    const oldVersion = String(component.version || '0.0.0');
    const nextVersion = `${oldVersion}-test.${Math.floor(Math.random() * 9000) + 1000}`;
    component.version = nextVersion;
    changes.push(`Sửa phiên bản ${componentLabel(component)}: ${oldVersion} -> ${nextVersion}`);
  }

  const addCount = clampMutationCount(counts.add);
  const now = Date.now();
  for (let index = 0; index < addCount; index += 1) {
    const suffix = `${now}-${index + 1}-${Math.floor(Math.random() * 9000) + 1000}`;
    const component = {
      type: 'library',
      name: `validation-extra-component-${suffix}`,
      version: `1.0.${Math.floor(Math.random() * 99) + 1}`,
      purl: `pkg:npm/validation-extra-component-${suffix}@1.0.0`,
      'bom-ref': `pkg:npm/validation-extra-component-${suffix}@1.0.0`,
    };
    sbom.components.push(component);
    changes.push(`Thêm component ${component.name}`);
  }

  return buildUploadedSbomState(uploadedSbom.fileName, sbom, changes);
};

const buildValidationGraphResponse = (
  graph: Graph | null,
  projectName: string,
  search: string,
  depthLimit: number,
  onlyVulnerable: boolean
): SbomGraphResponse | null => {
  if (!graph) return null;

  const sourceNodes = graph.nodes || [];
  const sourceEdges = graph.edges || [];
  const adjacency = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();
  for (const edge of sourceEdges) {
    adjacency.set(edge.source, [...(adjacency.get(edge.source) || []), edge.target]);
    incoming.set(edge.target, [...(incoming.get(edge.target) || []), edge.source]);
  }

  const rootIds = sourceNodes.filter(node => node.type === 'PROJECT').map(node => node.id);
  const queue = [...rootIds];
  const depthById = new Map<string, number>(rootIds.map(id => [id, 0]));
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    const nextDepth = (depthById.get(current) || 0) + 1;
    for (const target of adjacency.get(current) || []) {
      if (!depthById.has(target) || nextDepth < (depthById.get(target) || Number.MAX_SAFE_INTEGER)) {
        depthById.set(target, nextDepth);
        queue.push(target);
      }
    }
  }

  for (const node of sourceNodes) {
    if (!depthById.has(node.id)) depthById.set(node.id, 1);
  }

  const normalizedSearch = search.trim().toLowerCase();
  const visibleIds = new Set<string>();
  for (const node of sourceNodes) {
    const nodeDepth = depthById.get(node.id) || 0;
    const matchesDepth = node.type === 'PROJECT' || nodeDepth <= depthLimit;
    const matchesSearch = !normalizedSearch || node.label.toLowerCase().includes(normalizedSearch) || node.id.toLowerCase().includes(normalizedSearch);
    const matchesVulnerability = !onlyVulnerable;
    if (matchesDepth && matchesSearch && matchesVulnerability) {
      visibleIds.add(node.id);
      for (const parent of incoming.get(node.id) || []) visibleIds.add(parent);
    }
  }

  const levelMap = new Map<number, typeof sourceNodes>();
  for (const node of sourceNodes.filter(node => visibleIds.has(node.id))) {
    const nodeDepth = depthById.get(node.id) || 0;
    levelMap.set(nodeDepth, [...(levelMap.get(nodeDepth) || []), node]);
  }

  const nodes = [...levelMap.entries()]
    .sort(([a], [b]) => a - b)
    .flatMap(([level, nodesAtLevel]) =>
      nodesAtLevel
        .slice()
        .sort((a, b) => a.label.localeCompare(b.label))
        .map((node, index) => ({
          id: node.id,
          label: node.label,
          type: node.type === 'PROJECT' ? 'PROJECT' as const : 'COMPONENT' as const,
          ecosystem: node.ecosystem || 'unknown',
          vulnerabilityCount: 0,
          riskLevel: 'LOW' as const,
          depth: level,
          x: level * 340,
          y: index * 118,
        }))
    );

  const visibleNodeIds = new Set(nodes.map(node => node.id));
  const edges = sourceEdges
    .filter(edge => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target))
    .map(edge => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      relationship: 'DEPENDS_ON' as const,
      isTransitive: false,
    }));

  return {
    snapshotId: `validation-${projectName || 'repo'}`,
    nodes,
    edges,
    summary: {
      nodeCount: nodes.length,
      edgeCount: edges.length,
      maxDepth: nodes.reduce((max, node) => Math.max(max, node.depth), 0),
      cycleDetected: false,
      criticalCount: 0,
      highCount: 0,
    },
  };
};

const actionButtonClass = (action: StepAction) => {
  if (action.primary) return 'bg-blue-600 text-white border-blue-600 hover:bg-blue-700 disabled:hover:bg-blue-600';
  if (action.warning) return 'bg-amber-50 text-amber-800 border-amber-200 hover:bg-amber-100 disabled:hover:bg-amber-50';
  return 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 disabled:hover:bg-white';
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
  const [uploadedSbom, setUploadedSbom] = useState<UploadedSbom | null>(null);
  const [mutationCounts, setMutationCounts] = useState<MutationCounts>({ add: 1, remove: 1, version: 1 });
  const [verification, setVerification] = useState<VerificationReport | null>(null);
  const [testReport, setTestReport] = useState<TestReport | null>(null);
  const [graphSearch, setGraphSearch] = useState('');
  const [graphDepth, setGraphDepth] = useState(3);
  const [graphOnlyVulnerable, setGraphOnlyVulnerable] = useState(false);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const analysisSectionRef = useRef<HTMLElement | null>(null);
  const graphSectionRef = useRef<HTMLElement | null>(null);
  const selectedRepo = repositories.find(repo => repo.id === selectedRepoId) || repositories[0];
  const dependencyGraph = useMemo(
    () => buildValidationGraphResponse(graph, selectedRepo?.projectName || analysis?.projectName || 'validation', graphSearch, graphDepth, graphOnlyVulnerable),
    [graph, selectedRepo?.projectName, analysis?.projectName, graphSearch, graphDepth, graphOnlyVulnerable]
  );

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
      setError(formatUiError(error instanceof Error ? error.message : 'Thao tác thất bại.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const selectRepo = (repoId: string) => {
    setSelectedRepoId(repoId);
    setAnalysis(null);
    setGraph(null);
    setUploadedSbom(null);
    setVerification(null);
    setTestReport(null);
  };

  const analyze = () => runAction('Analyze Source', async () => {
    if (!selectedRepoId) return;
    setAnalysis(null);
    setGraph(null);
    setVerification(null);
    setTestReport(null);
    const res = await fetch(`${API_BASE}/api/validation-scenarios/${selectedRepoId}/analyze`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Phân tích nguồn thất bại.');
    setAnalysis(data.analysis);
    setGraph(data.graph);
    const detectedFiles = Array.isArray(data.analysis?.dependencyFiles)
      ? data.analysis.dependencyFiles
        .map((file: { path?: string; name?: string }) => file.path || file.name)
        .filter(Boolean)
      : [];
    if (detectedFiles.length > 0) {
      setRepositories(current => current.map(repo =>
        repo.id === selectedRepoId ? { ...repo, dependencyFiles: detectedFiles } : repo
      ));
    }
  });

  const handleSbomFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      const sbom = JSON.parse(text);
      if (!Array.isArray(sbom.components)) throw new Error('File SBOM phai la CycloneDX JSON co truong components.');
      setUploadedSbom(buildUploadedSbomState(file.name, sbom));
      setVerification(null);
      setTestReport(null);
    } catch (error) {
      setUploadedSbom(null);
      setError(error instanceof Error ? error.message : 'Không đọc được file SBOM JSON.');
    } finally {
      event.target.value = '';
    }
  };

  const updateMutationCount = (key: keyof MutationCounts, value: string) => {
    setMutationCounts(current => ({ ...current, [key]: clampMutationCount(Number(value)) }));
  };

  const applyRandomMutations = () => {
    if (!uploadedSbom) return;
    const mutated = mutateUploadedSbom(uploadedSbom, mutationCounts);
    setUploadedSbom(mutated);
    setVerification(null);
    setTestReport(null);
  };

  const verify = () => runAction('Verify SBOM', async () => {
    if (!analysis?.runId) return;
    const targetSbom = uploadedSbom?.sbom;
    if (!targetSbom) throw new Error('Hãy tải file SBOM CycloneDX JSON lên để kiểm chứng.');

    const res = await fetch(`${API_BASE}/api/validation-scenarios/runs/${analysis.runId}/verify-uploaded`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sbom: targetSbom,
        fileName: uploadedSbom?.fileName || 'uploaded-sbom.json',
      }),
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

  const exportTestReportPdf = () => {
    if (!testReport) return;
    const evidenceRows = Object.entries(testReport.evidence || {})
      .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(value)}</td></tr>`)
      .join('');
    const steps = (testReport.steps || []).map(step => `<li>${escapeHtml(translateText(step))}</li>`).join('');
    const preconditions = (testReport.preconditions || []).map(item => `<li>${escapeHtml(translateText(item))}</li>`).join('');
    const popup = window.open('', '_blank', 'width=900,height=1100');
    if (!popup) {
      setError('Trình duyệt đã chặn cửa sổ xuất báo cáo. Hãy cho phép popup và thử lại.');
      return;
    }
    popup.document.write(`<!doctype html>
      <html>
        <head>
          <meta charset="utf-8" />
          <title>${escapeHtml(testReport.testCaseId)} - SBOM verification report</title>
          <style>
            body { font-family: Arial, sans-serif; color: #0f172a; margin: 32px; line-height: 1.45; }
            h1 { font-size: 22px; margin: 0 0 6px; }
            h2 { font-size: 15px; margin: 24px 0 8px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
            .meta { color: #475569; font-size: 12px; margin-bottom: 18px; }
            .status { display: inline-block; padding: 4px 9px; border-radius: 999px; font-weight: 700; background: ${testReport.result === 'PASS' ? '#dcfce7' : '#fee2e2'}; color: ${testReport.result === 'PASS' ? '#166534' : '#991b1b'}; }
            table { width: 100%; border-collapse: collapse; font-size: 12px; }
            th, td { border: 1px solid #e2e8f0; padding: 8px; text-align: left; vertical-align: top; }
            th { width: 190px; background: #f8fafc; color: #475569; }
            ul { margin-top: 6px; }
            @media print { body { margin: 18mm; } button { display: none; } }
          </style>
        </head>
        <body>
          <button onclick="window.print()" style="float:right;padding:8px 12px;border:1px solid #cbd5e1;background:white;border-radius:6px;">Luu PDF</button>
          <h1>SBOM Verification Report</h1>
          <div class="meta">Generated: ${escapeHtml(new Date().toLocaleString('vi-VN'))}</div>
          <table>
            <tr><th>Test case ID</th><td>${escapeHtml(testReport.testCaseId)}</td></tr>
            <tr><th>Name</th><td>${escapeHtml(translateTestReportName(testReport.name))}</td></tr>
            <tr><th>Result</th><td><span class="status">${escapeHtml(translateStatus(testReport.result))}</span></td></tr>
            <tr><th>Scope</th><td>${escapeHtml(translateText(testReport.scope))}</td></tr>
            <tr><th>Application type</th><td>${escapeHtml(translateApplicationType(testReport.applicationType))}</td></tr>
            <tr><th>Repo scope</th><td>${escapeHtml(translateRepoScope(testReport.repoScope))}</td></tr>
            <tr><th>Architecture</th><td>${escapeHtml(translateArchitecture(testReport.architectureType))}</td></tr>
            <tr><th>Input repo</th><td>${escapeHtml(testReport.inputRepo)}</td></tr>
            <tr><th>Expected result</th><td>${escapeHtml(translateText(testReport.expectedResult))}</td></tr>
            <tr><th>Actual result</th><td>${escapeHtml(translateActualResult(testReport.actualResult))}</td></tr>
          </table>
          <h2>Preconditions</h2>
          <ul>${preconditions}</ul>
          <h2>Steps</h2>
          <ul>${steps}</ul>
          <h2>Evidence</h2>
          <table>${evidenceRows}</table>
        </body>
      </html>`);
    popup.document.close();
    popup.focus();
    popup.print();
  };

  const hasVerificationSbom = Boolean(uploadedSbom);

  const stepGroups: StepGroup[] = [
    {
      title: 'Chuẩn bị nguồn đối chiếu',
      description: 'Chọn repository đã lưu và cập nhật source thật để làm dữ liệu đối chiếu khi kiểm chứng.',
      actions: [{
        label: 'Chuẩn bị source',
        icon: <Play className="h-4 w-4" />,
        onClick: analyze,
        disabled: !selectedRepo || Boolean(loadingAction),
        loading: loadingAction === 'Analyze Source',
        primary: true,
        helper: !selectedRepo ? 'Hãy chọn repository trước.' : 'Đang có thao tác khác chạy.',
      }],
    },
    {
      title: 'Dữ liệu đối chiếu',
      description: 'Xem source đã chuẩn bị và file SBOM tải lên từ máy sẽ dùng để kiểm chứng.',
      actions: [
        {
          label: 'Xem file phụ thuộc',
          icon: <GitBranch className="h-4 w-4" />,
          onClick: () => analysisSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
          disabled: !analysis,
          helper: 'Chưa chuẩn bị source nên chưa có danh sách phụ thuộc.',
        },
        {
          label: 'Xem đồ thị phụ thuộc',
          icon: <Network className="h-4 w-4" />,
          onClick: () => graphSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
          disabled: !graph,
          helper: 'Chưa chuẩn bị source nên chưa có dữ liệu đồ thị.',
        },
      ],
    },
    {
      title: 'Kiểm chứng SBOM',
      description: 'So sánh source thật với file SBOM CycloneDX JSON được tải lên từ máy.',
      actions: [
        {
          label: 'Verify SBOM',
          icon: <ShieldCheck className="h-4 w-4" />,
          onClick: verify,
          disabled: !analysis || !hasVerificationSbom || Boolean(loadingAction),
          loading: loadingAction === 'Verify SBOM',
          primary: Boolean(analysis && hasVerificationSbom),
          helper: !analysis ? 'Cần chuẩn bị source trước.' : !hasVerificationSbom ? 'Cần tải file SBOM lên.' : 'Đang có thao tác khác chạy.',
        },
      ],
    },
    {
      title: 'Báo cáo',
      description: 'Mở báo cáo test case và evidence của lần kiểm chứng hiện tại.',
      actions: [
        {
          label: 'View Test Report',
          icon: <TestTube2 className="h-4 w-4" />,
          onClick: loadReport,
          disabled: !analysis || Boolean(loadingAction),
          loading: loadingAction === 'View Test Report',
          helper: !analysis ? 'Cần chuẩn bị source trước.' : 'Đang có thao tác khác chạy.',
        },
        {
          label: 'Xuất PDF',
          icon: <Download className="h-4 w-4" />,
          onClick: exportTestReportPdf,
          disabled: !testReport || Boolean(loadingAction),
          helper: !testReport ? 'Cần có báo cáo kiểm thử trước.' : 'Đang có thao tác khác chạy.',
        },
      ],
    },
  ];


  return (
    <div className="space-y-6">
      <header className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="max-w-4xl">
          <h2 className="text-2xl font-bold text-slate-900">Kiểm chứng SBOM</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            Phạm vi hiện tại chỉ xử lý repository GitHub thật của ứng dụng web trong một kho lưu trữ. Multi-repo và microservice nhiều repo là hướng mở rộng, không phải hỗ trợ của phiên bản demo này.
          </p>
        </div>
      </header>

      {error && (
        <div className="flex flex-col gap-3 rounded-lg border border-rose-100 bg-rose-50 px-4 py-3 text-sm text-rose-700 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-2">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <p className="max-h-48 min-w-0 overflow-auto whitespace-pre-wrap break-words leading-5">{error}</p>
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

      <div className="space-y-6">
        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-col gap-2 border-b border-slate-100 px-5 py-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Danh sách repository kiểm thử</h3>
              <p className="mt-1 text-sm text-slate-500">Repository được lấy từ các dự án đã lưu trong hệ thống và có URL nguồn.</p>
            </div>
            <span className={mutedBadge}>{repositories.length || 0} repo</span>
          </div>

          <div className="hidden max-h-[420px] overflow-auto lg:block">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Repository</th>
                  <th className="px-4 py-3">File phụ thuộc</th>
                  <th className="px-4 py-3 text-right">Hành động</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {catalogLoading ? (
                  <tr><td colSpan={3} className="px-4 py-10 text-center text-slate-500">Đang tải danh sách repository...</td></tr>
                ) : repositories.length === 0 ? (
                  <tr><td colSpan={3} className="px-4 py-10 text-center text-slate-500">Chưa có repository nào. Hãy tạo pipeline cho dự án và nhập URL repository trước.</td></tr>
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
                      <td className="px-4 py-4 font-mono text-xs leading-5 text-slate-600">{repo.dependencyFiles.join(', ')}</td>
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

          <div className="grid max-h-[520px] grid-cols-1 gap-3 overflow-y-auto p-4 lg:hidden">
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

          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <p className="text-xs font-bold uppercase tracking-wide text-slate-400">SBOM tải lên từ máy</p>
                <h3 className="mt-1 text-lg font-bold text-slate-900">File SBOM dùng để kiểm chứng</h3>
                <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
                  Chọn repository thật, tải file SBOM CycloneDX JSON tương ứng lên, sau đó chạy Analyze Source và Verify SBOM để so sánh source thật với file này.
                </p>
              </div>
              <label className="inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-4 py-2 text-sm font-semibold text-blue-700 hover:bg-blue-100">
                <FileJson className="h-4 w-4" />
                Tải file SBOM
                <input type="file" accept=".json,application/json" onChange={handleSbomFile} className="hidden" />
              </label>
            </div>

            {uploadedSbom ? (
              <div className="mt-4 space-y-4">
                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                  <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                    <p className="text-xs font-bold uppercase tracking-wide text-slate-500">File</p>
                    <p className="mt-1 break-all text-sm font-semibold text-slate-900">{uploadedSbom.fileName}</p>
                  </div>
                  <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                    <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Components trong SBOM</p>
                    <p className="mt-1 text-xl font-bold text-slate-900">{uploadedSbom.componentCount}</p>
                  </div>
                  <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                    <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Dependencies trong SBOM</p>
                    <p className="mt-1 text-xl font-bold text-slate-900">{uploadedSbom.dependencyCount}</p>
                  </div>
                </div>
                <div className="rounded-lg border border-amber-100 bg-amber-50/60 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wide text-amber-700">Tạo lỗi kiểm thử tự động</p>
                      <p className="mt-1 text-sm leading-6 text-slate-600">
                        Chọn số component cần thêm, xóa hoặc sửa phiên bản, công cụ sẽ chọn ngẫu nhiên trong SBOM đang tải lên.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={applyRandomMutations}
                      className="inline-flex items-center justify-center gap-2 rounded-lg border border-amber-200 bg-white px-4 py-2 text-sm font-semibold text-amber-800 hover:bg-amber-100"
                    >
                      <TestTube2 className="h-4 w-4" />
                      Áp dụng ngẫu nhiên
                    </button>
                  </div>
                  <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                    {[
                      ['add', 'Thêm component'],
                      ['remove', 'Xóa component'],
                      ['version', 'Sửa phiên bản'],
                    ].map(([key, label]) => (
                      <label key={key} className="block text-sm font-semibold text-slate-700">
                        {label}
                        <input
                          type="number"
                          min={0}
                          max={100}
                          value={mutationCounts[key as keyof MutationCounts]}
                          onChange={event => updateMutationCount(key as keyof MutationCounts, event.target.value)}
                          className="mt-2 w-full rounded-lg border border-amber-200 bg-white px-3 py-2 text-sm text-slate-900 focus:border-amber-400 focus:outline-none focus:ring-2 focus:ring-amber-100"
                        />
                      </label>
                    ))}
                  </div>
                  {uploadedSbom.changes.length > 0 && (
                    <div className="mt-4 rounded-md border border-amber-100 bg-white p-3">
                      <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Thay đổi vừa tạo</p>
                      <ul className="mt-2 max-h-32 space-y-1 overflow-auto text-xs leading-5 text-slate-600">
                        {uploadedSbom.changes.map((change, index) => (
                          <li key={`${change}-${index}`}>{change}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="mt-4 rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500">
                Chưa có file SBOM. Hãy tải file CycloneDX JSON đã lưu trên máy để kiểm chứng với repository đang chọn.
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

          {analysis.inferredMetadata && (
            <div className="rounded-xl border border-blue-100 bg-blue-50/60 p-5 shadow-sm">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <h3 className="font-bold text-slate-900">Thông tin metadata do công cụ phát hiện</h3>
                  <p className="mt-1 text-sm text-slate-600">
                    Các trường này được suy luận từ Git history, file metadata và cấu trúc repository. Người dùng chỉ xem lại và xác nhận.
                  </p>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
                {[
                  ['Tác giả', analysis.inferredMetadata.authors],
                  ['Dịch vụ', analysis.inferredMetadata.services],
                  ['Giai đoạn vòng đời', analysis.inferredMetadata.lifecyclePhase],
                ].map(([label, field]) => {
                  const item = field as InferredField;
                  return (
                    <div key={label as string} className="rounded-lg border border-slate-200 bg-white p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-xs font-bold uppercase tracking-wide text-slate-500">{label as string}</p>
                        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${confidenceClass(item.confidence)}`}>
                          {item.confidence}
                        </span>
                      </div>
                      <p className="mt-2 text-sm font-semibold leading-5 text-slate-900">{formatInferredValue(item)}</p>
                      <p className="mt-2 text-xs leading-4 text-slate-500">Nguồn: {item.source}</p>
                      {item.reason && <p className="mt-1 text-xs leading-4 text-amber-700">{item.reason}</p>}
                      {item.suggestions && item.suggestions.length > 0 && (
                        <p className="mt-1 text-xs leading-4 text-blue-700">Gợi ý thêm: {item.suggestions.join(', ')}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

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
            <p className="mt-1 text-sm text-slate-500">Visualize component/package và quan hệ phụ thuộc bằng cùng kiểu đồ thị ở các trang SBOM khác.</p>
          </div>
          <span className="text-sm text-slate-500">{dependencyGraph ? `${dependencyGraph.summary.nodeCount} nodes / ${dependencyGraph.summary.edgeCount} edges` : 'Chưa có dữ liệu'}</span>
        </div>
        <SbomDependencyGraph
          graph={dependencyGraph}
          search={graphSearch}
          depth={graphDepth}
          onlyVulnerable={graphOnlyVulnerable}
          onSearchChange={setGraphSearch}
          onDepthChange={setGraphDepth}
          onOnlyVulnerableChange={setGraphOnlyVulnerable}
        />
      </section>



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

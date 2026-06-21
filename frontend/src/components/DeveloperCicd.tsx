import React, { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  FileCode2,
  GitBranch,
  GitMerge,
  Import,
  Layers3,
  ListChecks,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  UploadCloud,
  XCircle,
} from 'lucide-react';
import SbomDependencyGraph from './SbomDependencyGraph';
import {
  type CicdPipeline,
  type CicdPipelineRun,
  type DevTask,
  type ProjectArtifact,
  type SbomChangeLog,
  type SbomGraphResponse,
  type SbomSnapshot,
} from '../types/sbom';
import { API_BASE_URL } from '../api';

const API_BASE = API_BASE_URL;

type SystemOption = {
  system_id: number;
  name: string;
  description?: string | null;
};

type Props = {
  systems: SystemOption[];
  refreshSystems?: () => Promise<void>;
};

const statusClass: Record<string, string> = {
  TODO: 'border-slate-200 bg-slate-50 text-slate-700',
  IN_PROGRESS: 'border-sky-100 bg-sky-50 text-sky-700',
  DONE: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  BLOCKED: 'border-rose-100 bg-rose-50 text-rose-700',
  PENDING: 'border-slate-200 bg-slate-50 text-slate-700',
  RUNNING: 'border-sky-100 bg-sky-50 text-sky-700',
  SUCCESS: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  FAILED: 'border-rose-100 bg-rose-50 text-rose-700',
  CANCELLED: 'border-amber-100 bg-amber-50 text-amber-700',
  LOW: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  MEDIUM: 'border-sky-100 bg-sky-50 text-sky-700',
  HIGH: 'border-amber-100 bg-amber-50 text-amber-700',
  INTERNAL: 'border-slate-200 bg-white text-slate-700',
  GITHUB_ACTIONS: 'border-sky-100 bg-sky-50 text-sky-700',
  JENKINS: 'border-amber-100 bg-amber-50 text-amber-700',
  GITLAB_CI: 'border-orange-100 bg-orange-50 text-orange-700',
  FULL_SCAN: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  INCREMENTAL_UPDATE: 'border-sky-100 bg-sky-50 text-sky-700',
  AUTO_GENERATED: 'border-indigo-100 bg-indigo-50 text-indigo-700',
  IMPORT: 'border-violet-100 bg-violet-50 text-violet-700',
  NO_CHANGES: 'border-slate-200 bg-slate-50 text-slate-700',
  PASS: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  WARN: 'border-amber-100 bg-amber-50 text-amber-700',
  FAIL: 'border-rose-100 bg-rose-50 text-rose-700',
};

const dependencyManifest = {
  artifactPath: 'package.json',
  artifactName: 'package.json',
  artifactType: 'package.json',
  content: JSON.stringify({
    name: 'developer-sbom-demo',
    version: '1.0.0',
    dependencies: {
      '@vitejs/plugin-react': '^6.0.1',
      axios: '^1.16.0',
      react: '^19.2.5',
      recharts: '^3.8.1',
    },
  }, null, 2),
};

const importedCycloneDx = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: 'urn:uuid:developer-import-demo',
  metadata: {
    timestamp: new Date().toISOString(),
    component: {
      type: 'application',
      name: 'third-party-web-module',
      version: '2.0.0',
      'bom-ref': 'third-party-web-module',
    },
  },
  components: [
    {
      type: 'library',
      name: 'axios',
      version: '1.16.0',
      purl: 'pkg:npm/axios@1.16.0',
      'bom-ref': 'pkg:npm/axios@1.16.0',
      licenses: [{ license: { id: 'MIT' } }],
    },
    {
      type: 'library',
      name: 'react',
      version: '19.2.5',
      purl: 'pkg:npm/react@19.2.5',
      'bom-ref': 'pkg:npm/react@19.2.5',
      licenses: [{ license: { id: 'MIT' } }],
    },
  ],
  dependencies: [
    {
      ref: 'third-party-web-module',
      dependsOn: ['pkg:npm/axios@1.16.0', 'pkg:npm/react@19.2.5'],
    },
  ],
};

const Badge = ({ value }: { value?: string | null }) => (
  <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${statusClass[value || ''] || statusClass.PENDING}`}>
    {value || '-'}
  </span>
);

const FieldLabel = ({ children }: { children: React.ReactNode }) => (
  <span className="mb-1 block text-xs font-semibold text-slate-500">{children}</span>
);

const DeveloperCicd: React.FC<Props> = ({ systems, refreshSystems }) => {
  const preferredSystem = useMemo(
    () => systems.find(system => system.name === 'LaKhe-Management-v2') || systems[0],
    [systems]
  );
  const [projectId, setProjectId] = useState<number | ''>('');
  const [tasks, setTasks] = useState<DevTask[]>([]);
  const [pipelines, setPipelines] = useState<CicdPipeline[]>([]);
  const [runs, setRuns] = useState<CicdPipelineRun[]>([]);
  const [snapshots, setSnapshots] = useState<SbomSnapshot[]>([]);
  const [artifacts, setArtifacts] = useState<ProjectArtifact[]>([]);
  const [selectedPipelineId, setSelectedPipelineId] = useState<number | null>(null);
  const [selectedRun, setSelectedRun] = useState<CicdPipelineRun | null>(null);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [changes, setChanges] = useState<SbomChangeLog[]>([]);
  const [graph, setGraph] = useState<SbomGraphResponse | null>(null);
  const [graphSearch, setGraphSearch] = useState('');
  const [graphDepth, setGraphDepth] = useState(5);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const [taskForm, setTaskForm] = useState({
    title: 'Update axios dependency',
    description: 'Update dependency manifest, generate a new SBOM snapshot, and trace the change through CI/CD.',
    priority: 'MEDIUM',
    assignedTo: 'Developer',
    relatedPipelineId: '',
  });
  const [pipelineForm, setPipelineForm] = useState({
    name: 'sbom-incremental-scan',
    branch: 'main',
    provider: 'GITHUB_ACTIONS',
    triggerType: 'PUSH',
    repoUrl: 'https://github.com/owner/repo.git',
    workflowFile: 'sbom.yml',
  });

  const selectedProject = systems.find(system => system.system_id === projectId);
  const selectedPipeline = pipelines.find(pipeline => pipeline.pipeline_id === selectedPipelineId) || null;
  const selectedSnapshot = snapshots.find(snapshot => snapshot.snapshot_id === selectedSnapshotId) || null;
  const summary = selectedRun?.snapshot_summary || selectedSnapshot?.summary || null;
  const validation = selectedRun?.validation_report || null;

  useEffect(() => {
    if (!projectId && preferredSystem) setProjectId(preferredSystem.system_id);
  }, [preferredSystem, projectId]);

  const loadProjectData = async (id: number) => {
    const [tasksRes, pipelinesRes, snapshotsRes, artifactsRes] = await Promise.all([
      fetch(`${API_BASE}/api/projects/${id}/tasks`),
      fetch(`${API_BASE}/api/projects/${id}/pipelines`),
      fetch(`${API_BASE}/api/projects/${id}/sbom/snapshots`),
      fetch(`${API_BASE}/api/projects/${id}/artifacts`),
    ]);
    const [tasksData, pipelinesData, snapshotsData, artifactsData] = await Promise.all([
      tasksRes.json(),
      pipelinesRes.json(),
      snapshotsRes.json(),
      artifactsRes.json(),
    ]);
    setTasks(Array.isArray(tasksData) ? tasksData : []);
    setPipelines(Array.isArray(pipelinesData) ? pipelinesData : []);
    setSnapshots(Array.isArray(snapshotsData) ? snapshotsData : []);
    setArtifacts(Array.isArray(artifactsData) ? artifactsData : []);
    const nextPipelineId = pipelinesData[0]?.pipeline_id || null;
    const nextSnapshotId = snapshotsData[0]?.snapshot_id || null;
    setSelectedPipelineId(current => current || nextPipelineId);
    setSelectedSnapshotId(current => current || nextSnapshotId);
  };

  const loadRuns = async (pipelineId: number) => {
    const res = await fetch(`${API_BASE}/api/pipelines/${pipelineId}/runs`);
    const data = await res.json();
    setRuns(Array.isArray(data) ? data : []);
    if (data[0]) await loadRunDetail(data[0].run_id);
  };

  const loadRunDetail = async (runId: number) => {
    const res = await fetch(`${API_BASE}/api/pipeline-runs/${runId}`);
    const data = await res.json();
    setSelectedRun(data);
    if (data.generated_sbom_snapshot_id) setSelectedSnapshotId(data.generated_sbom_snapshot_id);
  };

  const loadSnapshotResult = async (snapshotId: string) => {
    const query = new URLSearchParams({
      depth: String(graphDepth),
      onlyVulnerable: String(onlyVulnerable),
      search: graphSearch,
    });
    const [changesRes, graphRes] = await Promise.all([
      fetch(`${API_BASE}/api/sbom/snapshots/${snapshotId}/changes`),
      fetch(`${API_BASE}/api/sbom/snapshots/${snapshotId}/graph?${query.toString()}`),
    ]);
    const [changesData, graphData] = await Promise.all([changesRes.json(), graphRes.json()]);
    setChanges(Array.isArray(changesData) ? changesData : []);
    setGraph(graphData?.nodes ? graphData : null);
  };

  const withLoading = async (action: () => Promise<void>, successMessage: string) => {
    setLoading(true);
    setMessage('');
    try {
      await action();
      setMessage(successMessage);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Không thể hoàn tất thao tác.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!projectId) return;
    loadProjectData(Number(projectId)).catch(() => setMessage('Không tải được dữ liệu Developer workflow.'));
  }, [projectId]);

  useEffect(() => {
    if (!selectedPipelineId) {
      setRuns([]);
      setSelectedRun(null);
      return;
    }
    loadRuns(selectedPipelineId).catch(() => setMessage('Không tải được pipeline runs.'));
  }, [selectedPipelineId]);

  useEffect(() => {
    if (!selectedPipelineId || selectedPipeline?.provider !== 'GITHUB_ACTIONS') return;
    const timer = window.setInterval(() => {
      loadRuns(selectedPipelineId).catch(() => undefined);
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [selectedPipelineId, selectedPipeline?.provider]);

  useEffect(() => {
    if (!selectedSnapshotId) {
      setChanges([]);
      setGraph(null);
      return;
    }
    loadSnapshotResult(selectedSnapshotId).catch(() => setMessage('Không tải được kết quả SBOM.'));
  }, [selectedSnapshotId, graphSearch, graphDepth, onlyVulnerable]);

  const createTask = () => withLoading(async () => {
    if (!projectId) return;
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...taskForm,
        status: 'TODO',
        relatedPipelineId: taskForm.relatedPipelineId ? Number(taskForm.relatedPipelineId) : null,
      }),
    });
    if (!res.ok) throw new Error('Không tạo được task.');
    await loadProjectData(Number(projectId));
  }, 'Đã tạo task và gắn vào project.');

  const createPipeline = () => withLoading(async () => {
    if (!projectId) return;
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/pipelines`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pipelineForm),
    });
    if (!res.ok) throw new Error('Không tạo được pipeline.');
    const pipeline = await res.json();
    await loadProjectData(Number(projectId));
    setSelectedPipelineId(pipeline.pipeline_id);
  }, 'Đã tạo pipeline CI/CD cho project.');

  const saveDependencyFiles = () => withLoading(async () => {
    if (!projectId) return;
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/artifacts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dependencyFiles: [dependencyManifest] }),
    });
    if (!res.ok) throw new Error('Không lưu được dependency file.');
    await loadProjectData(Number(projectId));
  }, 'Đã lưu package.json làm nguồn cập nhật thành phần/phụ thuộc.');

  const generateSnapshot = () => withLoading(async () => {
    if (!projectId) return;
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/sbom/auto-generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dependencyFiles: [dependencyManifest] }),
    });
    if (!res.ok) throw new Error('Không sinh được SBOM snapshot.');
    const result = await res.json();
    await loadProjectData(Number(projectId));
    setSelectedSnapshotId(result.snapshotId);
  }, 'Đã khởi tạo/cập nhật SBOM snapshot từ dependency file.');

  const importSbom = () => withLoading(async () => {
    if (!projectId) return;
    const res = await fetch(`${API_BASE}/api/sboms/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_id: projectId,
        sbom: importedCycloneDx,
        repoUrl: pipelineForm.repoUrl,
      }),
    });
    if (!res.ok) throw new Error('Không import được SBOM.');
    const snapshotRes = await fetch(`${API_BASE}/api/projects/${projectId}/sbom/incremental-generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sbom: importedCycloneDx }),
    });
    if (!snapshotRes.ok) throw new Error('Đã import SBOM nhưng chưa tạo được snapshot phân tích.');
    const result = await snapshotRes.json();
    await refreshSystems?.();
    await loadProjectData(Number(projectId));
    setSelectedSnapshotId(result.snapshotId);
  }, 'Đã import SBOM CycloneDX và chuẩn hóa thành snapshot phân tích.');

  const runPipeline = () => withLoading(async () => {
    if (!selectedPipelineId) return;
    const res = await fetch(`${API_BASE}/api/pipelines/${selectedPipelineId}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ triggeredBy: 'Developer' }),
    });
    if (!res.ok) throw new Error('Không chạy được pipeline.');
    const run = await res.json();
    if (projectId) await loadProjectData(Number(projectId));
    await loadRuns(selectedPipelineId);
    await loadRunDetail(run.run_id);
  }, selectedPipeline?.provider === 'GITHUB_ACTIONS'
    ? 'Đã gửi yêu cầu chạy workflow tới GitHub Actions. Trạng thái sẽ tự đồng bộ.'
    : 'Pipeline nội bộ đã chạy xong và lưu SBOM.');

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-200 pb-5">
        <p className="text-xs font-bold uppercase tracking-wide text-slate-400">Developer workflow</p>
        <h2 className="mt-1 text-2xl font-bold text-slate-900">Quản lý Task, CI/CD và SBOM tập trung</h2>
        <p className="mt-2 max-w-4xl text-sm text-slate-500">
          Theo dõi task, pipeline, dependency file, SBOM import/generated, change log và đồ thị phụ thuộc trên cùng một project.
        </p>
      </div>

      {message && (
        <div className="rounded-lg border border-sky-100 bg-sky-50 px-4 py-3 text-sm font-medium text-sky-700">{message}</div>
      )}

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex items-center gap-2">
          <Server className="h-4 w-4 text-sky-500" />
          <h3 className="text-sm font-bold text-slate-800">Project scope</h3>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[320px_1fr]">
          <select
            value={projectId}
            onChange={event => {
              setProjectId(Number(event.target.value));
              setSelectedPipelineId(null);
              setSelectedRun(null);
              setSelectedSnapshotId(null);
            }}
            className="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-sky-300 focus:ring-2 focus:ring-sky-100"
          >
            <option value="">Chọn project</option>
            {systems.map(system => (
              <option key={system.system_id} value={system.system_id}>{system.name}</option>
            ))}
          </select>
          <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 text-sm text-slate-600">
            <p className="font-semibold text-slate-800">{selectedProject?.name || 'Chưa chọn project'}</p>
            <p className="mt-1 text-xs">{selectedProject?.description || 'Task, pipeline, dependency file và SBOM snapshot sẽ được gắn với project này.'}</p>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-indigo-500" />
            <h3 className="text-sm font-bold text-slate-800">1. Quản lý nhiệm vụ và liên kết pipeline/SBOM</h3>
          </div>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_150px_150px_180px_auto]">
            <input
              value={taskForm.title}
              onChange={event => setTaskForm(current => ({ ...current, title: event.target.value }))}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
              placeholder="Task title"
            />
            <select value={taskForm.priority} onChange={event => setTaskForm(current => ({ ...current, priority: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm">
              <option>LOW</option>
              <option>MEDIUM</option>
              <option>HIGH</option>
            </select>
            <input value={taskForm.assignedTo} onChange={event => setTaskForm(current => ({ ...current, assignedTo: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="Assignee" />
            <select value={taskForm.relatedPipelineId} onChange={event => setTaskForm(current => ({ ...current, relatedPipelineId: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm">
              <option value="">Chưa gắn pipeline</option>
              {pipelines.map(pipeline => (
                <option key={pipeline.pipeline_id} value={pipeline.pipeline_id}>{pipeline.name}</option>
              ))}
            </select>
            <button type="button" onClick={createTask} disabled={!projectId || loading} className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50">
              Tạo task
            </button>
          </div>
          <div className="mt-4 overflow-hidden rounded-lg border border-slate-100">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Task</th>
                  <th className="px-4 py-3">Pipeline</th>
                  <th className="px-4 py-3">Latest SBOM</th>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tasks.map(task => (
                  <tr key={task.task_id}>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-800">{task.title}</p>
                      <p className="mt-1 text-xs text-slate-500">{task.assigned_to || '-'}</p>
                    </td>
                    <td className="px-4 py-3 text-slate-600">{task.related_pipeline_name || task.related_pipeline_id || '-'}</td>
                    <td className="px-4 py-3 text-slate-600">{task.latest_snapshot_version ? `v${task.latest_snapshot_version}` : '-'}</td>
                    <td className="px-4 py-3"><Badge value={task.priority} /></td>
                    <td className="px-4 py-3"><Badge value={task.status} /></td>
                  </tr>
                ))}
                {tasks.length === 0 && <tr><td colSpan={5} className="px-4 py-8 text-center text-slate-400">Chưa có task</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <UploadCloud className="h-4 w-4 text-emerald-500" />
            <h3 className="text-sm font-bold text-slate-800">2, 3, 6. SBOM và dependency source</h3>
          </div>
          <div className="space-y-3">
            <button type="button" onClick={saveDependencyFiles} disabled={!projectId || loading} className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50">
              <FileCode2 className="h-4 w-4" />
              Lưu/cập nhật package.json
            </button>
            <button type="button" onClick={generateSnapshot} disabled={!projectId || loading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50">
              <Layers3 className="h-4 w-4" />
              Khởi tạo/cập nhật SBOM
            </button>
            <button type="button" onClick={importSbom} disabled={!projectId || loading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50">
              <Import className="h-4 w-4" />
              Import SBOM CycloneDX
            </button>
          </div>
          <div className="mt-4 rounded-lg border border-slate-100 bg-slate-50 p-3">
            <p className="text-xs font-bold uppercase text-slate-400">Dependency files</p>
            <div className="mt-2 space-y-2">
              {artifacts.map(artifact => (
                <div key={artifact.artifact_id} className="flex items-center justify-between gap-3 text-xs">
                  <span className="font-medium text-slate-700">{artifact.artifact_path}</span>
                  <span className="font-mono text-slate-400">{artifact.hash.slice(0, 8)}</span>
                </div>
              ))}
              {artifacts.length === 0 && <p className="text-xs text-slate-400">Chưa lưu dependency file.</p>}
            </div>
          </div>
        </section>
      </div>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-sky-500" />
            <h3 className="text-sm font-bold text-slate-800">5. Tích hợp tạo SBOM vào CI/CD</h3>
          </div>
          {loading && <RefreshCw className="h-4 w-4 animate-spin text-sky-500" />}
        </div>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="min-w-0 md:col-span-2">
              <FieldLabel>Pipeline name</FieldLabel>
              <input value={pipelineForm.name} onChange={event => setPipelineForm(current => ({ ...current, name: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm" />
            </label>
            <label className="min-w-0">
              <FieldLabel>Branch</FieldLabel>
              <input value={pipelineForm.branch} onChange={event => setPipelineForm(current => ({ ...current, branch: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm" />
            </label>
            <label className="min-w-0">
              <FieldLabel>Provider</FieldLabel>
              <select value={pipelineForm.provider} onChange={event => setPipelineForm(current => ({ ...current, provider: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm">
                <option>INTERNAL</option>
                <option>GITHUB_ACTIONS</option>
                <option>JENKINS</option>
                <option>GITLAB_CI</option>
                <option>CIRCLECI</option>
              </select>
            </label>
            <label className="min-w-0">
              <FieldLabel>Trigger</FieldLabel>
              <select value={pipelineForm.triggerType} onChange={event => setPipelineForm(current => ({ ...current, triggerType: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm">
                <option>MANUAL</option>
                <option>PUSH</option>
                <option>PULL_REQUEST</option>
                <option>SCHEDULE</option>
              </select>
            </label>
            <label className="min-w-0 md:col-span-2">
              <FieldLabel>Repo URL</FieldLabel>
              <input value={pipelineForm.repoUrl} onChange={event => setPipelineForm(current => ({ ...current, repoUrl: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="https://github.com/owner/repo.git" />
            </label>
            {pipelineForm.provider === 'GITHUB_ACTIONS' && (
              <label className="min-w-0 md:col-span-2">
                <FieldLabel>Workflow file</FieldLabel>
                <input value={pipelineForm.workflowFile} onChange={event => setPipelineForm(current => ({ ...current, workflowFile: event.target.value }))} className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="sbom.yml" />
              </label>
            )}
            <button type="button" onClick={createPipeline} disabled={!projectId || loading} className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50">
              Tạo pipeline
            </button>
          </div>

          <div className="rounded-lg border border-sky-100 bg-sky-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Pipeline đang chọn</p>
            <p className="mt-1 truncate text-sm font-bold text-slate-800">{selectedPipeline?.name || 'Chưa chọn pipeline'}</p>
            <p className="mt-2 break-all text-xs text-slate-500">{selectedPipeline?.repo_url || 'Tạo hoặc chọn pipeline để chạy.'}</p>
            {selectedPipeline?.provider === 'GITHUB_ACTIONS' && <p className="mt-2 text-xs font-medium text-sky-700">Workflow: {selectedPipeline.workflow_file || 'sbom.yml'}</p>}
            <button type="button" onClick={runPipeline} disabled={!selectedPipelineId || loading} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-sky-700 disabled:opacity-50">
              {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Run pipeline
            </button>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-3 lg:grid-cols-3">
          {pipelines.map(pipeline => (
            <button key={pipeline.pipeline_id} type="button" onClick={() => setSelectedPipelineId(pipeline.pipeline_id)} className={`min-w-0 rounded-lg border p-4 text-left transition ${selectedPipelineId === pipeline.pipeline_id ? 'border-sky-300 bg-sky-50' : 'border-slate-200 bg-white hover:bg-slate-50'}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-bold text-slate-800">{pipeline.name}</p>
                  <p className="mt-1 flex items-center gap-1 text-xs text-slate-500"><GitBranch className="h-3.5 w-3.5" /> {pipeline.branch} | {pipeline.provider}</p>
                </div>
                <Badge value={pipeline.latest_status || 'PENDING'} />
              </div>
              <p className="mt-3 break-all text-xs text-slate-500">{pipeline.repo_url || 'No repository URL'}</p>
            </button>
          ))}
          {pipelines.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-6 text-sm text-slate-400">Chưa có pipeline</div>}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[420px_1fr]">
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="mb-4 text-sm font-bold text-slate-800">Pipeline runs và SBOM snapshots</h3>
          <div className="space-y-2">
            {runs.map(run => (
              <button key={run.run_id} type="button" onClick={() => loadRunDetail(run.run_id)} className={`w-full rounded-lg border p-3 text-left transition ${selectedRun?.run_id === run.run_id ? 'border-sky-300 bg-sky-50' : 'border-slate-200 hover:bg-slate-50'}`}>
                <div className="flex items-center justify-between gap-3">
                  <p className="font-semibold text-slate-800">Run #{run.run_number} | {run.branch || selectedPipeline?.branch}</p>
                  <Badge value={run.status} />
                </div>
                <p className="mt-1 text-xs text-slate-500">{run.generated_snapshot_version ? `Snapshot v${run.generated_snapshot_version}` : 'No snapshot yet'} | {run.commit_hash}</p>
              </button>
            ))}
            {runs.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-6 text-center text-sm text-slate-400">Chưa có pipeline run</div>}
          </div>

          <div className="mt-5 border-t border-slate-100 pt-4">
            <h4 className="mb-3 text-xs font-bold uppercase text-slate-400">Snapshots</h4>
            <div className="space-y-2">
              {snapshots.map(snapshot => (
                <button key={snapshot.snapshot_id} type="button" onClick={() => setSelectedSnapshotId(snapshot.snapshot_id)} className={`w-full rounded-lg border p-3 text-left text-sm ${selectedSnapshotId === snapshot.snapshot_id ? 'border-emerald-300 bg-emerald-50' : 'border-slate-200 hover:bg-slate-50'}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-800">Snapshot v{snapshot.version_number}</span>
                    <Badge value={snapshot.source_type} />
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-500">{snapshot.snapshot_id}</p>
                </button>
              ))}
              {snapshots.length === 0 && <p className="text-sm text-slate-400">Chưa có snapshot.</p>}
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-800">Pipeline run detail</h3>
              <p className="mt-1 text-xs text-slate-500">{selectedRun ? `${selectedRun.pipeline_name || selectedPipeline?.name} | ${selectedRun.repo_url || selectedPipeline?.repo_url || ''}` : 'Chọn run để xem các bước thực thi'}</p>
            </div>
            {selectedRun && <Badge value={selectedRun.status} />}
          </div>
          {selectedRun?.external_run_url && (
            <a href={selectedRun.external_run_url} target="_blank" rel="noreferrer" className="mb-4 inline-flex items-center gap-1.5 text-xs font-semibold text-sky-600 hover:underline">
              Mở workflow run trên GitHub <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {(selectedRun?.steps || []).map(step => (
              <div key={step.step_id} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    {step.status === 'SUCCESS' ? <CheckCircle2 className="h-4 w-4 flex-none text-emerald-500" /> : step.status === 'FAILED' ? <XCircle className="h-4 w-4 flex-none text-rose-500" /> : <RefreshCw className="h-4 w-4 flex-none text-slate-400" />}
                    <p className="truncate text-sm font-semibold text-slate-800">{step.name}</p>
                  </div>
                  <Badge value={step.status} />
                </div>
                <p className="mt-2 text-xs leading-relaxed text-slate-500">{step.logs || '-'}</p>
              </div>
            ))}
            {!selectedRun && <div className="rounded-lg border border-dashed border-slate-200 p-8 text-sm text-slate-400">Run detail sẽ hiển thị tại đây</div>}
          </div>
        </section>
      </div>

      {selectedSnapshotId && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-800">4. Xem và phân tích SBOM</h3>
              <p className="mt-1 text-xs text-slate-500">Snapshot {selectedSnapshot ? `v${selectedSnapshot.version_number}` : ''} | {selectedSnapshotId}</p>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <span className="rounded-md border border-emerald-100 bg-emerald-50 px-3 py-2 text-emerald-700">Added: {summary?.added ?? 0}</span>
              <span className="rounded-md border border-sky-100 bg-sky-50 px-3 py-2 text-sky-700">Updated: {summary?.updated ?? 0}</span>
              <span className="rounded-md border border-rose-100 bg-rose-50 px-3 py-2 text-rose-700">Removed: {summary?.removed ?? 0}</span>
              <span className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-slate-700">Unchanged: {summary?.unchanged ?? 0}</span>
            </div>
          </div>

          {validation && (
            <div className="mb-4 rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="rounded-lg bg-white p-2 text-emerald-600 ring-1 ring-slate-200">
                    <ShieldCheck className="h-5 w-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900">Kiểm chứng SBOM với mã nguồn</h4>
                    <p className="mt-1 text-xs text-slate-500">So sánh component trong snapshot với dependency files đang lưu của project.</p>
                  </div>
                </div>
                <Badge value={validation.status} />
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                <div className="rounded-md border border-slate-200 bg-white p-3"><p className="text-xs font-semibold uppercase text-slate-400">Compatibility</p><p className="mt-1 text-2xl font-bold text-slate-900">{validation.score}%</p></div>
                <div className="rounded-md border border-slate-200 bg-white p-3"><p className="text-xs font-semibold uppercase text-slate-400">Matched</p><p className="mt-1 text-2xl font-bold text-emerald-600">{validation.matchedCount}/{validation.sourceComponentCount}</p></div>
                <div className="rounded-md border border-slate-200 bg-white p-3"><p className="text-xs font-semibold uppercase text-slate-400">Missing</p><p className="mt-1 text-2xl font-bold text-rose-600">{validation.missingFromSbom.length}</p></div>
                <div className="rounded-md border border-slate-200 bg-white p-3"><p className="text-xs font-semibold uppercase text-slate-400">Extra</p><p className="mt-1 text-2xl font-bold text-amber-600">{validation.extraInSbom.length}</p></div>
              </div>
            </div>
          )}

          <div className="mb-4 overflow-hidden rounded-lg border border-slate-100">
            <div className="max-h-80 overflow-auto">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Change</th>
                    <th className="px-4 py-3">Entity</th>
                    <th className="px-4 py-3">Component</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {changes.map(change => (
                    <tr key={change.change_id || change.entity_key}>
                      <td className="px-4 py-3"><Badge value={change.change_type} /></td>
                      <td className="px-4 py-3 text-slate-600">{change.entity_type}</td>
                      <td className="px-4 py-3 font-medium text-slate-800">{change.component_name || change.entity_key}</td>
                    </tr>
                  ))}
                  {changes.length === 0 && <tr><td colSpan={3} className="px-4 py-8 text-center text-slate-400">Không có change log mới</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
          <SbomDependencyGraph
            graph={graph}
            onSearchChange={setGraphSearch}
            onDepthChange={setGraphDepth}
            onOnlyVulnerableChange={setOnlyVulnerable}
            search={graphSearch}
            depth={graphDepth}
            onlyVulnerable={onlyVulnerable}
          />
        </section>
      )}
    </div>
  );
};

export default DeveloperCicd;

import React, { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, GitBranch, GitMerge, ListChecks, Play, RefreshCw, Server, XCircle } from 'lucide-react';
import SbomDependencyGraph from './SbomDependencyGraph';
import {
  type CicdPipeline,
  type CicdPipelineRun,
  type DevTask,
  type SbomChangeLog,
  type SbomGraphResponse,
} from '../types/sbom';

const API_BASE = 'http://localhost:5000';

type SystemOption = {
  system_id: number;
  name: string;
  description?: string | null;
};

type Props = {
  systems: SystemOption[];
  refreshSystems: () => Promise<void>;
};

const statusClass: Record<string, string> = {
  TODO: 'border-slate-200 bg-slate-50 text-slate-700',
  IN_PROGRESS: 'border-blue-100 bg-blue-50 text-blue-700',
  DONE: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  BLOCKED: 'border-rose-100 bg-rose-50 text-rose-700',
  PENDING: 'border-slate-200 bg-slate-50 text-slate-700',
  RUNNING: 'border-blue-100 bg-blue-50 text-blue-700',
  SUCCESS: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  FAILED: 'border-rose-100 bg-rose-50 text-rose-700',
  CANCELLED: 'border-amber-100 bg-amber-50 text-amber-700',
  MEDIUM: 'border-blue-100 bg-blue-50 text-blue-700',
  LOW: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  HIGH: 'border-amber-100 bg-amber-50 text-amber-700',
};

const Badge = ({ value }: { value?: string | null }) => (
  <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${statusClass[value || ''] || statusClass.PENDING}`}>
    {value || '-'}
  </span>
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
  const [selectedPipelineId, setSelectedPipelineId] = useState<number | null>(null);
  const [selectedRun, setSelectedRun] = useState<CicdPipelineRun | null>(null);
  const [changes, setChanges] = useState<SbomChangeLog[]>([]);
  const [graph, setGraph] = useState<SbomGraphResponse | null>(null);
  const [graphSearch, setGraphSearch] = useState('');
  const [graphDepth, setGraphDepth] = useState(5);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const [taskForm, setTaskForm] = useState({
    title: 'Update axios dependency',
    description: 'Add axios for API client and update dependency manifest.',
    priority: 'MEDIUM',
    assignedTo: 'Developer',
  });
  const [pipelineForm, setPipelineForm] = useState({
    name: 'sbom-incremental-scan',
    branch: 'main',
    provider: 'INTERNAL',
    triggerType: 'MANUAL',
    repoUrl: 'https://github.com/owner/repo.git',
  });

  const selectedProject = systems.find(system => system.system_id === projectId);
  const selectedPipeline = pipelines.find(pipeline => pipeline.pipeline_id === selectedPipelineId) || null;

  useEffect(() => {
    if (!projectId && preferredSystem) setProjectId(preferredSystem.system_id);
  }, [preferredSystem, projectId]);

  const loadProjectData = async (id: number) => {
    const [tasksRes, pipelinesRes] = await Promise.all([
      fetch(`${API_BASE}/api/projects/${id}/tasks`),
      fetch(`${API_BASE}/api/projects/${id}/pipelines`),
    ]);
    const [tasksData, pipelinesData] = await Promise.all([tasksRes.json(), pipelinesRes.json()]);
    setTasks(tasksData);
    setPipelines(pipelinesData);
    const nextPipelineId = pipelinesData[0]?.pipeline_id || null;
    setSelectedPipelineId(current => current || nextPipelineId);
  };

  const loadRuns = async (pipelineId: number) => {
    const res = await fetch(`${API_BASE}/api/pipelines/${pipelineId}/runs`);
    const data = await res.json();
    setRuns(data);
    if (!selectedRun && data[0]) await loadRunDetail(data[0].run_id);
  };

  const loadRunDetail = async (runId: number) => {
    const res = await fetch(`${API_BASE}/api/pipeline-runs/${runId}`);
    const data = await res.json();
    setSelectedRun(data);
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
    setChanges(changesData);
    setGraph(graphData);
  };

  useEffect(() => {
    if (!projectId) return;
    loadProjectData(Number(projectId)).catch(() => setMessage('Không tải được dữ liệu CI/CD'));
  }, [projectId]);

  useEffect(() => {
    if (!selectedPipelineId) {
      setRuns([]);
      return;
    }
    loadRuns(selectedPipelineId).catch(() => setMessage('Không tải được pipeline runs'));
  }, [selectedPipelineId]);

  useEffect(() => {
    const snapshotId = selectedRun?.generated_sbom_snapshot_id;
    if (!snapshotId) {
      setChanges([]);
      setGraph(null);
      return;
    }
    loadSnapshotResult(snapshotId).catch(() => setMessage('Không tải được kết quả SBOM'));
  }, [selectedRun?.generated_sbom_snapshot_id, graphSearch, graphDepth, onlyVulnerable]);

  const ensureDemoProject = async () => {
    setLoading(true);
    setMessage('');
    try {
      const existing = systems.find(system => system.name === 'LaKhe-Management-v2');
      if (existing) {
        setProjectId(existing.system_id);
        return;
      }
      const res = await fetch(`${API_BASE}/api/systems`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'LaKhe-Management-v2',
          description: 'Demo project for CI/CD SBOM pipeline',
        }),
      });
      const data = await res.json();
      await refreshSystems();
      setProjectId(data.system_id);
      setMessage('Đã tạo project demo LaKhe-Management-v2');
    } finally {
      setLoading(false);
    }
  };

  const createTask = async () => {
    if (!projectId) return;
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch(`${API_BASE}/api/projects/${projectId}/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(taskForm),
      });
      if (!res.ok) throw new Error('Create task failed');
      await loadProjectData(Number(projectId));
      setMessage('Đã tạo task phát triển');
    } finally {
      setLoading(false);
    }
  };

  const createPipeline = async () => {
    if (!projectId) return;
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch(`${API_BASE}/api/projects/${projectId}/pipelines`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pipelineForm),
      });
      if (!res.ok) throw new Error('Create pipeline failed');
      const pipeline = await res.json();
      await loadProjectData(Number(projectId));
      setSelectedPipelineId(pipeline.pipeline_id);
      setMessage('Đã tạo pipeline CI/CD');
    } finally {
      setLoading(false);
    }
  };

  const runPipeline = async () => {
    if (!selectedPipelineId) return;
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch(`${API_BASE}/api/pipelines/${selectedPipelineId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ triggeredBy: 'Developer' }),
      });
      if (!res.ok) throw new Error('Run pipeline failed');
      const run = await res.json();
      await loadRuns(selectedPipelineId);
      await loadRunDetail(run.run_id);
      setMessage(`Pipeline run #${run.run_number} hoàn tất với trạng thái ${run.status}`);
    } finally {
      setLoading(false);
    }
  };

  const summary = selectedRun?.snapshot_summary;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 border-b border-slate-200 pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-bold uppercase tracking-wide text-slate-400">Developer CI/CD</p>
          <h2 className="mt-1 text-2xl font-bold text-slate-900">Pipeline tạo SBOM tự động</h2>
          <p className="mt-2 max-w-3xl text-sm text-slate-500">
            Chọn project, tạo task, tạo pipeline, nhập GitHub repo URL, chạy pipeline và xem snapshot/change log/graph được sinh ra.
          </p>
        </div>
        <button
          type="button"
          onClick={ensureDemoProject}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-blue-100 bg-blue-50 px-4 py-2 text-sm font-semibold text-blue-700 hover:bg-blue-100 disabled:opacity-60"
        >
          <Server className="h-4 w-4" />
          Dùng project demo
        </button>
      </div>

      {message && (
        <div className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm font-medium text-blue-700">{message}</div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[340px_1fr]">
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Server className="h-4 w-4 text-blue-500" />
            <h3 className="text-sm font-bold text-slate-800">1. Chọn Project</h3>
          </div>
          <select
            value={projectId}
            onChange={event => {
              setProjectId(Number(event.target.value));
              setSelectedPipelineId(null);
              setSelectedRun(null);
            }}
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
          >
            <option value="">Chọn project</option>
            {systems.map(system => (
              <option key={system.system_id} value={system.system_id}>{system.name}</option>
            ))}
          </select>
          <div className="mt-4 rounded-lg border border-slate-100 bg-slate-50 p-3 text-sm text-slate-600">
            <p className="font-semibold text-slate-800">{selectedProject?.name || 'Chưa chọn project'}</p>
            <p className="mt-1 text-xs">{selectedProject?.description || 'SBOM, task và pipeline sẽ được gắn vào project này.'}</p>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-indigo-500" />
            <h3 className="text-sm font-bold text-slate-800">2. Tạo Task phát triển</h3>
          </div>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_150px_160px_auto]">
            <input
              value={taskForm.title}
              onChange={event => setTaskForm(current => ({ ...current, title: event.target.value }))}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
              placeholder="Task title"
            />
            <select
              value={taskForm.priority}
              onChange={event => setTaskForm(current => ({ ...current, priority: event.target.value }))}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
            >
              <option>LOW</option>
              <option>MEDIUM</option>
              <option>HIGH</option>
            </select>
            <input
              value={taskForm.assignedTo}
              onChange={event => setTaskForm(current => ({ ...current, assignedTo: event.target.value }))}
              className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
              placeholder="Assignee"
            />
            <button
              type="button"
              onClick={createTask}
              disabled={!projectId || loading}
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
            >
              Tạo Task
            </button>
          </div>
          <div className="mt-4 overflow-hidden rounded-lg border border-slate-100">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Task</th>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Assignee</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tasks.map(task => (
                  <tr key={task.task_id}>
                    <td className="px-4 py-3 font-medium text-slate-800">{task.title}</td>
                    <td className="px-4 py-3"><Badge value={task.priority} /></td>
                    <td className="px-4 py-3 text-slate-600">{task.assigned_to || '-'}</td>
                    <td className="px-4 py-3"><Badge value={task.status} /></td>
                  </tr>
                ))}
                {tasks.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-8 text-center text-slate-400">Chưa có task</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-blue-500" />
            <h3 className="text-sm font-bold text-slate-800">3-5. Tạo Pipeline, nhập GitHub Repo URL và Run Pipeline</h3>
          </div>
          <button
            type="button"
            onClick={runPipeline}
            disabled={!selectedPipelineId || loading}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run Pipeline
          </button>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_120px_150px_150px_1.4fr_auto]">
          <input value={pipelineForm.name} onChange={event => setPipelineForm(current => ({ ...current, name: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="Pipeline name" />
          <input value={pipelineForm.branch} onChange={event => setPipelineForm(current => ({ ...current, branch: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="Branch" />
          <select value={pipelineForm.provider} onChange={event => setPipelineForm(current => ({ ...current, provider: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm">
            <option>INTERNAL</option>
            <option>GITHUB_ACTIONS</option>
            <option>JENKINS</option>
            <option>GITLAB_CI</option>
            <option>CIRCLECI</option>
          </select>
          <select value={pipelineForm.triggerType} onChange={event => setPipelineForm(current => ({ ...current, triggerType: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm">
            <option>MANUAL</option>
            <option>PUSH</option>
            <option>PULL_REQUEST</option>
            <option>SCHEDULE</option>
          </select>
          <input value={pipelineForm.repoUrl} onChange={event => setPipelineForm(current => ({ ...current, repoUrl: event.target.value }))} className="rounded-lg border border-slate-200 px-3 py-2 text-sm" placeholder="https://github.com/owner/repo.git" />
          <button type="button" onClick={createPipeline} disabled={!projectId || loading} className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50">
            Tạo Pipeline
          </button>
        </div>
        <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
          {pipelines.map(pipeline => (
            <button
              key={pipeline.pipeline_id}
              type="button"
              onClick={() => setSelectedPipelineId(pipeline.pipeline_id)}
              className={`rounded-lg border p-4 text-left transition ${selectedPipelineId === pipeline.pipeline_id ? 'border-blue-300 bg-blue-50/50' : 'border-slate-200 bg-white hover:bg-slate-50'}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-bold text-slate-800">{pipeline.name}</p>
                  <p className="mt-1 flex items-center gap-1 text-xs text-slate-500"><GitBranch className="h-3.5 w-3.5" /> {pipeline.branch} · {pipeline.provider}</p>
                </div>
                <Badge value={pipeline.latest_status || 'PENDING'} />
              </div>
              <p className="mt-3 truncate text-xs text-slate-500">{pipeline.repo_url || 'No repository URL'}</p>
            </button>
          ))}
          {pipelines.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-6 text-sm text-slate-400">Chưa có pipeline</div>}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[420px_1fr]">
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="mb-4 text-sm font-bold text-slate-800">6. Pipeline Runs</h3>
          <div className="space-y-2">
            {runs.map(run => (
              <button
                key={run.run_id}
                type="button"
                onClick={() => loadRunDetail(run.run_id)}
                className={`w-full rounded-lg border p-3 text-left transition ${selectedRun?.run_id === run.run_id ? 'border-blue-300 bg-blue-50/50' : 'border-slate-200 hover:bg-slate-50'}`}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="font-semibold text-slate-800">Run #{run.run_number} | {run.branch || selectedPipeline?.branch}</p>
                  <Badge value={run.status} />
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  {run.generated_snapshot_version ? `Snapshot v${run.generated_snapshot_version}` : 'No snapshot yet'} · {run.commit_hash}
                </p>
              </button>
            ))}
            {runs.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-8 text-center text-sm text-slate-400">Chưa có pipeline run</div>}
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-800">7. Pipeline Run Detail</h3>
              <p className="mt-1 text-xs text-slate-500">{selectedRun ? `${selectedRun.pipeline_name || selectedPipeline?.name} · ${selectedRun.repo_url || selectedPipeline?.repo_url || ''}` : 'Chọn một run để xem chi tiết'}</p>
            </div>
            {selectedRun && <Badge value={selectedRun.status} />}
          </div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {(selectedRun?.steps || []).map(step => (
              <div key={step.step_id} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {step.status === 'SUCCESS' ? <CheckCircle2 className="h-4 w-4 text-emerald-500" /> : step.status === 'FAILED' ? <XCircle className="h-4 w-4 text-rose-500" /> : <RefreshCw className="h-4 w-4 text-slate-400" />}
                    <p className="text-sm font-semibold text-slate-800">{step.name}</p>
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

      {selectedRun?.generated_sbom_snapshot_id && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-800">8. SBOM Snapshot, Change Log và Graph</h3>
              <p className="mt-1 text-xs text-slate-500">
                Snapshot v{selectedRun.generated_snapshot_version} · {selectedRun.generated_sbom_snapshot_id}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <span className="rounded-md border border-emerald-100 bg-emerald-50 px-3 py-2 text-emerald-700">Added: {summary?.added ?? 0}</span>
              <span className="rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-blue-700">Updated: {summary?.updated ?? 0}</span>
              <span className="rounded-md border border-rose-100 bg-rose-50 px-3 py-2 text-rose-700">Removed: {summary?.removed ?? 0}</span>
              <span className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-slate-700">Unchanged: {summary?.unchanged ?? 0}</span>
            </div>
          </div>
          <div className="mb-4 overflow-hidden rounded-lg border border-slate-100">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500">
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

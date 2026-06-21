import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock3,
  ExternalLink,
  GitBranch,
  RefreshCw,
  Timer,
  XCircle,
} from 'lucide-react';
import { API_BASE_URL } from '../api';

type SystemOption = { system_id: number; name: string };

type MonitoringRun = {
  run_id: number;
  run_number: number;
  pipeline_name: string;
  provider: string;
  status: string;
  branch?: string | null;
  commit_hash?: string | null;
  external_run_url?: string | null;
  event_name?: string | null;
  triggered_by?: string | null;
  duration_ms?: number | null;
  generated_snapshot_version?: number | null;
  created_at: string;
};

type MonitoringResponse = {
  summary: {
    total_runs: number;
    running_runs: number;
    pending_runs: number;
    successful_runs: number;
    failed_runs: number;
    average_duration_ms: number;
    success_rate: string | number;
    last_completed_at?: string | null;
    monitored_projects: number;
  };
  recentRuns: MonitoringRun[];
  trend: Array<{ day: string; total: number; success: number; failed: number }>;
};

const statusClass: Record<string, string> = {
  SUCCESS: 'border-emerald-100 bg-emerald-50 text-emerald-700',
  FAILED: 'border-rose-100 bg-rose-50 text-rose-700',
  RUNNING: 'border-sky-100 bg-sky-50 text-sky-700',
  PENDING: 'border-amber-100 bg-amber-50 text-amber-700',
  CANCELLED: 'border-slate-200 bg-slate-50 text-slate-600',
};

const formatDuration = (value?: number | null) => {
  const milliseconds = Number(value || 0);
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${(milliseconds / 60_000).toFixed(1)} min`;
};

const formatDate = (value?: string | null) => value
  ? new Date(value).toLocaleString('vi-VN')
  : '-';

const CicdMonitoring = ({ systems }: { systems: SystemOption[] }) => {
  const [projectId, setProjectId] = useState('');
  const [data, setData] = useState<MonitoringResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError('');
    try {
      const query = projectId ? `?projectId=${encodeURIComponent(projectId)}` : '';
      const response = await fetch(`${API_BASE_URL}/api/cicd/monitoring${query}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.message || payload.error || 'Không tải được dữ liệu giám sát.');
      setData(payload);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Không tải được dữ liệu giám sát.');
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => load(true), 15_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);

  const maxTrend = useMemo(
    () => Math.max(1, ...(data?.trend || []).map(item => Number(item.total))),
    [data]
  );
  const summary = data?.summary;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-5">
        <div>
          <p className="text-xs font-bold uppercase tracking-wide text-slate-400">GitHub Actions observability</p>
          <h2 className="mt-1 text-2xl font-bold text-slate-900 dark:text-slate-100">Giám sát CI/CD và SBOM</h2>
          <p className="mt-2 text-sm text-slate-500">Theo dõi workflow run thật, commit, thời gian chạy và snapshot SBOM nhận từ GitHub.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={projectId} onChange={event => setProjectId(event.target.value)} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
            <option value="">Tất cả project</option>
            {systems.map(system => <option key={system.system_id} value={system.system_id}>{system.name}</option>)}
          </select>
          <label className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 dark:border-slate-700 dark:text-slate-300">
            <input type="checkbox" checked={autoRefresh} onChange={event => setAutoRefresh(event.target.checked)} />
            Tự làm mới 15 giây
          </label>
          <button type="button" onClick={() => load()} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-700">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Làm mới
          </button>
        </div>
      </div>

      {error && <div className="rounded-lg border border-rose-100 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {[
          { label: 'Tổng số run', value: summary?.total_runs || 0, icon: Activity, color: 'text-indigo-500' },
          { label: 'Đang chạy / chờ', value: `${summary?.running_runs || 0} / ${summary?.pending_runs || 0}`, icon: RefreshCw, color: 'text-sky-500' },
          { label: 'Thành công', value: summary?.successful_runs || 0, icon: CheckCircle2, color: 'text-emerald-500' },
          { label: 'Thất bại', value: summary?.failed_runs || 0, icon: XCircle, color: 'text-rose-500' },
          { label: 'Tỷ lệ thành công', value: `${Number(summary?.success_rate || 0).toFixed(1)}%`, icon: Timer, color: 'text-amber-500' },
        ].map(card => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between"><p className="text-xs font-bold uppercase text-slate-400">{card.label}</p><card.icon className={`h-5 w-5 ${card.color}`} /></div>
            <p className="mt-3 text-2xl font-bold text-slate-900 dark:text-slate-100">{card.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_320px]">
        <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
            <div><h3 className="font-bold text-slate-800 dark:text-slate-100">Workflow runs gần nhất</h3><p className="mt-1 text-xs text-slate-500">Dữ liệu đồng bộ từ callback và webhook GitHub Actions</p></div>
            <span className="text-xs text-slate-400">TB {formatDuration(summary?.average_duration_ms)}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 dark:bg-slate-950/60"><tr><th className="px-5 py-3">Pipeline</th><th className="px-4 py-3">Run</th><th className="px-4 py-3">Commit</th><th className="px-4 py-3">Trạng thái</th><th className="px-4 py-3">Thời gian</th><th className="px-4 py-3">SBOM</th></tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {(data?.recentRuns || []).map(run => (
                  <tr key={run.run_id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40">
                    <td className="px-5 py-3"><p className="font-semibold text-slate-800 dark:text-slate-100">{run.pipeline_name}</p><p className="mt-1 text-xs text-slate-400">{run.provider} · {run.event_name || 'manual'}</p></td>
                    <td className="px-4 py-3">{run.external_run_url ? <a href={run.external_run_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold text-sky-600 hover:underline">#{run.run_number}<ExternalLink className="h-3.5 w-3.5" /></a> : `#${run.run_number}`}</td>
                    <td className="px-4 py-3"><p className="flex items-center gap-1 text-xs text-slate-600 dark:text-slate-300"><GitBranch className="h-3.5 w-3.5" />{run.branch || '-'}</p><p className="mt-1 font-mono text-xs text-slate-400">{run.commit_hash?.slice(0, 8) || '-'}</p></td>
                    <td className="px-4 py-3"><span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${statusClass[run.status] || statusClass.PENDING}`}>{run.status}</span></td>
                    <td className="px-4 py-3"><p className="text-xs text-slate-600 dark:text-slate-300">{formatDuration(run.duration_ms)}</p><p className="mt-1 text-xs text-slate-400">{formatDate(run.created_at)}</p></td>
                    <td className="px-4 py-3 text-xs text-slate-600 dark:text-slate-300">{run.generated_snapshot_version ? `Snapshot v${run.generated_snapshot_version}` : 'Chưa nhận'}</td>
                  </tr>
                ))}
                {!data?.recentRuns?.length && <tr><td colSpan={6} className="px-5 py-12 text-center text-slate-400">Chưa có workflow run nào.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 className="font-bold text-slate-800 dark:text-slate-100">Xu hướng 14 ngày</h3>
          <p className="mt-1 text-xs text-slate-500">Run thành công và thất bại theo ngày</p>
          <div className="mt-5 space-y-3">
            {(data?.trend || []).map(item => (
              <div key={item.day}>
                <div className="mb-1 flex justify-between text-xs"><span className="text-slate-500">{item.day}</span><span className="font-semibold text-slate-700 dark:text-slate-300">{item.total}</span></div>
                <div className="flex h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" style={{ width: `${Math.max(12, (item.total / maxTrend) * 100)}%` }}>
                  <div className="bg-emerald-500" style={{ width: `${item.total ? (item.success / item.total) * 100 : 0}%` }} />
                  <div className="bg-rose-500" style={{ width: `${item.total ? (item.failed / item.total) * 100 : 0}%` }} />
                </div>
              </div>
            ))}
            {!data?.trend?.length && <div className="py-10 text-center text-sm text-slate-400">Chưa đủ dữ liệu xu hướng.</div>}
          </div>
          <div className="mt-6 border-t border-slate-100 pt-4 text-xs text-slate-500 dark:border-slate-800">
            <p className="flex items-center gap-2"><Clock3 className="h-4 w-4" />Run hoàn tất gần nhất: {formatDate(summary?.last_completed_at)}</p>
            <p className="mt-2">Đang giám sát {summary?.monitored_projects || 0} project.</p>
          </div>
        </section>
      </div>
    </div>
  );
};

export default CicdMonitoring;

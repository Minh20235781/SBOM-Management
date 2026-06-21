import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Clock3, RefreshCw, ShieldAlert } from 'lucide-react';
import { API_BASE } from '../api';
import type { CicdPipeline, CicdPipelineRun } from '../types/sbom';

type SystemOption = { system_id: number; name: string };
type Props = {
  systems: SystemOption[];
  onOpenPipeline: (pipeline: CicdPipeline) => void;
};

type PipelineObservation = { pipeline: CicdPipeline; runs: CicdPipelineRun[]; latest?: CicdPipelineRun };
type Recommendation = { id: string; level: 'CRITICAL' | 'WARNING' | 'INFO'; title: string; detail: string; pipeline: CicdPipeline };
const UI_TRIGGER_SOURCE = 'SBOM_MANAGEMENT_UI';

const panel = 'rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900';
const statusTone: Record<string, string> = {
  SUCCESS: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300',
  RUNNING: 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-300',
  FAILED: 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300',
  PENDING: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300',
};

const Status = ({ value }: { value: string }) => <span className={`inline-flex whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-bold ${statusTone[value] || statusTone.PENDING}`}>{value}</span>;
const formatDate = (value?: string | null) => value ? new Date(value).toLocaleString('vi-VN') : 'Chưa chạy';

export default function PipelineMonitoring({ systems, onOpenPipeline }: Props) {
  const [observations, setObservations] = useState<PipelineObservation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const pipelineResponses = await Promise.all(systems.map(async system => {
        const response = await fetch(`${API_BASE}/projects/${system.system_id}/pipelines`);
        if (!response.ok) throw new Error(`Không tải được pipeline của ${system.name}`);
        const data = await response.json();
        return Array.isArray(data) ? data as CicdPipeline[] : [];
      }));
      const livePipelines = pipelineResponses.flat();
      const data = await Promise.all(livePipelines.map(async pipeline => {
        const response = await fetch(`${API_BASE}/pipelines/${pipeline.pipeline_id}/runs`);
        if (!response.ok) throw new Error(`Không tải được run của ${pipeline.name}`);
        const runs = await response.json();
        const normalizedRuns: CicdPipelineRun[] = Array.isArray(runs)
          ? runs.filter(run => run.triggered_by === UI_TRIGGER_SOURCE)
          : [];
        if (normalizedRuns.length === 0) return null;
        return { pipeline, runs: normalizedRuns, latest: normalizedRuns[0] } as PipelineObservation;
      }));
      setObservations(data.filter((item): item is PipelineObservation => item !== null));
      setLastUpdated(new Date());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Không tải được dữ liệu giám sát pipeline.');
    } finally {
      setLoading(false);
    }
  }, [systems]);

  useEffect(() => {
    const initialRefresh = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 15000);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(timer);
    };
  }, [refresh]);

  const recommendations = useMemo<Recommendation[]>(() => observations.flatMap(({ pipeline, latest }) => {
    if (!latest) return [];
    if (latest.status === 'FAILED') return [{ id: `failed-${latest.run_id}`, level: 'CRITICAL', title: `Run #${latest.run_number} thất bại`, detail: 'Mở pipeline, kiểm tra bước FAILED và log lỗi trước khi chạy lại.', pipeline }];
    if (latest.status === 'RUNNING' || latest.status === 'PENDING') return [{ id: `active-${latest.run_id}`, level: 'INFO', title: `Run #${latest.run_number} đang xử lý`, detail: 'Hệ thống sẽ tự làm mới sau 15 giây. Không cần tạo run trùng lặp.', pipeline }];
    const suggestions: Recommendation[] = [];
    if ((latest.vulnerability_count || 0) > 0) suggestions.push({ id: `vuln-${latest.run_id}`, level: 'CRITICAL', title: `${latest.vulnerability_count} lỗ hổng cần xem xét`, detail: 'Ưu tiên package Critical/High, kiểm tra fixed version rồi cập nhật dependency.', pipeline });
    if (!latest.generated_sbom_snapshot_id) suggestions.push({ id: `snapshot-${latest.run_id}`, level: 'WARNING', title: 'Run chưa tạo được snapshot SBOM', detail: 'Kiểm tra Syft, quyền truy cập repository và bước lưu SBOM.', pipeline });
    const validation = latest.validation_report;
    if (validation && validation.status !== 'PASS') suggestions.push({ id: `validation-${latest.run_id}`, level: 'WARNING', title: `Độ tương thích SBOM: ${validation.score}%`, detail: 'Đối chiếu component thiếu, thừa hoặc sai phiên bản trong báo cáo validation.', pipeline });
    return suggestions;
  }), [observations]);

  const totalRuns = observations.reduce((sum, item) => sum + item.runs.length, 0);
  const successful = observations.filter(item => item.latest?.status === 'SUCCESS').length;
  const failed = observations.filter(item => item.latest?.status === 'FAILED').length;
  const running = observations.filter(item => ['RUNNING', 'PENDING'].includes(item.latest?.status || '')).length;

  return <div className="space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-5 dark:border-slate-800"><div><h2 className="text-2xl font-bold text-slate-900 dark:text-white">Giám sát CI/CD</h2><p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Dữ liệu trực tiếp từ pipeline run, snapshot, validation và kết quả quét lỗ hổng.</p></div><button type="button" onClick={refresh} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Làm mới</button></div>
    {error && <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">{error}</div>}
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[['Pipeline đã chạy', observations.length], ['Tổng số run', totalRuns], ['Run thành công', successful], ['Đang chạy / lỗi', `${running} / ${failed}`]].map(([label, value]) => <div key={label} className={panel}><p className="text-xs font-bold uppercase text-slate-400">{label}</p><p className="mt-2 text-3xl font-bold text-slate-900 dark:text-white">{value}</p></div>)}</div>
    <section className={panel}><div className="mb-4 flex items-center justify-between gap-3"><h3 className="flex items-center gap-2 font-bold text-slate-900 dark:text-white"><Activity className="h-5 w-5 text-blue-500" />Trạng thái pipeline</h3><span className="text-xs text-slate-400">{lastUpdated ? `Cập nhật ${lastUpdated.toLocaleTimeString('vi-VN')}` : 'Đang tải...'}</span></div><div className="grid gap-3 lg:grid-cols-2">{observations.map(({ pipeline, latest }) => <button type="button" key={pipeline.pipeline_id} onClick={() => onOpenPipeline(pipeline)} className="rounded-lg border border-slate-200 p-4 text-left transition hover:border-blue-300 hover:bg-blue-50/40 dark:border-slate-700 dark:hover:border-blue-800 dark:hover:bg-blue-950/20"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate font-bold text-slate-800 dark:text-slate-100">{pipeline.name}</p><p className="mt-1 truncate text-xs text-slate-500">{pipeline.repo_url || 'Chưa cấu hình repository'}</p></div><Status value={latest?.status || 'PENDING'} /></div><div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-500"><span>Provider: {pipeline.provider}</span><span>Branch: {latest?.branch || pipeline.branch}</span><span>Run: {latest ? `#${latest.run_number}` : '-'}</span><span>{formatDate(latest?.started_at)}</span><span>Component: {latest?.component_count || 0}</span><span>Lỗ hổng: {latest?.vulnerability_count || 0}</span></div></button>)}{!loading && observations.length === 0 && <p className="col-span-full py-10 text-center text-sm text-slate-400">Chưa có pipeline để giám sát.</p>}</div></section>
    <section className={panel}><h3 className="mb-4 flex items-center gap-2 font-bold text-slate-900 dark:text-white"><ShieldAlert className="h-5 w-5 text-red-500" />Đề xuất từ kết quả chạy gần nhất</h3><div className="space-y-3">{recommendations.map(item => <button type="button" key={item.id} onClick={() => onOpenPipeline(item.pipeline)} className={`flex w-full items-start gap-3 rounded-lg border p-4 text-left ${item.level === 'CRITICAL' ? 'border-red-200 bg-red-50/70 dark:border-red-900 dark:bg-red-950/30' : item.level === 'WARNING' ? 'border-amber-200 bg-amber-50/70 dark:border-amber-900 dark:bg-amber-950/30' : 'border-blue-200 bg-blue-50/70 dark:border-blue-900 dark:bg-blue-950/30'}`}>{item.level === 'CRITICAL' ? <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" /> : item.level === 'WARNING' ? <Clock3 className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" /> : <Activity className="mt-0.5 h-5 w-5 shrink-0 text-blue-500" />}<div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="font-bold text-slate-800 dark:text-slate-100">{item.title}</p><span className="rounded-full border border-current px-2 py-0.5 text-[10px] font-bold">{item.level}</span></div><p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{item.detail}</p><p className="mt-2 text-xs font-semibold text-slate-400">{item.pipeline.name}</p></div></button>)}{observations.length === 0 ? <p className="py-10 text-center text-sm text-slate-400">Chưa có dữ liệu. Hãy bấm Run pipeline để bắt đầu giám sát.</p> : recommendations.length === 0 && <div className="flex items-center gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300"><CheckCircle2 className="h-5 w-5" /><p className="text-sm font-semibold">Các pipeline gần nhất đang ổn định và chưa có đề xuất ưu tiên.</p></div>}</div></section>
    <p className="text-xs text-slate-400">Đang theo dõi {systems.length} hệ thống · tự làm mới mỗi 15 giây.</p>
  </div>;
}

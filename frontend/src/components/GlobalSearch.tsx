import { useEffect, useMemo, useRef, useState } from 'react';
import { GitMerge, Search, Server, ShieldAlert } from 'lucide-react';
import type { BackendVulnerability, CicdPipeline } from '../types/sbom';

type SystemResult = { system_id: number; name: string; description?: string | null };
type SearchResult =
  | { key: string; type: 'SYSTEM'; title: string; subtitle: string; system: SystemResult }
  | { key: string; type: 'CVE'; title: string; subtitle: string; vulnerability: BackendVulnerability }
  | { key: string; type: 'PIPELINE'; title: string; subtitle: string; pipeline: CicdPipeline };

type Props = {
  systems: SystemResult[];
  vulnerabilities: BackendVulnerability[];
  pipelines: CicdPipeline[];
  onSelectSystem: (system: SystemResult) => void;
  onSelectVulnerability: (vulnerability: BackendVulnerability) => void;
  onSelectPipeline: (pipeline: CicdPipeline) => void;
};

const typeLabel = { SYSTEM: 'Hệ thống', CVE: 'CVE', PIPELINE: 'Pipeline' } as const;

const ResultIcon = ({ type }: { type: SearchResult['type'] }) => {
  if (type === 'CVE') return <ShieldAlert className="h-4 w-4 text-red-500" />;
  if (type === 'PIPELINE') return <GitMerge className="h-4 w-4 text-sky-500" />;
  return <Server className="h-4 w-4 text-indigo-500" />;
};

export default function GlobalSearch({ systems, vulnerabilities, pipelines, onSelectSystem, onSelectVulnerability, onSelectPipeline }: Props) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const results = useMemo<SearchResult[]>(() => {
    const normalized = query.trim().toLowerCase();
    const matches = (values: Array<string | null | undefined>) => !normalized || values.some(value => value?.toLowerCase().includes(normalized));
    const systemResults: SearchResult[] = systems.filter(system => matches([system.name, system.description])).map(system => ({ key: `system-${system.system_id}`, type: 'SYSTEM', title: system.name, subtitle: system.description || `System #${system.system_id}`, system }));
    const vulnerabilityResults: SearchResult[] = vulnerabilities.filter(item => matches([item.cve_id, item.vulnerability, item.name, item.severity])).map(vulnerability => ({ key: `cve-${vulnerability.vuln_id}`, type: 'CVE', title: vulnerability.cve_id || vulnerability.vulnerability || `Vulnerability #${vulnerability.vuln_id}`, subtitle: `${vulnerability.name || 'Unknown component'} · ${vulnerability.severity || 'UNKNOWN'}`, vulnerability }));
    const pipelineResults: SearchResult[] = pipelines.filter(item => matches([item.name, item.provider, item.repo_url, item.branch])).map(pipeline => ({ key: `pipeline-${pipeline.pipeline_id}`, type: 'PIPELINE', title: pipeline.name, subtitle: `${pipeline.provider} · ${pipeline.branch}`, pipeline }));
    return [...systemResults, ...vulnerabilityResults, ...pipelineResults].slice(0, 10);
  }, [pipelines, query, systems, vulnerabilities]);

  useEffect(() => {
    const closeOnOutsideClick = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', closeOnOutsideClick);
    return () => document.removeEventListener('mousedown', closeOnOutsideClick);
  }, []);

  const selectResult = (result: SearchResult) => {
    if (result.type === 'SYSTEM') onSelectSystem(result.system);
    if (result.type === 'CVE') onSelectVulnerability(result.vulnerability);
    if (result.type === 'PIPELINE') onSelectPipeline(result.pipeline);
    setQuery('');
    setOpen(false);
  };

  return (
    <div ref={containerRef} className="relative w-full max-w-sm lg:max-w-md">
      <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
      <input type="search" value={query} onChange={event => { setQuery(event.target.value); setOpen(true); }} onFocus={() => setOpen(true)} onKeyDown={event => { if (event.key === 'Escape') setOpen(false); if (event.key === 'Enter' && results[0]) selectResult(results[0]); }} placeholder="Tìm hệ thống, CVE, pipeline..." aria-label="Tìm kiếm toàn hệ thống" aria-expanded={open} className="w-full rounded-full border border-slate-200 bg-slate-50 py-2 pl-10 pr-4 text-sm outline-none transition-all placeholder:text-slate-400 focus:border-blue-300 focus:bg-white focus:ring-2 focus:ring-blue-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:focus:bg-slate-900 dark:focus:ring-blue-900/50" />
      {open && <div className="absolute left-0 right-0 top-[calc(100%+8px)] z-50 max-h-96 overflow-y-auto rounded-xl border border-slate-200 bg-white p-2 shadow-xl dark:border-slate-700 dark:bg-slate-900">
        {results.map(result => <button key={result.key} type="button" onClick={() => selectResult(result)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition hover:bg-slate-50 focus:bg-blue-50 focus:outline-none dark:hover:bg-slate-800 dark:focus:bg-slate-800"><span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800"><ResultIcon type={result.type} /></span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-semibold text-slate-800 dark:text-slate-100">{result.title}</span><span className="block truncate text-xs text-slate-500">{result.subtitle}</span></span><span className="rounded-full bg-slate-100 px-2 py-1 text-[10px] font-bold uppercase text-slate-500 dark:bg-slate-800">{typeLabel[result.type]}</span></button>)}
        {results.length === 0 && <p className="px-3 py-8 text-center text-sm text-slate-400">Không tìm thấy kết quả phù hợp.</p>}
        {!query.trim() && results.length > 0 && <p className="border-t border-slate-100 px-3 pt-2 text-[11px] text-slate-400 dark:border-slate-800">Nhập từ khóa hoặc chọn một gợi ý gần đây.</p>}
      </div>}
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { GitBranchPlus, RefreshCw } from 'lucide-react';
import SbomDependencyGraph from './SbomDependencyGraph';
import { type SbomChangeLog, type SbomGraphResponse, type SbomSnapshot } from '../types/sbom';
import { API_BASE_URL } from '../api';

const API_BASE = API_BASE_URL;

type Props = {
  systems: Array<{ system_id: number; name: string }>;
};

const badgeClass: Record<string, string> = {
  ADDED: 'bg-emerald-50 text-emerald-700 border-emerald-100',
  UPDATED: 'bg-blue-50 text-blue-700 border-blue-100',
  REMOVED: 'bg-rose-50 text-rose-700 border-rose-100',
  UNCHANGED: 'bg-slate-50 text-slate-600 border-slate-100',
};

const SbomSnapshots: React.FC<Props> = ({ systems }) => {
  const [projectId, setProjectId] = useState<number | ''>(systems[0]?.system_id || '');
  const [snapshots, setSnapshots] = useState<SbomSnapshot[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState('');
  const [changes, setChanges] = useState<SbomChangeLog[]>([]);
  const [graph, setGraph] = useState<SbomGraphResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [depth, setDepth] = useState(1);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [artifactMessage, setArtifactMessage] = useState<string | null>(null);
  const selectedSnapshot = snapshots.find(snapshot => snapshot.snapshot_id === selectedSnapshotId);

  useEffect(() => {
    if (!projectId && systems[0]?.system_id) setProjectId(systems[0].system_id);
  }, [systems, projectId]);

  const loadSnapshots = async (id = projectId) => {
    if (!id) return;
    const res = await fetch(`${API_BASE}/api/projects/${id}/sbom/snapshots`);
    const data = await res.json();
    setSnapshots(data);
    if (data[0]?.snapshot_id) setSelectedSnapshotId(data[0].snapshot_id);
  };

  const runIncremental = async () => {
    if (!projectId) return;
    setRunning(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/projects/${projectId}/sbom/incremental-generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ artifactName: 'latest-imported-sbom' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || 'Generate failed');
      await loadSnapshots(projectId);
      setSelectedSnapshotId(data.snapshotId);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Generate failed';
      setError(message);
      alert(message);
    } finally {
      setRunning(false);
    }
  };

  const uploadDependencyFilesAndGenerate = async (files: FileList | null) => {
    if (!projectId || !files || files.length === 0) return;
    setRunning(true);
    setError(null);
    setArtifactMessage(null);
    try {
      const dependencyFiles = await Promise.all(
        Array.from(files).map(async file => ({
          artifactPath: file.webkitRelativePath || file.name,
          artifactName: file.name,
          artifactType: file.name,
          content: await file.text(),
        }))
      );
      const res = await fetch(`${API_BASE}/api/projects/${projectId}/sbom/auto-generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dependencyFiles }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || 'Auto generate failed');
      await loadSnapshots(projectId);
      if (data.snapshotId) setSelectedSnapshotId(data.snapshotId);
      setArtifactMessage(data.skipped ? data.reason : `Auto-generated ${data.mode}: ${dependencyFiles.length} artifact file(s) scanned.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Auto generate failed';
      setError(message);
      alert(message);
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    loadSnapshots();
  }, [projectId]);

  useEffect(() => {
    if (!selectedSnapshotId) {
      setChanges([]);
      setGraph(null);
      return;
    }

    let cancelled = false;
    const load = async () => {
      setLoadingGraph(true);
      try {
        const query = new URLSearchParams({
          depth: String(depth),
          onlyVulnerable: String(onlyVulnerable),
          search,
        });
        const [changesRes, graphRes] = await Promise.all([
          fetch(`${API_BASE}/api/sbom/snapshots/${selectedSnapshotId}/changes`),
          fetch(`${API_BASE}/api/sbom/snapshots/${selectedSnapshotId}/graph?${query.toString()}`),
        ]);
        const [changesData, graphData] = await Promise.all([changesRes.json(), graphRes.json()]);
        if (cancelled) return;
        setChanges(changesData);
        setGraph(graphData);
      } finally {
        if (!cancelled) setLoadingGraph(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [selectedSnapshotId, depth, onlyVulnerable, search]);

  const summary = selectedSnapshot?.summary;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 flex-1">
            <label className="text-sm text-slate-600">
              Dự án / Hệ thống
              <select
                value={projectId}
                onChange={event => setProjectId(Number(event.target.value))}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-sm"
              >
                <option value="">Chọn hệ thống</option>
                {systems.map(system => (
                  <option key={system.system_id} value={system.system_id}>{system.name}</option>
                ))}
              </select>
            </label>
            <label className="text-sm text-slate-600">
              Phiên bản snapshot
              <select
                value={selectedSnapshotId}
                onChange={event => setSelectedSnapshotId(event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-sm"
              >
                <option value="">Chưa có snapshot</option>
                {snapshots.map(snapshot => (
                  <option key={snapshot.snapshot_id} value={snapshot.snapshot_id}>
                    v{snapshot.version_number} · {snapshot.source_type}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <button
            type="button"
            onClick={runIncremental}
            disabled={!projectId || running}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm disabled:opacity-60"
          >
            {running ? <RefreshCw className="h-4 w-4 animate-spin" /> : <GitBranchPlus className="h-4 w-4" />}
            Tạo SBOM tự động
          </button>
        </div>
        <div className="mt-4 rounded-xl border border-blue-100 bg-blue-50/60 p-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div>
              <p className="font-semibold text-slate-800 text-sm">SBOM tự động sinh từ trạng thái dự án</p>
              <p className="text-xs text-slate-500 mt-1">
                Tải lên các file quản lý package như package.json, package-lock.json, requirements.txt, pom.xml, build.gradle, Dockerfile. Backend sẽ quét các file này, tạo dấu vân tay (fingerprint) và chỉ tạo snapshot mới khi có thay đổi.
              </p>
            </div>
            <label className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white shadow-sm cursor-pointer">
              Tải lên file phụ thuộc
              <input
                type="file"
                multiple
                className="hidden"
                accept=".json,.txt,.xml,.gradle,.lock,.yaml,.yml,Dockerfile"
                onChange={event => {
                  uploadDependencyFilesAndGenerate(event.target.files);
                  event.target.value = '';
                }}
              />
            </label>
          </div>
          {artifactMessage && (
            <div className="mt-3 rounded-lg border border-emerald-100 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
              {artifactMessage}
            </div>
          )}
        </div>
        {error && (
          <div className="mt-4 rounded-lg border border-rose-100 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        )}
        {!error && projectId && snapshots.length === 0 && (
          <div className="mt-4 rounded-lg border border-amber-100 bg-amber-50 px-4 py-3 text-sm text-amber-800">
            Chưa có snapshot cho hệ thống này. Hãy upload SBOM với đúng system name trước, sau đó bấm Generate Incremental SBOM.
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          ['Tổng thành phần', summary?.totalComponents || 0, 'text-slate-800'],
          ['Đã thêm', summary?.added || 0, 'text-emerald-600'],
          ['Đã cập nhật', summary?.updated || 0, 'text-blue-600'],
          ['Đã xóa', summary?.removed || 0, 'text-rose-600'],
          ['Giữ nguyên', summary?.unchanged || 0, 'text-slate-500'],
        ].map(([label, value, color]) => (
          <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs uppercase tracking-wide text-slate-500 font-bold">{label}</p>
            <p className={`mt-2 text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 font-bold text-slate-800">Nhật ký thay đổi</div>
        <div className="overflow-auto max-h-80">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-50 text-xs uppercase text-slate-500">
              <tr>
                <th className="text-left px-4 py-3">Loại</th>
                <th className="text-left px-4 py-3">Thực thể</th>
                <th className="text-left px-4 py-3">Thành phần</th>
                <th className="text-left px-4 py-3">Khóa</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {changes.length === 0 ? (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-slate-400">Chưa có change log.</td></tr>
              ) : changes.map((change, index) => (
                <tr key={change.change_id || index}>
                  <td className="px-4 py-3"><span className={`rounded-full border px-2 py-1 text-xs font-semibold ${badgeClass[change.change_type]}`}>{change.change_type}</span></td>
                  <td className="px-4 py-3">{change.entity_type}</td>
                  <td className="px-4 py-3">{change.component_name || '-'}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 break-all">{change.entity_key}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <SbomDependencyGraph
        graph={graph}
        loading={loadingGraph}
        search={search}
        depth={depth}
        onlyVulnerable={onlyVulnerable}
        onSearchChange={setSearch}
        onDepthChange={setDepth}
        onOnlyVulnerableChange={setOnlyVulnerable}
      />
    </div>
  );
};

export default SbomSnapshots;

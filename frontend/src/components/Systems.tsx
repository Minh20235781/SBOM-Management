import React, { useMemo, useState } from 'react';

type System = {
  system_id: number;
  name: string;
  description?: string | null;
  created_timestamp?: string | null;
  last_uploaded_at?: string | null;
  latest_sbom_timestamp?: string | null;
  sbom_count?: number;
};

type SystemDetail = {
  system: System;
  sboms: Array<{
    sbom_id: string;
    created_timestamp?: string | null;
    tool_components?: string | null;
    component_count: number;
    dependency_count: number;
    vulnerability_count: number;
  }>;
  snapshots: Array<{
    snapshot_id: string;
    version_number: number;
    source_type: string;
    created_at: string;
  }>;
  unlinkedSboms?: Array<{
    sbom_id: string;
    created_timestamp?: string | null;
    tool_components?: string | null;
  }>;
};

type Props = {
  systems: System[];
  refresh: () => void;
  onDelete?: (system_id: number) => void | Promise<void>;
  onViewDetail?: (system: System) => void;
};

const Systems: React.FC<Props> = ({ systems, refresh, onDelete, onViewDetail }) => {
  const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://localhost:5000';
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [nameFilter, setNameFilter] = useState('');
  const [createdDateFilter, setCreatedDateFilter] = useState('');
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');
  const [detail, setDetail] = useState<SystemDetail | null>(null);
  const [detailLoadingId, setDetailLoadingId] = useState<number | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [selectedUnlinkedSbomId, setSelectedUnlinkedSbomId] = useState('');
  const [linkingSbom, setLinkingSbom] = useState(false);

  const formatDateTimeVN = (value?: string | null) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString('vi-VN');
  };

  const getDisplayTimestamp = (system: System) =>
    system.latest_sbom_timestamp || system.last_uploaded_at || null;

  const getLocalDateKey = (value?: string | null) => {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  };

  const filteredSystems = useMemo(() => {
    const normalizedName = nameFilter.trim().toLowerCase();
    return [...systems]
      .filter(system => {
        const matchesName = !normalizedName || system.name.toLowerCase().includes(normalizedName);
        const matchesDate = !createdDateFilter || getLocalDateKey(getDisplayTimestamp(system)) === createdDateFilter;
        return matchesName && matchesDate;
      })
      .sort((left, right) => {
        const leftDate = new Date(getDisplayTimestamp(left) || 0).getTime() || 0;
        const rightDate = new Date(getDisplayTimestamp(right) || 0).getTime() || 0;
        return sortOrder === 'newest' ? rightDate - leftDate : leftDate - rightDate;
      });
  }, [systems, nameFilter, createdDateFilter, sortOrder]);

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshError(null);
    try {
      await refresh();
    } catch (e: unknown) {
      setRefreshError(e instanceof Error ? e.message : 'Không thể làm mới dữ liệu');
    } finally {
      setRefreshing(false);
    }
  };

  const handleViewDetail = async (id: number) => {
    const selected = systems.find(system => system.system_id === id);
    if (selected && onViewDetail) {
      onViewDetail(selected);
      return;
    }
    setDetailLoadingId(id);
    setDetailError(null);
    try {
      const res = await fetch(`${API_BASE}/api/systems/${id}/detail`);
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(body?.error || body?.message || `HTTP ${res.status}`);
      setDetail(body);
      setSelectedUnlinkedSbomId(body?.unlinkedSboms?.[0]?.sbom_id || '');
    } catch (e: unknown) {
      setDetailError(e instanceof Error ? e.message : 'Không thể tải chi tiết hệ thống');
    } finally {
      setDetailLoadingId(null);
    }
  };

  const handleLinkExistingSbom = async () => {
    if (!detail || !selectedUnlinkedSbomId) return;
    setLinkingSbom(true);
    setDetailError(null);
    try {
      const res = await fetch(`${API_BASE}/api/systems/${detail.system.system_id}/link-sbom`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sbomId: selectedUnlinkedSbomId }),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(body?.error || body?.message || `HTTP ${res.status}`);
      await refresh();
      await handleViewDetail(detail.system.system_id);
    } catch (e: unknown) {
      setDetailError(e instanceof Error ? e.message : 'Khong the gan SBOM');
    } finally {
      setLinkingSbom(false);
    }
  };

  const handleDeleteClick = (id: number, name: string) => {
    const confirmed = window.confirm(`Bạn có chắc chắn muốn xóa hệ thống "${name}" cùng toàn bộ dữ liệu SBOM liên quan không?`);
    if (!confirmed) return;
    (async () => {
      setDeleteError(null);
      if (onDelete) {
        try {
          setDeletingId(id);
          await onDelete(id);
          await refresh();
        } catch (e: unknown) {
          setDeleteError(e instanceof Error ? e.message : 'Không thể xóa hệ thống');
        } finally {
          setDeletingId(null);
        }
        return;
      }

      setDeletingId(id);
      try {
        const res = await fetch(`${API_BASE}/api/systems/${id}`, { method: 'DELETE' });
        if (!res.ok) {
          const body = await res.json().catch(() => null);
          throw new Error(body?.error || `HTTP ${res.status}`);
        }
        if (detail?.system.system_id === id) setDetail(null);
        await refresh();
      } catch (e: unknown) {
        setDeleteError(e instanceof Error ? e.message : 'Không thể xóa hệ thống');
      } finally {
        setDeletingId(null);
      }
    })();
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-bold text-slate-800">Danh sách hệ thống</h3>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-200 bg-blue-50 text-blue-700 text-sm font-medium shadow-sm hover:shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${refreshing ? 'bg-amber-400 animate-pulse' : 'bg-emerald-500'}`} />
          {refreshing ? 'Đang làm mới...' : 'Làm mới'}
        </button>
      </div>

      <div className="mb-4 rounded-lg border border-slate-100 bg-slate-50 px-4 py-3 text-sm text-slate-600">
        Mỗi hệ thống có thể gắn nhiều SBOM. Cột "Số SBOM" cho biết dữ liệu SBOM đã thực sự được gắn với hệ thống đó.
      </div>

      {refreshError && <div className="text-sm text-red-600 mb-4">{refreshError}</div>}
      {deleteError && <div className="text-sm text-red-600 mb-4">{deleteError}</div>}
      {detailError && <div className="text-sm text-red-600 mb-4">{detailError}</div>}

      <div className="mb-4 grid grid-cols-1 lg:grid-cols-12 gap-3 items-end">
        <div className="lg:col-span-5">
          <label className="block text-xs font-medium text-slate-500 mb-1">Lọc theo tên</label>
          <input value={nameFilter} onChange={event => setNameFilter(event.target.value)} placeholder="Nhập tên hệ thống..." className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100" />
        </div>
        <div className="lg:col-span-4">
          <label className="block text-xs font-medium text-slate-500 mb-1">Lọc theo lần tải lên</label>
          <input type="date" value={createdDateFilter} onChange={event => setCreatedDateFilter(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100 text-slate-600" />
        </div>
        <div className="lg:col-span-3">
          <label className="block text-xs font-medium text-slate-500 mb-1">Sắp xếp theo</label>
          <select value={sortOrder} onChange={event => setSortOrder(event.target.value as 'newest' | 'oldest')} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100">
            <option value="newest">Mới nhất</option>
            <option value="oldest">Cũ nhất</option>
          </select>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <span className="rounded-full bg-slate-100 px-3 py-1">Tổng: {systems.length}</span>
        <span className="rounded-full bg-blue-50 px-3 py-1 text-blue-700">Đang hiển thị: {filteredSystems.length}</span>
        {(nameFilter || createdDateFilter) && (
          <button type="button" onClick={() => { setNameFilter(''); setCreatedDateFilter(''); }} className="rounded-full bg-rose-50 px-3 py-1 text-rose-700 hover:bg-rose-100 transition">Xóa bộ lọc</button>
        )}
      </div>

      <div className="overflow-auto max-h-[480px] rounded-xl border border-slate-100">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 text-slate-500 text-xs uppercase tracking-wider font-semibold border-b border-slate-200">
            <tr>
              <th className="px-4 py-3">Tên hệ thống</th>
              <th className="px-4 py-3">Số SBOM</th>
              <th className="px-4 py-3">Lần tải lên gần nhất</th>
              <th className="px-4 py-3 text-center w-64">Hành động</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {filteredSystems.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-slate-400">Không có hệ thống nào.</td></tr>
            ) : filteredSystems.map(system => (
              <tr key={system.system_id} className="hover:bg-slate-50/50">
                <td className="px-4 py-3 font-medium text-slate-800">{system.name}</td>
                <td className="px-4 py-3 text-slate-700">{system.sbom_count ?? 0}</td>
                <td className="px-4 py-3 text-slate-700">{formatDateTimeVN(getDisplayTimestamp(system))}</td>
                <td className="px-4 py-3 text-center whitespace-nowrap">
                  <button type="button" onClick={() => handleViewDetail(system.system_id)} disabled={detailLoadingId === system.system_id} className="mr-2 inline-flex items-center justify-center px-3 py-1 text-xs font-semibold text-blue-600 border border-blue-200 rounded-lg bg-white hover:bg-blue-50 hover:text-blue-700 active:bg-blue-100 transition shadow-sm outline-none disabled:opacity-60">
                    {detailLoadingId === system.system_id ? 'Đang tải...' : 'Chi tiết'}
                  </button>
                  <button type="button" onClick={() => handleDeleteClick(system.system_id, system.name)} disabled={deletingId === system.system_id} className={`inline-flex items-center justify-center px-3 py-1 text-xs font-semibold text-rose-600 border border-rose-200 rounded-lg bg-white hover:bg-rose-50 hover:text-rose-700 active:bg-rose-100 transition shadow-sm outline-none ${deletingId === system.system_id ? 'opacity-60 cursor-not-allowed' : ''}`}>
                    {deletingId === system.system_id ? 'Đang xóa...' : 'Xóa'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {detail && (
        <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50/70 p-5">
          <div className="flex items-start justify-between gap-4 mb-4">
              <div>
              <h4 className="font-bold text-slate-800">Chi tiết hệ thống: {detail.system.name}</h4>
              <p className="text-sm text-slate-500 mt-1">ID {detail.system.system_id} - Lần tải lên gần nhất: {formatDateTimeVN(detail.system.latest_sbom_timestamp || detail.system.last_uploaded_at)}</p>
            </div>
            <button type="button" onClick={() => setDetail(null)} className="rounded-lg border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-100">Đóng</button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-5">
            <div className="rounded-lg border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-400">SBOM đã gắn</p><p className="mt-2 text-2xl font-bold text-slate-800">{detail.sboms.length}</p></div>
            <div className="rounded-lg border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-400">Snapshot</p><p className="mt-2 text-2xl font-bold text-blue-600">{detail.snapshots.length}</p></div>
            <div className="rounded-lg border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-400">Tổng component</p><p className="mt-2 text-2xl font-bold text-emerald-600">{detail.sboms.reduce((sum, sbom) => sum + Number(sbom.component_count || 0), 0)}</p></div>
          </div>

          <div className="mb-5 rounded-xl border border-blue-100 bg-blue-50/60 p-4">
            <div className="flex flex-col lg:flex-row lg:items-end gap-3">
              <label className="flex-1 text-sm text-slate-700">
                Gắn SBOM có sẵn chưa thuộc hệ thống nào
                <select value={selectedUnlinkedSbomId} onChange={event => setSelectedUnlinkedSbomId(event.target.value)} className="mt-1 w-full rounded-lg border border-blue-200 bg-white px-3 py-2 text-sm">
                  <option value="">Không có SBOM chưa gắn</option>
                  {(detail.unlinkedSboms || []).map(sbom => (
                    <option key={sbom.sbom_id} value={sbom.sbom_id}>{sbom.sbom_id} - {formatDateTimeVN(sbom.created_timestamp)}</option>
                  ))}
                </select>
              </label>
              <button type="button" onClick={handleLinkExistingSbom} disabled={!selectedUnlinkedSbomId || linkingSbom} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm disabled:opacity-60">
                {linkingSbom ? 'Đang gắn...' : 'Gắn vào hệ thống'}
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white overflow-auto max-h-80">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-white text-xs uppercase text-slate-500 border-b border-slate-200">
                <tr><th className="px-4 py-3">SBOM ID</th><th className="px-4 py-3">Thời gian tạo</th><th className="px-4 py-3">Components</th><th className="px-4 py-3">Dependencies</th><th className="px-4 py-3">Vulnerabilities</th><th className="px-4 py-3">Tool</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {detail.sboms.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-400">Chưa có SBOM nào được gắn với hệ thống này.</td></tr>
                ) : detail.sboms.map(sbom => (
                  <tr key={sbom.sbom_id}>
                    <td className="px-4 py-3 font-mono text-xs text-slate-500 max-w-[260px] truncate" title={sbom.sbom_id}>{sbom.sbom_id}</td>
                    <td className="px-4 py-3 text-slate-700">{formatDateTimeVN(sbom.created_timestamp)}</td>
                    <td className="px-4 py-3">{sbom.component_count}</td>
                    <td className="px-4 py-3">{sbom.dependency_count}</td>
                    <td className="px-4 py-3">{sbom.vulnerability_count}</td>
                    <td className="px-4 py-3 text-slate-500 max-w-[220px] truncate" title={sbom.tool_components || ''}>{sbom.tool_components || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Systems;

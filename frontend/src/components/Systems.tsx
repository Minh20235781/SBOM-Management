import React, { useMemo, useState } from 'react';

type System = {
  system_id: number;
  name: string;
  description?: string;
  created_timestamp?: string;
};

type Props = {
  systems: System[];
  refresh: () => void;
  onDelete?: (system_id: number) => void | Promise<void>; // Thêm hàm callback xử lý sự kiện xóa từ component cha
};


const Systems: React.FC<Props> = ({ systems, refresh, onDelete }) => {
  const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://localhost:5000';
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [nameFilter, setNameFilter] = useState('');
  const [createdDateFilter, setCreatedDateFilter] = useState('');
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');

  const formatDateTimeVN = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString('vi-VN');
  };

  const getLocalDateKey = (value?: string) => {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  const filteredSystems = useMemo(() => {
    const normalizedName = nameFilter.trim().toLowerCase();

    return [...systems]
      .filter(system => {
        const matchesName = !normalizedName || system.name.toLowerCase().includes(normalizedName);
        const matchesDate = !createdDateFilter || getLocalDateKey(system.created_timestamp) === createdDateFilter;
        
        return matchesName && matchesDate;
      })
      .sort((left, right) => {
        const leftId = Number(left.system_id) || 0;
        const rightId = Number(right.system_id) || 0;
        return sortOrder === 'newest' ? rightId - leftId : leftId - rightId;
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

  const handleDeleteClick = (id: number, name: string) => {
    const confirmed = window.confirm(`Bạn có chắc chắn muốn xóa hệ thống "${name}" cùng toàn bộ dữ liệu SBOM liên quan không?`);
    if (!confirmed) return;
    // Prefer parent callback if provided, otherwise call API directly
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
          throw new Error((body && body.error) ? body.error : `HTTP ${res.status}`);
        }
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
        <h3 className="font-bold text-slate-800">Danh sách Hệ thống</h3>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-200 bg-gradient-to-r from-blue-50 to-indigo-50 text-blue-700 text-sm font-medium shadow-sm hover:shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${refreshing ? 'bg-amber-400 animate-pulse' : 'bg-emerald-500'}`} />
            {refreshing ? 'Đang làm mới...' : 'Làm mới'}
          </button>
        </div>
      </div>
      <div className="mb-4 rounded-lg border border-slate-100 bg-slate-50 px-4 py-3 text-sm text-slate-600">
        Danh sách này được tự động tạo từ SBOM đã tải lên.
      </div>
      {refreshError && <div className="text-sm text-red-600 mb-4">{refreshError}</div>}
      {deleteError && <div className="text-sm text-red-600 mb-4">{deleteError}</div>}

      <div className="mb-4 grid grid-cols-1 lg:grid-cols-12 gap-3 items-end">
        <div className="lg:col-span-5">
          <label className="block text-xs font-medium text-slate-500 mb-1">Lọc theo tên</label>
          <input
            value={nameFilter}
            onChange={event => setNameFilter(event.target.value)}
            placeholder="Nhập tên hệ thống..."
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
          />
        </div>
        <div className="lg:col-span-4">
          <label className="block text-xs font-medium text-slate-500 mb-1">Lọc theo ngày tải lên</label>
          <input
            type="date"
            value={createdDateFilter}
            onChange={event => setCreatedDateFilter(event.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100 text-slate-600"
          />
        </div>
        <div className="lg:col-span-3">
          <label className="block text-xs font-medium text-slate-500 mb-1">Sắp xếp theo</label>
          <select
            value={sortOrder}
            onChange={event => setSortOrder(event.target.value as 'newest' | 'oldest')}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
          >
            <option value="newest">Mới nhất</option>
            <option value="oldest">Cũ nhất</option>
          </select>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <span className="rounded-full bg-slate-100 px-3 py-1">Tổng: {systems.length}</span>
        <span className="rounded-full bg-blue-50 px-3 py-1 text-blue-700">Đang hiển thị: {filteredSystems.length}</span>
        {(nameFilter || createdDateFilter) && (
          <button
            type="button"
            onClick={() => {
              setNameFilter('');
              setCreatedDateFilter('');
            }}
            className="rounded-full bg-rose-50 px-3 py-1 text-rose-700 hover:bg-rose-100 transition"
          >
            Xóa bộ lọc
          </button>
        )}
      </div>

      {systems.length === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-dashed border-slate-200 rounded-xl bg-slate-50/60">
          Chưa có hệ thống nào. Tải lên SBOM với tên hệ thống để tạo.
        </div>
      ) : filteredSystems.length === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-dashed border-slate-200 rounded-xl bg-slate-50/60">
          Không có hệ thống nào khớp bộ lọc hiện tại.
        </div>
      ) : (
        <div className="overflow-auto max-h-[480px] rounded-xl border border-slate-100">
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 text-slate-500 text-xs uppercase tracking-wider font-semibold border-b border-slate-200">
              <tr>
                <th className="px-4 py-3 w-16">ID</th>
                <th className="px-4 py-3">Tên hệ thống</th>
                <th className="px-4 py-3">Ngày tải lên</th>
                <th className="px-4 py-3 text-center w-56">Hành động</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredSystems.map(s => (
                <tr key={s.system_id} className="hover:bg-slate-50/50">
                  <td className="px-4 py-3 font-mono text-slate-700">{s.system_id}</td>
                  <td className="px-4 py-3 font-medium text-slate-800">{s.name}</td>
                  <td className="px-4 py-3 text-slate-700">{formatDateTimeVN(s.created_timestamp)}</td>
                  <td className="px-4 py-3 text-center">
                    <button
                      type="button"
                      onClick={() => handleDeleteClick(s.system_id, s.name)}
                      disabled={deletingId === s.system_id}
                      className={`inline-flex items-center justify-center px-3 py-1 text-xs font-semibold text-rose-600 border border-rose-200 rounded-lg bg-white hover:bg-rose-50 hover:text-rose-700 active:bg-rose-100 transition shadow-sm outline-none ${deletingId === s.system_id ? 'opacity-60 cursor-not-allowed' : ''}`}
                    >
                      {deletingId === s.system_id ? 'Đang xóa...' : 'Xóa'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Systems;
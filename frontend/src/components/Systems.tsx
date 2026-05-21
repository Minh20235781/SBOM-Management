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
};

const Systems: React.FC<Props> = ({ systems, refresh }) => {
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
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

  const parseDDMMYYYYToKey = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return '';
    const match = trimmed.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (!match) return '__invalid__';
    const [, day, month, year] = match;
    return `${year}-${month}-${day}`;
  };

  const filteredSystems = useMemo(() => {
    const normalizedName = nameFilter.trim().toLowerCase();
    const normalizedDateKey = parseDDMMYYYYToKey(createdDateFilter);
    const shouldApplyDateFilter = normalizedDateKey !== '' && normalizedDateKey !== '__invalid__';

    return [...systems]
      .filter(system => {
        const matchesName = !normalizedName || system.name.toLowerCase().includes(normalizedName);
        const matchesDate = !createdDateFilter || (shouldApplyDateFilter && getLocalDateKey(system.created_timestamp) === normalizedDateKey);
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
          <label className="block text-xs font-medium text-slate-500 mb-1">Lọc theo ngày tạo</label>
          <input
            type="text"
            value={createdDateFilter}
            onChange={event => setCreatedDateFilter(event.target.value)}
            placeholder="dd/mm/yyyy"
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
          />
        </div>
        <div className="lg:col-span-3">
          <label className="block text-xs font-medium text-slate-500 mb-1">Sắp xếp theo ID</label>
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
          Chưa có hệ thống nào. Tải lên SBOM với tên hệ thống để tạo, hoặc dùng form trên để thêm.
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
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredSystems.map(s => (
                <tr key={s.system_id} className="hover:bg-slate-50/50">
                  <td className="px-4 py-3 font-mono text-slate-700">{s.system_id}</td>
                  <td className="px-4 py-3 font-medium text-slate-800">{s.name}</td>
                  <td className="px-4 py-3 text-slate-700">{s.description || '-'}</td>
                  <td className="px-4 py-3 text-slate-700">{formatDateTimeVN(s.created_timestamp)}</td>
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

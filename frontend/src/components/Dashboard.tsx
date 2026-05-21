import React, { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';

const API_BASE = 'http://localhost:5000/api';

const sparklineData1 = [ { value: 20 }, { value: 25 }, { value: 22 }, { value: 30 }, { value: 28 }, { value: 45 }, { value: 75 }, { value: 70 } ];
const sparklineData2 = [ { value: 5 }, { value: 5 }, { value: 10 }, { value: 15 }, { value: 12 }, { value: 20 }, { value: 25 }, { value: 29 } ];
const sparklineData3 = [ { value: 100 }, { value: 120 }, { value: 110 }, { value: 150 }, { value: 140 }, { value: 250 }, { value: 350 }, { value: 790 } ];
const sparklineData4 = [ { value: 5000 }, { value: 5200 }, { value: 5100 }, { value: 5800 }, { value: 6000 }, { value: 15000 }, { value: 22000 }, { value: 41978 } ];

const policyData = [
  { name: '1', value: 0 }, { name: '2', value: 0 }, { name: '3', value: 0 }, { name: '4', value: 1 }
];

type SbomMeta = { sbom_id: string } & Record<string, any>;
type SystemRecord = {
  system_id: number;
  name: string;
  description?: string | null;
  created_timestamp?: string | null;
};

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [sboms, setSboms] = useState<SbomMeta[]>([]);
  const [systems, setSystems] = useState<SystemRecord[]>([]);
  const [chartData, setChartData] = useState<Array<{ name: string; vulnerabilities: number; sboms: number }>>([]);
  const [totalVulns, setTotalVulns] = useState(0);
  const [projectsAtRisk, setProjectsAtRisk] = useState(0);
  const [vulnerableComponents, setVulnerableComponents] = useState(0);
  const [inheritedRisk, setInheritedRisk] = useState(0);

  const formatDateTimeVN = (value?: string | null) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString('vi-VN');
  };

  const formatDateKeyVN = (value?: string | null) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '-';
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  };

  useEffect(() => {
    let cancelled = false;

    const fetchData = async () => {
      try {
        const [sbomRes, systemRes] = await Promise.all([
          fetch(`${API_BASE}/sboms`),
          fetch(`${API_BASE}/systems`),
        ]);

        if (!sbomRes.ok) throw new Error('Failed to fetch sboms');
        if (!systemRes.ok) throw new Error('Failed to fetch systems');

        const [meta, systemsData] = await Promise.all([
          sbomRes.json(),
          systemRes.json(),
        ]);
        if (cancelled) return;
        setSboms(meta);
        setSystems(systemsData);

        // Fetch vulnerabilities/components per SBOM in parallel
        const vulnPromises = meta.map((s: SbomMeta) => fetch(`${API_BASE}/sboms/${encodeURIComponent(s.sbom_id)}/vulnerabilities`).then(r => r.json()).catch(() => []));
        const compPromises = meta.map((s: SbomMeta) => fetch(`${API_BASE}/sboms/${encodeURIComponent(s.sbom_id)}/components`).then(r => r.json()).catch(() => []));

        const vulnsBySbom = await Promise.all(vulnPromises);
        const compsBySbom = await Promise.all(compPromises);
        if (cancelled) return;

        // total vulnerabilities
        const total = vulnsBySbom.reduce((acc: number, arr: any[]) => acc + (Array.isArray(arr) ? arr.length : 0), 0);
        setTotalVulns(total);

        const chartBuckets = new Map<string, { date: string; vulnerabilities: number; sboms: number; sortKey: number }>();
        meta.forEach((sbom: SbomMeta, index: number) => {
          const sbomDate = sbom.created_timestamp ? new Date(sbom.created_timestamp) : null;
          if (!sbomDate || Number.isNaN(sbomDate.getTime())) return;
          const sortKey = new Date(sbomDate.getFullYear(), sbomDate.getMonth(), sbomDate.getDate()).getTime();
          const dateLabel = formatDateKeyVN(sbom.created_timestamp);
          const key = `${sortKey}-${dateLabel}`;
          const vulnCount = Array.isArray(vulnsBySbom[index]) ? vulnsBySbom[index].length : 0;
          const current = chartBuckets.get(key) || { date: dateLabel, vulnerabilities: 0, sboms: 0, sortKey };
          current.vulnerabilities += vulnCount;
          current.sboms += 1;
          chartBuckets.set(key, current);
        });

        const sortedBuckets = [...chartBuckets.values()].sort((left, right) => left.sortKey - right.sortKey);
        let cumulativeVulnerabilities = 0;
        let cumulativeSboms = 0;
        const liveChartData = sortedBuckets.map(bucket => {
          cumulativeVulnerabilities += bucket.vulnerabilities;
          cumulativeSboms += bucket.sboms;
          return {
            name: bucket.date,
            vulnerabilities: cumulativeVulnerabilities,
            sboms: cumulativeSboms,
          };
        });
        setChartData(liveChartData);

        // projects at risk = number of sboms with >=1 vuln
        const projects = vulnsBySbom.reduce((acc: number, arr: any[]) => acc + (Array.isArray(arr) && arr.length > 0 ? 1 : 0), 0);
        setProjectsAtRisk(projects);

        // vulnerable components = unique affected_component_ref from all vulnerabilities
        const compSet = new Set<string>();
        vulnsBySbom.forEach((arr: any[]) => {
          if (Array.isArray(arr)) {
            arr.forEach(v => { if (v && v.affected_component_ref) compSet.add(v.affected_component_ref); });
          }
        });
        // fallback: if no affected_component_ref, count unique component ids from components list
        if (compSet.size === 0) {
          const allCompIds = new Set<string>();
          compsBySbom.forEach((arr: any[]) => { if (Array.isArray(arr)) arr.forEach(c => { if (c && c.component_id) allCompIds.add(c.component_id); }); });
          setVulnerableComponents(allCompIds.size);
        } else {
          setVulnerableComponents(compSet.size);
        }

        // inherited risk = sum of numeric risk values across all vulnerabilities
        let riskSum = 0;
        vulnsBySbom.forEach((arr: any[]) => {
          if (Array.isArray(arr)) {
            arr.forEach(v => {
              const r = v && v.risk ? Number(v.risk) : 0;
              if (!Number.isNaN(r)) riskSum += r;
            });
          }
        });
        setInheritedRisk(Math.round(riskSum));

      } catch (err) {
        console.error('Dashboard data error', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchData();
    return () => { cancelled = true; };
  }, []);

  if (loading) return <div>Đang tải dashboard...</div>;

  const recentSystems = [...systems].sort((left, right) => (Number(right.system_id) || 0) - (Number(left.system_id) || 0)).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* 1. Header Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Lỗ hổng của toàn bộ danh mục</p>
            <p className="text-3xl font-bold text-slate-800">{totalVulns.toLocaleString()}</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData1}>
                <Line type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Dự án có rủi ro</p>
            <p className="text-3xl font-bold text-slate-800">{projectsAtRisk}</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData2}>
                <Line type="monotone" dataKey="value" stroke="#a855f7" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Thành phần dễ bị tấn công</p>
            <p className="text-3xl font-bold text-slate-800">{vulnerableComponents}</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData3}>
                <Line type="monotone" dataKey="value" stroke="#6366f1" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Điểm rủi ro kế thừa</p>
            <p className="text-3xl font-bold text-slate-800">{inheritedRisk.toLocaleString()}</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData4}>
                <Line type="monotone" dataKey="value" stroke="#f43f5e" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Hệ thống</p>
            <p className="text-3xl font-bold text-slate-800">{systems.length}</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData2}>
                <Line type="monotone" dataKey="value" stroke="#0f766e" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 2. Main Chart Section */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        <h3 className="font-bold text-slate-800 text-lg mb-1">Lỗ hổng của toàn bộ danh mục</h3>
        <p className="text-xs text-slate-500 mb-6">Lần đo gần nhất: 27/12/2020 lúc 22:25:38</p>
        
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorVulnerabilities" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorSboms" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
              <XAxis dataKey="name" tick={{fontSize: 12, fill: '#64748b'}} tickMargin={10} axisLine={false} tickLine={false} />
              <YAxis tick={{fontSize: 12, fill: '#64748b'}} axisLine={false} tickLine={false} />
              <Tooltip cursor={{stroke: '#cbd5e1', strokeWidth: 1, strokeDasharray: '3 3'}} contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'}} />
              <Area type="monotone" dataKey="vulnerabilities" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorVulnerabilities)" />
              <Area type="monotone" dataKey="sboms" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#colorSboms)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Stats below Main Chart */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 pt-6 border-t border-slate-100">
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Dự án có lỗ hổng</p>
            <p className="text-2xl font-bold text-slate-800">{projectsAtRisk}</p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-emerald-500 h-1 rounded-full" style={{ width: '100%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Vi phạm đã kiểm tra</p>
            <p className="text-2xl font-bold text-slate-800">0 <span className="text-sm font-normal text-slate-500">(0%)</span></p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-slate-300 h-1 rounded-full" style={{ width: '0%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Thành phần có lỗ hổng</p>
            <p className="text-2xl font-bold text-slate-800">{vulnerableComponents}</p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-amber-500 h-1 rounded-full" style={{ width: '100%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Phát hiện đã kiểm tra</p>
            <p className="text-2xl font-bold text-slate-800">0 <span className="text-sm font-normal text-slate-500">(0%)</span></p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-slate-300 h-1 rounded-full" style={{ width: '0%' }}></div></div>
          </div>
        </div>
      </div>

      {/* 3. Bottom Section (2 Columns) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Recent Systems */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-2">Hệ thống gần đây</h3>
          <p className="text-xs text-slate-500 mb-4">Các hệ thống vừa được tạo từ SBOM upload</p>
          <div className="space-y-3 max-h-56 overflow-auto pr-1">
            {recentSystems.length === 0 ? (
              <div className="text-sm text-slate-400 py-10 text-center border border-dashed border-slate-200 rounded-xl bg-slate-50/60">
                Chưa có hệ thống nào.
              </div>
            ) : (
              recentSystems.map(system => (
                <div key={system.system_id} className="flex items-center justify-between rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                  <div>
                    <p className="font-semibold text-slate-800">{system.name}</p>
                    <p className="text-xs text-slate-500">ID: {system.system_id} · {formatDateTimeVN(system.created_timestamp)}</p>
                  </div>
                  <div className="text-xs text-slate-500 max-w-[40%] truncate text-right">
                    {system.description || 'Không có mô tả'}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Auditing Progress */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-6">Tiến độ kiểm tra</h3>
          <div className="h-40 w-full relative">
             <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <YAxis tick={{fontSize: 10, fill: '#64748b'}} axisLine={false} tickLine={false} />
               <Line type="monotone" dataKey="vulnerabilities" stroke="#64748b" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
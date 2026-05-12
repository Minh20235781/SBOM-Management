import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';

const sparklineData1 = [ { value: 20 }, { value: 25 }, { value: 22 }, { value: 30 }, { value: 28 }, { value: 45 }, { value: 75 }, { value: 70 } ];
const sparklineData2 = [ { value: 5 }, { value: 5 }, { value: 10 }, { value: 15 }, { value: 12 }, { value: 20 }, { value: 25 }, { value: 29 } ];
const sparklineData3 = [ { value: 100 }, { value: 120 }, { value: 110 }, { value: 150 }, { value: 140 }, { value: 250 }, { value: 350 }, { value: 790 } ];
const sparklineData4 = [ { value: 5000 }, { value: 5200 }, { value: 5100 }, { value: 5800 }, { value: 6000 }, { value: 15000 }, { value: 22000 }, { value: 41978 } ];

const mainChartData = [
  { name: '28 Nov', projects: 10, components: 20 },
  { name: '29 Nov', projects: 15, components: 35 },
  { name: '02 Dec', projects: 12, components: 30 },
  { name: '05 Dec', projects: 40, components: 120 },
  { name: '08 Dec', projects: 10, components: 25 },
  { name: '12 Dec', projects: 20, components: 40 },
  { name: '16 Dec', projects: 80, components: 450 },
  { name: '20 Dec', projects: 85, components: 460 },
  { name: '27 Dec', projects: 90, components: 500 },
];

const policyData = [
  { name: '1', value: 0 }, { name: '2', value: 0 }, { name: '3', value: 0 }, { name: '4', value: 1 }
];

const Dashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* 1. Header Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between h-36 relative overflow-hidden">
          <div className="z-10">
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Portfolio Vulnerabilities</p>
            <p className="text-3xl font-bold text-slate-800">7,249</p>
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
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Projects at Risk</p>
            <p className="text-3xl font-bold text-slate-800">29</p>
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
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Vulnerable Components</p>
            <p className="text-3xl font-bold text-slate-800">790</p>
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
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Inherited Risk Score</p>
            <p className="text-3xl font-bold text-slate-800">41,978</p>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-16 opacity-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparklineData4}>
                <Line type="monotone" dataKey="value" stroke="#f43f5e" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 2. Main Chart Section */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        <h3 className="font-bold text-slate-800 text-lg mb-1">Portfolio Vulnerabilities</h3>
        <p className="text-xs text-slate-500 mb-6">Last Measurement: 27 Dec 2020 at 22:25:38</p>
        
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={mainChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorProjects" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorComponents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
              <XAxis dataKey="name" tick={{fontSize: 12, fill: '#64748b'}} tickMargin={10} axisLine={false} tickLine={false} />
              <YAxis tick={{fontSize: 12, fill: '#64748b'}} axisLine={false} tickLine={false} />
              <Tooltip cursor={{stroke: '#cbd5e1', strokeWidth: 1, strokeDasharray: '3 3'}} contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'}} />
              <Area type="monotone" dataKey="projects" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorProjects)" />
              <Area type="monotone" dataKey="components" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#colorComponents)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Stats below Main Chart */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 pt-6 border-t border-slate-100">
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Vulnerable Projects</p>
            <p className="text-2xl font-bold text-slate-800">29</p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-emerald-500 h-1 rounded-full" style={{ width: '100%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Violations Audited</p>
            <p className="text-2xl font-bold text-slate-800">0 <span className="text-sm font-normal text-slate-500">(0%)</span></p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-slate-300 h-1 rounded-full" style={{ width: '0%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Vulnerable Components</p>
            <p className="text-2xl font-bold text-slate-800">790</p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-amber-500 h-1 rounded-full" style={{ width: '100%' }}></div></div>
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-slate-600 mb-1">Findings Audited</p>
            <p className="text-2xl font-bold text-slate-800">0 <span className="text-sm font-normal text-slate-500">(0%)</span></p>
            <div className="w-full bg-slate-100 rounded-full h-1 mt-2"><div className="bg-slate-300 h-1 rounded-full" style={{ width: '0%' }}></div></div>
          </div>
        </div>
      </div>

      {/* 3. Bottom Section (2 Columns) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Policy Violations */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-6">Policy Violations</h3>
          <div className="h-40 w-full relative">
             <ResponsiveContainer width="100%" height="100%">
              <LineChart data={policyData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                 <YAxis tick={{fontSize: 10, fill: '#64748b'}} axisLine={false} tickLine={false} tickCount={3} />
                <Line type="stepAfter" dataKey="value" stroke="#ef4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Auditing Progress */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-6">Auditing Progress</h3>
          <div className="h-40 w-full relative">
             <ResponsiveContainer width="100%" height="100%">
              <LineChart data={mainChartData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <YAxis tick={{fontSize: 10, fill: '#64748b'}} axisLine={false} tickLine={false} />
               <Line type="monotone" dataKey="projects" stroke="#64748b" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
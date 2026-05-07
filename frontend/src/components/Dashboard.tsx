import React from 'react';
import { Activity, ShieldCheck, Server, AlertTriangle, GitMerge, FileKey } from 'lucide-react';

const Dashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* 1. Header Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
          <div className="p-3 bg-blue-50 text-blue-600 rounded-lg">
            <Server className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Tổng hệ thống</p>
            <p className="text-2xl font-bold text-slate-800">42</p>
          </div>
        </div>
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
          <div className="p-3 bg-emerald-50 text-emerald-600 rounded-lg">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Mức độ tuân thủ</p>
            <p className="text-2xl font-bold text-slate-800">94%</p>
          </div>
        </div>
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
          <div className="p-3 bg-red-50 text-red-600 rounded-lg">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Lỗ hổng (Nghiêm trọng)</p>
            <p className="text-2xl font-bold text-slate-800">12</p>
          </div>
        </div>
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
          <div className="p-3 bg-purple-50 text-purple-600 rounded-lg">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Quét tự động hôm nay</p>
            <p className="text-2xl font-bold text-slate-800">1,208</p>
          </div>
        </div>
      </div>

      {/* 2. Charts / Metrics section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Phân bổ lỗ hổng theo Environment */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-6 flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-500" /> Tình trạng theo Môi trường
          </h3>
          <div className="space-y-5">
            <div>
              <div className="flex justify-between text-sm mb-2"><span className="text-slate-600 font-medium">Production</span><span className="font-bold text-slate-700">18 Rủi ro cao</span></div>
              <div className="w-full bg-slate-100 rounded-full h-2"><div className="bg-red-500 h-2 rounded-full" style={{ width: '15%' }}></div></div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2"><span className="text-slate-600 font-medium">Staging</span><span className="font-bold text-slate-700">45 Rủi ro cao</span></div>
              <div className="w-full bg-slate-100 rounded-full h-2"><div className="bg-amber-400 h-2 rounded-full" style={{ width: '30%' }}></div></div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2"><span className="text-slate-600 font-medium">Development</span><span className="font-bold text-slate-700">92 Rủi ro cao</span></div>
              <div className="w-full bg-slate-100 rounded-full h-2"><div className="bg-amber-300 h-2 rounded-full" style={{ width: '50%' }}></div></div>
            </div>
          </div>
        </div>

        {/* Hoạt động gần đây */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="font-bold text-slate-800 mb-6 flex items-center gap-2">
            <GitMerge className="w-4 h-4 text-emerald-500" /> Hoạt động Pipeline
          </h3>
          <div className="space-y-4">
            <div className="flex items-start gap-4">
              <div className="w-8 h-8 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-800">Quét SBOM hoàn tất: frontend-service</p>
                <p className="text-xs text-slate-500 mt-1">Không phát hiện CVE mới. ✓</p>
                <p className="text-xs text-slate-400 mt-1">10 phút trước</p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <div className="w-8 h-8 rounded-full bg-red-100 text-red-600 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-800">Phát hiện Rủi ro: payment-gateway</p>
                <p className="text-xs text-slate-500 mt-1">CVE-2024-3094 phát hiện trong nhánh staging.</p>
                <p className="text-xs text-slate-400 mt-1">2 giờ trước</p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <div className="w-8 h-8 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
                <FileKey className="w-4 h-4" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-800">Cập nhật License: auth-service</p>
                <p className="text-xs text-slate-500 mt-1">Đã phê duyệt ngoại lệ sử dụng GPL-3.0.</p>
                <p className="text-xs text-slate-400 mt-1">1 ngày trước</p>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
import React, { useState, useRef } from 'react';
import { Upload, FileCode, Shield } from 'lucide-react';

const API_BASE = 'http://localhost:5000/api';

// VỊ TRÍ 1: Định nghĩa interface cho Props ngay trên đầu component
interface Props {
  onUploadSuccess: (data: Record<string, unknown>) => void;
}

// VỊ TRÍ 2: Thêm kiểu React.FC<Props> và destructure prop vào tham số của function
const SBOMUpload: React.FC<Props> = ({ onUploadSuccess }) => {
  const [fileName, setFileName] = useState<string | null>(null);
  const [systemName, setSystemName] = useState<string>('');
  const [savingSystem, setSavingSystem] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFileName(file.name);
      const reader = new FileReader();

      reader.onload = (event) => {
        try {
          const json = JSON.parse(event.target?.result as string);
          console.log("Dữ liệu SBOM nhận được:", json);

          // Gọi hàm callback để truyền dữ liệu ngược về App.tsx kèm tên system nếu nhập
          onUploadSuccess({ sbom: json, systemName: systemName && systemName.trim() ? systemName.trim() : undefined });

        } catch (err) {
          console.error("Lỗi phân tích file SBOM:", err);
          alert("File không đúng định dạng JSON chuẩn!");
        }
      };
      reader.readAsText(file);
    }
  };

  const triggerFileSelect = () => fileInputRef.current?.click();

  const saveSystem = async () => {
    const name = systemName?.trim();
    if (!name) { setSaveMsg('Tên hệ thống trống'); return; }
    setSavingSystem(true); setSaveMsg(null);
    try {
      const res = await fetch(`${API_BASE}/systems`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      const raw = await res.text();
      let json: { error?: string; message?: string; system_id?: number } = {};
      if (raw) {
        try {
          json = JSON.parse(raw);
        } catch {
          json = {};
        }
      }
      if (!res.ok) throw new Error(json.error || json.message || raw || 'Create failed');
      setSaveMsg('Đã lưu hệ thống');
    } catch (err: unknown) {
      setSaveMsg(err instanceof Error ? err.message : 'Lỗi khi lưu');
    } finally {
      setSavingSystem(false);
    }
  };

  return (
    <div className="p-6 border-2 border-dashed border-slate-300 rounded-xl bg-white hover:border-indigo-400 transition-colors group cursor-pointer relative shadow-sm">
      <input
        ref={fileInputRef}
        type="file"
        style={{ display: 'none' }}
        accept=".json,.xml"
        onChange={handleFileChange}
      />
      <div className="flex flex-col items-center justify-center space-y-3">
        <div className="flex gap-4 mb-2">
          <FileCode className="w-6 h-6 text-slate-400" />
          <Shield className="w-6 h-6 text-slate-400" />
        </div>
        <div className="p-3 bg-indigo-50 rounded-full group-hover:bg-indigo-100 transition-colors">
          <button type="button" onClick={triggerFileSelect} className="rounded-full p-2">
            <Upload className="w-8 h-8 text-indigo-500" />
          </button>
        </div>
        <div className="text-center">
          <p className="text-lg font-medium text-slate-800">
            {fileName ? fileName : "Tải lên file SBOM"}
          </p>
          <p className="text-sm text-slate-500">
            Hỗ trợ định dạng JSON (CycloneDX)
          </p>
        </div>
        <div className="w-full mt-3">
          <label className="text-xs text-slate-500">System name (tùy chọn)</label>
          <input value={systemName} onChange={(e)=>setSystemName(e.target.value)} placeholder="Tên hệ thống để lưu" className="mt-1 block w-full rounded-md border border-slate-200 px-3 py-2 text-sm" />
        </div>
        <div className="mt-3">
          <button type="button" onClick={saveSystem} disabled={savingSystem} className="rounded-full p-2 bg-indigo-500 text-white">
            {savingSystem ? 'Đang lưu...' : 'Lưu hệ thống'}
          </button>
          {saveMsg && <p className="text-sm text-slate-500">{saveMsg}</p>}
        </div>
      </div>
    </div>
  );
};

export default SBOMUpload;
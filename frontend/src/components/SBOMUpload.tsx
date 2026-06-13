import React, { useRef, useState } from 'react';
import { FileCode, GitBranch, Loader2, Shield, Upload, Wand2 } from 'lucide-react';
import { API_BASE } from '../api';

interface Props {
  onUploadSuccess: (data: Record<string, unknown>) => void | Promise<void>;
}

const SBOMUpload: React.FC<Props> = ({ onUploadSuccess }) => {
  const [fileName, setFileName] = useState<string | null>(null);
  const [systemName, setSystemName] = useState('');
  const [savingSystem, setSavingSystem] = useState(false);
  const [generatingRepo, setGeneratingRepo] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [pendingSbom, setPendingSbom] = useState<Record<string, unknown> | null>(null);
  const [mode, setMode] = useState<'file' | 'github'>('file');
  const [repoUrl, setRepoUrl] = useState('');

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();

    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target?.result as string);
        setPendingSbom(json);
        onUploadSuccess({
          sbom: json,
          systemName: systemName.trim() || undefined,
        });
      } catch (err) {
        console.error('Không thể phân tích tệp SBOM:', err);
        alert('Tệp không phải là SBOM JSON hợp lệ.');
      }
    };

    reader.readAsText(file);
  };

  const triggerFileSelect = () => fileInputRef.current?.click();

  const saveSystem = async () => {
    const name = systemName.trim();
    if (!name) {
      setSaveMsg('Vui lòng nhập tên hệ thống');
      return;
    }

    setSavingSystem(true);
    setSaveMsg(null);
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
      if (!res.ok) throw new Error(json.error || json.message || raw || 'Tạo hệ thống thất bại');

      if (pendingSbom) {
        await Promise.resolve(onUploadSuccess({ sbom: pendingSbom, systemName: name }));
        setSaveMsg('Đã lưu hệ thống và liên kết SBOM');
      } else {
        setSaveMsg('Đã lưu hệ thống');
      }
    } catch (err: unknown) {
      setSaveMsg(err instanceof Error ? err.message : 'Lưu thất bại');
    } finally {
      setSavingSystem(false);
    }
  };

  const generateFromRepo = async () => {
    const trimmedRepoUrl = repoUrl.trim();
    if (!trimmedRepoUrl) {
      setSaveMsg('Vui lòng nhập URL repository GitHub');
      return;
    }

    setGeneratingRepo(true);
    setSaveMsg(null);
    try {
      const res = await fetch(`${API_BASE}/sboms/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl: trimmedRepoUrl,
          systemName: systemName.trim() || undefined,
        })
      });
      const raw = await res.text();
      const json = raw ? JSON.parse(raw) : {};
      if (!res.ok) throw new Error(json.error || json.message || raw || 'Sinh SBOM thất bại');

      await Promise.resolve(onUploadSuccess(json));
      setSaveMsg('Đã tạo và lưu SBOM từ repository GitHub');
    } catch (err: unknown) {
      setSaveMsg(err instanceof Error ? err.message : 'Tạo SBOM thất bại');
    } finally {
      setGeneratingRepo(false);
    }
  };

  return (
    <div className="p-6 border-2 border-dashed border-slate-300 rounded-xl bg-white hover:border-indigo-400 transition-colors group relative shadow-sm">
      <input
        ref={fileInputRef}
        type="file"
        style={{ display: 'none' }}
        accept=".json,.xml"
        onChange={handleFileChange}
      />

      <div className="flex flex-col items-center justify-center space-y-3">
        <div className="grid w-full grid-cols-2 rounded-lg border border-slate-200 bg-slate-50 p-1 text-sm font-medium">
          <button
            type="button"
            onClick={() => setMode('file')}
            className={`flex items-center justify-center gap-2 rounded-md px-3 py-2 transition ${mode === 'file' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
          >
            <Upload className="h-4 w-4" />
            Tải tệp lên
          </button>
          <button
            type="button"
            onClick={() => setMode('github')}
            className={`flex items-center justify-center gap-2 rounded-md px-3 py-2 transition ${mode === 'github' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
          >
            <GitBranch className="h-4 w-4" />
            Repository GitHub
          </button>
        </div>

        <div className="flex gap-4 mb-2">
          <FileCode className="w-6 h-6 text-slate-400" />
          <Shield className="w-6 h-6 text-slate-400" />
        </div>

        {mode === 'file' ? (
          <>
            <div className="p-3 bg-indigo-50 rounded-full group-hover:bg-indigo-100 transition-colors">
              <button type="button" onClick={triggerFileSelect} className="rounded-full p-2">
                <Upload className="w-8 h-8 text-indigo-500" />
              </button>
            </div>
            <div className="text-center">
              <p className="text-lg font-medium text-slate-800">
                {fileName ? fileName : 'Tải tệp SBOM lên'}
              </p>
              <p className="text-sm text-slate-500">
                Hỗ trợ JSON theo chuẩn CycloneDX/SPDX
              </p>
            </div>
          </>
        ) : (
          <div className="w-full space-y-3">
            <div className="flex justify-center">
              <div className="p-3 bg-blue-50 rounded-full">
                <GitBranch className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            <div className="text-center">
              <p className="text-lg font-medium text-slate-800">Sinh SBOM từ GitHub</p>
              <p className="text-sm text-slate-500">Backend sẽ clone repository và chạy Syft</p>
            </div>
            <div>
              <label className="text-xs text-slate-500">URL repository GitHub</label>
              <input
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="mt-1 block w-full rounded-md border border-slate-200 px-3 py-2 text-sm"
              />
            </div>
          </div>
        )}

        <div className="w-full mt-3">
          <label className="text-xs text-slate-500">Tên hệ thống</label>
          <input
            value={systemName}
            onChange={(e) => setSystemName(e.target.value)}
            placeholder={mode === 'github' ? 'Mặc định là tên repository' : 'Tên hệ thống cần lưu'}
            className="mt-1 block w-full rounded-md border border-slate-200 px-3 py-2 text-sm"
          />
        </div>

        <div className="mt-3 flex flex-col items-center">
          {mode === 'file' ? (
            <button
              type="button"
              onClick={saveSystem}
              disabled={savingSystem}
              className="rounded-full px-4 py-2 bg-indigo-500 text-white disabled:opacity-60"
            >
              {savingSystem ? 'Đang lưu...' : 'Lưu hệ thống'}
            </button>
          ) : (
            <button
              type="button"
              onClick={generateFromRepo}
              disabled={generatingRepo}
              className="inline-flex items-center gap-2 rounded-full px-4 py-2 bg-blue-600 text-white disabled:opacity-60"
            >
              {generatingRepo ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
              {generatingRepo ? 'Đang tạo...' : 'Sinh SBOM'}
            </button>
          )}
          {saveMsg && <p className="mt-2 text-sm text-slate-500">{saveMsg}</p>}
        </div>
      </div>
    </div>
  );
};

export default SBOMUpload;

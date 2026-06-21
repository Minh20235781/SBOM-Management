import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCode,
  GitBranch,
  Loader2,
  Shield,
  Upload,
  Wand2,
} from 'lucide-react';
import { API_BASE } from '../api';

interface Props {
  onUploadSuccess: (data: Record<string, unknown>) => void | Promise<void>;
  session: SBOMUploadSession;
  onSessionChange: (session: SBOMUploadSession) => void;
}

type RepoAnalysis = {
  repoUrl: string;
  repoName: string;
  bomFormat: string;
  specVersion?: string | null;
  serialNumber?: string | null;
  componentCount: number;
  dependencyCount: number;
  dependencyReferenceCount: number;
  ecosystems: string[];
  toolInfo: string;
  createdTimestamp: string;
  sbomSizeBytes: number;
  analysisDurationMs: number;
  inferredMetadata?: InferredMetadata | null;
  sbomOrigin?: 'SOURCE_REPOSITORY' | 'GENERATED_BY_SYFT';
  existingSbomDetected?: boolean;
  detectedSbomFile?: { path: string; format: string; componentCount: number; sizeBytes: number } | null;
};

type InferredField = {
  value: string | string[];
  source: string;
  confidence: 'high' | 'medium' | 'low';
  reason?: string;
  suggestions?: string[];
};

type InferredMetadata = {
  authors: InferredField;
  services: InferredField;
  lifecyclePhase: InferredField;
};

export type SBOMUploadSession = {
  fileName: string | null;
  systemName: string;
  saveMsg: string | null;
  pendingSbom: Record<string, unknown> | null;
  mode: 'file' | 'github';
  repoUrl: string;
  repoAnalysis: RepoAnalysis | null;
  repoConfirmed: boolean;
  generatedRepoSbom: boolean;
};

export const createDefaultSBOMUploadSession = (): SBOMUploadSession => ({
  fileName: null,
  systemName: '',
  saveMsg: null,
  pendingSbom: null,
  mode: 'file',
  repoUrl: '',
  repoAnalysis: null,
  repoConfirmed: false,
  generatedRepoSbom: false,
});

const SBOMUpload: React.FC<Props> = ({ onUploadSuccess, session, onSessionChange }) => {
  const { fileName, systemName, saveMsg, pendingSbom, mode, repoUrl, repoAnalysis, repoConfirmed, generatedRepoSbom } = session;
  const [savingSystem, setSavingSystem] = useState(false);
  const [analyzingRepo, setAnalyzingRepo] = useState(false);
  const [generatingRepo, setGeneratingRepo] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const sessionRef = useRef(session);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  const updateSession = (patch: Partial<SBOMUploadSession>) => {
    const nextSession = { ...sessionRef.current, ...patch };
    sessionRef.current = nextSession;
    onSessionChange(nextSession);
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  const downloadSbom = () => {
    if (!pendingSbom) return;
    const name = repoAnalysis?.repoName || systemName.trim() || 'repository';
    const blob = new Blob([JSON.stringify(pendingSbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${name}-sbom-cyclonedx.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const renderInferredValue = (field?: InferredField) => {
    if (!field) return 'Không phát hiện được từ mã nguồn';
    return Array.isArray(field.value) ? field.value.join(', ') : field.value;
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    updateSession({ fileName: file.name });
    const reader = new FileReader();

    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target?.result as string);
        updateSession({ pendingSbom: json });
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
      updateSession({ saveMsg: 'Vui lòng nhập tên hệ thống' });
      return;
    }

    setSavingSystem(true);
    updateSession({ saveMsg: null });
    try {
      const res = await fetch(`${API_BASE}/systems`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
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
        updateSession({ saveMsg: 'Đã lưu hệ thống và liên kết SBOM' });
      } else {
        updateSession({ saveMsg: 'Đã lưu hệ thống' });
      }
    } catch (err: unknown) {
      updateSession({ saveMsg: err instanceof Error ? err.message : 'Lưu thất bại' });
    } finally {
      setSavingSystem(false);
    }
  };

  const analyzeFromRepo = async () => {
    const trimmedRepoUrl = repoUrl.trim();
    if (!trimmedRepoUrl) {
      updateSession({ saveMsg: 'Vui lòng nhập URL repository GitHub' });
      return;
    }

    setAnalyzingRepo(true);
    updateSession({ saveMsg: null, repoAnalysis: null, repoConfirmed: false, generatedRepoSbom: false });
    try {
      const res = await fetch(`${API_BASE}/sboms/analyze-repo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: trimmedRepoUrl }),
      });
      const raw = await res.text();
      const json = raw ? JSON.parse(raw) : {};
      if (!res.ok) throw new Error(json.error || json.message || raw || 'Phân tích SBOM thất bại');

      updateSession({
        pendingSbom: json.sbom,
        repoAnalysis: json.analysis,
        saveMsg: json.analysis?.existingSbomDetected
          ? `Đã nhận diện SBOM có sẵn trong repository: ${json.analysis.detectedSbomFile?.path || 'SBOM file'}.`
          : 'Đã phân tích repository. Không tìm thấy SBOM có sẵn; hãy xác nhận để sinh SBOM bằng Syft.',
      });
    } catch (err: unknown) {
      updateSession({ saveMsg: err instanceof Error ? err.message : 'Phân tích SBOM thất bại' });
    } finally {
      setAnalyzingRepo(false);
    }
  };

  const confirmRepoAnalysis = () => {
    if (!repoAnalysis) return;
    updateSession({ repoConfirmed: true, saveMsg: 'Đã xác nhận kết quả phân tích. Bạn có thể sinh và tải SBOM.' });
  };

  const generateConfirmedRepoSbom = async () => {
    if (!pendingSbom || !repoAnalysis || !repoConfirmed) {
      updateSession({ saveMsg: 'Vui lòng phân tích và xác nhận trước khi sinh SBOM' });
      return;
    }

    setGeneratingRepo(true);
    updateSession({ saveMsg: null });
    try {
      await Promise.resolve(onUploadSuccess({
        sbom: pendingSbom,
        systemName: systemName.trim() || repoAnalysis.repoName,
        repoUrl: repoAnalysis.repoUrl,
      }));
      updateSession({ generatedRepoSbom: true });
      downloadSbom();
      updateSession({ saveMsg: 'Đã sinh, lưu và tải file SBOM về máy.' });
    } catch (err: unknown) {
      updateSession({ saveMsg: err instanceof Error ? err.message : 'Sinh SBOM thất bại' });
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
            onClick={() => updateSession({ mode: 'file' })}
            className={`flex items-center justify-center gap-2 rounded-md px-3 py-2 transition ${mode === 'file' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
          >
            <Upload className="h-4 w-4" />
            Tải tệp lên
          </button>
          <button
            type="button"
            onClick={() => updateSession({ mode: 'github' })}
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
              <p className="text-lg font-medium text-slate-800">Phân tích SBOM từ GitHub</p>
              <p className="text-sm text-slate-500">
                Backend clone repository, dò SBOM có sẵn trước; chỉ chạy Syft để sinh mới khi repository chưa có SBOM dùng được.
              </p>
            </div>
            <div>
              <label className="text-xs text-slate-500">URL repository GitHub</label>
              <input
                value={repoUrl}
                onChange={(e) => updateSession({ repoUrl: e.target.value })}
                placeholder="https://github.com/owner/repo"
                className="mt-1 block w-full rounded-md border border-slate-200 px-3 py-2 text-sm"
              />
            </div>
            {repoAnalysis && (
              <div className="rounded-xl border border-blue-100 bg-blue-50/60 p-4 text-left">
                {repoAnalysis.existingSbomDetected ? (
                  <div className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
                    <p className="flex items-center gap-2 font-bold"><CheckCircle2 className="h-4 w-4" />Repository đã có SBOM</p>
                    <p className="mt-1 font-mono text-xs">{repoAnalysis.detectedSbomFile?.path} · {repoAnalysis.detectedSbomFile?.format} · {repoAnalysis.detectedSbomFile?.componentCount ?? 0} components</p>
                    <p className="mt-1 text-xs">Kết quả được đọc từ chính SBOM trong source, không phải SBOM vừa generate bởi Syft.</p>
                  </div>
                ) : (
                  <div className="mb-3 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
                    <p className="flex items-center gap-2 font-bold"><AlertTriangle className="h-4 w-4" />Không tìm thấy SBOM có sẵn trong repository</p>
                    <p className="mt-1 text-xs">Đã quét source tree nhưng không có CycloneDX/SPDX hợp lệ. Kết quả bên dưới được Syft phân tích từ source hiện tại; hãy xác nhận nếu muốn generate SBOM mới.</p>
                  </div>
                )}
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-bold text-slate-900">Kết quả phân tích tạm thời</p>
                    <p className="mt-1 break-all text-xs text-slate-600">{repoAnalysis.repoUrl}</p>
                  </div>
                  {repoConfirmed && (
                    <span className="inline-flex items-center gap-1 rounded-full border border-emerald-100 bg-emerald-50 px-2 py-1 text-xs font-semibold text-emerald-700">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Đã xác nhận
                    </span>
                  )}
                </div>
                <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-700">
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Component</p><p className="text-lg font-bold text-slate-900">{repoAnalysis.componentCount}</p></div>
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Dependency</p><p className="text-lg font-bold text-slate-900">{repoAnalysis.dependencyCount}</p></div>
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Ecosystem</p><p className="font-semibold text-slate-900">{repoAnalysis.ecosystems.join(', ') || '-'}</p></div>
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Kích thước</p><p className="font-semibold text-slate-900">{formatBytes(repoAnalysis.sbomSizeBytes)}</p></div>
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Tool</p><p className="font-semibold text-slate-900">{repoAnalysis.toolInfo}</p></div>
                  <div className="rounded-lg bg-white p-2"><p className="text-slate-500">Thời gian</p><p className="font-semibold text-slate-900">{repoAnalysis.analysisDurationMs} ms</p></div>
                </div>
                {repoAnalysis.inferredMetadata && (
                  <div className="mt-3 rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Thông tin metadata do công cụ phát hiện</p>
                    <dl className="mt-2 grid grid-cols-[92px_1fr] gap-x-3 gap-y-2 text-xs">
                      <dt className="font-semibold text-slate-500">Tác giả</dt>
                      <dd className="text-slate-800">{renderInferredValue(repoAnalysis.inferredMetadata.authors)}</dd>
                      <dt className="font-semibold text-slate-500">Dịch vụ</dt>
                      <dd className="text-slate-800">{renderInferredValue(repoAnalysis.inferredMetadata.services)}</dd>
                      <dt className="font-semibold text-slate-500">Vòng đời</dt>
                      <dd className="text-slate-800">{renderInferredValue(repoAnalysis.inferredMetadata.lifecyclePhase)}</dd>
                      <dt className="font-semibold text-slate-500">Nguồn</dt>
                      <dd className="text-slate-600">
                        {repoAnalysis.inferredMetadata.authors.source}; {repoAnalysis.inferredMetadata.services.source}; {repoAnalysis.inferredMetadata.lifecyclePhase.source}
                      </dd>
                    </dl>
                  </div>
                )}
                <p className="mt-3 text-xs text-slate-500">
                  Hãy kiểm tra thông tin phân tích. Nếu đúng, bấm Xác nhận phân tích rồi mới Sinh và tải SBOM.
                </p>
              </div>
            )}
          </div>
        )}

        <div className="w-full mt-3">
          <label className="text-xs text-slate-500">Tên hệ thống</label>
          <input
            value={systemName}
            onChange={(e) => updateSession({ systemName: e.target.value })}
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
            <div className="flex flex-col items-center gap-2">
              <button
                type="button"
                onClick={analyzeFromRepo}
                disabled={analyzingRepo || generatingRepo}
                className="inline-flex items-center gap-2 rounded-full px-4 py-2 bg-blue-600 text-white disabled:opacity-60"
              >
                {analyzingRepo ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
                {analyzingRepo ? 'Đang phân tích...' : 'Phân tích SBOM'}
              </button>
              <div className="flex flex-wrap justify-center gap-2">
                <button
                  type="button"
                  onClick={confirmRepoAnalysis}
                  disabled={!repoAnalysis || repoConfirmed || analyzingRepo || generatingRepo}
                  title={!repoAnalysis ? 'Cần phân tích SBOM trước' : repoConfirmed ? 'Đã xác nhận' : 'Xác nhận kết quả phân tích'}
                  className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 disabled:opacity-45"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  Xác nhận phân tích
                </button>
                <button
                  type="button"
                  onClick={generateConfirmedRepoSbom}
                  disabled={!repoConfirmed || analyzingRepo || generatingRepo}
                  title={!repoConfirmed ? 'Cần xác nhận phân tích trước khi sinh SBOM' : 'Sinh, lưu và tải SBOM'}
                  className="inline-flex items-center gap-2 rounded-full bg-emerald-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-45"
                >
                  {generatingRepo ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  {generatedRepoSbom ? 'Tải lại SBOM' : 'Sinh và tải SBOM'}
                </button>
              </div>
            </div>
          )}
          {saveMsg && <p className="mt-2 text-sm text-slate-500">{saveMsg}</p>}
        </div>
      </div>
    </div>
  );
};

export default SBOMUpload;

import React, { useState } from 'react';
import { Upload, FileCode, Shield } from 'lucide-react';

// VỊ TRÍ 1: Định nghĩa interface cho Props ngay trên đầu component
interface Props {
  onUploadSuccess: (data: Record<string, unknown>) => void;
}

// VỊ TRÍ 2: Thêm kiểu React.FC<Props> và destructure prop vào tham số của function
const SBOMUpload: React.FC<Props> = ({ onUploadSuccess }) => {
  const [fileName, setFileName] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFileName(file.name);
      const reader = new FileReader();
      
      reader.onload = (event) => {
        try {
          const json = JSON.parse(event.target?.result as string);
          console.log("Dữ liệu SBOM nhận được:", json);

          // VỊ TRÍ 3: Gọi hàm callback để truyền dữ liệu ngược về App.tsx
          onUploadSuccess(json);

        } catch (err) {
          console.error("Lỗi phân tích file SBOM:", err);
          alert("File không đúng định dạng JSON chuẩn!");
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="p-6 border-2 border-dashed border-slate-300 rounded-xl bg-white hover:border-indigo-400 transition-colors group cursor-pointer relative shadow-sm">
      <input 
        type="file" 
        className="absolute inset-0 opacity-0 cursor-pointer" 
        accept=".json,.xml"
        onChange={handleFileChange}
      />
      <div className="flex flex-col items-center justify-center space-y-3">
        <div className="flex gap-4 mb-2">
          <FileCode className="w-6 h-6 text-slate-400" />
          <Shield className="w-6 h-6 text-slate-400" />
        </div>
        <div className="p-3 bg-indigo-50 rounded-full group-hover:bg-indigo-100 transition-colors">
          <Upload className="w-8 h-8 text-indigo-500" />
        </div>
        <div className="text-center">
          <p className="text-lg font-medium text-slate-800">
            {fileName ? fileName : "Tải lên file SBOM"}
          </p>
          <p className="text-sm text-slate-500">
            Hỗ trợ định dạng JSON (CycloneDX, SPDX)
          </p>
        </div>
      </div>
    </div>
  );
};

export default SBOMUpload;
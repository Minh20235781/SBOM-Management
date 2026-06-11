import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.GRYPE_TIMEOUT_MS || 120000);

const extractNumericEpss = (epssValue: any): number | null => {
  if (typeof epssValue === 'number' && Number.isFinite(epssValue)) {
    return epssValue;
  }

  if (typeof epssValue === 'string') {
    const parsed = Number.parseFloat(epssValue);
    return Number.isFinite(parsed) ? parsed : null;
  }

  if (Array.isArray(epssValue)) {
    for (const item of epssValue) {
      const extracted = extractNumericEpss(item);
      if (extracted !== null) {
        return extracted;
      }
    }
    return null;
  }

  if (epssValue && typeof epssValue === 'object') {
    return extractNumericEpss(epssValue.epss);
  }

  return null;
};

export const scanSBOMWithGrype = async (sbomData: any): Promise<any[]> => {
  const tempId = uuidv4();
  const tempFilePath = path.join(os.tmpdir(), `sbom-${tempId}.json`);
  
  try {
    // 1. Lưu SBOM ra file tạm
    await fs.writeFile(tempFilePath, JSON.stringify(sbomData), 'utf8');
    
    // 2. Chạy child_process gọi Grype CLI (quét file sbom và trả kết quả dạng JSON)
    // Ưu tiên đọc biến môi trường GRYPE_BIN để tránh lỗi PATH
    const grypeBin = process.env.GRYPE_BIN || 'grype';
    const { stdout } = await execFilePromise(
      grypeBin,
      [`sbom:${tempFilePath}`, '-o', 'json', '-q'],
      { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER }
    );
    
    // 3. Phân tích kết quả JSON
    const result = JSON.parse(stdout);
    
    if (!result || !result.matches) {
        return [];
    }

    // 4. Map dữ liệu sang cấu trúc vulnerability của Backend
    const vulnerabilities = result.matches.map((match: any) => {
      let affectedRef = null;
      // Grype thường gán SBOM component id (bom-ref / SPDXID) vào artifact.id
      if (match.artifact && match.artifact.id) {
         affectedRef = match.artifact.id;
      }
      
      const artifact = match.artifact || {};
      const vulnInfo = match.vulnerability || {};
      const fixVersions = Array.isArray(vulnInfo.fix?.versions) ? vulnInfo.fix.versions : [];
      
      return {
        name: artifact.name || null,
        installed: artifact.version || null,
        fixed_in: fixVersions[0] || null,
        package_type: artifact.type || null,
        vulnerability: vulnInfo.id || 'UNKNOWN',
        cve_id: vulnInfo.id || 'UNKNOWN',
        severity: vulnInfo.severity || 'Unknown',
        epss: extractNumericEpss(vulnInfo.epss ?? vulnInfo.score),
        risk: vulnInfo.risk || vulnInfo.riskScore || null,
        // Lấy description ưu tiên từ vulnInfo, nếu không có lấy từ relatedVulnerabilities
        description: vulnInfo.description || match.relatedVulnerabilities?.[0]?.description || '',
        affected_component_ref: affectedRef,
      };
    });
    
    return vulnerabilities;
  } catch (error: any) {
    const message = error?.stderr || error?.stdout || error?.message || 'Unknown Grype error';
    console.error('Lỗi khi quét bằng Grype:', String(message).trim());
    // Trả về mảng rỗng thay vì ném lỗi để không làm sập tiến trình upload SBOM chung
    return [];
  } finally {
    // 5. Dọn dẹp file tạm
    try {
      await fs.unlink(tempFilePath);
    } catch (e) {
      console.error('Không thể xóa file SBOM tạm:', e);
    }
  }
};

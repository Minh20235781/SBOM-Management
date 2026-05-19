import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';

const execFilePromise = util.promisify(execFile);

export const scanSBOMWithGrype = async (sbomData: any): Promise<any[]> => {
  const tempId = uuidv4();
  const tempFilePath = path.join(os.tmpdir(), `sbom-${tempId}.json`);
  
  try {
    // 1. Lưu SBOM ra file tạm
    await fs.writeFile(tempFilePath, JSON.stringify(sbomData), 'utf8');
    
    // 2. Chạy child_process gọi Grype CLI (quét file sbom và trả kết quả dạng JSON)
    // Ưu tiên đọc biến môi trường GRYPE_BIN để tránh lỗi PATH
    const grypeBin = process.env.GRYPE_BIN || 'grype';
    const { stdout } = await execFilePromise(grypeBin, [`sbom:${tempFilePath}`, '-o', 'json', '-q']);
    
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
      
      const vulnInfo = match.vulnerability || {};
      
      return {
        cve_id: vulnInfo.id || 'UNKNOWN',
        severity: vulnInfo.severity || 'Unknown',
        // Lấy description ưu tiên từ vulnInfo, nếu không có lấy từ relatedVulnerabilities
        description: vulnInfo.description || match.relatedVulnerabilities?.[0]?.description || '',
        affected_component_ref: affectedRef,
      };
    });
    
    return vulnerabilities;
  } catch (error: any) {
    console.error('Lỗi khi quét bằng Grype:', error.message);
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

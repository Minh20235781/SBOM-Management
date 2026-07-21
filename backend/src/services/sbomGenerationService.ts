import { execFile } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import util from 'util';
import { sourceCloneService } from './sourceCloneService';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 100 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 180000);

const outputRootName = 'generated';

export const sbomGenerationService = {
  generateCycloneDxFromSource: async (repoPath: string, scenarioId: string) => {
    // Khai báo đường dẫn binary cho cả 2 công cụ
    const syftBin = process.env.SYFT_BIN || 'syft';
    const grypeBin = process.env.GRYPE_BIN || 'grype'; 
    const started = Date.now();
    
    const workDir = await sourceCloneService.ensureWorkDir();
    const cacheDir = path.join(workDir, 'cache');
    const outputDir = path.join(workDir, outputRootName);
    
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.mkdir(outputDir, { recursive: true });

    const syftTarget = `dir:${path.resolve(repoPath)}`;
    const timestamp = Date.now();
    
    // Tạo 2 tên file riêng biệt: 1 bản gốc, 1 bản đã được làm giàu (enriched)
    const baseSbomFilename = `${scenarioId}-${timestamp}-base-cyclonedx.json`;
    const enrichedSbomFilename = `${scenarioId}-${timestamp}-enriched-cyclonedx.json`;
    
    const baseSbomPath = path.join(outputDir, baseSbomFilename);
    const enrichedSbomPath = path.join(outputDir, enrichedSbomFilename);

    // --- BƯỚC 1: CHẠY SYFT ĐỂ TẠO SBOM GỐC ---
    try {
      await execFilePromise(
        syftBin, 
        [syftTarget, '-o', `cyclonedx-json=${baseSbomFilename}`], 
        {
          cwd: outputDir, // Chạy trực tiếp trong thư mục output
          timeout: TIMEOUT_MS * 3,
          maxBuffer: MAX_BUFFER,
          env: {
            ...process.env,
            XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
            SYFT_CHECK_FOR_APP_UPDATE: 'false',
            SYFT_LOG_LEVEL: 'error', // Chỉ hiện log lỗi
          },
        }
      );
    } catch (error: any) {
      const message = error?.stderr || error?.stdout || error?.message || 'Unknown error';
      throw new Error(`Syft scan failed for ${syftTarget}:\n${message.trim()}`);
    }

    // --- BƯỚC 2: CHẠY GRYPE ĐỂ TÌM VÀ NHÚNG LỖ HỔNG VÀO SBOM ---
    try {
      await execFilePromise(
        grypeBin, 
        // Grype đọc sbom gốc và xuất ra định dạng cyclonedx-json
        [`sbom:${baseSbomFilename}`, '--add-cpes-if-none', '-o', `cyclonedx-json=${enrichedSbomFilename}`], 
        {
          cwd: outputDir,
          timeout: TIMEOUT_MS * 3, // Quét lỗ hổng có thể tốn thời gian
          maxBuffer: MAX_BUFFER,
          env: {
            ...process.env,
            GRYPE_CHECK_FOR_APP_UPDATE: 'false',
            GRYPE_LOG_LEVEL: 'error',
            // Trỏ thư mục cache DB của Grype để tải CVE nhanh hơn cho các lần sau
            GRYPE_DB_CACHE_DIR: path.join(cacheDir, 'grype-db'), 
          },
        }
      );
    } catch (error: any) {
      const message = error?.stderr || error?.stdout || error?.message || 'Unknown error';
      throw new Error(`Grype vulnerability scan failed:\n${message.trim()}`);
    }

    const analysisDurationMs = Date.now() - started;
    
    // --- BƯỚC 3: ĐỌC VÀ TRẢ VỀ SBOM ĐÃ LÀM GIÀU ---
    // Đọc file enriched thay vì file base
    const sbomContent = await fs.readFile(enrichedSbomPath, 'utf8');
    const sbom = JSON.parse(sbomContent);
    const stat = await fs.stat(enrichedSbomPath);

    // Tùy chọn: Xóa file SBOM gốc đi cho nhẹ server nếu không cần thiết
    await fs.unlink(baseSbomPath).catch(() => {});

    return {
      sbom,
      sbomPath: enrichedSbomPath,
      sbomSizeBytes: stat.size,
      analysisDurationMs,
      toolInfo: 'Syft + Grype (CycloneDX JSON)',
      createdTimestamp: sbom.metadata?.timestamp || new Date().toISOString(),
    };
  },
};
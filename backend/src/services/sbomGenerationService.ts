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
    const syftBin = process.env.SYFT_BIN || 'syft';
    const started = Date.now();
    
    const workDir = await sourceCloneService.ensureWorkDir();
    const cacheDir = path.join(workDir, 'cache');
    const outputDir = path.join(workDir, outputRootName);
    
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.mkdir(outputDir, { recursive: true });

    const syftTarget = `dir:${path.resolve(repoPath)}`;
    // Chỉ lấy tên file, không dùng đường dẫn tuyệt đối C:\...
    const sbomFilename = `${scenarioId}-${Date.now()}-cyclonedx.json`;
    const sbomPath = path.join(outputDir, sbomFilename);

    try {
      await execFilePromise(
        syftBin, 
        // Bỏ cờ -q (quiet) để hiện log lỗi nếu có. 
        // Chỉ truyền tên file vào -o để tránh lỗi parse dấu ":" của Windows
        [syftTarget, '-o', `cyclonedx-json=${sbomFilename}`], 
        {
          cwd: outputDir, // Ép Syft chạy ngay tại thư mục outputDir
          timeout: TIMEOUT_MS * 3, // Tăng thời gian chờ (timeout)
          maxBuffer: MAX_BUFFER,
          env: {
            ...process.env,
            XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
            SYFT_CHECK_FOR_APP_UPDATE: 'false',
            SYFT_LOG_LEVEL: 'error', // Chỉ in ra lỗi thực sự, bỏ qua log rác
          },
        }
      );
    } catch (error: any) {
      // Bây giờ nếu lỗi, error.stderr sẽ chứa nguyên nhân chính xác từ Syft
      const message = error?.stderr || error?.stdout || error?.message || 'Unknown error';
      throw new Error(`Syft scan failed for ${syftTarget}:\n${message.trim()}`);
    }

    const analysisDurationMs = Date.now() - started;
    
    // Đọc kết quả SBOM từ file đã lưu
    const sbomContent = await fs.readFile(sbomPath, 'utf8');
    const sbom = JSON.parse(sbomContent);
    const stat = await fs.stat(sbomPath);

    return {
      sbom,
      sbomPath,
      sbomSizeBytes: stat.size,
      analysisDurationMs,
      toolInfo: 'Syft CycloneDX JSON',
      createdTimestamp: sbom.metadata?.timestamp || new Date().toISOString(),
    };
  },
};

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
    await fs.mkdir(cacheDir, { recursive: true });
    const { stdout } = await execFilePromise(syftBin, [repoPath, '-o', 'cyclonedx-json', '-q'], {
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      env: {
        ...process.env,
        XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
        SYFT_CHECK_FOR_APP_UPDATE: 'false',
      },
    });
    const analysisDurationMs = Date.now() - started;
    const sbom = JSON.parse(stdout);
    const outputDir = path.join(workDir, outputRootName);
    await fs.mkdir(outputDir, { recursive: true });
    const sbomPath = path.join(outputDir, `${scenarioId}-${Date.now()}-cyclonedx.json`);
    await fs.writeFile(sbomPath, JSON.stringify(sbom, null, 2), 'utf8');
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

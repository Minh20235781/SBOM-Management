import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import { metadataInferenceService, InferredMetadata } from './metadataInferenceService';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 120000);

export interface GeneratedSbomResult {
  sbom: any;
  normalizedRepoUrl: string;
  repoName: string;
  inferredMetadata?: InferredMetadata;
}

const normalizeGitHubRepoUrl = (rawUrl: unknown) => {
  if (typeof rawUrl !== 'string') {
    throw new Error('Missing GitHub repository URL');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid GitHub repository URL');
  }

  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
    throw new Error('Only public HTTPS GitHub repository URLs are supported');
  }

  const [owner, repoSegment] = parsed.pathname.split('/').filter(Boolean);
  if (!owner || !repoSegment) {
    throw new Error('GitHub repository URL must include owner and repository name');
  }

  const repoName = repoSegment.replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repoName)) {
    throw new Error('GitHub repository owner or name contains unsupported characters');
  }

  return {
    normalizedRepoUrl: `https://github.com/${owner}/${repoName}.git`,
    repoName,
  };
};

export const generateSbomFromGitHubRepo = async (repoUrl: unknown): Promise<GeneratedSbomResult> => {
  const { normalizedRepoUrl, repoName } = normalizeGitHubRepoUrl(repoUrl);
  const tempRoot = path.join(os.tmpdir(), `syft-repo-${uuidv4()}`);
  const repoPath = path.join(tempRoot, 'repo');

  try {
    await fs.mkdir(tempRoot, { recursive: true });

    const gitBin = process.env.GIT_BIN || 'git';
    await execFilePromise(
      gitBin,
      ['clone', '--depth', '1', normalizedRepoUrl, repoPath],
      { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER }
    );

    const syftBin = process.env.SYFT_BIN || 'syft';
    const { stdout } = await execFilePromise(
      syftBin,
      [repoPath, '-o', 'cyclonedx-json', '-q'],
      { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER }
    );

    const sbom = JSON.parse(stdout);
    const inferredMetadata = await metadataInferenceService.infer(repoPath, {
      repoUrl: normalizedRepoUrl,
      repoName,
      context: 'manual',
    });
    const enrichedSbom = metadataInferenceService.injectIntoCycloneDx(sbom, inferredMetadata);
    return { sbom: enrichedSbom, normalizedRepoUrl, repoName, inferredMetadata };
  } catch (error: any) {
    const message = error?.stderr || error?.stdout || error?.message || 'Failed to generate SBOM with Syft';
    throw new Error(String(message).trim());
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
  }
};

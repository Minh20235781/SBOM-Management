import { execFile } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import util from 'util';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 30 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SOURCE_CLONE_TIMEOUT_MS || 180000);

const workspaceRoot = path.resolve(process.cwd(), process.env.SBOM_VALIDATION_WORKDIR || '.sbom-validation');
const sourceRoot = path.join(workspaceRoot, 'sources');

const safeName = (value: string) => value.replace(/[^a-zA-Z0-9_.-]/g, '-');

const gitConfigArgs = () => {
  const args: string[] = [];
  if (process.env.GIT_SSL_BACKEND) args.push('-c', `http.sslBackend=${process.env.GIT_SSL_BACKEND}`);
  if (process.env.GIT_SSL_VERIFY === 'false') args.push('-c', 'http.sslVerify=false');
  return args;
};

export const sourceCloneService = {
  cloneOrUpdate: async (scenarioId: string, githubUrl: string) => {
    await fs.mkdir(sourceRoot, { recursive: true });
    const repoPath = path.join(sourceRoot, safeName(scenarioId));
    const gitBin = process.env.GIT_BIN || 'git';

    await fs.rm(repoPath, { recursive: true, force: true }).catch(() => undefined);
    await execFilePromise(gitBin, [...gitConfigArgs(), 'clone', '--depth', '1', githubUrl, repoPath], {
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });

    return repoPath;
  },

  ensureWorkDir: async () => {
    await fs.mkdir(workspaceRoot, { recursive: true });
    return workspaceRoot;
  },
};

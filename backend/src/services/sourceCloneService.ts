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

const windowsReservedName = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const isInvalidWindowsSegment = (segment: string) =>
  /[<>:"\\|?*]/.test(segment) || /[. ]$/.test(segment) || windowsReservedName.test(segment);

const invalidCheckoutPrefixes = (gitPaths: string[]) => {
  const prefixes = new Set<string>();
  for (const gitPath of gitPaths) {
    const segments = gitPath.split('/');
    const invalidIndex = segments.findIndex(isInvalidWindowsSegment);
    if (invalidIndex >= 0) prefixes.add(segments.slice(0, invalidIndex + 1).join('/'));
  }
  return [...prefixes].sort();
};

const looksLikeSbomPath = (gitPath: string) => {
  const name = gitPath.split('/').pop()?.toLowerCase() || '';
  return /(?:sbom|bom|cyclonedx|spdx|cdx).*(?:\.json|\.xml|\.ya?ml)$/.test(name)
    || /^(?:bom|sbom|cyclonedx|spdx)\.(?:json|xml|ya?ml)$/.test(name);
};

const essentialSourceNames = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'pom.xml',
  'requirements.txt', 'pyproject.toml', 'poetry.lock', 'composer.json', 'composer.lock',
  'gemfile', 'gemfile.lock', 'go.mod', 'go.sum', 'cargo.toml', 'cargo.lock',
]);

const isEssentialSourcePath = (gitPath: string) => {
  const name = gitPath.split('/').pop()?.toLowerCase() || '';
  return essentialSourceNames.has(name) || /^readme(?:\..+)?$/i.test(name) || looksLikeSbomPath(gitPath);
};

const gitConfigArgs = () => {
  const args: string[] = ['-c', 'core.longpaths=true'];
  if (process.env.GIT_SSL_BACKEND) args.push('-c', `http.sslBackend=${process.env.GIT_SSL_BACKEND}`);
  if (process.env.GIT_SSL_VERIFY === 'false') args.push('-c', 'http.sslVerify=false');
  return args;
};

const resolveGitLfsContent = async (gitBin: string, repoPath: string, gitPath: string, content: Buffer | string) => {
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const pointer = buffer.toString('utf8');
  const match = /^version https:\/\/git-lfs\.github\.com\/spec\/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize \d+/i.exec(pointer);
  if (!match) return buffer;
  try {
    await execFilePromise(gitBin, ['-C', repoPath, 'lfs', 'fetch', 'origin', 'HEAD', `--include=${gitPath}`, '--exclude='], {
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
    const oid = match[1].toLowerCase();
    return await fs.readFile(path.join(repoPath, '.git', 'lfs', 'objects', oid.slice(0, 2), oid.slice(2, 4), oid));
  } catch {
    return buffer;
  }
};

export const sourceCloneService = {
  cloneInto: async (githubUrl: string, repoPath: string) => {
    const gitBin = process.env.GIT_BIN || 'git';
    await execFilePromise(gitBin, [...gitConfigArgs(), 'clone', '--depth', '1', '--no-checkout', githubUrl, repoPath], {
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });

    let skippedPaths: string[] = [];
    let gitPaths: string[] = [];
    if (process.platform === 'win32') {
      const { stdout } = await execFilePromise(gitBin, ['-C', repoPath, 'ls-tree', '-rz', '--name-only', 'HEAD'], {
        timeout: TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
        encoding: 'utf8',
      });
      gitPaths = stdout.split('\0').filter(Boolean);
      skippedPaths = invalidCheckoutPrefixes(gitPaths);
    }

    if (skippedPaths.length > 0) {
      const excludedRoots = new Set(skippedPaths.map(value => value.split('/')[0]));
      const essentialPaths = gitPaths
        .filter(isEssentialSourcePath)
        .filter(gitPath => !excludedRoots.has(gitPath.split('/')[0]))
        .slice(0, 1000);
      for (const gitPath of essentialPaths) {
        const { stdout: objectId } = await execFilePromise(gitBin, ['-C', repoPath, 'rev-parse', `HEAD:${gitPath}`], { timeout: 15000 });
        const { stdout: content } = await execFilePromise(gitBin, ['-C', repoPath, 'cat-file', 'blob', objectId.trim()], {
          timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, encoding: 'buffer',
        });
        const outputPath = path.join(repoPath, ...gitPath.split('/'));
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(outputPath, await resolveGitLfsContent(gitBin, repoPath, gitPath, content));
      }
    } else {
      await execFilePromise(gitBin, ['-C', repoPath, 'checkout', '--force', 'HEAD'], {
        timeout: TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
      });
    }

    if (skippedPaths.length > 0) {
      const invalidRoots = new Set(skippedPaths.map(value => value.split('/')[0]));
      const recoverableSboms = gitPaths
        .filter(gitPath => invalidRoots.has(gitPath.split('/')[0]) && looksLikeSbomPath(gitPath))
        .sort((left, right) => Number(!left.toLowerCase().endsWith('/cyclonedx.json')) - Number(!right.toLowerCase().endsWith('/cyclonedx.json')))
        .slice(0, 3);
      const recoveryRoot = path.join(repoPath, '.recovered-repository-sboms');
      await fs.mkdir(recoveryRoot, { recursive: true });
      for (const [index, gitPath] of recoverableSboms.entries()) {
        const { stdout: objectId } = await execFilePromise(gitBin, ['-C', repoPath, 'rev-parse', `HEAD:${gitPath}`], { timeout: 15000 });
        const { stdout } = await execFilePromise(gitBin, ['-C', repoPath, 'cat-file', 'blob', objectId.trim()], {
          timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, encoding: 'buffer',
        });
        const safeFileName = `${String(index + 1).padStart(2, '0')}-${path.basename(gitPath).replace(/[^a-zA-Z0-9_.-]/g, '-')}`;
        await fs.writeFile(path.join(recoveryRoot, safeFileName), await resolveGitLfsContent(gitBin, repoPath, gitPath, stdout));
      }
      await fs.writeFile(
        path.join(recoveryRoot, 'RECOVERY_INFO.json'),
        JSON.stringify({ reason: 'Windows-incompatible Git paths were skipped during checkout.', skippedPaths, recoveredSboms: recoverableSboms }, null, 2),
        'utf8'
      );
    }
    return { repoPath, skippedPaths };
  },

  cloneOrUpdate: async (scenarioId: string, githubUrl: string) => {
    await fs.mkdir(sourceRoot, { recursive: true });
    const repoPath = path.join(sourceRoot, safeName(scenarioId));
    await fs.rm(repoPath, { recursive: true, force: true }).catch(() => undefined);
    try {
      await sourceCloneService.cloneInto(githubUrl, repoPath);
    } catch (error: any) {
      const detail = String(error?.stderr || error?.message || '').trim();
      throw new Error(`SOURCE_CLONE_FAILED: Repository is unavailable or Git clone failed. ${detail}`);
    }

    return repoPath;
  },

  inspectRevision: async (repoPath: string) => {
    const gitBin = process.env.GIT_BIN || 'git';
    const [{ stdout: commit }, { stdout: branch }, { stdout: committedAt }] = await Promise.all([
      execFilePromise(gitBin, ['-C', repoPath, 'rev-parse', 'HEAD'], { timeout: 15000 }),
      execFilePromise(gitBin, ['-C', repoPath, 'rev-parse', '--abbrev-ref', 'HEAD'], { timeout: 15000 }),
      execFilePromise(gitBin, ['-C', repoPath, 'show', '-s', '--format=%cI', 'HEAD'], { timeout: 15000 }),
    ]);
    return {
      commit: commit.trim(),
      shortCommit: commit.trim().slice(0, 8),
      branch: branch.trim(),
      committedAt: committedAt.trim(),
    };
  },

  ensureWorkDir: async () => {
    await fs.mkdir(workspaceRoot, { recursive: true });
    return workspaceRoot;
  },
};

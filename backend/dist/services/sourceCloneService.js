"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sourceCloneService = void 0;
const child_process_1 = require("child_process");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const util_1 = __importDefault(require("util"));
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const MAX_BUFFER = 30 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SOURCE_CLONE_TIMEOUT_MS || 180000);
const workspaceRoot = path_1.default.resolve(process.cwd(), process.env.SBOM_VALIDATION_WORKDIR || '.sbom-validation');
const sourceRoot = path_1.default.join(workspaceRoot, 'sources');
const safeName = (value) => value.replace(/[^a-zA-Z0-9_.-]/g, '-');
const windowsReservedName = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const isInvalidWindowsSegment = (segment) => /[<>:"\\|?*]/.test(segment) || /[. ]$/.test(segment) || windowsReservedName.test(segment);
const invalidCheckoutPrefixes = (gitPaths) => {
    const prefixes = new Set();
    for (const gitPath of gitPaths) {
        const segments = gitPath.split('/');
        const invalidIndex = segments.findIndex(isInvalidWindowsSegment);
        if (invalidIndex >= 0)
            prefixes.add(segments.slice(0, invalidIndex + 1).join('/'));
    }
    return [...prefixes].sort();
};
const looksLikeSbomPath = (gitPath) => {
    const name = gitPath.split('/').pop()?.toLowerCase() || '';
    return /(?:sbom|bom|cyclonedx|spdx|cdx).*(?:\.json|\.xml|\.ya?ml)$/.test(name)
        || /^(?:bom|sbom|cyclonedx|spdx)\.(?:json|xml|ya?ml)$/.test(name);
};
const essentialSourceNames = new Set([
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'pom.xml',
    'requirements.txt', 'pyproject.toml', 'poetry.lock', 'composer.json', 'composer.lock',
    'gemfile', 'gemfile.lock', 'go.mod', 'go.sum', 'cargo.toml', 'cargo.lock',
]);
const isEssentialSourcePath = (gitPath) => {
    const name = gitPath.split('/').pop()?.toLowerCase() || '';
    return essentialSourceNames.has(name) || /^readme(?:\..+)?$/i.test(name) || looksLikeSbomPath(gitPath);
};
const gitConfigArgs = () => {
    const args = ['-c', 'core.longpaths=true'];
    if (process.env.GIT_SSL_BACKEND)
        args.push('-c', `http.sslBackend=${process.env.GIT_SSL_BACKEND}`);
    if (process.env.GIT_SSL_VERIFY === 'false')
        args.push('-c', 'http.sslVerify=false');
    return args;
};
const resolveGitLfsContent = async (gitBin, repoPath, gitPath, content) => {
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const pointer = buffer.toString('utf8');
    const match = /^version https:\/\/git-lfs\.github\.com\/spec\/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize \d+/i.exec(pointer);
    if (!match)
        return buffer;
    try {
        await execFilePromise(gitBin, ['-C', repoPath, 'lfs', 'fetch', 'origin', 'HEAD', `--include=${gitPath}`, '--exclude='], {
            timeout: TIMEOUT_MS,
            maxBuffer: MAX_BUFFER,
        });
        const oid = match[1].toLowerCase();
        return await promises_1.default.readFile(path_1.default.join(repoPath, '.git', 'lfs', 'objects', oid.slice(0, 2), oid.slice(2, 4), oid));
    }
    catch {
        return buffer;
    }
};
exports.sourceCloneService = {
    cloneInto: async (githubUrl, repoPath) => {
        const gitBin = process.env.GIT_BIN || 'git';
        await execFilePromise(gitBin, [...gitConfigArgs(), 'clone', '--depth', '1', '--no-checkout', githubUrl, repoPath], {
            timeout: TIMEOUT_MS,
            maxBuffer: MAX_BUFFER,
        });
        let skippedPaths = [];
        let gitPaths = [];
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
                const outputPath = path_1.default.join(repoPath, ...gitPath.split('/'));
                await promises_1.default.mkdir(path_1.default.dirname(outputPath), { recursive: true });
                await promises_1.default.writeFile(outputPath, await resolveGitLfsContent(gitBin, repoPath, gitPath, content));
            }
        }
        else {
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
            const recoveryRoot = path_1.default.join(repoPath, '.recovered-repository-sboms');
            await promises_1.default.mkdir(recoveryRoot, { recursive: true });
            for (const [index, gitPath] of recoverableSboms.entries()) {
                const { stdout: objectId } = await execFilePromise(gitBin, ['-C', repoPath, 'rev-parse', `HEAD:${gitPath}`], { timeout: 15000 });
                const { stdout } = await execFilePromise(gitBin, ['-C', repoPath, 'cat-file', 'blob', objectId.trim()], {
                    timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, encoding: 'buffer',
                });
                const safeFileName = `${String(index + 1).padStart(2, '0')}-${path_1.default.basename(gitPath).replace(/[^a-zA-Z0-9_.-]/g, '-')}`;
                await promises_1.default.writeFile(path_1.default.join(recoveryRoot, safeFileName), await resolveGitLfsContent(gitBin, repoPath, gitPath, stdout));
            }
            await promises_1.default.writeFile(path_1.default.join(recoveryRoot, 'RECOVERY_INFO.json'), JSON.stringify({ reason: 'Windows-incompatible Git paths were skipped during checkout.', skippedPaths, recoveredSboms: recoverableSboms }, null, 2), 'utf8');
        }
        return { repoPath, skippedPaths };
    },
    cloneOrUpdate: async (scenarioId, githubUrl) => {
        await promises_1.default.mkdir(sourceRoot, { recursive: true });
        const repoPath = path_1.default.join(sourceRoot, safeName(scenarioId));
        await promises_1.default.rm(repoPath, { recursive: true, force: true }).catch(() => undefined);
        try {
            await exports.sourceCloneService.cloneInto(githubUrl, repoPath);
        }
        catch (error) {
            const detail = String(error?.stderr || error?.message || '').trim();
            throw new Error(`SOURCE_CLONE_FAILED: Repository is unavailable or Git clone failed. ${detail}`);
        }
        return repoPath;
    },
    inspectRevision: async (repoPath) => {
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
        await promises_1.default.mkdir(workspaceRoot, { recursive: true });
        return workspaceRoot;
    },
};

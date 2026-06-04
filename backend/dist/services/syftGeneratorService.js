"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSbomFromGitHubRepo = void 0;
const child_process_1 = require("child_process");
const util_1 = __importDefault(require("util"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const uuid_1 = require("uuid");
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 120000);
const normalizeGitHubRepoUrl = (rawUrl) => {
    if (typeof rawUrl !== 'string') {
        throw new Error('Missing GitHub repository URL');
    }
    let parsed;
    try {
        parsed = new URL(rawUrl.trim());
    }
    catch {
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
const generateSbomFromGitHubRepo = async (repoUrl) => {
    const { normalizedRepoUrl, repoName } = normalizeGitHubRepoUrl(repoUrl);
    const tempRoot = path_1.default.join(os_1.default.tmpdir(), `syft-repo-${(0, uuid_1.v4)()}`);
    const repoPath = path_1.default.join(tempRoot, 'repo');
    try {
        await promises_1.default.mkdir(tempRoot, { recursive: true });
        const gitBin = process.env.GIT_BIN || 'git';
        await execFilePromise(gitBin, ['clone', '--depth', '1', normalizedRepoUrl, repoPath], { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER });
        const syftBin = process.env.SYFT_BIN || 'syft';
        const { stdout } = await execFilePromise(syftBin, [repoPath, '-o', 'cyclonedx-json', '-q'], { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER });
        const sbom = JSON.parse(stdout);
        return { sbom, normalizedRepoUrl, repoName };
    }
    catch (error) {
        const message = error?.stderr || error?.stdout || error?.message || 'Failed to generate SBOM with Syft';
        throw new Error(String(message).trim());
    }
    finally {
        await promises_1.default.rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
    }
};
exports.generateSbomFromGitHubRepo = generateSbomFromGitHubRepo;

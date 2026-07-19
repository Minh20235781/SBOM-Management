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
const metadataInferenceService_1 = require("./metadataInferenceService");
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 120000);
const SBOM_FILE_NAMES = new Set([
    'sbom.json', 'bom.json', 'cyclonedx.json', 'cyclonedx.xml',
    'spdx.json', 'spdx.rdf', 'spdx.yaml',
]);
const MANIFEST_FILE_NAMES = new Set([
    'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
    'pom.xml', 'build.gradle', 'requirements.txt', 'pyproject.toml',
    'go.mod', 'dockerfile',
]);
const SBOM_EXTENSIONS = ['.json', '.xml', '.yaml', '.yml', '.rdf', '.tag', '.spdx'];
const hasSbomLikeName = (lowerName, lowerPath) => {
    const extensionSupported = SBOM_EXTENSIONS.some(extension => lowerName.endsWith(extension));
    const inSbomDirectory = lowerPath.startsWith('.sbom/') || lowerPath.startsWith('sbom/')
        || lowerPath.includes('/.sbom/') || lowerPath.includes('/sbom/');
    const hasKnownName = SBOM_FILE_NAMES.has(lowerName)
        || lowerName.endsWith('.cdx.json')
        || lowerName.endsWith('.spdx.json')
        || lowerName.includes('cyclonedx')
        || lowerName.includes('spdx')
        || /(^|[-_.])(sbom|bom)([-_.]|$)/.test(lowerName);
    return extensionSupported && (inSbomDirectory || hasKnownName);
};
const hasSbomDocumentSignature = async (filePath) => {
    let handle = null;
    try {
        handle = await promises_1.default.open(filePath, 'r');
        const buffer = Buffer.alloc(512 * 1024);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const content = buffer.subarray(0, bytesRead).toString('utf8');
        return /["']bomFormat["']\s*:\s*["']CycloneDX["']/i.test(content)
            || /["']spdxVersion["']\s*:/i.test(content)
            || /["']SPDXID["']\s*:\s*["']SPDXRef-DOCUMENT["']/i.test(content)
            || /cyclonedx\.org\/schema\/bom/i.test(content)
            || /<\s*(?:\w+:)?SpdxDocument\b/i.test(content)
            || /^\s*bomFormat\s*:\s*CycloneDX\s*$/im.test(content)
            || /^\s*spdxVersion\s*:/im.test(content)
            || /^\s*SPDXID\s*:\s*SPDXRef-DOCUMENT\s*$/im.test(content);
    }
    catch {
        return false;
    }
    finally {
        await handle?.close().catch(() => undefined);
    }
};
const scanRepositoryFiles = async (repoPath) => {
    const sbomFiles = [];
    const manifestFiles = [];
    const queue = [''];
    while (queue.length > 0) {
        const relativeDir = queue.shift() || '';
        const absoluteDir = path_1.default.join(repoPath, relativeDir);
        const entries = await promises_1.default.readdir(absoluteDir, { withFileTypes: true });
        for (const entry of entries) {
            const relativePath = path_1.default.join(relativeDir, entry.name).replace(/\\/g, '/');
            if (entry.isDirectory()) {
                if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor')
                    continue;
                queue.push(relativePath);
                continue;
            }
            if (!entry.isFile())
                continue;
            const lowerName = entry.name.toLowerCase();
            const lowerPath = relativePath.toLowerCase();
            if (hasSbomLikeName(lowerName, lowerPath) && await hasSbomDocumentSignature(path_1.default.join(repoPath, relativePath))) {
                sbomFiles.push(relativePath);
            }
            if (MANIFEST_FILE_NAMES.has(lowerName))
                manifestFiles.push(relativePath);
        }
    }
    return {
        detectedSbomFiles: sbomFiles.sort(),
        detectedManifestFiles: manifestFiles.sort(),
    };
};
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
    const syftTarget = `dir:${path_1.default.resolve(repoPath)}`;
    const cacheDir = path_1.default.join(tempRoot, 'cache');
    try {
        await promises_1.default.mkdir(tempRoot, { recursive: true });
        await promises_1.default.mkdir(cacheDir, { recursive: true });
        const gitBin = process.env.GIT_BIN || 'git';
        try {
            await execFilePromise(gitBin, ['-c', 'core.longpaths=true', 'clone', '--depth', '1', normalizedRepoUrl, repoPath], { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER });
        }
        catch (error) {
            const message = error?.stderr || error?.stdout || error?.message || 'Failed to clone GitHub repository';
            throw new Error(`Git clone failed for ${normalizedRepoUrl}: ${String(message).trim()}`);
        }
        const detectedFiles = await scanRepositoryFiles(repoPath);
        const syftBin = process.env.SYFT_BIN || 'syft';
        const sbomOutputFile = path_1.default.join(tempRoot, 'sbom-output.json');
        try {
            const result = await execFilePromise(syftBin, [
                syftTarget,
                '--base-path', path_1.default.resolve(repoPath),
                // Đã xóa cờ '--name' / '--source-name' ở đây
                '-o', `cyclonedx-json=${sbomOutputFile}`,
                '-q'
            ], {
                timeout: TIMEOUT_MS * 3, // Giữ nguyên việc tăng timeout
                maxBuffer: MAX_BUFFER,
                env: {
                    ...process.env,
                    XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
                    SYFT_CHECK_FOR_APP_UPDATE: 'false',
                },
            });
        }
        catch (error) {
            const message = error?.stderr || error?.stdout || error?.message || 'Failed to generate SBOM with Syft';
            throw new Error(`Syft scan failed for ${syftTarget}: ${String(message).trim()}`);
        }
        // Đọc SBOM trực tiếp từ file đã được lưu vào ổ cứng
        const sbomContent = await promises_1.default.readFile(sbomOutputFile, 'utf8');
        const sbom = JSON.parse(sbomContent);
        const inferredMetadata = await metadataInferenceService_1.metadataInferenceService.infer(repoPath, {
            repoUrl: normalizedRepoUrl,
            repoName,
            context: 'manual',
        });
        const enrichedSbom = metadataInferenceService_1.metadataInferenceService.injectIntoCycloneDx(sbom, inferredMetadata);
        return { sbom: enrichedSbom, normalizedRepoUrl, repoName, inferredMetadata, ...detectedFiles };
    }
    catch (error) {
        throw new Error(String(error?.message || 'Failed to generate SBOM with Syft').trim());
    }
    finally {
        await promises_1.default.rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
    }
};
exports.generateSbomFromGitHubRepo = generateSbomFromGitHubRepo;

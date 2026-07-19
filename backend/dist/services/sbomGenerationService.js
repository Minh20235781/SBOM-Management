"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomGenerationService = void 0;
const child_process_1 = require("child_process");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const util_1 = __importDefault(require("util"));
const sourceCloneService_1 = require("./sourceCloneService");
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const MAX_BUFFER = 100 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 180000);
const outputRootName = 'generated';
exports.sbomGenerationService = {
    generateCycloneDxFromSource: async (repoPath, scenarioId) => {
        const syftBin = process.env.SYFT_BIN || 'syft';
        const started = Date.now();
        const workDir = await sourceCloneService_1.sourceCloneService.ensureWorkDir();
        const cacheDir = path_1.default.join(workDir, 'cache');
        const syftTarget = `dir:${path_1.default.resolve(repoPath)}`;
        await promises_1.default.mkdir(cacheDir, { recursive: true });
        let stdout;
        try {
            const result = await execFilePromise(syftBin, [syftTarget, '--base-path', path_1.default.resolve(repoPath), '--source-name', path_1.default.basename(repoPath), '-vv', '-o', 'cyclonedx-json'], {
                timeout: TIMEOUT_MS,
                maxBuffer: MAX_BUFFER,
                env: {
                    ...process.env,
                    XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
                    SYFT_CHECK_FOR_APP_UPDATE: 'false',
                },
            });
            stdout = result.stdout;
        }
        catch (error) {
            const message = error?.stderr || error?.stdout || error?.message || 'Failed to generate SBOM with Syft';
            throw new Error(`Syft scan failed for ${syftTarget}: ${String(message).trim()}`);
        }
        const analysisDurationMs = Date.now() - started;
        const sbom = JSON.parse(stdout);
        const outputDir = path_1.default.join(workDir, outputRootName);
        await promises_1.default.mkdir(outputDir, { recursive: true });
        const sbomPath = path_1.default.join(outputDir, `${scenarioId}-${Date.now()}-cyclonedx.json`);
        await promises_1.default.writeFile(sbomPath, JSON.stringify(sbom, null, 2), 'utf8');
        const stat = await promises_1.default.stat(sbomPath);
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

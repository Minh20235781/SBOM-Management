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
const gitConfigArgs = () => {
    const args = ['-c', 'core.longpaths=true'];
    if (process.env.GIT_SSL_BACKEND)
        args.push('-c', `http.sslBackend=${process.env.GIT_SSL_BACKEND}`);
    if (process.env.GIT_SSL_VERIFY === 'false')
        args.push('-c', 'http.sslVerify=false');
    return args;
};
exports.sourceCloneService = {
    cloneOrUpdate: async (scenarioId, githubUrl) => {
        await promises_1.default.mkdir(sourceRoot, { recursive: true });
        const repoPath = path_1.default.join(sourceRoot, safeName(scenarioId));
        const gitBin = process.env.GIT_BIN || 'git';
        await promises_1.default.rm(repoPath, { recursive: true, force: true }).catch(() => undefined);
        await execFilePromise(gitBin, [...gitConfigArgs(), 'clone', '--depth', '1', githubUrl, repoPath], {
            timeout: TIMEOUT_MS,
            maxBuffer: MAX_BUFFER,
        });
        return repoPath;
    },
    ensureWorkDir: async () => {
        await promises_1.default.mkdir(workspaceRoot, { recursive: true });
        return workspaceRoot;
    },
};

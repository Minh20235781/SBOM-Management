"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.dependencyFileDetectorService = void 0;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const dependencyFileNames = new Set([
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'pom.xml',
    'requirements.txt',
    'composer.json',
    'composer.lock',
    'Gemfile',
    'Gemfile.lock',
    'go.mod',
    'go.sum',
]);
const ignoredDirs = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.next', '.cache']);
const walk = async (root, current, files) => {
    const entries = await promises_1.default.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
        const absolute = path_1.default.join(current, entry.name);
        if (entry.isDirectory()) {
            if (!ignoredDirs.has(entry.name))
                await walk(root, absolute, files);
            continue;
        }
        if (!entry.isFile() || !dependencyFileNames.has(entry.name))
            continue;
        const stat = await promises_1.default.stat(absolute);
        files.push({
            path: path_1.default.relative(root, absolute).replace(/\\/g, '/'),
            name: entry.name,
            sizeBytes: stat.size,
        });
    }
};
exports.dependencyFileDetectorService = {
    detect: async (repoPath) => {
        const files = [];
        await walk(repoPath, repoPath, files);
        return files.sort((left, right) => left.path.localeCompare(right.path));
    },
};

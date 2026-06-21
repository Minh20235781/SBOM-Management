"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.repositorySbomDetectorService = void 0;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const ignoredDirectories = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.next', '.cache']);
const exactNames = new Set([
    'sbom.json', 'bom.json', 'cyclonedx.json', 'bom.xml', 'sbom.xml',
    'spdx.json', 'spdx.yaml', 'spdx.yml', 'sbom.spdx.json',
]);
const looksLikeSbom = (name) => {
    const lower = name.toLowerCase();
    return exactNames.has(lower)
        || /(?:^|[._-])(sbom|cyclonedx|spdx)(?:[._-]|$)/.test(lower)
        || lower.endsWith('.cdx.json');
};
const identifyJsonFormat = (payload) => {
    if (payload?.bomFormat === 'CycloneDX' || (Array.isArray(payload?.components) && payload?.specVersion))
        return 'CycloneDX';
    if (payload?.spdxVersion || payload?.SPDXID)
        return 'SPDX';
    return null;
};
const inferSourceCommit = (payload) => {
    const properties = [
        ...(Array.isArray(payload?.metadata?.properties) ? payload.metadata.properties : []),
        ...(Array.isArray(payload?.metadata?.component?.properties) ? payload.metadata.component.properties : []),
    ];
    const property = properties.find((item) => /(?:git|vcs).*(?:commit|revision)|(?:commit|revision).*(?:git|vcs)/i.test(String(item?.name || '')));
    const value = String(property?.value || '').trim();
    return /^[a-f0-9]{7,64}$/i.test(value) ? value : null;
};
exports.repositorySbomDetectorService = {
    detect: async (repoPath) => {
        const candidates = [];
        const walk = async (directory, depth) => {
            if (depth > 6)
                return;
            const entries = await promises_1.default.readdir(directory, { withFileTypes: true }).catch(() => []);
            for (const entry of entries) {
                const absolutePath = path_1.default.join(directory, entry.name);
                if (entry.isDirectory()) {
                    if (!ignoredDirectories.has(entry.name))
                        await walk(absolutePath, depth + 1);
                    continue;
                }
                if (!entry.isFile() || !looksLikeSbom(entry.name))
                    continue;
                const stat = await promises_1.default.stat(absolutePath);
                let format = 'Unknown';
                let parseable = false;
                let componentCount = 0;
                let sourceCommit = null;
                if (entry.name.toLowerCase().endsWith('.json')) {
                    try {
                        const payload = JSON.parse(await promises_1.default.readFile(absolutePath, 'utf8'));
                        format = identifyJsonFormat(payload) || 'Unknown';
                        parseable = format !== 'Unknown';
                        componentCount = format === 'CycloneDX'
                            ? (Array.isArray(payload.components) ? payload.components.length : 0)
                            : (Array.isArray(payload.packages) ? payload.packages.length : 0);
                        sourceCommit = inferSourceCommit(payload);
                    }
                    catch { /* Candidate remains visible with parseable=false. */ }
                }
                candidates.push({
                    path: path_1.default.relative(repoPath, absolutePath).replace(/\\/g, '/'),
                    absolutePath,
                    sizeBytes: stat.size,
                    format,
                    parseable,
                    componentCount,
                    sourceCommit,
                });
            }
        };
        await walk(repoPath, 0);
        candidates.sort((left, right) => Number(right.parseable) - Number(left.parseable) || left.path.localeCompare(right.path));
        const selected = candidates.find(file => file.parseable) || null;
        return {
            detected: candidates.length > 0,
            usableForVerification: Boolean(selected),
            files: candidates.map(({ absolutePath: _absolutePath, ...file }) => file),
            selectedPath: selected?.absolutePath || null,
            selectedFile: selected ? (({ absolutePath: _absolutePath, ...file }) => file)(selected) : null,
        };
    },
};

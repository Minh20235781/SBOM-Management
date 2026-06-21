"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.artifactScannerService = exports.dependencyExtractorService = void 0;
const sbomAlgorithms_1 = require("./sbomAlgorithms");
const trackedFileNames = new Set([
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'poetry.lock',
    'pom.xml',
    'build.gradle',
    'Dockerfile',
]);
const basename = (artifactPath) => artifactPath.replace(/\\/g, '/').split('/').pop() || artifactPath;
const cleanVersion = (value) => {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    if (!trimmed)
        return null;
    return trimmed.replace(/^[\^~>=<\s]+/, '') || trimmed;
};
const purlFor = (ecosystem, name, version) => {
    const encodedName = name.replace(/^@/, '%40');
    return version ? `pkg:${ecosystem}/${encodedName}@${version}` : `pkg:${ecosystem}/${encodedName}`;
};
const dependencyToComponent = (dep) => {
    const purl = purlFor(dep.ecosystem, dep.name, dep.version);
    const component = {
        componentId: purl,
        stableKey: '',
        name: dep.name,
        version: dep.version,
        purl,
        ecosystem: dep.ecosystem,
        supplier: null,
        licenses: null,
        hashes: null,
    };
    component.stableKey = `${dep.ecosystem}:${dep.name}`.toLowerCase();
    return component;
};
const parsePackageJson = (content, sourcePath) => {
    const parsed = JSON.parse(content);
    const groups = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
    const deps = [];
    for (const group of groups) {
        const entries = parsed[group] || {};
        for (const [name, version] of Object.entries(entries)) {
            deps.push({ ecosystem: 'npm', name, version: cleanVersion(version), scope: group, sourcePath });
        }
    }
    return deps;
};
const parsePackageLock = (content, sourcePath) => {
    const parsed = JSON.parse(content);
    const deps = [];
    const edges = [];
    if (parsed.packages && typeof parsed.packages === 'object') {
        const keyByPackagePath = new Map();
        for (const [pkgPath, info] of Object.entries(parsed.packages)) {
            if (!pkgPath.startsWith('node_modules/'))
                continue;
            const name = pkgPath.replace(/^node_modules\//, '');
            const dep = { ecosystem: 'npm', name, version: cleanVersion(info.version), sourcePath };
            deps.push(dep);
            keyByPackagePath.set(pkgPath, (0, sbomAlgorithms_1.stableComponentKey)({ purl: purlFor(dep.ecosystem, dep.name, dep.version) }));
        }
        for (const [pkgPath, info] of Object.entries(parsed.packages)) {
            if (!pkgPath.startsWith('node_modules/') || !info.dependencies)
                continue;
            const sourceKey = keyByPackagePath.get(pkgPath);
            if (!sourceKey)
                continue;
            for (const depName of Object.keys(info.dependencies)) {
                const targetPath = `node_modules/${depName}`;
                const targetKey = keyByPackagePath.get(targetPath);
                if (targetKey)
                    edges.push([sourceKey, targetKey]);
            }
        }
    }
    else if (parsed.dependencies && typeof parsed.dependencies === 'object') {
        for (const [name, info] of Object.entries(parsed.dependencies)) {
            deps.push({ ecosystem: 'npm', name, version: cleanVersion(info.version), sourcePath });
        }
    }
    return { deps, edges };
};
const parseRequirements = (content, sourcePath) => content.split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith('-'))
    .map(line => {
    const match = line.match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^;#\s]+)?/);
    return match ? { ecosystem: 'pypi', name: match[1], version: cleanVersion(match[2]), sourcePath } : null;
})
    .filter((dep) => Boolean(dep));
const parsePomXml = (content, sourcePath) => {
    const deps = [];
    const blocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
    for (const block of blocks) {
        const groupId = block.match(/<groupId>(.*?)<\/groupId>/)?.[1]?.trim();
        const artifactId = block.match(/<artifactId>(.*?)<\/artifactId>/)?.[1]?.trim();
        const version = block.match(/<version>(.*?)<\/version>/)?.[1]?.trim();
        if (artifactId)
            deps.push({ ecosystem: 'maven', name: groupId ? `${groupId}:${artifactId}` : artifactId, version: cleanVersion(version), sourcePath });
    }
    return deps;
};
const parseBuildGradle = (content, sourcePath) => {
    const deps = [];
    const regex = /(implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]/g;
    let match;
    while ((match = regex.exec(content))) {
        deps.push({ ecosystem: 'maven', name: `${match[2]}:${match[3]}`, version: cleanVersion(match[4]), scope: match[1], sourcePath });
    }
    return deps;
};
const parseDockerfile = (content, sourcePath) => content.split(/\r?\n/)
    .map(line => line.trim().match(/^FROM\s+([^\s]+)(?:\s+AS\s+\S+)?/i)?.[1])
    .filter((image) => Boolean(image))
    .map(image => {
    const [name, tag] = image.split(':');
    return { ecosystem: 'docker', name, version: cleanVersion(tag || 'latest'), sourcePath };
});
exports.dependencyExtractorService = {
    extract: (artifact) => {
        const name = basename(artifact.artifactPath);
        try {
            if (name === 'package.json')
                return { deps: parsePackageJson(artifact.content, artifact.artifactPath), edges: [] };
            if (name === 'package-lock.json')
                return parsePackageLock(artifact.content, artifact.artifactPath);
            if (name === 'requirements.txt')
                return { deps: parseRequirements(artifact.content, artifact.artifactPath), edges: [] };
            if (name === 'pom.xml')
                return { deps: parsePomXml(artifact.content, artifact.artifactPath), edges: [] };
            if (name === 'build.gradle')
                return { deps: parseBuildGradle(artifact.content, artifact.artifactPath), edges: [] };
            if (name === 'Dockerfile')
                return { deps: parseDockerfile(artifact.content, artifact.artifactPath), edges: [] };
        }
        catch {
            return { deps: [], edges: [] };
        }
        return { deps: [], edges: [] };
    },
};
const isTrackedFile = (artifactPath) => trackedFileNames.has(basename(artifactPath));
const normalizeArtifacts = (files) => files
    .filter(file => file.artifactPath && typeof file.content === 'string' && isTrackedFile(file.artifactPath))
    .map(file => ({
    artifactPath: file.artifactPath,
    artifactName: file.artifactName || basename(file.artifactPath),
    artifactType: file.artifactType || basename(file.artifactPath),
    content: file.content,
    hash: (0, sbomAlgorithms_1.sha256Json)({ path: file.artifactPath, content: file.content }),
}));
exports.artifactScannerService = {
    isTrackedFile,
    normalizeArtifacts,
    scanArtifacts: (projectId, files) => {
        const artifacts = normalizeArtifacts(files);
        const projectComponent = {
            componentId: `project:${projectId}`,
            stableKey: `project:${projectId}`,
            name: `project-${projectId}`,
            version: null,
            purl: null,
            ecosystem: 'project',
            supplier: null,
            licenses: null,
            hashes: null,
        };
        const components = new Map([[projectComponent.stableKey, projectComponent]]);
        const dependencies = [];
        const edgeSet = new Set();
        for (const artifact of artifacts) {
            const extracted = exports.dependencyExtractorService.extract(artifact);
            for (const dep of extracted.deps) {
                const component = dependencyToComponent(dep);
                components.set(component.stableKey, component);
                const edgeKey = `${projectComponent.stableKey}->${component.stableKey}`;
                if (!edgeSet.has(edgeKey)) {
                    dependencies.push({ sourceKey: projectComponent.stableKey, targetKey: component.stableKey, relationship: 'DEPENDS_ON' });
                    edgeSet.add(edgeKey);
                }
            }
            for (const [sourceKey, targetKey] of extracted.edges) {
                const edgeKey = `${sourceKey}->${targetKey}`;
                if (components.has(sourceKey) && components.has(targetKey) && !edgeSet.has(edgeKey)) {
                    dependencies.push({ sourceKey, targetKey, relationship: 'DEPENDS_ON' });
                    edgeSet.add(edgeKey);
                }
            }
        }
        return {
            artifacts,
            normalized: {
                components: [...components.values()],
                dependencies,
                vulnerabilities: [],
                rootKey: projectComponent.stableKey,
                format: 'INTERNAL',
            },
        };
    },
    saveProjectArtifacts: async (client, projectId, files) => {
        const artifacts = normalizeArtifacts(files);
        for (const artifact of artifacts) {
            await client.query(`INSERT INTO project_artifacts (project_id, artifact_path, artifact_name, artifact_type, content, hash, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
         ON CONFLICT (project_id, artifact_path) DO UPDATE SET
          artifact_name = EXCLUDED.artifact_name,
          artifact_type = EXCLUDED.artifact_type,
          content = EXCLUDED.content,
          hash = EXCLUDED.hash,
          updated_at = CURRENT_TIMESTAMP`, [projectId, artifact.artifactPath, artifact.artifactName, artifact.artifactType, artifact.content, artifact.hash]);
        }
        return artifacts;
    },
    loadProjectArtifacts: async (client, projectId) => {
        const { rows } = await client.query('SELECT artifact_path, artifact_name, artifact_type, content FROM project_artifacts WHERE project_id = $1 ORDER BY artifact_path', [projectId]);
        return rows.map(row => ({
            artifactPath: row.artifact_path,
            artifactName: row.artifact_name,
            artifactType: row.artifact_type,
            content: row.content,
        }));
    },
};

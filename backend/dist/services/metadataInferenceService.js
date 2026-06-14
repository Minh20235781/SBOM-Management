"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.metadataInferenceService = void 0;
const child_process_1 = require("child_process");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const util_1 = __importDefault(require("util"));
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const validPhases = new Set(['Plan', 'Code', 'Build', 'Test', 'Release', 'Deploy', 'Operate', 'Monitor']);
const missing = (reason) => ({
    value: 'Không phát hiện được từ mã nguồn',
    source: 'not-detected',
    confidence: 'low',
    reason,
});
const unique = (items) => [...new Set(items.map(item => item.trim()).filter(Boolean))];
const readTextIfExists = async (filePath) => {
    try {
        return await promises_1.default.readFile(filePath, 'utf8');
    }
    catch {
        return null;
    }
};
const findFiles = async (root, names, maxDepth = 4) => {
    const results = [];
    const ignored = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.next']);
    const walk = async (dir, depth) => {
        if (depth > maxDepth)
            return;
        const entries = await promises_1.default.readdir(dir, { withFileTypes: true }).catch(() => []);
        for (const entry of entries) {
            const absolute = path_1.default.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (!ignored.has(entry.name))
                    await walk(absolute, depth + 1);
            }
            else if (entry.isFile() && names.has(entry.name)) {
                results.push(absolute);
            }
        }
    };
    await walk(root, 0);
    return results;
};
const normalizeAuthor = (value) => {
    if (!value)
        return null;
    if (typeof value === 'string')
        return value.trim() || null;
    if (typeof value === 'object') {
        const raw = value;
        const name = raw.name?.trim();
        const email = raw.email?.trim();
        if (name && email)
            return `${name} <${email}>`;
        return name || email || raw.url || null;
    }
    return null;
};
const inferGitAuthors = async (repoPath) => {
    try {
        const gitBin = process.env.GIT_BIN || 'git';
        const { stdout } = await execFilePromise(gitBin, ['-C', repoPath, 'log', '--format=%an <%ae>', '--max-count=80'], {
            timeout: 15000,
            maxBuffer: 1024 * 1024,
        });
        return unique(stdout.split(/\r?\n/)).slice(0, 12);
    }
    catch {
        return [];
    }
};
const inferPackageJson = async (repoPath) => {
    const content = await readTextIfExists(path_1.default.join(repoPath, 'package.json'));
    if (!content)
        return { authors: [], serviceName: null };
    try {
        const parsed = JSON.parse(content);
        const authors = [
            normalizeAuthor(parsed.author),
            ...(Array.isArray(parsed.contributors) ? parsed.contributors.map(normalizeAuthor) : []),
        ].filter((item) => Boolean(item));
        return {
            authors: unique(authors),
            serviceName: typeof parsed.name === 'string' && parsed.name.trim() ? parsed.name.trim() : null,
        };
    }
    catch {
        return { authors: [], serviceName: null };
    }
};
const inferComposerJson = async (repoPath) => {
    const content = await readTextIfExists(path_1.default.join(repoPath, 'composer.json'));
    if (!content)
        return { authors: [], serviceName: null };
    try {
        const parsed = JSON.parse(content);
        const authors = Array.isArray(parsed.authors) ? parsed.authors.map(normalizeAuthor).filter(Boolean) : [];
        return {
            authors: unique(authors),
            serviceName: typeof parsed.name === 'string' && parsed.name.trim() ? parsed.name.trim() : null,
        };
    }
    catch {
        return { authors: [], serviceName: null };
    }
};
const inferPomXml = async (repoPath) => {
    const content = await readTextIfExists(path_1.default.join(repoPath, 'pom.xml'));
    if (!content)
        return { authors: [], serviceName: null };
    const developers = [...content.matchAll(/<developer>[\s\S]*?<\/developer>/g)]
        .map(match => {
        const block = match[0];
        const name = block.match(/<name>(.*?)<\/name>/)?.[1]?.trim();
        const email = block.match(/<email>(.*?)<\/email>/)?.[1]?.trim();
        return name && email ? `${name} <${email}>` : name || email || null;
    })
        .filter((item) => Boolean(item));
    const name = content.match(/<name>(.*?)<\/name>/)?.[1]?.trim();
    const artifactId = content.match(/<artifactId>(.*?)<\/artifactId>/)?.[1]?.trim();
    return { authors: unique(developers), serviceName: name || artifactId || null };
};
const inferReadmeTitle = async (repoPath) => {
    const files = await findFiles(repoPath, new Set(['README.md', 'readme.md', 'README']), 2);
    for (const file of files) {
        const content = await readTextIfExists(file);
        const title = content?.split(/\r?\n/).find(line => line.trim().startsWith('# '));
        if (title)
            return title.replace(/^#\s+/, '').trim();
    }
    return null;
};
const inferDockerComposeServices = async (repoPath) => {
    const files = await findFiles(repoPath, new Set(['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']), 4);
    const services = [];
    for (const file of files) {
        const content = await readTextIfExists(file);
        if (!content)
            continue;
        const lines = content.split(/\r?\n/);
        const servicesIndex = lines.findIndex(line => /^services:\s*$/.test(line.trim()));
        if (servicesIndex < 0)
            continue;
        for (const line of lines.slice(servicesIndex + 1)) {
            if (/^\S/.test(line) && !line.startsWith('services:'))
                break;
            const match = line.match(/^\s{2,}([A-Za-z0-9_.-]+):\s*$/);
            if (match && !['image', 'build', 'ports', 'environment', 'volumes', 'depends_on'].includes(match[1])) {
                services.push(match[1]);
            }
        }
    }
    return unique(services);
};
const inferKubernetesServices = async (repoPath) => {
    const files = await findFiles(repoPath, new Set(['deployment.yaml', 'deployment.yml', 'service.yaml', 'service.yml', 'k8s.yaml', 'k8s.yml']), 5);
    const services = [];
    for (const file of files) {
        const content = await readTextIfExists(file);
        if (!content || !/kind:\s*(Service|Deployment)/i.test(content))
            continue;
        const name = content.match(/metadata:\s*[\s\S]*?\n\s+name:\s*([A-Za-z0-9_.-]+)/)?.[1];
        if (name)
            services.push(name);
    }
    return unique(services);
};
const githubOwner = (repoUrl) => {
    try {
        const parsed = new URL(repoUrl.replace(/\.git$/i, ''));
        return parsed.pathname.split('/').filter(Boolean)[0] || null;
    }
    catch {
        return null;
    }
};
const hasReleaseTag = async (repoPath) => {
    try {
        const gitBin = process.env.GIT_BIN || 'git';
        const { stdout } = await execFilePromise(gitBin, ['-C', repoPath, 'describe', '--tags', '--exact-match'], {
            timeout: 5000,
            maxBuffer: 1024 * 128,
        });
        return Boolean(stdout.trim());
    }
    catch {
        return false;
    }
};
const hasDeploymentManifests = async (repoPath) => {
    const files = await findFiles(repoPath, new Set([
        'Dockerfile',
        'docker-compose.yml',
        'docker-compose.yaml',
        'compose.yml',
        'compose.yaml',
        'deployment.yaml',
        'deployment.yml',
        'service.yaml',
        'service.yml',
        'k8s.yaml',
        'k8s.yml',
    ]), 5);
    return files.length > 0;
};
exports.metadataInferenceService = {
    infer: async (repoPath, options) => {
        const [gitAuthors, packageMeta, pomMeta, composerMeta] = await Promise.all([
            inferGitAuthors(repoPath),
            inferPackageJson(repoPath),
            inferPomXml(repoPath),
            inferComposerJson(repoPath),
        ]);
        const owner = githubOwner(options.repoUrl);
        const fallbackAuthors = unique([...packageMeta.authors, ...pomMeta.authors, ...composerMeta.authors, owner || '']);
        const authors = gitAuthors.length > 0
            ? { value: gitAuthors, source: 'git log commit authors', confidence: 'high' }
            : fallbackAuthors.length > 0
                ? { value: fallbackAuthors, source: 'package/pom/composer metadata or GitHub owner fallback', confidence: 'medium' }
                : missing('Không có git log, package.json author/contributors, pom.xml developers, composer.json authors hoặc GitHub owner.');
        const [composeServices, kubernetesServices, readmeTitle] = await Promise.all([
            inferDockerComposeServices(repoPath),
            inferKubernetesServices(repoPath),
            inferReadmeTitle(repoPath),
        ]);
        const packageNames = unique([packageMeta.serviceName || '', pomMeta.serviceName || '', composerMeta.serviceName || '', readmeTitle || '']);
        const services = composeServices.length > 0
            ? { value: composeServices, source: 'docker-compose services', confidence: 'high' }
            : kubernetesServices.length > 0
                ? { value: kubernetesServices, source: 'Kubernetes manifests', confidence: 'high' }
                : packageNames.length > 0
                    ? { value: packageNames, source: 'package.json/pom.xml/composer.json/README title', confidence: 'medium' }
                    : options.repoName
                        ? { value: [options.repoName], source: 'repository name fallback', confidence: 'low' }
                        : missing('Không có docker-compose, Kubernetes manifest, package metadata, README title hoặc tên repository.');
        const deploy = await hasDeploymentManifests(repoPath);
        const release = options.context === 'release' || await hasReleaseTag(repoPath);
        const phase = options.context === 'verify'
            ? 'Test'
            : options.context === 'ci'
                ? 'Build'
                : release
                    ? 'Release'
                    : 'Code';
        const suggestions = deploy ? ['Deploy'] : [];
        const lifecyclePhase = {
            value: validPhases.has(phase) ? phase : 'Code',
            source: release ? 'release tag/context' : options.context === 'ci' ? 'CI/CD context' : options.context === 'verify' ? 'verify context' : 'manual GitHub/source analyze context',
            confidence: options.context === 'manual' || !options.context ? 'medium' : 'high',
            reason: deploy ? 'Phát hiện Docker/Kubernetes/deployment manifests; có thể gợi ý thêm phase Deploy.' : undefined,
            suggestions,
        };
        return { authors, services, lifecyclePhase };
    },
    injectIntoCycloneDx: (sbom, inferred) => {
        const cloned = JSON.parse(JSON.stringify(sbom || {}));
        cloned.metadata = cloned.metadata || {};
        const authorValues = Array.isArray(inferred.authors.value) ? inferred.authors.value : [String(inferred.authors.value)];
        cloned.metadata.authors = authorValues.map(author => ({ name: author }));
        const serviceValues = Array.isArray(inferred.services.value) ? inferred.services.value : [String(inferred.services.value)];
        cloned.services = serviceValues.map(service => ({ name: service }));
        const properties = Array.isArray(cloned.metadata.properties) ? cloned.metadata.properties : [];
        const withoutManaged = properties.filter((item) => ![
            'devops.lifecycle.phase',
            'devops.lifecycle.phase.source',
            'metadata.authors.source',
            'metadata.services.source',
        ].includes(item?.name));
        cloned.metadata.properties = [
            ...withoutManaged,
            { name: 'devops.lifecycle.phase', value: String(inferred.lifecyclePhase.value) },
            { name: 'devops.lifecycle.phase.source', value: inferred.lifecyclePhase.source },
            { name: 'metadata.authors.source', value: inferred.authors.source },
            { name: 'metadata.services.source', value: inferred.services.source },
        ];
        cloned.metadata.lifecycle_phase = String(inferred.lifecyclePhase.value);
        cloned.lifecycle_phase = String(inferred.lifecyclePhase.value);
        return cloned;
    },
};

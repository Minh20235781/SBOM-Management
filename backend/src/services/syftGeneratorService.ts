import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import { metadataInferenceService, InferredMetadata } from './metadataInferenceService';
import { normalizeSbomPayload, stableComponentKey, type NormalizedComponent } from './sbomAlgorithms';
import { scanSBOMWithGrypeReport, type GrypeFinding } from './grypeScannerService';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.SYFT_TIMEOUT_MS || 120000);

export interface GeneratedSbomResult {
  sbom: any;
  normalizedRepoUrl: string;
  repoName: string;
  inferredMetadata?: InferredMetadata;
  detectedSbomFiles: string[];
  detectedManifestFiles: string[];
  analysis: {
    repoUrl: string;
    repoName: string;
    bomFormat: string;
    specVersion?: string | null;
    serialNumber?: string | null;
    componentCount: number;
    syftComponentCount: number;
    webAddedComponentCount: number;
    dependencyCount: number;
    dependencyReferenceCount: number;
    ecosystems: string[];
    toolInfo: string;
    createdTimestamp: string;
    sbomSizeBytes: number;
    analysisDurationMs: number;
    embeddedVulnerabilityCount: number;
    vulnerabilityFindingCount: number;
    inferredMetadata?: InferredMetadata | null;
    hasExistingSbom: boolean;
    detectedSbomFiles: string[];
    detectedManifestFiles: string[];
  };
}

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

const hasSbomLikeName = (lowerName: string, lowerPath: string) => {
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

const hasSbomDocumentSignature = async (filePath: string) => {
  let handle: fs.FileHandle | null = null;
  try {
    handle = await fs.open(filePath, 'r');
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
  } catch {
    return false;
  } finally {
    await handle?.close().catch(() => undefined);
  }
};

const scanRepositoryFiles = async (repoPath: string) => {
  const sbomFiles: string[] = [];
  const manifestFiles: string[] = [];
  const queue = [''];

  while (queue.length > 0) {
    const relativeDir = queue.shift() || '';
    const absoluteDir = path.join(repoPath, relativeDir);
    const entries = await fs.readdir(absoluteDir, { withFileTypes: true });

    for (const entry of entries) {
      const relativePath = path.join(relativeDir, entry.name).replace(/\\/g, '/');
      if (entry.isDirectory()) {
        if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor') continue;
        queue.push(relativePath);
        continue;
      }

      if (!entry.isFile()) continue;
      const lowerName = entry.name.toLowerCase();
      const lowerPath = relativePath.toLowerCase();
      if (hasSbomLikeName(lowerName, lowerPath) && await hasSbomDocumentSignature(path.join(repoPath, relativePath))) {
        sbomFiles.push(relativePath);
      }
      if (MANIFEST_FILE_NAMES.has(lowerName)) manifestFiles.push(relativePath);
    }
  }

  return {
    detectedSbomFiles: sbomFiles.sort(),
    detectedManifestFiles: manifestFiles.sort(),
  };
};

const componentKey = (component: any) => stableComponentKey({
  purl: component?.purl || null,
  ecosystem: component?.type || null,
  name: component?.name || null,
  version: component?.version || null,
  hashes: null,
});

const componentBomRef = (component: any, fallbackIndex: number) => component?.['bom-ref']
  || component?.bomRef
  || component?.purl
  || `${component?.name || 'component'}@${component?.version || fallbackIndex}`;

const normalizedComponentToCycloneDx = (component: NormalizedComponent, fallbackIndex: number) => ({
  type: component.ecosystem && component.ecosystem !== 'unknown' ? component.ecosystem : 'library',
  name: component.name,
  version: component.version || undefined,
  purl: component.purl || undefined,
  'bom-ref': component.componentId || component.purl || component.stableKey || `web-${fallbackIndex}`,
  supplier: component.supplier ? { name: component.supplier } : undefined,
});

const mergeDetectedSbomComponents = async (repoPath: string, detectedSbomFiles: string[], baseSbom: any) => {
  const components = Array.isArray(baseSbom?.components) ? [...baseSbom.components] : [];
  const dependencies = Array.isArray(baseSbom?.dependencies) ? [...baseSbom.dependencies] : [];
  const vulnerabilities = Array.isArray(baseSbom?.vulnerabilities) ? [...baseSbom.vulnerabilities] : [];
  const seenComponents = new Set(components.map(componentKey));
  const seenDependencies = new Set(dependencies.map((dep: any) => `${dep?.ref || ''}->${Array.isArray(dep?.dependsOn) ? dep.dependsOn.join('|') : ''}`));
  const seenVulnerabilities = new Set(vulnerabilities.map((vuln: any) => `${vuln?.id || vuln?.cve || ''}:${Array.isArray(vuln?.affects) ? vuln.affects.map((affect: any) => affect?.ref || '').join('|') : ''}`));
  let webAddedComponentCount = 0;

  for (const relativePath of detectedSbomFiles) {
    if (!relativePath.toLowerCase().endsWith('.json')) continue;
    const absolutePath = path.join(repoPath, relativePath);
    let parsed: any;
    try {
      parsed = JSON.parse(await fs.readFile(absolutePath, 'utf8'));
    } catch {
      continue;
    }

    const normalized = normalizeSbomPayload(parsed);
    for (const [index, component] of normalized.components.entries()) {
      const rawComponent = normalizedComponentToCycloneDx(component, index);
      const key = componentKey(rawComponent);
      if (seenComponents.has(key)) continue;
      seenComponents.add(key);
      components.push(rawComponent);
      webAddedComponentCount += 1;
    }

    for (const dependency of Array.isArray(parsed?.dependencies) ? parsed.dependencies : []) {
      const dependencyKey = `${dependency?.ref || ''}->${Array.isArray(dependency?.dependsOn) ? dependency.dependsOn.join('|') : ''}`;
      if (seenDependencies.has(dependencyKey)) continue;
      seenDependencies.add(dependencyKey);
      dependencies.push(dependency);
    }

    for (const vulnerability of Array.isArray(parsed?.vulnerabilities) ? parsed.vulnerabilities : []) {
      const vulnerabilityKey = `${vulnerability?.id || vulnerability?.cve || ''}:${Array.isArray(vulnerability?.affects) ? vulnerability.affects.map((affect: any) => affect?.ref || '').join('|') : ''}`;
      if (seenVulnerabilities.has(vulnerabilityKey)) continue;
      seenVulnerabilities.add(vulnerabilityKey);
      vulnerabilities.push(vulnerability);
    }
  }

  return { components, dependencies, vulnerabilities, webAddedComponentCount };
};

const grypeFindingToCycloneDxVulnerability = (finding: GrypeFinding, componentRef: string | null) => ({
  id: finding.cve_id || finding.vulnerability,
  ratings: [{ severity: finding.severity }],
  description: finding.description || undefined,
  affects: componentRef ? [{ ref: componentRef }] : [],
});

const indexComponentsByRef = (components: any[]) => {
  const byRef = new Map<string, string>();
  for (const component of components) {
    const ref = componentBomRef(component, byRef.size);
    const key = componentKey(component);
    byRef.set(ref, ref);
    byRef.set(key, ref);
    if (typeof component?.purl === 'string') byRef.set(component.purl, ref);
    if (typeof component?.name === 'string') byRef.set(`${component.name}@${component.version || ''}`, ref);
  }
  return byRef;
};

const enrichWithGrypeFindings = async (sbom: any) => {
  const report = await scanSBOMWithGrypeReport(sbom);
  if (report.status !== 'COMPLETED' || report.findings.length === 0) {
    return { report, vulnerabilities: Array.isArray(sbom?.vulnerabilities) ? sbom.vulnerabilities : [] };
  }

  const vulnerabilities = Array.isArray(sbom?.vulnerabilities) ? [...sbom.vulnerabilities] : [];
  const seen = new Set(vulnerabilities.map((vuln: any) => `${vuln?.id || vuln?.cve || ''}:${Array.isArray(vuln?.affects) ? vuln.affects.map((affect: any) => affect?.ref || '').join('|') : ''}`));
  const componentIndex = indexComponentsByRef(Array.isArray(sbom?.components) ? sbom.components : []);

  for (const finding of report.findings) {
    const candidateRef = finding.affected_component_ref
      ? componentIndex.get(finding.affected_component_ref)
        || componentIndex.get(String(finding.affected_component_ref).toLowerCase())
        || componentIndex.get(String(finding.affected_component_ref))
      : null;
    const vulnerability = grypeFindingToCycloneDxVulnerability(finding, candidateRef || null);
    const vulnerabilityKey = `${vulnerability.id || ''}:${Array.isArray(vulnerability.affects) ? vulnerability.affects.map((affect: any) => affect?.ref || '').join('|') : ''}`;
    if (seen.has(vulnerabilityKey)) continue;
    seen.add(vulnerabilityKey);
    vulnerabilities.push(vulnerability);
  }

  return { report, vulnerabilities };
};

const normalizeGitHubRepoUrl = (rawUrl: unknown) => {
  if (typeof rawUrl !== 'string') {
    throw new Error('Missing GitHub repository URL');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
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

export const generateSbomFromGitHubRepo = async (repoUrl: unknown): Promise<GeneratedSbomResult> => {
  const { normalizedRepoUrl, repoName } = normalizeGitHubRepoUrl(repoUrl);
  const started = Date.now();
  const tempRoot = path.join(os.tmpdir(), `syft-repo-${uuidv4()}`);
  const repoPath = path.join(tempRoot, 'repo');
  const syftTarget = `dir:${path.resolve(repoPath)}`;
  const cacheDir = path.join(tempRoot, 'cache');

  try {
    await fs.mkdir(tempRoot, { recursive: true });
    await fs.mkdir(cacheDir, { recursive: true });

    const gitBin = process.env.GIT_BIN || 'git';
    try {
      await execFilePromise(
        gitBin,
        ['-c', 'core.longpaths=true', 'clone', '--depth', '1', normalizedRepoUrl, repoPath],
        { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER }
      );
    } catch (error: any) {
      const message = error?.stderr || error?.stdout || error?.message || 'Failed to clone GitHub repository';
      throw new Error(`Git clone failed for ${normalizedRepoUrl}: ${String(message).trim()}`);
    }

    const detectedFiles = await scanRepositoryFiles(repoPath);

    const syftBin = process.env.SYFT_BIN || 'syft';
    const sbomOutputFile = path.join(tempRoot, 'sbom-output.json');
    
    try {
      await execFilePromise(
        syftBin,
        [
          syftTarget, 
          '--base-path', path.resolve(repoPath), 
          // Đã xóa cờ '--name' / '--source-name' ở đây
          '-o', `cyclonedx-json=${sbomOutputFile}`, 
          '-q'
        ],
        {
          timeout: TIMEOUT_MS * 3, // Giữ nguyên việc tăng timeout
          maxBuffer: MAX_BUFFER,
          env: {
            ...process.env,
            XDG_CACHE_HOME: process.env.XDG_CACHE_HOME || cacheDir,
            SYFT_CHECK_FOR_APP_UPDATE: 'false',
          },
        }
      );
    } catch (error: any) {
      const message = error?.stderr || error?.stdout || error?.message || 'Failed to generate SBOM with Syft';
      throw new Error(`Syft scan failed for ${syftTarget}: ${String(message).trim()}`);
    }

    // Đọc SBOM trực tiếp từ file đã được lưu vào ổ cứng
    const sbomContent = await fs.readFile(sbomOutputFile, 'utf8');
    const sbom = JSON.parse(sbomContent);
    const syftComponentCount = Array.isArray(sbom.components) ? sbom.components.length : 0;
    const mergedSbom = await mergeDetectedSbomComponents(repoPath, detectedFiles.detectedSbomFiles, sbom);
    sbom.components = mergedSbom.components;
    sbom.dependencies = mergedSbom.dependencies;
    const inferredMetadata = await metadataInferenceService.infer(repoPath, {
      repoUrl: normalizedRepoUrl,
      repoName,
      context: 'manual',
    });
    const vulnerabilityInput = { ...sbom, vulnerabilities: mergedSbom.vulnerabilities };
    const { report: vulnerabilityReport, vulnerabilities } = await enrichWithGrypeFindings(vulnerabilityInput);
    sbom.vulnerabilities = vulnerabilities;
    const enrichedSbom = metadataInferenceService.injectIntoCycloneDx(sbom, inferredMetadata);
    const components = Array.isArray(enrichedSbom.components) ? enrichedSbom.components : [];
    const dependencyReferenceCount = Array.isArray(enrichedSbom.dependencies) ? enrichedSbom.dependencies.length : 0;
    const embeddedVulnerabilityCount = Array.isArray(enrichedSbom.vulnerabilities) ? enrichedSbom.vulnerabilities.length : 0;
    const sbomSizeBytes = Buffer.byteLength(JSON.stringify(enrichedSbom, null, 2), 'utf8');
    const ecosystems: string[] = Array.from(new Set<string>(components.map((component: any): string => {
      const purl = typeof component?.purl === 'string' ? component.purl : '';
      if (purl.startsWith('pkg:')) {
        const slash = purl.indexOf('/');
        return slash > 4 ? purl.slice(4, slash) : 'unknown';
      }
      return component?.type ? String(component.type) : 'unknown';
    }))).sort();
    const analysis = {
      repoUrl: normalizedRepoUrl,
      repoName,
      bomFormat: enrichedSbom.bomFormat || 'CycloneDX',
      specVersion: enrichedSbom.specVersion || null,
      serialNumber: enrichedSbom.serialNumber || null,
      componentCount: components.length,
      syftComponentCount,
      webAddedComponentCount: mergedSbom.webAddedComponentCount,
      dependencyCount: dependencyReferenceCount,
      dependencyReferenceCount,
      ecosystems,
      toolInfo: vulnerabilityReport.status === 'COMPLETED'
        ? 'Syft + Grype + repository SBOM enrichment'
        : 'Syft + repository SBOM enrichment',
      createdTimestamp: enrichedSbom.metadata?.timestamp || new Date().toISOString(),
      sbomSizeBytes,
      analysisDurationMs: Date.now() - started,
      embeddedVulnerabilityCount,
      vulnerabilityFindingCount: vulnerabilityReport.findingCount,
      inferredMetadata,
      hasExistingSbom: detectedFiles.detectedSbomFiles.length > 0,
      detectedSbomFiles: detectedFiles.detectedSbomFiles,
      detectedManifestFiles: detectedFiles.detectedManifestFiles,
    };
    return { sbom: enrichedSbom, normalizedRepoUrl, repoName, inferredMetadata, analysis, ...detectedFiles };
  } catch (error: any) {
    throw new Error(String(error?.message || 'Failed to generate SBOM with Syft').trim());
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
  }
};

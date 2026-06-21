import fs from 'fs/promises';
import path from 'path';

const ignoredDirectories = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.next', '.cache']);
const exactNames = new Set([
  'sbom.json', 'bom.json', 'cyclonedx.json', 'bom.xml', 'sbom.xml',
  'spdx.json', 'spdx.yaml', 'spdx.yml', 'sbom.spdx.json',
]);

const looksLikeSbom = (name: string) => {
  const lower = name.toLowerCase();
  return exactNames.has(lower)
    || /(?:^|[._-])(sbom|cyclonedx|spdx)(?:[._-]|$)/.test(lower)
    || lower.endsWith('.cdx.json');
};

const identifyJsonFormat = (payload: any) => {
  if (payload?.bomFormat === 'CycloneDX' || (Array.isArray(payload?.components) && payload?.specVersion)) return 'CycloneDX';
  if (payload?.spdxVersion || payload?.SPDXID) return 'SPDX';
  return null;
};

export type RepositorySbomFile = {
  path: string;
  absolutePath: string;
  sizeBytes: number;
  format: 'CycloneDX' | 'SPDX' | 'Unknown';
  parseable: boolean;
  componentCount: number;
  sourceCommit: string | null;
};

const inferSourceCommit = (payload: any) => {
  const properties = [
    ...(Array.isArray(payload?.metadata?.properties) ? payload.metadata.properties : []),
    ...(Array.isArray(payload?.metadata?.component?.properties) ? payload.metadata.component.properties : []),
  ];
  const property = properties.find((item: any) =>
    /(?:git|vcs).*(?:commit|revision)|(?:commit|revision).*(?:git|vcs)/i.test(String(item?.name || ''))
  );
  const value = String(property?.value || '').trim();
  return /^[a-f0-9]{7,64}$/i.test(value) ? value : null;
};

export const repositorySbomDetectorService = {
  detect: async (repoPath: string) => {
    const candidates: RepositorySbomFile[] = [];
    const walk = async (directory: string, depth: number) => {
      if (depth > 6) return;
      const entries = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
      for (const entry of entries) {
        const absolutePath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          if (!ignoredDirectories.has(entry.name)) await walk(absolutePath, depth + 1);
          continue;
        }
        if (!entry.isFile() || !looksLikeSbom(entry.name)) continue;
        const stat = await fs.stat(absolutePath);
        let format: RepositorySbomFile['format'] = 'Unknown';
        let parseable = false;
        let componentCount = 0;
        let sourceCommit: string | null = null;
        if (entry.name.toLowerCase().endsWith('.json')) {
          try {
            const payload = JSON.parse(await fs.readFile(absolutePath, 'utf8'));
            format = identifyJsonFormat(payload) || 'Unknown';
            parseable = format !== 'Unknown';
            componentCount = format === 'CycloneDX'
              ? (Array.isArray(payload.components) ? payload.components.length : 0)
              : (Array.isArray(payload.packages) ? payload.packages.length : 0);
            sourceCommit = inferSourceCommit(payload);
          } catch { /* Candidate remains visible with parseable=false. */ }
        }
        candidates.push({
          path: path.relative(repoPath, absolutePath).replace(/\\/g, '/'),
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

import fs from 'fs/promises';
import path from 'path';

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

export type DetectedDependencyFile = {
  path: string;
  name: string;
  sizeBytes: number;
};

const walk = async (root: string, current: string, files: DetectedDependencyFile[]) => {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (!ignoredDirs.has(entry.name)) await walk(root, absolute, files);
      continue;
    }
    if (!entry.isFile() || !dependencyFileNames.has(entry.name)) continue;
    const stat = await fs.stat(absolute);
    files.push({
      path: path.relative(root, absolute).replace(/\\/g, '/'),
      name: entry.name,
      sizeBytes: stat.size,
    });
  }
};

export const dependencyFileDetectorService = {
  detect: async (repoPath: string) => {
    const files: DetectedDependencyFile[] = [];
    await walk(repoPath, repoPath, files);
    return files.sort((left, right) => left.path.localeCompare(right.path));
  },
};

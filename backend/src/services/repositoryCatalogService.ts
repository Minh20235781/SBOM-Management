import { pool } from '../config/db';
import { sbomStatusService } from './sbomStatusService';

export type ValidationScenarioRepository = {
  id: string;
  systemId?: number | null;
  projectName: string;
  githubUrl: string;
  applicationType: 'Web Application';
  repoScope: 'Single Repository';
  architectureType: string;
  techStack: string[];
  packageManager: string[];
  dependencyFiles: string[];
  description: string;
  supportStatus: string;
  sbomStatus: string;
  latestSbomId?: string | null;
  sourceCommit?: string | null;
  analyzedAt?: string | null;
};

const toRepository = async (row: any): Promise<ValidationScenarioRepository> => {
  const status = await sbomStatusService.forRepository(row.repository_id);
  return {
    id: row.repository_id,
    systemId: row.system_id ? Number(row.system_id) : null,
    projectName: row.name,
    githubUrl: String(row.github_url).replace(/\.git$/i, ''),
    applicationType: 'Web Application',
    repoScope: 'Single Repository',
    architectureType: row.architecture_type,
    techStack: row.tech_stack || [],
    packageManager: row.package_managers || [],
    dependencyFiles: row.expected_dependency_files || [],
    description: row.description || '',
    supportStatus: 'Ready for source-based SBOM analysis',
    ...status,
  };
};

export const repositoryCatalogService = {
  list: async () => {
    const { rows } = await pool.query('SELECT * FROM sbom_repositories ORDER BY name');
    return Promise.all(rows.map(toRepository));
  },

  getById: async (id: string) => {
    const { rows } = await pool.query('SELECT * FROM sbom_repositories WHERE repository_id = $1', [id]);
    if (!rows[0]) throw new Error(`Repository demo not found: ${id}`);
    return toRepository(rows[0]);
  },
};

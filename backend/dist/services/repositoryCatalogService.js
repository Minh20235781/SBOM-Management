"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.repositoryCatalogService = void 0;
const db_1 = require("../config/db");
const normalizeGitHubUrl = (value) => value.trim().replace(/\.git$/i, '');
const inferDependencyFiles = (ecosystem) => {
    const value = String(ecosystem || '').toLowerCase();
    if (value.includes('maven') || value.includes('java'))
        return ['pom.xml'];
    if (value.includes('python') || value.includes('pypi'))
        return ['requirements.txt', 'pyproject.toml'];
    if (value.includes('go'))
        return ['go.mod'];
    if (value.includes('composer') || value.includes('php'))
        return ['composer.json'];
    if (value.includes('ruby') || value.includes('gem'))
        return ['Gemfile'];
    return ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
};
const toRepository = (row) => {
    const repoUrl = normalizeGitHubUrl(row.repo_url || '');
    const ecosystem = row.ecosystem || '';
    const storedDependencyFiles = Array.isArray(row.dependency_files)
        ? row.dependency_files.filter((file) => typeof file === 'string' && file.trim().length > 0)
        : [];
    const dependencyFiles = storedDependencyFiles.length > 0 ? storedDependencyFiles : inferDependencyFiles(ecosystem);
    return {
        id: `project-${row.system_id}`,
        systemId: Number(row.system_id),
        pipelineId: row.pipeline_id ? Number(row.pipeline_id) : null,
        projectName: row.name,
        githubUrl: repoUrl,
        applicationType: 'Web Application',
        repoScope: 'Single Repository',
        architectureType: row.description || 'Saved project repository',
        techStack: ecosystem ? [ecosystem] : [],
        packageManager: ecosystem ? [ecosystem] : [],
        dependencyFiles,
        description: row.description || `Repository saved for project ${row.name}.`,
        supportStatus: 'Saved in SBOM Management system',
    };
};
const projectRepositoryQuery = `
  SELECT
    s.system_id,
    s.name,
    s.description,
    p.pipeline_id,
    p.repo_url,
    component_stats.ecosystem,
    COALESCE(
      NULLIF(latest_validation.dependency_files::text[], ARRAY[]::text[]),
      NULLIF(artifact_files.dependency_files::text[], ARRAY[]::text[])
    ) AS dependency_files
  FROM system s
  JOIN LATERAL (
    SELECT pipeline_id, repo_url
    FROM cicd_pipelines
    WHERE project_id = s.system_id
      AND repo_url IS NOT NULL
      AND btrim(repo_url) <> ''
    ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, pipeline_id DESC
    LIMIT 1
  ) p ON true
  LEFT JOIN LATERAL (
    SELECT
      CASE
        WHEN c.purl LIKE 'pkg:%/%' THEN split_part(split_part(c.purl, ':', 2), '/', 1)
        ELSE NULL
      END AS ecosystem
    FROM sbom_metadata m
    JOIN component c ON c.sbom_id = m.sbom_id
    WHERE m.system_id = s.system_id
    ORDER BY m.created_timestamp DESC NULLS LAST
    LIMIT 1
  ) component_stats ON true
  LEFT JOIN LATERAL (
    SELECT ARRAY(
      SELECT dep_file
      FROM (
        SELECT DISTINCT COALESCE(file_item->>'path', file_item->>'name') AS dep_file
        FROM jsonb_array_elements(COALESCE(r.analysis->'dependencyFiles', '[]'::jsonb)) AS file_item
        WHERE COALESCE(file_item->>'path', file_item->>'name') IS NOT NULL
          AND btrim(COALESCE(file_item->>'path', file_item->>'name')) <> ''
      ) files
      ORDER BY dep_file
    ) AS dependency_files
    FROM sbom_validation_runs r
    WHERE r.scenario_id = 'project-' || s.system_id::text
      AND r.analysis ? 'dependencyFiles'
    ORDER BY r.updated_at DESC NULLS LAST
    LIMIT 1
  ) latest_validation ON true
  LEFT JOIN LATERAL (
    SELECT ARRAY(
      SELECT artifact_file
      FROM (
        SELECT DISTINCT COALESCE(pa.artifact_path, pa.artifact_name) AS artifact_file
        FROM project_artifacts pa
        WHERE pa.project_id = s.system_id
          AND COALESCE(pa.artifact_path, pa.artifact_name) IS NOT NULL
          AND btrim(COALESCE(pa.artifact_path, pa.artifact_name)) <> ''
      ) files
      ORDER BY artifact_file
    ) AS dependency_files
  ) artifact_files ON true
`;
exports.repositoryCatalogService = {
    list: async () => {
        const { rows } = await db_1.pool.query(`
      ${projectRepositoryQuery}
      ORDER BY s.name ASC
    `);
        return rows.map(toRepository);
    },
    getById: async (id) => {
        const match = /^project-(\d+)$/.exec(id);
        if (!match)
            throw new Error(`Unknown validation project: ${id}`);
        const { rows } = await db_1.pool.query(`${projectRepositoryQuery}
       WHERE s.system_id = $1
       LIMIT 1`, [Number(match[1])]);
        if (!rows[0]) {
            throw new Error(`Validation project not found or has no repository URL: ${id}`);
        }
        return toRepository(rows[0]);
    },
};

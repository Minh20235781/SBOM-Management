"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.repositoryCatalogService = void 0;
const db_1 = require("../config/db");
const sbomStatusService_1 = require("./sbomStatusService");
const toRepository = async (row) => {
    const status = await sbomStatusService_1.sbomStatusService.forRepository(row.repository_id);
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
exports.repositoryCatalogService = {
    list: async () => {
        const { rows } = await db_1.pool.query('SELECT * FROM sbom_repositories ORDER BY name');
        return Promise.all(rows.map(toRepository));
    },
    getById: async (id) => {
        const { rows } = await db_1.pool.query('SELECT * FROM sbom_repositories WHERE repository_id = $1', [id]);
        if (!rows[0])
            throw new Error(`Repository demo not found: ${id}`);
        return toRepository(rows[0]);
    },
};

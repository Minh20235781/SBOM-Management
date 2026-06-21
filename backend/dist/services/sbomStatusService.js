"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomStatusService = void 0;
const db_1 = require("../config/db");
exports.sbomStatusService = {
    forRepository: async (repositoryId) => {
        const latestAnalysis = await db_1.pool.query(`SELECT analysis FROM sbom_validation_runs
       WHERE scenario_id = $1 AND analysis IS NOT NULL
       ORDER BY updated_at DESC LIMIT 1`, [repositoryId]);
        const analyzed = latestAnalysis.rows[0]?.analysis;
        if (analyzed?.repositorySbom?.usableForVerification) {
            return {
                sbomStatus: 'Đã nhận diện SBOM trong repository',
                latestSbomId: `repository:${analyzed.repositorySbom.selectedFile?.path || 'sbom'}`,
                sourceCommit: analyzed.sourceCommit || null,
                analyzedAt: analyzed.analyzedAt || null,
            };
        }
        const { rows } = await db_1.pool.query(`SELECT m.sbom_id, m.source_commit, m.analyzed_at, r.verification_report
       FROM sbom_metadata m
       LEFT JOIN LATERAL (
         SELECT verification_report FROM sbom_validation_runs
         WHERE scenario_id = $1 AND sbom_id = m.sbom_id AND verification_report IS NOT NULL
         ORDER BY updated_at DESC LIMIT 1
       ) r ON true
       WHERE m.repository_id = $1
       ORDER BY m.created_timestamp DESC NULLS LAST LIMIT 1`, [repositoryId]);
        if (!rows[0])
            return {
                sbomStatus: analyzed ? 'Chưa có SBOM trong repository' : 'Chưa phân tích repository',
                latestSbomId: null,
                sourceCommit: analyzed?.sourceCommit || null,
                analyzedAt: analyzed?.analyzedAt || null,
            };
        const report = rows[0].verification_report;
        const sourceChanged = Boolean(report?.sourceChangedSinceGeneration);
        const needsUpdate = report && report.status !== 'PASS';
        return {
            sbomStatus: needsUpdate ? 'Cần cập nhật SBOM' : sourceChanged ? 'Source đã thay đổi' : 'Đã có SBOM',
            latestSbomId: rows[0].sbom_id,
            sourceCommit: rows[0].source_commit,
            analyzedAt: rows[0].analyzed_at,
        };
    },
};

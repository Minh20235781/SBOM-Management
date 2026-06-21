"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validationScenarioService = void 0;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const db_1 = require("../config/db");
const sbomParserService_1 = require("./sbomParserService");
const dependencyFileDetectorService_1 = require("./dependencyFileDetectorService");
const dependencyGraphService_1 = require("./dependencyGraphService");
const faultySbomDemoService_1 = require("./faultySbomDemoService");
const repositoryCatalogService_1 = require("./repositoryCatalogService");
const sbomGenerationService_1 = require("./sbomGenerationService");
const sbomVerificationService_1 = require("./sbomVerificationService");
const sourceCloneService_1 = require("./sourceCloneService");
const testReportService_1 = require("./testReportService");
const metadataInferenceService_1 = require("./metadataInferenceService");
const repositorySbomDetectorService_1 = require("./repositorySbomDetectorService");
const findOrCreateSystem = async (client, name, description) => {
    const existing = await client.query('SELECT system_id FROM system WHERE LOWER(name) = LOWER($1) LIMIT 1', [name]);
    if (existing.rows[0])
        return existing.rows[0].system_id;
    const inserted = await client.query('INSERT INTO system (name, description, last_uploaded_at) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING system_id', [name, description]);
    return inserted.rows[0].system_id;
};
const saveRun = async (client, run) => {
    await client.query(`INSERT INTO sbom_validation_runs
      (run_id, scenario_id, project_name, github_url, application_type, repo_scope, architecture_type, status, source_path, sbom_id, sbom_path, faulty_sbom_path, confirmed, analysis, graph, verification_report, test_report, error_message, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,CURRENT_TIMESTAMP)
     ON CONFLICT (run_id) DO UPDATE SET
      status = EXCLUDED.status,
      source_path = EXCLUDED.source_path,
      sbom_id = EXCLUDED.sbom_id,
      sbom_path = EXCLUDED.sbom_path,
      faulty_sbom_path = EXCLUDED.faulty_sbom_path,
      confirmed = EXCLUDED.confirmed,
      analysis = EXCLUDED.analysis,
      graph = EXCLUDED.graph,
      verification_report = EXCLUDED.verification_report,
      test_report = EXCLUDED.test_report,
      error_message = EXCLUDED.error_message,
      updated_at = CURRENT_TIMESTAMP`, [
        run.runId,
        run.scenarioId,
        run.projectName,
        run.githubUrl,
        run.applicationType || 'Web Application',
        run.repoScope || 'Single Repository',
        run.architectureType,
        run.status,
        run.sourcePath || null,
        run.sbomId || null,
        run.sbomPath || null,
        run.faultySbomPath || null,
        Boolean(run.confirmed),
        run.analysis ? JSON.stringify(run.analysis) : null,
        run.graph ? JSON.stringify(run.graph) : null,
        run.verificationReport ? JSON.stringify(run.verificationReport) : null,
        run.testReport ? JSON.stringify(run.testReport) : null,
        run.errorMessage || null,
    ]);
};
const readRun = async (runId) => {
    const { rows } = await db_1.pool.query('SELECT * FROM sbom_validation_runs WHERE run_id = $1', [runId]);
    if (!rows[0])
        throw new Error(`Validation run not found: ${runId}`);
    return rows[0];
};
const buildRunId = (scenarioId) => `${scenarioId}-${Date.now()}`;
const toGitCloneUrl = (githubUrl) => githubUrl.endsWith('.git') ? githubUrl : `${githubUrl}.git`;
const ecosystemSummary = (components) => {
    const ecosystems = new Set();
    for (const component of components) {
        const purl = typeof component.purl === 'string' ? component.purl : '';
        if (purl.startsWith('pkg:')) {
            const slash = purl.indexOf('/');
            ecosystems.add(slash > 4 ? purl.slice(4, slash) : 'unknown');
        }
        else if (component.type) {
            ecosystems.add(String(component.type));
        }
    }
    return [...ecosystems].sort();
};
exports.validationScenarioService = {
    listCatalog: () => repositoryCatalogService_1.repositoryCatalogService.list(),
    analyze: async (scenarioId) => {
        const repo = await repositoryCatalogService_1.repositoryCatalogService.getById(scenarioId);
        const runId = buildRunId(scenarioId);
        const baseRun = {
            runId,
            scenarioId,
            projectName: repo.projectName,
            githubUrl: repo.githubUrl,
            applicationType: repo.applicationType,
            repoScope: repo.repoScope,
            architectureType: repo.architectureType,
            status: 'RUNNING',
        };
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            await saveRun(client, baseRun);
            await client.query('COMMIT');
        }
        finally {
            client.release();
        }
        try {
            const sourcePath = await sourceCloneService_1.sourceCloneService.cloneOrUpdate(repo.id, toGitCloneUrl(repo.githubUrl));
            const dependencyFiles = await dependencyFileDetectorService_1.dependencyFileDetectorService.detect(sourcePath);
            if (dependencyFiles.length === 0) {
                throw new Error('DEPENDENCY_FILES_NOT_FOUND: No supported dependency file was found in this repository.');
            }
            const revision = await sourceCloneService_1.sourceCloneService.inspectRevision(sourcePath);
            const repositorySbom = await repositorySbomDetectorService_1.repositorySbomDetectorService.detect(sourcePath);
            const generated = await sbomGenerationService_1.sbomGenerationService.generateCycloneDxFromSource(sourcePath, repo.id);
            const inferredMetadata = await metadataInferenceService_1.metadataInferenceService.infer(sourcePath, {
                repoUrl: repo.githubUrl,
                repoName: repo.projectName,
                context: 'manual',
            });
            const enrichedSbom = metadataInferenceService_1.metadataInferenceService.injectIntoCycloneDx(generated.sbom, inferredMetadata);
            await promises_1.default.writeFile(generated.sbomPath, JSON.stringify(enrichedSbom, null, 2), 'utf8');
            const graph = dependencyGraphService_1.dependencyGraphService.buildFromSbom(enrichedSbom, repo.projectName);
            const components = Array.isArray(enrichedSbom.components) ? enrichedSbom.components : [];
            const dependencies = Array.isArray(enrichedSbom.dependencies) ? enrichedSbom.dependencies : [];
            const saveClient = await db_1.pool.connect();
            try {
                await saveClient.query('BEGIN');
                const analysis = {
                    runId,
                    scenarioId: repo.id,
                    projectName: repo.projectName,
                    githubUrl: repo.githubUrl,
                    applicationType: repo.applicationType,
                    repoScope: repo.repoScope,
                    architectureType: repo.architectureType,
                    sourcePath,
                    dependencyFiles,
                    repositorySbom,
                    workflowScenario: repositorySbom.usableForVerification
                        ? 'SERVICE_HAS_SBOM'
                        : 'SERVICE_WITHOUT_SBOM',
                    sourceCommit: revision.commit,
                    shortCommit: revision.shortCommit,
                    branch: revision.branch,
                    commitTimestamp: revision.committedAt,
                    analyzedAt: new Date().toISOString(),
                    dependencyFileCount: dependencyFiles.length,
                    componentCount: components.length,
                    dependencyCount: dependencies.reduce((sum, dep) => sum + (Array.isArray(dep.dependsOn) ? dep.dependsOn.length : 0), 0),
                    ecosystems: ecosystemSummary(components),
                    analysisDurationMs: generated.analysisDurationMs,
                    sbomSizeBytes: generated.sbomSizeBytes,
                    sbomId: enrichedSbom.serialNumber || null,
                    sbomPath: generated.sbomPath,
                    toolInfo: generated.toolInfo,
                    createdTimestamp: generated.createdTimestamp,
                    inferredMetadata,
                    components: components.slice(0, 500).map((component) => ({
                        name: component.name,
                        version: component.version || null,
                        type: component.type || 'library',
                        purl: component.purl || null,
                    })),
                    confirmed: false,
                };
                await saveRun(saveClient, {
                    ...baseRun,
                    status: repositorySbom.usableForVerification ? 'REPOSITORY_SBOM_DETECTED' : 'ANALYZED',
                    sourcePath,
                    sbomId: null,
                    sbomPath: generated.sbomPath,
                    analysis,
                    graph,
                });
                await saveClient.query('COMMIT');
                return { repo, runId, analysis, graph };
            }
            catch (error) {
                await saveClient.query('ROLLBACK');
                throw error;
            }
            finally {
                saveClient.release();
            }
        }
        catch (error) {
            const message = error?.stderr || error?.stdout || error?.message || 'Analyze source failed';
            const errorClient = await db_1.pool.connect();
            try {
                await errorClient.query('BEGIN');
                await saveRun(errorClient, { ...baseRun, status: 'ERROR', errorMessage: String(message).trim() });
                await errorClient.query('COMMIT');
            }
            finally {
                errorClient.release();
            }
            throw new Error(String(message).trim());
        }
    },
    getRun: readRun,
    confirm: async (runId) => {
        const run = await readRun(runId);
        if (!run.analysis)
            throw new Error('Analysis must finish before confirmation.');
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            await saveRun(client, {
                runId: run.run_id,
                scenarioId: run.scenario_id,
                projectName: run.project_name,
                githubUrl: run.github_url,
                applicationType: run.application_type,
                repoScope: run.repo_scope,
                architectureType: run.architecture_type,
                status: 'CONFIRMED',
                sourcePath: run.source_path,
                sbomId: run.sbom_id,
                sbomPath: run.sbom_path,
                faultySbomPath: run.faulty_sbom_path,
                confirmed: true,
                analysis: { ...run.analysis, confirmed: true },
                graph: run.graph,
                verificationReport: run.verification_report,
                testReport: run.test_report,
            });
            await client.query('COMMIT');
            return { success: true, runId, confirmed: true };
        }
        finally {
            client.release();
        }
    },
    generate: async (runId) => {
        const run = await readRun(runId);
        if (!run.confirmed)
            throw new Error('Confirm Analysis is required before Generate SBOM.');
        if (!run.sbom_path)
            throw new Error('No generated SBOM path found for this run.');
        const sbom = JSON.parse(await promises_1.default.readFile(run.sbom_path, 'utf8'));
        const repo = await repositoryCatalogService_1.repositoryCatalogService.getById(run.scenario_id);
        const client = await db_1.pool.connect();
        let sbomId = run.sbom_id;
        try {
            await client.query('BEGIN');
            const systemId = repo.systemId || await findOrCreateSystem(client, repo.projectName, `${repo.applicationType}; ${repo.repoScope}; ${repo.githubUrl}`);
            sbomId = await (0, sbomParserService_1.parseAndSaveSBOM)(client, { sbom, system_id: systemId });
            await client.query(`UPDATE sbom_metadata SET repository_id = $1, source_commit = $2, analyzed_at = $3, source_repository_url = $4
         WHERE sbom_id = $5`, [repo.id, run.analysis?.sourceCommit || null, run.analysis?.analyzedAt || new Date(), repo.githubUrl, sbomId]);
            await client.query('UPDATE sbom_repositories SET system_id = $1, updated_at = CURRENT_TIMESTAMP WHERE repository_id = $2', [systemId, repo.id]);
            await saveRun(client, {
                runId: run.run_id,
                scenarioId: run.scenario_id,
                projectName: run.project_name,
                githubUrl: run.github_url,
                applicationType: run.application_type,
                repoScope: run.repo_scope,
                architectureType: run.architecture_type,
                status: 'GENERATED',
                sourcePath: run.source_path,
                sbomId,
                sbomPath: run.sbom_path,
                faultySbomPath: run.faulty_sbom_path,
                confirmed: run.confirmed,
                analysis: { ...run.analysis, sbomId },
                graph: run.graph,
                verificationReport: run.verification_report,
                testReport: run.test_report,
            });
            await client.query('COMMIT');
        }
        catch (error) {
            await client.query('ROLLBACK');
            throw error;
        }
        finally {
            client.release();
        }
        return {
            runId,
            sbom,
            sbomPath: run.sbom_path,
            sbomId,
            inferredMetadata: run.analysis?.inferredMetadata || null,
            metadata: sbom.metadata || {},
            components: sbom.components || [],
            dependencies: sbom.dependencies || [],
            toolInfo: run.analysis?.toolInfo || 'Syft CycloneDX JSON',
            createdTimestamp: run.analysis?.createdTimestamp || sbom.metadata?.timestamp || run.created_at,
        };
    },
    createFaulty: async (runId) => {
        const run = await readRun(runId);
        if (!run.sbom_path)
            throw new Error('Generate/analyze a valid SBOM before creating faulty demo SBOM.');
        const sbom = JSON.parse(await promises_1.default.readFile(run.sbom_path, 'utf8'));
        const faulty = await faultySbomDemoService_1.faultySbomDemoService.createFaultySbom(run.scenario_id, sbom);
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            await saveRun(client, {
                runId: run.run_id,
                scenarioId: run.scenario_id,
                projectName: run.project_name,
                githubUrl: run.github_url,
                applicationType: run.application_type,
                repoScope: run.repo_scope,
                architectureType: run.architecture_type,
                status: 'FAULTY_SBOM_CREATED',
                sourcePath: run.source_path,
                sbomId: run.sbom_id,
                sbomPath: run.sbom_path,
                faultySbomPath: faulty.faultySbomPath,
                confirmed: run.confirmed,
                analysis: run.analysis,
                graph: run.graph,
                verificationReport: run.verification_report,
                testReport: run.test_report,
            });
            await client.query('COMMIT');
            return { runId, faultySbomPath: faulty.faultySbomPath, changes: faulty.changes };
        }
        finally {
            client.release();
        }
    },
    verify: async (runId, useFaulty = false) => {
        const run = await readRun(runId);
        const repositorySbomPath = run.analysis?.repositorySbom?.selectedPath;
        const targetPath = useFaulty ? run.faulty_sbom_path : repositorySbomPath || run.sbom_path;
        if (!targetPath)
            throw new Error(useFaulty ? 'Faulty SBOM demo has not been created.' : 'No repository or generated SBOM is available for verification.');
        const sbom = JSON.parse(await promises_1.default.readFile(targetPath, 'utf8'));
        const repo = await repositoryCatalogService_1.repositoryCatalogService.getById(run.scenario_id);
        const currentSourcePath = await sourceCloneService_1.sourceCloneService.cloneOrUpdate(repo.id, toGitCloneUrl(repo.githubUrl));
        const currentRevision = await sourceCloneService_1.sourceCloneService.inspectRevision(currentSourcePath);
        const verificationReport = {
            ...(await sbomVerificationService_1.sbomVerificationService.verifySourceAgainstSbom(currentSourcePath, sbom)),
            repository: repo.githubUrl,
            sbomOrigin: repositorySbomPath ? 'SOURCE_REPOSITORY' : 'SBOM_MANAGEMENT',
            repositorySbomFile: run.analysis?.repositorySbom?.selectedFile || null,
            sbomSourceCommit: run.analysis?.repositorySbom?.selectedFile?.sourceCommit || run.analysis?.sourceCommit || repo.sourceCommit || null,
            currentCommit: currentRevision.commit,
            verifiedAt: new Date().toISOString(),
            sourceChangedSinceGeneration: Boolean((run.analysis?.repositorySbom?.selectedFile?.sourceCommit || run.analysis?.sourceCommit || repo.sourceCommit)
                && !(currentRevision.commit.startsWith(run.analysis?.repositorySbom?.selectedFile?.sourceCommit || run.analysis?.sourceCommit || repo.sourceCommit)
                    || (run.analysis?.repositorySbom?.selectedFile?.sourceCommit || run.analysis?.sourceCommit || repo.sourceCommit).startsWith(currentRevision.commit))),
        };
        Object.assign(verificationReport, {
            recommendation: verificationReport.status === 'PASS' ? 'SBOM is up-to-date' : 'SBOM needs update',
        });
        const testReport = testReportService_1.testReportService.build(repo, { ...run, verification_report: verificationReport }, verificationReport);
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            await saveRun(client, {
                runId: run.run_id,
                scenarioId: run.scenario_id,
                projectName: run.project_name,
                githubUrl: run.github_url,
                applicationType: run.application_type,
                repoScope: run.repo_scope,
                architectureType: run.architecture_type,
                status: useFaulty ? 'FAULTY_VERIFIED' : 'VERIFIED',
                sourcePath: run.source_path,
                sbomId: run.sbom_id,
                sbomPath: run.sbom_path,
                faultySbomPath: run.faulty_sbom_path,
                confirmed: run.confirmed,
                analysis: run.analysis,
                graph: run.graph,
                verificationReport,
                testReport,
            });
            await client.query('COMMIT');
            return { runId, verificationReport, testReport };
        }
        finally {
            client.release();
        }
    },
    verifyCurrent: async (scenarioId) => {
        const { rows } = await db_1.pool.query(`SELECT run_id FROM sbom_validation_runs
       WHERE scenario_id = $1 AND sbom_path IS NOT NULL
         AND status IN ('REPOSITORY_SBOM_DETECTED','GENERATED','VERIFIED','FAULTY_VERIFIED')
       ORDER BY updated_at DESC LIMIT 1`, [scenarioId]);
        if (!rows[0])
            throw new Error('CURRENT_SBOM_NOT_FOUND: This repository has no generated SBOM to verify.');
        return exports.validationScenarioService.verify(rows[0].run_id, false);
    },
    verifyUploaded: async (runId, sbom, fileName = 'uploaded-sbom.json') => {
        const run = await readRun(runId);
        if (!run.source_path)
            throw new Error('Source code repository has not been cloned for this run.');
        if (!sbom || typeof sbom !== 'object')
            throw new Error('Uploaded SBOM JSON is required.');
        if (!Array.isArray(sbom.components))
            throw new Error('Uploaded SBOM must be a CycloneDX JSON document with components.');
        const workDir = await sourceCloneService_1.sourceCloneService.ensureWorkDir();
        const outputDir = path_1.default.join(workDir, 'generated');
        await promises_1.default.mkdir(outputDir, { recursive: true });
        const safeFileName = String(fileName || 'uploaded-sbom.json').replace(/[^a-zA-Z0-9._-]/g, '_');
        const uploadedSbomPath = path_1.default.join(outputDir, `${run.scenario_id}-${Date.now()}-${safeFileName}`);
        await promises_1.default.writeFile(uploadedSbomPath, JSON.stringify(sbom, null, 2), 'utf8');
        const verificationReport = await sbomVerificationService_1.sbomVerificationService.verifySourceAgainstSbom(run.source_path, sbom);
        const repo = await repositoryCatalogService_1.repositoryCatalogService.getById(run.scenario_id);
        const analysis = {
            ...(run.analysis || {}),
            uploadedSbomFileName: fileName,
            uploadedSbomPath,
            uploadedSbomComponentCount: Array.isArray(sbom.components) ? sbom.components.length : 0,
            uploadedSbomDependencyCount: Array.isArray(sbom.dependencies) ? sbom.dependencies.length : 0,
        };
        const testReport = testReportService_1.testReportService.build(repo, { ...run, analysis, sbom_path: uploadedSbomPath, verification_report: verificationReport }, verificationReport);
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            await saveRun(client, {
                runId: run.run_id,
                scenarioId: run.scenario_id,
                projectName: run.project_name,
                githubUrl: run.github_url,
                applicationType: run.application_type,
                repoScope: run.repo_scope,
                architectureType: run.architecture_type,
                status: 'UPLOADED_SBOM_VERIFIED',
                sourcePath: run.source_path,
                sbomId: run.sbom_id,
                sbomPath: uploadedSbomPath,
                faultySbomPath: run.faulty_sbom_path,
                confirmed: run.confirmed,
                analysis,
                graph: run.graph,
                verificationReport,
                testReport,
            });
            await client.query('COMMIT');
            return { runId, uploadedSbomPath, uploadedFileName: fileName, verificationReport, testReport };
        }
        catch (error) {
            await client.query('ROLLBACK');
            throw error;
        }
        finally {
            client.release();
        }
    },
    report: async (runId) => {
        const run = await readRun(runId);
        return run.test_report || null;
    },
};

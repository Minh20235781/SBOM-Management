import fs from 'fs/promises';
import { PoolClient } from 'pg';
import { pool } from '../config/db';
import { parseAndSaveSBOM } from './sbomParserService';
import { dependencyFileDetectorService } from './dependencyFileDetectorService';
import { dependencyGraphService } from './dependencyGraphService';
import { faultySbomDemoService } from './faultySbomDemoService';
import { repositoryCatalogService } from './repositoryCatalogService';
import { sbomGenerationService } from './sbomGenerationService';
import { sbomVerificationService } from './sbomVerificationService';
import { sourceCloneService } from './sourceCloneService';
import { testReportService } from './testReportService';

const findOrCreateSystem = async (client: PoolClient, name: string, description: string) => {
  const existing = await client.query('SELECT system_id FROM system WHERE LOWER(name) = LOWER($1) LIMIT 1', [name]);
  if (existing.rows[0]) return existing.rows[0].system_id;
  const inserted = await client.query(
    'INSERT INTO system (name, description, last_uploaded_at) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING system_id',
    [name, description]
  );
  return inserted.rows[0].system_id;
};

const saveRun = async (client: PoolClient, run: any) => {
  await client.query(
    `INSERT INTO sbom_validation_runs
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
      updated_at = CURRENT_TIMESTAMP`,
    [
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
    ]
  );
};

const readRun = async (runId: string) => {
  const { rows } = await pool.query('SELECT * FROM sbom_validation_runs WHERE run_id = $1', [runId]);
  if (!rows[0]) throw new Error(`Validation run not found: ${runId}`);
  return rows[0];
};

const buildRunId = (scenarioId: string) => `${scenarioId}-${Date.now()}`;

const toGitCloneUrl = (githubUrl: string) => githubUrl.endsWith('.git') ? githubUrl : `${githubUrl}.git`;

const ecosystemSummary = (components: any[]) => {
  const ecosystems = new Set<string>();
  for (const component of components) {
    const purl = typeof component.purl === 'string' ? component.purl : '';
    if (purl.startsWith('pkg:')) {
      const slash = purl.indexOf('/');
      ecosystems.add(slash > 4 ? purl.slice(4, slash) : 'unknown');
    } else if (component.type) {
      ecosystems.add(String(component.type));
    }
  }
  return [...ecosystems].sort();
};

export const validationScenarioService = {
  listCatalog: () => repositoryCatalogService.list(),

  analyze: async (scenarioId: string) => {
    const repo = await repositoryCatalogService.getById(scenarioId);
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

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await saveRun(client, baseRun);
      await client.query('COMMIT');
    } finally {
      client.release();
    }

    try {
      const sourcePath = await sourceCloneService.cloneOrUpdate(repo.id, toGitCloneUrl(repo.githubUrl));
      const dependencyFiles = await dependencyFileDetectorService.detect(sourcePath);
      const generated = await sbomGenerationService.generateCycloneDxFromSource(sourcePath, repo.id);
      const graph = dependencyGraphService.buildFromSbom(generated.sbom, repo.projectName);
      const components = Array.isArray(generated.sbom.components) ? generated.sbom.components : [];
      const dependencies = Array.isArray(generated.sbom.dependencies) ? generated.sbom.dependencies : [];

      const saveClient = await pool.connect();
      let sbomId = '';
      try {
        await saveClient.query('BEGIN');
        const systemId = repo.systemId || await findOrCreateSystem(
          saveClient,
          repo.projectName,
          `${repo.applicationType}; ${repo.repoScope}; ${repo.githubUrl}`
        );
        sbomId = await parseAndSaveSBOM(saveClient, { sbom: generated.sbom, system_id: systemId });
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
          dependencyFileCount: dependencyFiles.length,
          componentCount: components.length,
          dependencyCount: dependencies.reduce((sum: number, dep: any) => sum + (Array.isArray(dep.dependsOn) ? dep.dependsOn.length : 0), 0),
          ecosystems: ecosystemSummary(components),
          analysisDurationMs: generated.analysisDurationMs,
          sbomSizeBytes: generated.sbomSizeBytes,
          sbomId,
          sbomPath: generated.sbomPath,
          toolInfo: generated.toolInfo,
          createdTimestamp: generated.createdTimestamp,
          confirmed: false,
        };
        await saveRun(saveClient, {
          ...baseRun,
          status: 'ANALYZED',
          sourcePath,
          sbomId,
          sbomPath: generated.sbomPath,
          analysis,
          graph,
        });
        await saveClient.query('COMMIT');
        return { repo, runId, analysis, graph };
      } catch (error) {
        await saveClient.query('ROLLBACK');
        throw error;
      } finally {
        saveClient.release();
      }
    } catch (error: any) {
      const message = error?.stderr || error?.stdout || error?.message || 'Analyze source failed';
      const errorClient = await pool.connect();
      try {
        await errorClient.query('BEGIN');
        await saveRun(errorClient, { ...baseRun, status: 'ERROR', errorMessage: String(message).trim() });
        await errorClient.query('COMMIT');
      } finally {
        errorClient.release();
      }
      throw new Error(String(message).trim());
    }
  },

  getRun: readRun,

  confirm: async (runId: string) => {
    const run = await readRun(runId);
    if (!run.analysis) throw new Error('Analysis must finish before confirmation.');
    const client = await pool.connect();
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
    } finally {
      client.release();
    }
  },

  generate: async (runId: string) => {
    const run = await readRun(runId);
    if (!run.confirmed) throw new Error('Confirm Analysis is required before Generate SBOM.');
    if (!run.sbom_path) throw new Error('No generated SBOM path found for this run.');
    const sbom = JSON.parse(await fs.readFile(run.sbom_path, 'utf8'));
    return {
      runId,
      sbom,
      sbomPath: run.sbom_path,
      metadata: sbom.metadata || {},
      components: sbom.components || [],
      dependencies: sbom.dependencies || [],
      toolInfo: run.analysis?.toolInfo || 'Syft CycloneDX JSON',
      createdTimestamp: run.analysis?.createdTimestamp || sbom.metadata?.timestamp || run.created_at,
    };
  },

  createFaulty: async (runId: string) => {
    const run = await readRun(runId);
    if (!run.sbom_path) throw new Error('Generate/analyze a valid SBOM before creating faulty demo SBOM.');
    const sbom = JSON.parse(await fs.readFile(run.sbom_path, 'utf8'));
    const faulty = await faultySbomDemoService.createFaultySbom(run.scenario_id, sbom);
    const client = await pool.connect();
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
    } finally {
      client.release();
    }
  },

  verify: async (runId: string, useFaulty = false) => {
    const run = await readRun(runId);
    const targetPath = useFaulty ? run.faulty_sbom_path : run.sbom_path;
    if (!run.source_path) throw new Error('Source code repository has not been cloned for this run.');
    if (!targetPath) throw new Error(useFaulty ? 'Faulty SBOM demo has not been created.' : 'SBOM has not been generated.');
    const sbom = JSON.parse(await fs.readFile(targetPath, 'utf8'));
    const verificationReport = await sbomVerificationService.verifySourceAgainstSbom(run.source_path, sbom);
    const repo = await repositoryCatalogService.getById(run.scenario_id);
    const testReport = testReportService.build(repo, { ...run, verification_report: verificationReport }, verificationReport);
    const client = await pool.connect();
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
    } finally {
      client.release();
    }
  },

  report: async (runId: string) => {
    const run = await readRun(runId);
    return run.test_report || null;
  },
};

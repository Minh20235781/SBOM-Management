import { ValidationScenarioRepository } from './repositoryCatalogService';

export const testReportService = {
  build: (repo: ValidationScenarioRepository, run: any, verificationReport: any) => {
    const analysis = run.analysis || {};
    const graph = run.graph || {};
    const passed = Boolean(
      analysis.componentCount > 0
      && analysis.dependencyFileCount > 0
      && verificationReport
    );

    return {
      testCaseId: `SBOM-VAL-${repo.id.toUpperCase()}`,
      name: `Validate CycloneDX SBOM against real repository ${repo.projectName}`,
      scope: 'SBOM validation demo for real Web Application source code in one GitHub repository.',
      applicationType: repo.applicationType,
      repoScope: repo.repoScope,
      architectureType: repo.architectureType,
      inputRepo: repo.githubUrl,
      preconditions: [
        'Git is available on backend host.',
        'Syft is available on backend host.',
        'Repository is public and cloneable.',
        'Current version supports Web Application + Single Repository only.',
      ],
      steps: [
        'Select the real GitHub repository from SBOM Validation Scenarios.',
        'Clone or update the selected Single Repository source.',
        'Detect dependency files in the source tree.',
        'Run Syft and parse CycloneDX JSON.',
        'Persist metadata, components, and dependency relationships.',
        'Confirm analysis before generating downloadable SBOM.',
        'Verify the SBOM by regenerating source analysis and comparing components.',
      ],
      expectedResult: 'SBOM is generated from the real repository and verification reports MATCHED, MISSING_IN_SBOM, EXTRA_IN_SBOM, VERSION_MISMATCH, counts, and Trust Score.',
      actualResult: verificationReport
        ? `Verification finished with ${verificationReport.trustLevel} (${verificationReport.trustScore}%).`
        : 'Verification has not been run yet.',
      result: passed ? 'PASS' : 'FAIL',
      evidence: {
        componentCount: analysis.componentCount || 0,
        dependencyCount: analysis.dependencyCount || 0,
        dependencyFileCount: analysis.dependencyFileCount || 0,
        graphNodes: graph.summary?.nodeCount || 0,
        graphEdges: graph.summary?.edgeCount || 0,
        sbomPath: run.sbom_path || null,
        generatedTimestamp: analysis.createdTimestamp || null,
        trustScore: verificationReport?.trustScore ?? null,
      },
    };
  },
};

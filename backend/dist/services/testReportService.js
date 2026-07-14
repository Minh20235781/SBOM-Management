"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.testReportService = void 0;
exports.testReportService = {
    build: (repo, run, verificationReport) => {
        const analysis = run.analysis || {};
        const graph = run.graph || {};
        const vulnerabilityScan = analysis.vulnerabilityScan || null;
        const passed = Boolean(analysis.componentCount > 0
            && analysis.dependencyFileCount > 0
            && verificationReport);
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
                'Grype is available on backend host to enrich the verification report with CVE findings.',
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
                'Scan the verified SBOM with Grype and record CVE findings separately from static source verification.',
            ],
            expectedResult: 'SBOM is generated from the real repository; source verification reports component differences and Trust Score; Grype enrichment records CVE findings with package and fix information.',
            actualResult: verificationReport
                ? `Verification finished with ${verificationReport.trustLevel} (${verificationReport.trustScore}%). Grype status: ${vulnerabilityScan?.status || 'NOT_RUN'}; findings: ${vulnerabilityScan?.findingCount ?? 0}.`
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
                vulnerabilityScanner: vulnerabilityScan?.scanner || 'Grype',
                vulnerabilityScanStatus: vulnerabilityScan?.status || 'NOT_RUN',
                vulnerabilityFindingCount: vulnerabilityScan?.findingCount ?? 0,
                vulnerabilityScannedAt: vulnerabilityScan?.scannedAt || null,
                vulnerabilityVerificationLimit: 'CVE findings come from Grype enrichment and are not independently verified by static source comparison.',
            },
        };
    },
};

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomVerificationService = void 0;
const sbomAlgorithms_1 = require("./sbomAlgorithms");
const sbomGenerationService_1 = require("./sbomGenerationService");
const componentToComparable = (component) => ({
    key: `${component.ecosystem || 'unknown'}:${component.name}:${component.version || 'unknown'}`.toLowerCase(),
    familyKey: `${component.ecosystem || 'unknown'}:${component.name}`.toLowerCase(),
    name: component.name,
    version: component.version,
    ecosystem: component.ecosystem || 'unknown',
    purl: component.purl,
});
const display = (component) => `${component.ecosystem}:${component.name}${component.version ? `@${component.version}` : '@(no-version)'}`;
const trustLevel = (score) => {
    if (score >= 90)
        return 'High trust';
    if (score >= 70)
        return 'Medium';
    if (score >= 50)
        return 'Low';
    return 'Untrusted';
};
exports.sbomVerificationService = {
    verifySourceAgainstSbom: async (repoPath, sbom) => {
        const regenerated = await sbomGenerationService_1.sbomGenerationService.generateCycloneDxFromSource(repoPath, 'verification-source');
        const source = (0, sbomAlgorithms_1.normalizeSbomPayload)(regenerated.sbom).components.map(componentToComparable);
        const candidate = (0, sbomAlgorithms_1.normalizeSbomPayload)(sbom).components.map(componentToComparable);
        const sourceByExact = new Map(source.map(component => [component.key, component]));
        const candidateByExact = new Map(candidate.map(component => [component.key, component]));
        const sourceByFamily = new Map(source.map(component => [component.familyKey, component]));
        const candidateByFamily = new Map(candidate.map(component => [component.familyKey, component]));
        const matched = source.filter(component => candidateByExact.has(component.key));
        const missingInSbom = [];
        const versionMismatch = [];
        for (const sourceComponent of source) {
            if (candidateByExact.has(sourceComponent.key))
                continue;
            const candidateFamily = candidateByFamily.get(sourceComponent.familyKey);
            if (candidateFamily) {
                versionMismatch.push({
                    component: sourceComponent.name,
                    sourceVersion: sourceComponent.version,
                    sbomVersion: candidateFamily.version,
                    ecosystem: sourceComponent.ecosystem,
                });
            }
            else {
                missingInSbom.push(sourceComponent);
            }
        }
        const extraInSbom = candidate.filter(component => !sourceByExact.has(component.key) && !sourceByFamily.has(component.familyKey));
        const denominator = source.length + extraInSbom.length;
        const trustScore = denominator > 0 ? (matched.length / denominator) * 100 : 100;
        const roundedTrustScore = Number(trustScore.toFixed(2));
        return {
            status: missingInSbom.length === 0 && extraInSbom.length === 0 && versionMismatch.length === 0 ? 'PASS' : 'FAIL',
            trustLevel: trustLevel(roundedTrustScore),
            trustScore: roundedTrustScore,
            matchedCount: matched.length,
            missingCount: missingInSbom.length,
            extraCount: extraInSbom.length,
            versionMismatchCount: versionMismatch.length,
            sourceComponentCount: source.length,
            sbomComponentCount: candidate.length,
            MATCHED: matched.map(display),
            MISSING_IN_SBOM: missingInSbom.map(display),
            EXTRA_IN_SBOM: extraInSbom.map(display),
            VERSION_MISMATCH: versionMismatch,
            formula: 'matchedExactCount / (sourceComponentCount + extraInSbomCount) * 100',
            evidence: {
                sourceRegeneratedComponentCount: source.length,
                sourceRegeneratedSbomSizeBytes: regenerated.sbomSizeBytes,
                sourceRegeneratedAt: regenerated.createdTimestamp,
            },
        };
    },
};

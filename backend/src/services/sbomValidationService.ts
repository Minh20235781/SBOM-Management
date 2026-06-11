import { PoolClient } from 'pg';
import { artifactScannerService } from './artifactScannerService';

type ValidationComponent = {
  key: string;
  name: string;
  version: string | null;
};

const displayName = (component: ValidationComponent) =>
  `${component.name}${component.version ? `@${component.version}` : ''}`;

const mapByKey = (components: ValidationComponent[]) =>
  new Map(components.map(component => [component.key, component]));

export const sbomValidationService = {
  validateSnapshotAgainstSource: async (client: PoolClient, projectId: number, snapshotId: string) => {
    const artifacts = await artifactScannerService.loadProjectArtifacts(client, projectId);
    const scanned = artifactScannerService.scanArtifacts(projectId, artifacts);
    const sourceComponents = scanned.normalized.components
      .filter(component => component.stableKey !== `project:${projectId}`)
      .map(component => ({
        key: component.stableKey,
        name: component.name,
        version: component.version,
      }));

    const snapshotResult = await client.query(
      `SELECT stable_key, name, version
       FROM sbom_components
       WHERE snapshot_id = $1
       ORDER BY name`,
      [snapshotId]
    );
    const snapshotComponents = snapshotResult.rows
      .filter(row => row.stable_key !== `project:${projectId}`)
      .map(row => ({
        key: row.stable_key,
        name: row.name,
        version: row.version,
      }));

    const sourceByKey = mapByKey(sourceComponents);
    const snapshotByKey = mapByKey(snapshotComponents);

    const matched: string[] = [];
    const missingFromSbom: string[] = [];
    const extraInSbom: string[] = [];
    const versionMismatches: Array<{ component: string; sourceVersion: string | null; sbomVersion: string | null }> = [];

    for (const source of sourceComponents) {
      const snapshot = snapshotByKey.get(source.key);
      if (!snapshot) {
        missingFromSbom.push(displayName(source));
        continue;
      }
      if ((source.version || null) !== (snapshot.version || null)) {
        versionMismatches.push({
          component: source.name,
          sourceVersion: source.version,
          sbomVersion: snapshot.version,
        });
        continue;
      }
      matched.push(displayName(source));
    }

    for (const snapshot of snapshotComponents) {
      if (!sourceByKey.has(snapshot.key)) extraInSbom.push(displayName(snapshot));
    }

    const denominator = Math.max(sourceComponents.length, snapshotComponents.length, 1);
    const score = Math.max(0, Math.round((matched.length / denominator) * 100));
    const status = score >= 90 && missingFromSbom.length === 0 && versionMismatches.length === 0
      ? 'PASS'
      : score >= 70
        ? 'WARN'
        : 'FAIL';

    return {
      status,
      score,
      matchedCount: matched.length,
      sourceComponentCount: sourceComponents.length,
      sbomComponentCount: snapshotComponents.length,
      missingFromSbom,
      extraInSbom,
      versionMismatches,
      evidence: {
        artifactCount: artifacts.length,
        artifactPaths: artifacts.map(artifact => artifact.artifactPath),
        method: 'Compared dependency files scanned from project_artifacts with generated SBOM snapshot components.',
      },
    };
  },
};

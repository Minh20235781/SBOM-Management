"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.incrementalSbomService = void 0;
const uuid_1 = require("uuid");
const sbomAlgorithms_1 = require("./sbomAlgorithms");
const artifactScannerService_1 = require("./artifactScannerService");
const requestArtifactFiles = (body) => {
    const files = body?.dependencyFiles || body?.projectFiles || body?.artifactFiles || [];
    if (!Array.isArray(files))
        return [];
    return files
        .filter(file => file && file.artifactPath && typeof file.content === 'string')
        .map(file => ({
        artifactPath: file.artifactPath,
        artifactName: file.artifactName,
        artifactType: file.artifactType,
        content: file.content,
    }));
};
const snapshotToNormalized = async (client, snapshotId) => {
    const components = await client.query('SELECT * FROM sbom_components WHERE snapshot_id = $1', [snapshotId]);
    const dependencies = await client.query('SELECT * FROM sbom_dependencies WHERE snapshot_id = $1', [snapshotId]);
    const vulnerabilities = await client.query(`SELECT c.stable_key, v.severity
     FROM sbom_components c
     LEFT JOIN vulnerability v ON v.affected_component_ref = c.component_ref OR v.affected_component_ref = c.component_id::text
     WHERE c.snapshot_id = $1`, [snapshotId]);
    return {
        format: 'INTERNAL',
        rootKey: null,
        components: components.rows.map(row => ({
            componentId: row.component_ref || row.stable_key,
            stableKey: row.stable_key,
            name: row.name,
            version: row.version,
            purl: row.purl,
            ecosystem: row.ecosystem || 'unknown',
            supplier: row.supplier_name,
            licenses: row.licenses,
            hashes: row.hashes,
        })),
        dependencies: dependencies.rows.map(row => ({
            sourceKey: row.source_key,
            targetKey: row.target_key,
            relationship: row.relationship || 'DEPENDS_ON',
        })),
        vulnerabilities: vulnerabilities.rows
            .filter(row => row.severity)
            .map(row => ({ affectedKey: row.stable_key, severity: row.severity })),
    };
};
const latestSbomForProject = async (client, projectId) => {
    const { rows } = await client.query('SELECT * FROM sbom_metadata WHERE system_id = $1 ORDER BY created_timestamp DESC NULLS LAST LIMIT 1', [projectId]);
    return rows[0] || null;
};
const sbomMetadataToNormalized = async (client, sbomId) => {
    const [components, dependencies, vulnerabilities] = await Promise.all([
        client.query('SELECT * FROM component WHERE sbom_id = $1', [sbomId]),
        client.query('SELECT * FROM dependency WHERE sbom_id = $1', [sbomId]),
        client.query('SELECT * FROM vulnerability WHERE sbom_id = $1', [sbomId]),
    ]);
    const componentByRef = new Map();
    const normalizedComponents = components.rows.map(row => {
        const stableKey = (0, sbomAlgorithms_1.stableComponentKey)({
            purl: row.purl,
            ecosystem: row.purl?.startsWith('pkg:') ? row.purl.slice(4, row.purl.indexOf('/')) : 'unknown',
            name: row.name,
            version: row.version,
            hashes: row.hashes,
        });
        componentByRef.set(row.component_id, stableKey);
        return {
            componentId: row.component_id,
            stableKey,
            name: row.name,
            version: row.version,
            purl: row.purl,
            ecosystem: row.purl?.startsWith('pkg:') ? row.purl.slice(4, row.purl.indexOf('/')) : 'unknown',
            supplier: row.supplier_name,
            licenses: row.licenses,
            hashes: row.hashes,
        };
    });
    return {
        format: 'INTERNAL',
        rootKey: null,
        components: normalizedComponents,
        dependencies: dependencies.rows
            .map(row => ({
            sourceKey: componentByRef.get(row.component_ref),
            targetKey: componentByRef.get(row.depends_on_ref),
            relationship: 'DEPENDS_ON',
        }))
            .filter(row => row.sourceKey && row.targetKey),
        vulnerabilities: vulnerabilities.rows.map(row => ({
            affectedKey: row.affected_component_ref ? componentByRef.get(row.affected_component_ref) || row.affected_component_ref : null,
            severity: row.severity,
        })),
    };
};
const saveSnapshot = async (client, projectId, sourceType, baseSnapshotId, normalized, summary) => {
    const snapshotId = (0, uuid_1.v4)();
    const versionResult = await client.query('SELECT COALESCE(MAX(version_number), 0) + 1 AS version_number FROM sbom_snapshots WHERE project_id = $1', [projectId]);
    const versionNumber = Number(versionResult.rows[0].version_number);
    await client.query(`INSERT INTO sbom_snapshots
      (snapshot_id, project_id, version_number, source_type, base_snapshot_id, summary)
     VALUES ($1, $2, $3, $4, $5, $6)`, [snapshotId, projectId, versionNumber, sourceType, baseSnapshotId, summary]);
    for (const component of normalized.components) {
        await client.query(`INSERT INTO sbom_components
        (snapshot_id, stable_key, component_ref, name, version, purl, ecosystem, supplier_name, licenses, hashes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (snapshot_id, stable_key) DO NOTHING`, [
            snapshotId,
            component.stableKey,
            component.componentId,
            component.name,
            component.version,
            component.purl,
            component.ecosystem,
            component.supplier,
            component.licenses,
            component.hashes,
        ]);
    }
    const dependencySet = new Set();
    for (const dep of normalized.dependencies) {
        const key = `${dep.sourceKey}->${dep.targetKey}`;
        if (dependencySet.has(key))
            continue;
        dependencySet.add(key);
        await client.query(`INSERT INTO sbom_dependencies (snapshot_id, source_key, target_key, relationship, is_transitive)
       VALUES ($1,$2,$3,$4,$5)`, [snapshotId, dep.sourceKey, dep.targetKey, dep.relationship, false]);
    }
    return { snapshotId, versionNumber };
};
const buildArtifactFingerprints = (projectId, snapshotId, body, scannedArtifacts = []) => {
    if (scannedArtifacts.length > 0) {
        return scannedArtifacts.map(artifact => ({
            artifactPath: artifact.artifactPath,
            artifactName: artifact.artifactName,
            artifactType: artifact.artifactType,
            hash: artifact.hash,
            content: artifact.content,
        }));
    }
    const explicit = Array.isArray(body?.artifacts) ? body.artifacts : [];
    if (explicit.length > 0)
        return explicit;
    if (body?.sbom) {
        return [{
                artifactName: body.artifactName || 'uploaded-sbom.json',
                artifactPath: body.artifactPath || 'uploaded-sbom.json',
                artifactType: body.sbom.bomFormat || (body.sbom.spdxVersion ? 'SPDX' : 'SBOM_JSON'),
                content: body.sbom,
            }];
    }
    return [{
            artifactName: `project-${projectId}-latest-sbom`,
            artifactPath: `project-${projectId}-latest-sbom`,
            artifactType: 'IMPORTED_SBOM',
            content: { projectId, snapshotId },
        }];
};
exports.incrementalSbomService = {
    generate: async (client, projectId, body = {}) => {
        const uploadedArtifactFiles = requestArtifactFiles(body);
        const hasDirectUploadInput = uploadedArtifactFiles.length > 0 || Boolean(body?.sbom);
        const latestSnapshot = await client.query('SELECT * FROM sbom_snapshots WHERE project_id = $1 ORDER BY version_number DESC LIMIT 1', [projectId]);
        const baseSnapshot = latestSnapshot.rows[0] || null;
        const previous = baseSnapshot ? await snapshotToNormalized(client, baseSnapshot.snapshot_id) : { components: [], dependencies: [], vulnerabilities: [], rootKey: null, format: 'INTERNAL' };
        let current;
        let scannedArtifacts = [];
        let generationSource = 'IMPORTED_SBOM';
        if (uploadedArtifactFiles.length > 0) {
            await artifactScannerService_1.artifactScannerService.saveProjectArtifacts(client, projectId, uploadedArtifactFiles);
            const scanned = artifactScannerService_1.artifactScannerService.scanArtifacts(projectId, uploadedArtifactFiles);
            current = scanned.normalized;
            scannedArtifacts = scanned.artifacts;
            generationSource = 'PROJECT_ARTIFACTS';
        }
        else {
            const storedArtifacts = await artifactScannerService_1.artifactScannerService.loadProjectArtifacts(client, projectId);
            if (storedArtifacts.length > 0) {
                const scanned = artifactScannerService_1.artifactScannerService.scanArtifacts(projectId, storedArtifacts);
                current = scanned.normalized;
                scannedArtifacts = scanned.artifacts;
                generationSource = 'PROJECT_ARTIFACTS';
            }
            else if (body?.sbom) {
                current = (0, sbomAlgorithms_1.normalizeSbomPayload)(body.sbom);
                generationSource = 'SBOM_PAYLOAD';
            }
            else {
                const latestSbom = await latestSbomForProject(client, projectId);
                if (!latestSbom && !baseSnapshot) {
                    throw new Error(`No project artifacts or imported SBOM found for projectId ${projectId}. Upload dependency files/package manager files or link an SBOM first.`);
                }
                else {
                    current = latestSbom ? await sbomMetadataToNormalized(client, latestSbom.sbom_id) : previous;
                }
            }
        }
        const diff = (0, sbomAlgorithms_1.diffSboms)(previous, current);
        const mode = generationSource === 'PROJECT_ARTIFACTS'
            ? (baseSnapshot ? 'AUTO_GENERATED' : 'FULL_SCAN')
            : (baseSnapshot ? 'INCREMENTAL_UPDATE' : 'FULL_SCAN');
        const currentFingerprintSet = new Set(scannedArtifacts.map(artifact => `${artifact.artifactPath}:${artifact.hash}`));
        if (baseSnapshot && scannedArtifacts.length > 0) {
            const previousFingerprints = await client.query('SELECT artifact_path, hash FROM sbom_artifact_fingerprints WHERE snapshot_id = $1', [baseSnapshot.snapshot_id]);
            const previousFingerprintSet = new Set(previousFingerprints.rows.map(row => `${row.artifact_path}:${row.hash}`));
            const fingerprintChanged = currentFingerprintSet.size !== previousFingerprintSet.size
                || [...currentFingerprintSet].some(item => !previousFingerprintSet.has(item));
            if (!fingerprintChanged) {
                if (hasDirectUploadInput) {
                    await client.query('UPDATE system SET last_uploaded_at = CURRENT_TIMESTAMP WHERE system_id = $1', [projectId]);
                }
                return {
                    snapshotId: baseSnapshot.snapshot_id,
                    projectId,
                    mode: 'NO_CHANGES',
                    summary: {
                        totalComponents: previous.components.length,
                        added: 0,
                        updated: 0,
                        removed: 0,
                        unchanged: previous.components.length,
                    },
                    changedArtifacts: [],
                    changeLogs: [],
                    skipped: true,
                    reason: 'Artifact fingerprints unchanged; no new snapshot was created.',
                };
            }
        }
        const saved = await saveSnapshot(client, projectId, mode, baseSnapshot?.snapshot_id || null, current, diff.summary);
        const changedArtifacts = buildArtifactFingerprints(projectId, saved.snapshotId, body, scannedArtifacts).map(artifact => ({
            projectId,
            artifactPath: artifact.artifactPath || artifact.artifactName || 'artifact',
            artifactName: artifact.artifactName || artifact.artifactPath || 'artifact',
            artifactType: artifact.artifactType || 'UNKNOWN',
            hash: artifact.hash || (0, sbomAlgorithms_1.sha256Json)(artifact.content || artifact),
        }));
        for (const artifact of changedArtifacts) {
            await client.query(`INSERT INTO sbom_artifact_fingerprints
          (project_id, artifact_path, artifact_name, artifact_type, hash, snapshot_id)
         VALUES ($1,$2,$3,$4,$5,$6)`, [projectId, artifact.artifactPath, artifact.artifactName, artifact.artifactType, artifact.hash, saved.snapshotId]);
        }
        for (const log of diff.changeLogs) {
            await client.query(`INSERT INTO sbom_change_logs
          (snapshot_id, change_type, entity_type, entity_key, component_name, previous_value, current_value)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`, [
                saved.snapshotId,
                log.changeType,
                log.entityType,
                log.entityKey,
                log.componentName || null,
                log.previousValue ? JSON.stringify(log.previousValue) : null,
                log.currentValue ? JSON.stringify(log.currentValue) : null,
            ]);
        }
        await client.query('UPDATE system SET last_uploaded_at = CURRENT_TIMESTAMP WHERE system_id = $1', [projectId]);
        return {
            snapshotId: saved.snapshotId,
            projectId,
            mode,
            summary: diff.summary,
            changedArtifacts,
            changeLogs: diff.changeLogs,
        };
    },
    listSnapshots: async (client, projectId) => {
        const { rows } = await client.query('SELECT * FROM sbom_snapshots WHERE project_id = $1 ORDER BY version_number DESC', [projectId]);
        return rows;
    },
    getChanges: async (client, snapshotId) => {
        const { rows } = await client.query('SELECT * FROM sbom_change_logs WHERE snapshot_id = $1 ORDER BY change_id ASC', [snapshotId]);
        return rows;
    },
    exportSnapshot: async (client, snapshotId) => {
        const snapshot = await client.query('SELECT * FROM sbom_snapshots WHERE snapshot_id = $1', [snapshotId]);
        const components = await client.query('SELECT * FROM sbom_components WHERE snapshot_id = $1 ORDER BY name', [snapshotId]);
        const dependencies = await client.query('SELECT * FROM sbom_dependencies WHERE snapshot_id = $1', [snapshotId]);
        return {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            serialNumber: `urn:uuid:${snapshotId}`,
            metadata: { timestamp: snapshot.rows[0]?.created_at, component: { type: 'application', name: `project-${snapshot.rows[0]?.project_id}` } },
            components: components.rows.map(row => ({
                'bom-ref': row.stable_key,
                type: row.ecosystem || 'library',
                name: row.name,
                version: row.version,
                purl: row.purl,
                licenses: row.licenses ? [{ license: { id: row.licenses } }] : undefined,
            })),
            dependencies: dependencies.rows.reduce((acc, row) => {
                let dep = acc.find(item => item.ref === row.source_key);
                if (!dep) {
                    dep = { ref: row.source_key, dependsOn: [] };
                    acc.push(dep);
                }
                dep.dependsOn.push(row.target_key);
                return acc;
            }, []),
        };
    },
};

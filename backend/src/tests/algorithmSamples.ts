import { diffSboms, normalizeSbomPayload, severityToRisk } from '../services/sbomAlgorithms';
import { artifactScannerService } from '../services/artifactScannerService';

const assertEqual = (actual: unknown, expected: unknown, message: string) => {
  if (actual !== expected) {
    throw new Error(`${message}. Expected ${expected}, got ${actual}`);
  }
};

const baseSbom = {
  bomFormat: 'CycloneDX',
  metadata: { component: { 'bom-ref': 'app', type: 'application', name: 'demo-app', version: '1.0.0' } },
  components: [
    { 'bom-ref': 'lodash', type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
    { 'bom-ref': 'axios', type: 'library', name: 'axios', version: '1.6.0', purl: 'pkg:npm/axios@1.6.0' },
  ],
  dependencies: [
    { ref: 'app', dependsOn: ['lodash', 'axios'] },
  ],
};

const addedSbom = {
  ...baseSbom,
  components: [
    ...baseSbom.components,
    { 'bom-ref': 'react', type: 'library', name: 'react', version: '19.2.5', purl: 'pkg:npm/react@19.2.5' },
  ],
  dependencies: [
    { ref: 'app', dependsOn: ['lodash', 'axios', 'react'] },
  ],
};

const updatedSbom = {
  ...baseSbom,
  components: [
    { 'bom-ref': 'lodash', type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    { 'bom-ref': 'axios', type: 'library', name: 'axios', version: '1.6.0', purl: 'pkg:npm/axios@1.6.0' },
  ],
};

const removedSbom = {
  ...baseSbom,
  components: [
    { 'bom-ref': 'lodash', type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
  ],
  dependencies: [
    { ref: 'app', dependsOn: ['lodash'] },
  ],
};

const initial = diffSboms(normalizeSbomPayload({ components: [] }), normalizeSbomPayload(baseSbom));
assertEqual(initial.summary.added, 3, 'Initial full generation should add root + 2 components');

const added = diffSboms(normalizeSbomPayload(baseSbom), normalizeSbomPayload(addedSbom));
assertEqual(added.summary.added, 1, 'Adding one dependency should be detected');

const updated = diffSboms(normalizeSbomPayload(baseSbom), normalizeSbomPayload(updatedSbom));
assertEqual(updated.summary.added, 1, 'Version change with purl creates a new stable component key');
assertEqual(updated.summary.removed, 1, 'Old version is removed when purl version changes');

const removed = diffSboms(normalizeSbomPayload(baseSbom), normalizeSbomPayload(removedSbom));
assertEqual(removed.summary.removed, 1, 'Removing one dependency should be detected');

const multiLevel = normalizeSbomPayload({
  ...baseSbom,
  components: [
    ...baseSbom.components,
    { 'bom-ref': 'follow-redirects', type: 'library', name: 'follow-redirects', version: '1.15.6', purl: 'pkg:npm/follow-redirects@1.15.6' },
  ],
  dependencies: [
    { ref: 'app', dependsOn: ['axios'] },
    { ref: 'axios', dependsOn: ['follow-redirects'] },
  ],
});
assertEqual(multiLevel.dependencies.length, 2, 'Multi-level graph sample should keep transitive dependency edges');

const cycle = normalizeSbomPayload({
  ...baseSbom,
  dependencies: [
    { ref: 'app', dependsOn: ['lodash'] },
    { ref: 'lodash', dependsOn: ['app'] },
  ],
});
assertEqual(cycle.dependencies.length, 2, 'Cycle graph sample should normalize without crashing');

assertEqual(severityToRisk(['low']), 'LOW', 'Low severity maps to LOW risk');
assertEqual(severityToRisk(['critical', 'medium']), 'CRITICAL', 'Critical severity dominates risk');

const projectV1 = artifactScannerService.scanArtifacts(1, [{
  artifactPath: 'package.json',
  content: JSON.stringify({ dependencies: { react: '^18.0.0', vite: '^5.0.0', moment: '^2.29.4' } }),
}]);

const projectV2 = artifactScannerService.scanArtifacts(1, [{
  artifactPath: 'package.json',
  content: JSON.stringify({ dependencies: { react: '^18.0.0', vite: '^5.0.0', axios: '^1.6.0', 'socket.io-client': '^4.7.0' } }),
}]);

const autoDiff = diffSboms(projectV1.normalized, projectV2.normalized);
assertEqual(autoDiff.summary.added, 2, 'Auto-generated project scan detects two added dependencies');
assertEqual(autoDiff.summary.removed, 1, 'Auto-generated project scan detects removed dependency');
assertEqual(autoDiff.summary.unchanged, 3, 'Project root plus react and vite are unchanged');

console.log('Algorithm samples passed: initial, added, updated, removed, multi-level graph, cycle, vulnerability filter inputs, auto project dependency scan.');

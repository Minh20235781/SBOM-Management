"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dependencyGraphService = void 0;
const sbomAlgorithms_1 = require("./sbomAlgorithms");
exports.dependencyGraphService = {
    buildFromSbom: (sbom, projectName) => {
        const normalized = (0, sbomAlgorithms_1.normalizeSbomPayload)(sbom);
        const nodes = normalized.components.map(component => ({
            id: component.stableKey,
            label: `${component.name}${component.version ? `@${component.version}` : ''}`,
            type: 'COMPONENT',
            ecosystem: component.ecosystem || 'unknown',
            version: component.version,
            purl: component.purl,
        }));
        const nodeIds = new Set(nodes.map(node => node.id));
        const rootId = normalized.rootKey && nodeIds.has(normalized.rootKey)
            ? normalized.rootKey
            : `project:${projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
        if (!nodeIds.has(rootId)) {
            nodes.unshift({
                id: rootId,
                label: projectName,
                type: 'PROJECT',
                ecosystem: 'web-application',
                version: null,
                purl: null,
            });
        }
        const edges = normalized.dependencies
            .filter(dep => nodeIds.has(dep.sourceKey) && nodeIds.has(dep.targetKey))
            .map(dep => ({
            id: `${dep.sourceKey}->${dep.targetKey}`,
            source: dep.sourceKey,
            target: dep.targetKey,
            relationship: dep.relationship || 'DEPENDS_ON',
        }));
        if (edges.length === 0) {
            for (const node of nodes) {
                if (node.id !== rootId) {
                    edges.push({
                        id: `${rootId}->${node.id}`,
                        source: rootId,
                        target: node.id,
                        relationship: 'DEPENDS_ON',
                    });
                }
            }
        }
        return {
            nodes,
            edges,
            summary: {
                nodeCount: nodes.length,
                edgeCount: edges.length,
            },
        };
    },
};

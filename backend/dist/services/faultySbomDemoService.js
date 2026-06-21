"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.faultySbomDemoService = void 0;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const sourceCloneService_1 = require("./sourceCloneService");
exports.faultySbomDemoService = {
    createFaultySbom: async (scenarioId, sbom) => {
        const faulty = JSON.parse(JSON.stringify(sbom));
        const components = Array.isArray(faulty.components) ? faulty.components : [];
        const removedComponent = components.length > 0 ? components.shift() : null;
        const versionMutatedComponent = components.find((component) => component && component.name);
        if (versionMutatedComponent) {
            versionMutatedComponent.version = '0.0.0-demo-mismatch';
        }
        components.push({
            type: 'library',
            name: 'fake-lib-demo',
            version: '9.9.9',
            purl: 'pkg:npm/fake-lib-demo@9.9.9',
            'bom-ref': 'pkg:npm/fake-lib-demo@9.9.9',
        });
        faulty.components = components;
        faulty.metadata = {
            ...(faulty.metadata || {}),
            timestamp: new Date().toISOString(),
            properties: [
                ...((faulty.metadata && faulty.metadata.properties) || []),
                { name: 'demo:faulty-sbom', value: 'removed one real component, added fake-lib-demo@9.9.9, changed one real component version' },
            ],
        };
        const workDir = await sourceCloneService_1.sourceCloneService.ensureWorkDir();
        const outputDir = path_1.default.join(workDir, 'generated');
        await promises_1.default.mkdir(outputDir, { recursive: true });
        const faultySbomPath = path_1.default.join(outputDir, `${scenarioId}-${Date.now()}-faulty-cyclonedx.json`);
        await promises_1.default.writeFile(faultySbomPath, JSON.stringify(faulty, null, 2), 'utf8');
        return {
            sbom: faulty,
            faultySbomPath,
            changes: {
                removedComponent: removedComponent ? `${removedComponent.name || 'unknown'}@${removedComponent.version || 'unknown'}` : null,
                addedComponent: 'fake-lib-demo@9.9.9',
                versionMutatedComponent: versionMutatedComponent
                    ? `${versionMutatedComponent.name || 'unknown'} -> 0.0.0-demo-mismatch`
                    : null,
            },
        };
    },
};

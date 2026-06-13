import fs from 'fs/promises';
import path from 'path';
import { sourceCloneService } from './sourceCloneService';

export const faultySbomDemoService = {
  createFaultySbom: async (scenarioId: string, sbom: any) => {
    const faulty = JSON.parse(JSON.stringify(sbom));
    const components = Array.isArray(faulty.components) ? faulty.components : [];
    const removedComponent = components.length > 0 ? components.shift() : null;
    const versionMutatedComponent = components.find((component: any) => component && component.name);

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

    const workDir = await sourceCloneService.ensureWorkDir();
    const outputDir = path.join(workDir, 'generated');
    await fs.mkdir(outputDir, { recursive: true });
    const faultySbomPath = path.join(outputDir, `${scenarioId}-${Date.now()}-faulty-cyclonedx.json`);
    await fs.writeFile(faultySbomPath, JSON.stringify(faulty, null, 2), 'utf8');

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

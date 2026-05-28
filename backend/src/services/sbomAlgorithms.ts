import crypto from 'crypto';

export type SourceType = 'FULL_SCAN' | 'INCREMENTAL_UPDATE' | 'IMPORT' | 'AUTO_GENERATED' | 'NO_CHANGES';
export type ChangeType = 'ADDED' | 'UPDATED' | 'REMOVED' | 'UNCHANGED';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type NormalizedComponent = {
  componentId: string;
  stableKey: string;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string;
  supplier: string | null;
  licenses: string | null;
  hashes: string | null;
};

export type NormalizedDependency = {
  sourceKey: string;
  targetKey: string;
  relationship: string;
};

export type NormalizedVulnerability = {
  affectedKey: string | null;
  severity: string | null;
};

export type NormalizedSbom = {
  components: NormalizedComponent[];
  dependencies: NormalizedDependency[];
  vulnerabilities: NormalizedVulnerability[];
  rootKey: string | null;
  format: 'CycloneDX' | 'SPDX' | 'INTERNAL';
};

export type DiffResult = {
  changeLogs: Array<{
    changeType: ChangeType;
    entityType: 'COMPONENT' | 'DEPENDENCY';
    entityKey: string;
    componentName?: string | null;
    previousValue?: unknown;
    currentValue?: unknown;
  }>;
  summary: {
    totalComponents: number;
    added: number;
    updated: number;
    removed: number;
    unchanged: number;
  };
};

const text = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
};

const inferEcosystem = (purl?: string | null, type?: string | null) => {
  if (purl?.startsWith('pkg:')) {
    const slash = purl.indexOf('/');
    return slash > 4 ? purl.slice(4, slash) : 'unknown';
  }
  if (type) return type.toLowerCase();
  return 'unknown';
};

export const stableComponentKey = (component: {
  purl?: string | null;
  ecosystem?: string | null;
  name?: string | null;
  version?: string | null;
  hashes?: string | null;
}) => {
  const purl = text(component.purl);
  if (purl) return purl.toLowerCase();

  const name = text(component.name) || 'unknown';
  const version = text(component.version) || 'unknown';
  const ecosystem = text(component.ecosystem);
  if (ecosystem) return `${ecosystem}:${name}:${version}`.toLowerCase();

  const hashes = text(component.hashes);
  return `${name}:${version}:${hashes || 'no-hash'}`.toLowerCase();
};

export const sha256Json = (value: unknown) =>
  crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');

const componentComparable = (component: NormalizedComponent) => ({
  name: component.name,
  version: component.version,
  purl: component.purl,
  licenses: component.licenses,
  hashes: component.hashes,
  supplier: component.supplier,
});

export const normalizeSbomPayload = (payload: any): NormalizedSbom => {
  const sbom = payload && payload.sbom ? payload.sbom : payload;
  const componentsByRef = new Map<string, NormalizedComponent>();
  const dependencies: NormalizedDependency[] = [];
  const vulnerabilities: NormalizedVulnerability[] = [];
  let rootKey: string | null = null;

  if (sbom?.bomFormat === 'CycloneDX' || sbom?.components) {
    const addComponent = (raw: any) => {
      const ref = raw?.['bom-ref'] || raw?.bomRef || raw?.purl || `${raw?.name || 'unknown'}@${raw?.version || ''}`;
      const license = raw?.licenses?.[0]?.license?.id || raw?.licenses?.[0]?.license?.name || raw?.licenses || null;
      const hashes = Array.isArray(raw?.hashes)
        ? raw.hashes.map((h: any) => `${h.alg || h.algorithm}:${h.content || h.value}`).join(',')
        : text(raw?.hashes);
      const component: NormalizedComponent = {
        componentId: ref,
        stableKey: '',
        name: raw?.name || 'Unknown',
        version: text(raw?.version),
        purl: text(raw?.purl),
        ecosystem: inferEcosystem(raw?.purl, raw?.type),
        supplier: text(raw?.supplier?.name || raw?.supplier),
        licenses: text(license),
        hashes,
      };
      component.stableKey = stableComponentKey(component);
      componentsByRef.set(ref, component);
      componentsByRef.set(component.stableKey, component);
      return component;
    };

    if (sbom.metadata?.component) {
      rootKey = addComponent(sbom.metadata.component).stableKey;
    }
    for (const raw of sbom.components || []) addComponent(raw);

    for (const dep of sbom.dependencies || []) {
      const source = componentsByRef.get(dep.ref);
      for (const targetRef of dep.dependsOn || []) {
        const target = componentsByRef.get(targetRef);
        if (source && target) {
          dependencies.push({ sourceKey: source.stableKey, targetKey: target.stableKey, relationship: 'DEPENDS_ON' });
        }
      }
    }

    for (const vuln of sbom.vulnerabilities || []) {
      const severity = vuln?.ratings?.[0]?.severity || vuln?.severity || null;
      const affects = vuln?.affects || [];
      if (affects.length === 0) vulnerabilities.push({ affectedKey: null, severity });
      for (const affect of affects) {
        vulnerabilities.push({ affectedKey: componentsByRef.get(affect.ref)?.stableKey || affect.ref || null, severity });
      }
    }

    return { components: uniqueComponents(componentsByRef), dependencies, vulnerabilities, rootKey, format: 'CycloneDX' };
  }

  if (sbom?.spdxVersion || sbom?.SPDXID) {
    for (const pkg of sbom.packages || []) {
      const purl = pkg.externalRefs?.find((ref: any) => ref.referenceType === 'purl')?.referenceLocator || null;
      const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : pkg.licenseDeclared;
      const component: NormalizedComponent = {
        componentId: pkg.SPDXID || pkg.name,
        stableKey: '',
        name: pkg.name || 'Unknown',
        version: text(pkg.versionInfo),
        purl,
        ecosystem: inferEcosystem(purl, null),
        supplier: text(pkg.supplier),
        licenses: text(license),
        hashes: Array.isArray(pkg.checksums) ? pkg.checksums.map((h: any) => `${h.algorithm}:${h.checksumValue}`).join(',') : null,
      };
      component.stableKey = stableComponentKey(component);
      componentsByRef.set(component.componentId, component);
      componentsByRef.set(component.stableKey, component);
    }

    for (const rel of sbom.relationships || []) {
      const forward = ['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType);
      const reverse = ['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType);
      const source = componentsByRef.get(forward ? rel.spdxElementId : rel.relatedSpdxElement);
      const target = componentsByRef.get(forward ? rel.relatedSpdxElement : rel.spdxElementId);
      if ((forward || reverse) && source && target) {
        dependencies.push({ sourceKey: source.stableKey, targetKey: target.stableKey, relationship: 'DEPENDS_ON' });
      }
    }

    return { components: uniqueComponents(componentsByRef), dependencies, vulnerabilities, rootKey, format: 'SPDX' };
  }

  return { components: [], dependencies: [], vulnerabilities: [], rootKey, format: 'INTERNAL' };
};

const uniqueComponents = (componentsByRef: Map<string, NormalizedComponent>) => {
  const byKey = new Map<string, NormalizedComponent>();
  for (const component of componentsByRef.values()) byKey.set(component.stableKey, component);
  return [...byKey.values()];
};

export const diffSboms = (previous: NormalizedSbom, current: NormalizedSbom): DiffResult => {
  const previousComponents = new Map(previous.components.map(component => [component.stableKey, component]));
  const currentComponents = new Map(current.components.map(component => [component.stableKey, component]));
  const changeLogs: DiffResult['changeLogs'] = [];
  let added = 0;
  let updated = 0;
  let removed = 0;
  let unchanged = 0;

  for (const component of current.components) {
    const old = previousComponents.get(component.stableKey);
    if (!old) {
      added += 1;
      changeLogs.push({ changeType: 'ADDED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, currentValue: componentComparable(component) });
      continue;
    }
    if (JSON.stringify(componentComparable(old)) !== JSON.stringify(componentComparable(component))) {
      updated += 1;
      changeLogs.push({ changeType: 'UPDATED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, previousValue: componentComparable(old), currentValue: componentComparable(component) });
    } else {
      unchanged += 1;
      changeLogs.push({ changeType: 'UNCHANGED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name });
    }
  }

  for (const component of previous.components) {
    if (!currentComponents.has(component.stableKey)) {
      removed += 1;
      changeLogs.push({ changeType: 'REMOVED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, previousValue: componentComparable(component) });
    }
  }

  const previousDeps = new Set(previous.dependencies.map(dep => `${dep.sourceKey}->${dep.targetKey}`));
  const currentDeps = new Set(current.dependencies.map(dep => `${dep.sourceKey}->${dep.targetKey}`));
  for (const dep of currentDeps) {
    if (!previousDeps.has(dep)) changeLogs.push({ changeType: 'ADDED', entityType: 'DEPENDENCY', entityKey: dep });
  }
  for (const dep of previousDeps) {
    if (!currentDeps.has(dep)) changeLogs.push({ changeType: 'REMOVED', entityType: 'DEPENDENCY', entityKey: dep });
  }

  return {
    changeLogs,
    summary: { totalComponents: current.components.length, added, updated, removed, unchanged },
  };
};

export const riskRank = (risk: RiskLevel) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 })[risk];

export const severityToRisk = (severities: Array<string | null | undefined>): RiskLevel => {
  const normalized = severities.map(severity => (severity || '').toLowerCase());
  if (normalized.includes('critical')) return 'CRITICAL';
  if (normalized.includes('high')) return 'HIGH';
  if (normalized.includes('medium')) return 'MEDIUM';
  return 'LOW';
};

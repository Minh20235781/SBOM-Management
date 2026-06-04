import {
  type BackendVulnerability,
  type Dependency,
  type SBOMComponent,
  type SbomGraphEdge,
  type SbomGraphNode,
  type SbomGraphResponse,
} from '../types/sbom';

const riskRank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;

const getRiskLevel = (vulnerabilities: BackendVulnerability[]): SbomGraphNode['riskLevel'] => {
  const severities = vulnerabilities.map(vuln => (vuln.severity || '').toLowerCase());
  if (severities.includes('critical')) return 'CRITICAL';
  if (severities.includes('high')) return 'HIGH';
  if (severities.includes('medium')) return 'MEDIUM';
  return 'LOW';
};

const detectEcosystem = (component: SBOMComponent) => {
  const purl = component.purl || '';
  const match = purl.match(/^pkg:([^/]+)/);
  if (match?.[1]) return match[1];
  return 'unknown';
};

const buildComponentLookup = (components: SBOMComponent[]) => {
  const lookup = new Map<string, SBOMComponent>();
  components.forEach(component => {
    lookup.set(component.component_id, component);
    if (component.purl) lookup.set(component.purl, component);
    if (component.name) lookup.set(component.name, component);
  });
  return lookup;
};

const resolveComponentId = (ref: string, lookup: Map<string, SBOMComponent>) => {
  const component = lookup.get(ref);
  return component?.component_id || ref;
};

export const buildSbomGraphFromParsedData = ({
  projectName,
  sbomId,
  components,
  dependencies,
  vulnerabilities,
  search = '',
  depthLimit = 5,
  onlyVulnerable = false,
}: {
  projectName: string;
  sbomId?: string;
  components: SBOMComponent[];
  dependencies: Dependency[];
  vulnerabilities: BackendVulnerability[];
  search?: string;
  depthLimit?: number;
  onlyVulnerable?: boolean;
}): SbomGraphResponse => {
  const rootId = `project:${sbomId || projectName || 'uploaded-sbom'}`;
  const lookup = buildComponentLookup(components);
  const vulnerabilitiesByComponent = new Map<string, BackendVulnerability[]>();

  vulnerabilities.forEach(vulnerability => {
    const rawRef = vulnerability.affected_component_ref || vulnerability.name || '';
    if (!rawRef) return;
    const componentId = resolveComponentId(rawRef, lookup);
    const list = vulnerabilitiesByComponent.get(componentId) || [];
    list.push(vulnerability);
    vulnerabilitiesByComponent.set(componentId, list);
  });

  const componentNodes: SbomGraphNode[] = components.map(component => {
    const componentVulnerabilities = vulnerabilitiesByComponent.get(component.component_id) || [];
    return {
      id: component.component_id,
      label: `${component.name}${component.version ? `@${component.version}` : ''}`,
      type: 'COMPONENT',
      ecosystem: detectEcosystem(component),
      version: component.version || null,
      license: component.licenses || null,
      purl: component.purl || null,
      supplier: component.supplier_name || null,
      hash: component.hashes || null,
      vulnerabilityCount: componentVulnerabilities.length,
      vulnerabilities: componentVulnerabilities.map(vuln => ({
        severity: vuln.severity,
        id: vuln.vulnerability || vuln.cve_id,
      })),
      riskLevel: getRiskLevel(componentVulnerabilities),
      depth: Number.MAX_SAFE_INTEGER,
      x: 0,
      y: 0,
    };
  });

  const nodeById = new Map(componentNodes.map(node => [node.id, node]));
  const dependencyEdges: SbomGraphEdge[] = [];
  const incoming = new Set<string>();
  const outgoing = new Set<string>();

  dependencies.forEach((dependency, index) => {
    const source = resolveComponentId(dependency.component_ref, lookup);
    const target = resolveComponentId(dependency.depends_on_ref, lookup);
    if (!nodeById.has(source) || !nodeById.has(target) || source === target) return;
    outgoing.add(source);
    incoming.add(target);
    dependencyEdges.push({
      id: `dep:${dependency.dependency_id || index}:${source}->${target}`,
      source,
      target,
      relationship: 'DEPENDS_ON',
      isTransitive: false,
    });
  });

  const directComponentIds = componentNodes
    .filter(node => outgoing.has(node.id) && !incoming.has(node.id))
    .map(node => node.id);
  const rootTargets = directComponentIds.length > 0
    ? directComponentIds
    : componentNodes.filter(node => !incoming.has(node.id)).map(node => node.id);

  const rootEdges = rootTargets.map(target => ({
    id: `root:${rootId}->${target}`,
    source: rootId,
    target,
    relationship: 'DEPENDS_ON' as const,
    isTransitive: false,
  }));

  const rootNode: SbomGraphNode = {
    id: rootId,
    label: projectName || 'Project',
    type: 'PROJECT',
    ecosystem: 'project',
    version: null,
    license: null,
    purl: null,
    supplier: null,
    hash: null,
    vulnerabilityCount: 0,
    riskLevel: 'LOW',
    depth: 0,
    x: 0,
    y: 0,
  };

  const allNodes = [rootNode, ...componentNodes];
  const allEdges = [...rootEdges, ...dependencyEdges];
  const adjacency = new Map<string, SbomGraphEdge[]>();
  allEdges.forEach(edge => {
    const list = adjacency.get(edge.source) || [];
    list.push(edge);
    adjacency.set(edge.source, list);
  });

  const cycleEdges = new Set<string>();
  const queue = [rootId];
  rootNode.depth = 0;

  while (queue.length > 0) {
    const current = queue.shift() as string;
    const currentNode = allNodes.find(node => node.id === current);
    const currentDepth = currentNode?.depth ?? 0;
    for (const edge of adjacency.get(current) || []) {
      const targetNode = allNodes.find(node => node.id === edge.target);
      if (!targetNode) continue;
      if (currentDepth + 1 >= targetNode.depth) {
        cycleEdges.add(edge.id);
        targetNode.hasCycle = true;
        continue;
      }
      targetNode.depth = currentDepth + 1;
      queue.push(edge.target);
    }
  }

  componentNodes.forEach(node => {
    if (node.depth === Number.MAX_SAFE_INTEGER) node.depth = 1;
  });

  const normalizedSearch = search.trim().toLowerCase();
  const includedIds = new Set<string>([rootId]);
  allNodes.forEach(node => {
    const withinDepth = node.depth <= Math.max(1, depthLimit);
    const matchesSearch = !normalizedSearch || node.label.toLowerCase().includes(normalizedSearch);
    const matchesVulnerability = !onlyVulnerable || node.type === 'PROJECT' || node.vulnerabilityCount > 0;
    if (withinDepth && matchesSearch && matchesVulnerability) includedIds.add(node.id);
  });

  allEdges.forEach(edge => {
    if (includedIds.has(edge.target)) includedIds.add(edge.source);
  });

  const visibleNodes = allNodes.filter(node => includedIds.has(node.id));
  const visibleEdges = allEdges
    .filter(edge => includedIds.has(edge.source) && includedIds.has(edge.target))
    .map(edge => ({ ...edge, hasCycle: cycleEdges.has(edge.id) }));

  const horizontalSpacing = 430;
  const verticalSpacing = 126;
  const levels = new Map<number, SbomGraphNode[]>();
  visibleNodes.forEach(node => {
    const list = levels.get(node.depth) || [];
    list.push(node);
    levels.set(node.depth, list);
  });

  levels.forEach((nodes, depth) => {
    nodes
      .sort((left, right) => (
        riskRank[right.riskLevel] - riskRank[left.riskLevel]
        || right.vulnerabilityCount - left.vulnerabilityCount
        || left.label.localeCompare(right.label)
      ))
      .forEach((node, index) => {
        node.x = depth * horizontalSpacing;
        node.y = index * verticalSpacing + (depth % 2 === 0 ? 0 : verticalSpacing / 2);
      });
  });

  const criticalCount = visibleNodes.filter(node => node.riskLevel === 'CRITICAL').length;
  const highCount = visibleNodes.filter(node => node.riskLevel === 'HIGH').length;

  return {
    snapshotId: sbomId || 'parsed-sbom',
    nodes: visibleNodes,
    edges: visibleEdges,
    summary: {
      nodeCount: visibleNodes.length,
      edgeCount: visibleEdges.length,
      maxDepth: Math.max(0, ...visibleNodes.map(node => node.depth)),
      cycleDetected: cycleEdges.size > 0,
      criticalCount,
      highCount,
    },
  };
};

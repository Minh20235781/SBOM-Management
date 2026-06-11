import { PoolClient } from 'pg';
import { riskRank, RiskLevel, severityToRisk } from './sbomAlgorithms';

type GraphOptions = {
  depth?: number;
  onlyVulnerable?: boolean;
  search?: string;
};

const horizontalSpacing = 460;
const verticalSpacing = 112;
const minNodeGap = 112;

export const sbomGraphService = {
  buildGraph: async (client: PoolClient, snapshotId: string, options: GraphOptions = {}) => {
    const [snapshotResult, componentResult, dependencyResult, vulnerabilityResult] = await Promise.all([
      client.query('SELECT * FROM sbom_snapshots WHERE snapshot_id = $1', [snapshotId]),
      client.query('SELECT * FROM sbom_components WHERE snapshot_id = $1', [snapshotId]),
      client.query('SELECT * FROM sbom_dependencies WHERE snapshot_id = $1', [snapshotId]),
      client.query(
        `SELECT c.stable_key, v.severity, v.cve_id, v.vulnerability
         FROM sbom_components c
         LEFT JOIN vulnerability v ON v.affected_component_ref = c.component_ref OR v.affected_component_ref = c.stable_key
         WHERE c.snapshot_id = $1`,
        [snapshotId]
      ),
    ]);

    const snapshot = snapshotResult.rows[0];
    const projectNodeId = `project:${snapshot?.project_id || 'unknown'}`;
    const systemResult = snapshot?.project_id
      ? await client.query('SELECT name FROM system WHERE system_id = $1', [snapshot.project_id])
      : { rows: [] as Array<{ name: string }> };
    const projectName = systemResult.rows[0]?.name?.trim() || `Project ${snapshot?.project_id || ''}`.trim();
    const vulnerabilitiesByKey = new Map<string, Array<{ severity: string | null; id: string | null }>>();
    for (const row of vulnerabilityResult.rows) {
      if (!row.severity && !row.cve_id && !row.vulnerability) continue;
      const list = vulnerabilitiesByKey.get(row.stable_key) || [];
      list.push({ severity: row.severity, id: row.cve_id || row.vulnerability });
      vulnerabilitiesByKey.set(row.stable_key, list);
    }

    const componentRows = componentResult.rows.filter(row => row.stable_key !== projectNodeId);
    const componentByKey = new Map(componentRows.map(row => [row.stable_key, row]));
    const incoming = new Set(dependencyResult.rows.map(row => row.target_key));
    const roots = componentRows.filter(row => !incoming.has(row.stable_key));
    const graphEdgeMap = new Map<string, { source: string; target: string; relationship: string }>();
    for (const row of roots) {
      graphEdgeMap.set(`${projectNodeId}->${row.stable_key}`, { source: projectNodeId, target: row.stable_key, relationship: 'DEPENDS_ON' });
    }
    for (const row of dependencyResult.rows) {
      if (row.source_key === row.target_key) continue;
      graphEdgeMap.set(`${row.source_key}->${row.target_key}`, { source: row.source_key, target: row.target_key, relationship: row.relationship || 'DEPENDS_ON' });
    }
    const graphEdges = [...graphEdgeMap.values()];

    const adjacency = new Map<string, string[]>();
    for (const edge of graphEdges) {
      const list = adjacency.get(edge.source) || [];
      list.push(edge.target);
      adjacency.set(edge.source, list);
    }

    const depths = new Map<string, number>([[projectNodeId, 0]]);
    const cycleNodes = new Set<string>();
    const cycleEdges = new Set<string>();
    const queue = [projectNodeId];
    const visitingPath = new Set<string>();

    while (queue.length > 0) {
      const source = queue.shift() as string;
      visitingPath.add(source);
      const sourceDepth = depths.get(source) || 0;
      for (const target of adjacency.get(source) || []) {
        const edgeKey = `${source}->${target}`;
        if (visitingPath.has(target) || (depths.has(target) && (depths.get(target) || 0) <= sourceDepth)) {
          cycleNodes.add(source);
          cycleNodes.add(target);
          cycleEdges.add(edgeKey);
          continue;
        }
        const nextDepth = sourceDepth + 1;
        if (!depths.has(target) || nextDepth < (depths.get(target) || Number.MAX_SAFE_INTEGER)) {
          depths.set(target, nextDepth);
          queue.push(target);
        }
      }
      visitingPath.delete(source);
    }

    const maxDepthFilter = Number.isFinite(options.depth) ? Number(options.depth) : Number.MAX_SAFE_INTEGER;
    const search = options.search?.trim().toLowerCase();

    let nodes = componentRows.map(row => {
      const vulns = vulnerabilitiesByKey.get(row.stable_key) || [];
      const riskLevel = severityToRisk(vulns.map(v => v.severity));
      return {
        id: row.stable_key,
        label: `${row.name}${row.version ? `@${row.version}` : ''}`,
        type: 'COMPONENT',
        ecosystem: row.ecosystem || 'unknown',
        version: row.version,
        license: row.licenses,
        purl: row.purl,
        supplier: row.supplier_name,
        hash: row.hashes,
        vulnerabilityCount: vulns.length,
        vulnerabilities: vulns,
        riskLevel,
        depth: depths.get(row.stable_key) ?? 1,
        x: 0,
        y: 0,
        hasCycle: cycleNodes.has(row.stable_key),
      };
    });

    nodes = nodes.filter(node => node.depth <= maxDepthFilter);
    if (options.onlyVulnerable) nodes = nodes.filter(node => node.vulnerabilityCount > 0);
    if (search) nodes = nodes.filter(node => node.label.toLowerCase().includes(search) || node.purl?.toLowerCase().includes(search));

    const visible = new Set(nodes.map(node => node.id));
    visible.add(projectNodeId);

    const projectNode = {
      id: projectNodeId,
      label: projectName,
      type: 'PROJECT',
      ecosystem: 'project',
      version: null,
      license: null,
      vulnerabilityCount: 0,
      vulnerabilities: [],
      riskLevel: 'LOW' as RiskLevel,
      depth: 0,
      x: 0,
      y: 0,
      hasCycle: false,
    };

    const allNodes = [projectNode, ...nodes];
    const nodeById = new Map(allNodes.map(node => [node.id, node]));
    const treeChildren = new Map<string, string[]>();
    for (const edge of graphEdges) {
      if (!visible.has(edge.source) || !visible.has(edge.target)) continue;
      const list = treeChildren.get(edge.source) || [];
      list.push(edge.target);
      treeChildren.set(edge.source, list);
    }

    for (const [source, children] of treeChildren) {
      treeChildren.set(source, [...new Set(children)].sort((leftId, rightId) => {
        const left = nodeById.get(leftId);
        const right = nodeById.get(rightId);
        if (!left || !right) return leftId.localeCompare(rightId);
        return riskRank(right.riskLevel) - riskRank(left.riskLevel)
          || right.vulnerabilityCount - left.vulnerabilityCount
          || left.label.localeCompare(right.label);
      }));
    }

    let leafIndex = 0;
    const positioned = new Set<string>();
    const positionNode = (nodeId: string, depth: number, path: Set<string>): number => {
      const node = nodeById.get(nodeId);
      if (!node) return leafIndex * verticalSpacing;
      node.depth = depth;
      node.x = depth * horizontalSpacing;

      if (path.has(nodeId)) {
        node.y = leafIndex++ * verticalSpacing;
        positioned.add(nodeId);
        return node.y;
      }

      if (positioned.has(nodeId)) return node.y;

      const children = (treeChildren.get(nodeId) || []).filter(childId => nodeById.has(childId));
      if (children.length === 0) {
        node.y = leafIndex++ * verticalSpacing;
      } else {
        const nextPath = new Set(path);
        nextPath.add(nodeId);
        const childYs = children.map(childId => positionNode(childId, depth + 1, nextPath));
        node.y = (Math.min(...childYs) + Math.max(...childYs)) / 2;
      }
      positioned.add(nodeId);
      return node.y;
    };

    positionNode(projectNodeId, 0, new Set());
    for (const node of allNodes) {
      if (!positioned.has(node.id)) {
        positionNode(node.id, node.depth || 1, new Set());
      }
    }
    projectNode.y = 0;

    const nodesByDepth = new Map<number, typeof allNodes>();
    for (const node of allNodes) {
      const levelNodes = nodesByDepth.get(node.depth) || [];
      levelNodes.push(node);
      nodesByDepth.set(node.depth, levelNodes);
    }
    for (const levelNodes of nodesByDepth.values()) {
      levelNodes.sort((left, right) => left.y - right.y || left.label.localeCompare(right.label));
      let nextAvailableY = Number.NEGATIVE_INFINITY;
      for (const node of levelNodes) {
        if (node.y < nextAvailableY) node.y = nextAvailableY;
        nextAvailableY = node.y + minNodeGap;
      }
    }

    const edges = graphEdges
      .filter(edge => visible.has(edge.source) && visible.has(edge.target))
      .map(edge => ({
        id: `${edge.source}->${edge.target}`,
        source: edge.source,
        target: edge.target,
        relationship: edge.relationship,
        isTransitive: (depths.get(edge.source) || 0) > 0,
        hasCycle: cycleEdges.has(`${edge.source}->${edge.target}`),
      }));

    const maxDepth = allNodes.reduce((max, node) => Math.max(max, node.depth), 0);
    const countRisk = (risk: RiskLevel) => allNodes.filter(node => node.riskLevel === risk).length;

    return {
      snapshotId,
      nodes: allNodes,
      edges,
      summary: {
        nodeCount: allNodes.length,
        edgeCount: edges.length,
        maxDepth,
        cycleDetected: cycleEdges.size > 0,
        criticalCount: countRisk('CRITICAL'),
        highCount: countRisk('HIGH'),
      },
      componentByKey,
    };
  },
};

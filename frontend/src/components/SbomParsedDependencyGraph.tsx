import React, { useMemo, useState } from 'react';
import SbomDependencyGraph from './SbomDependencyGraph';
import { buildSbomGraphFromParsedData } from '../utils/sbomGraphBuilder';
import {
  type BackendVulnerability,
  type Dependency,
  type SBOMComponent,
} from '../types/sbom';

type Props = {
  projectName: string;
  sbomId?: string;
  components: SBOMComponent[];
  dependencies: Dependency[];
  vulnerabilities: BackendVulnerability[];
};

const SbomParsedDependencyGraph: React.FC<Props> = ({
  projectName,
  sbomId,
  components,
  dependencies,
  vulnerabilities,
}) => {
  const [search, setSearch] = useState('');
  const [depth, setDepth] = useState(1);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);

  const graph = useMemo(() => buildSbomGraphFromParsedData({
    projectName,
    sbomId,
    components,
    dependencies,
    vulnerabilities,
    search,
    depthLimit: depth,
    onlyVulnerable,
  }), [projectName, sbomId, components, dependencies, vulnerabilities, search, depth, onlyVulnerable]);

  return (
    <SbomDependencyGraph
      graph={graph}
      search={search}
      depth={depth}
      onlyVulnerable={onlyVulnerable}
      onSearchChange={setSearch}
      onDepthChange={setDepth}
      onOnlyVulnerableChange={setOnlyVulnerable}
    />
  );
};

export default SbomParsedDependencyGraph;

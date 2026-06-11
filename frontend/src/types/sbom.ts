// src/types/sbom.ts
export interface SBOMTool {
  vendor?: string;
  name?: string;
  version?: string;
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
}

export interface SBOMService {
  vendor?: string;
  name?: string;
  version?: string;
  endpoints?: string[];
  authenticated?: boolean;
  'x-trust-boundary'?: boolean;
}

export interface CycloneDXVulnerability {
  id?: string;
  ratings?: Array<{
    severity?: string;
    method?: string;
    score?: number;
  }>;
  affects?: Array<{
    ref: string;
  }>;
}

export interface BackendVulnerability {
  vuln_id: number;
  sbom_id: string;
  name?: string | null;
  installed?: string | null;
  fixed_in?: string | null;
  package_type?: string | null;
  vulnerability?: string | null;
  severity?: string | null;
  epss?: number | null;
  risk?: string | null;
  cve_id?: string | null;
  description?: string | null;
  affected_component_ref?: string | null;
}

export interface CycloneDXRaw {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  metadata?: {
    timestamp?: string;
    // Thay vì 'any', ta định nghĩa rõ cấu trúc tools
    tools?: {
      components?: SBOMTool[]; // Tương ứng tool_components trong SQL
      services?: SBOMService[]; // Đã thay thế any bằng SBOMService
    } | SBOMTool[];           // Một số bản cũ dùng mảng trực tiếp
  };
  components?: Array<{
    name: string;
    version: string;
    type: string;
    'bom-ref'?: string;
    purl?: string;
    licenses?: Array<{
      license: {
        id?: string;
        name?: string;
      };
    }>;
  }>;
  dependencies?: Array<{
    ref: string;
    dependsOn?: string[];
  }>;
}
export interface SBOMMetadata {
  sbom_id: string;
  authors?: string;
  created_timestamp: string;
  tool_components?: string;
  tool_services?: string;
  lifecycle_phase?: string;
}

export interface SBOMComponent {
  component_id: string;
  sbom_id: string;
  supplier_name?: string;
  name: string;
  version?: string;
  purl?: string;
  cpe?: string;
  hashes?: string; // Hoặc string[] nếu bạn lưu dạng mảng
  licenses?: string;
  support_level?: string;
  end_of_support?: string;
}

export interface Dependency {
  dependency_id: number;
  sbom_id: string;
  component_ref: string;
  depends_on_ref: string;
}

export interface Vulnerability {
  vuln_id: number;
  sbom_id: string;
  cve_id: string;
  name?: string;
  installed?: string;
  fixed_in?: string;
  package_type?: string;
  vulnerability?: string;
  description?: string;
  severity?: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  epss?: number;
  risk?: string;
  affected_component_ref?: string;
}

// Kiểu dữ liệu tổng hợp để trả về từ API
export interface FullSBOM {
  metadata: SBOMMetadata;
  components: SBOMComponent[];
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
}

export interface SbomSnapshot {
  snapshot_id: string;
  project_id: number;
  version_number: number;
  created_at: string;
  source_type: 'FULL_SCAN' | 'INCREMENTAL_UPDATE' | 'IMPORT';
  base_snapshot_id?: string | null;
  summary?: {
    totalComponents: number;
    added: number;
    updated: number;
    removed: number;
    unchanged: number;
  };
}

export interface SbomChangeLog {
  change_id?: number;
  snapshot_id?: string;
  change_type: 'ADDED' | 'UPDATED' | 'REMOVED' | 'UNCHANGED';
  entity_type: 'COMPONENT' | 'DEPENDENCY';
  entity_key: string;
  component_name?: string | null;
}

export interface SbomGraphNode {
  id: string;
  label: string;
  type: 'PROJECT' | 'COMPONENT';
  ecosystem: string;
  version?: string | null;
  license?: string | null;
  purl?: string | null;
  supplier?: string | null;
  hash?: string | null;
  vulnerabilityCount: number;
  vulnerabilities?: Array<{ severity?: string | null; id?: string | null }>;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  depth: number;
  x: number;
  y: number;
  hasCycle?: boolean;
}

export interface SbomGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: 'DEPENDS_ON';
  isTransitive: boolean;
  hasCycle?: boolean;
}

export interface SbomGraphResponse {
  snapshotId: string;
  nodes: SbomGraphNode[];
  edges: SbomGraphEdge[];
  summary: {
    nodeCount: number;
    edgeCount: number;
    maxDepth: number;
    cycleDetected: boolean;
    criticalCount: number;
    highCount: number;
  };
}

export interface DevTask {
  task_id: number;
  project_id: number;
  title: string;
  description?: string | null;
  status: 'TODO' | 'IN_PROGRESS' | 'DONE' | 'BLOCKED';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  assigned_to?: string | null;
  related_pipeline_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface CicdPipeline {
  pipeline_id: number;
  project_id: number;
  name: string;
  provider: 'INTERNAL' | 'JENKINS' | 'GITHUB_ACTIONS' | 'GITLAB_CI' | 'CIRCLECI';
  branch: string;
  trigger_type: 'MANUAL' | 'PUSH' | 'PULL_REQUEST' | 'SCHEDULE';
  repo_url?: string | null;
  latest_run_id?: number | null;
  latest_status?: string | null;
  latest_snapshot_id?: string | null;
  latest_run_number?: number | null;
  created_at: string;
  updated_at: string;
}

export interface CicdPipelineRun {
  run_id: number;
  pipeline_id: number;
  project_id: number;
  run_number: number;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'CANCELLED';
  commit_hash?: string | null;
  branch?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  triggered_by?: string | null;
  generated_sbom_snapshot_id?: string | null;
  generated_snapshot_version?: number | null;
  snapshot_summary?: SbomSnapshot['summary'] | null;
  pipeline_name?: string;
  repo_url?: string | null;
  steps?: CicdPipelineStep[];
}

export interface CicdPipelineStep {
  step_id: number;
  pipeline_run_id: number;
  name: string;
  step_order: number;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SKIPPED';
  started_at?: string | null;
  finished_at?: string | null;
  logs?: string | null;
}

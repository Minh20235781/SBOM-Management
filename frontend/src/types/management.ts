export interface ComponentItem {
  id: string;
  name: string;
  version?: string;
  purl?: string;
  license?: string;
  supplier?: string;
  ecosystem: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface DependencyItem {
  id: string;
  source: string;
  target: string;
  type: 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN';
  scope: 'RUNTIME' | 'DEV' | 'TEST' | 'UNKNOWN';
  status: 'VERIFIED' | 'MISSING_INFO';
}

export interface VulnerabilityItem {
  id: string;
  component: string;
  affectedVersion?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssScore?: number;
  description?: string;
  recommendation: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'FIXED' | 'ACCEPTED_RISK';
}

export interface ComplianceCheck {
  id: string;
  criterion: string;
  status: 'PASS' | 'WARNING' | 'FAIL';
  impact: 'LOW' | 'MEDIUM' | 'HIGH';
  recommendation: string;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  actor: string;
  action: 'IMPORT' | 'GENERATE' | 'VERIFY' | 'UPDATE';
  target: string;
  result: 'SUCCESS' | 'FAILED';
  detail: string;
}

export interface MonitoringStatus {
  id: string;
  service: string;
  status: 'ONLINE' | 'WARNING' | 'ERROR';
  detail: string;
  checkedAt: string;
}

export interface MonitoringAlert {
  id: string;
  timestamp: string;
  repository: string;
  type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  message: string;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED';
}

export interface PipelineStep {
  name: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SKIPPED';
  logs?: string;
}

export interface PipelineRun {
  id: number;
  repository?: string;
  branch?: string;
  triggerSource?: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'CANCELLED';
  componentCount?: number;
  dependencyCount?: number;
  vulnerabilityCount?: number;
  steps?: PipelineStep[];
}

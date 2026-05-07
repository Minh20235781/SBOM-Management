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
  description?: string;
  severity?: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  affected_component_ref?: string;
}

// Kiểu dữ liệu tổng hợp để trả về từ API
export interface FullSBOM {
  metadata: SBOMMetadata;
  components: SBOMComponent[];
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
}
import { PoolClient } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { scanSBOMWithGrype } from './grypeScannerService';

export const parseAndSaveSBOM = async (client: PoolClient, data: any) => {
  let sbomId = uuidv4();
    // Support wrapper payload: { sbom: <object>, system_id?: <int> }
    const payload = data && data.sbom ? data.sbom : data;
    const providedSystemId = data && (data.system_id || data.systemId) ? (data.system_id || data.systemId) : null;
    let vulnerabilitiesInserted = false;
  
  // 1. Parsing cho SPDX
  if (payload.spdxVersion || payload.SPDXID) {
    sbomId = payload.documentNamespace || payload.SPDXID || sbomId;

    const creationInfo = payload.creationInfo || {};
    const creators = creationInfo.creators as string[] | undefined;
    const toolComponentsStr = creators?.filter(c => c.startsWith('Tool:')).join(', ') || 'N/A';
    const authorsStr = creators?.filter(c => !c.startsWith('Tool:')).join(', ') || 'N/A';

    // Insert Metadata
      await client.query(
        `INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO NOTHING`,
        [
          sbomId,
          authorsStr,
          creationInfo.created || new Date().toISOString(),
          providedSystemId,
          toolComponentsStr,
          'N/A',
          'N/A'
        ]
      );

    // Insert Components
    const packages = payload.packages || [];
    const validComponentIds = new Set<string>();
    for (const pkg of packages) {
      const compId = pkg.SPDXID || uuidv4();
      validComponentIds.add(compId);
      const externalRefs = pkg.externalRefs || [];
      const purlRef = externalRefs.find((ref: any) => ref.referenceType === 'purl');
      const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : (pkg.licenseDeclared !== 'NOASSERTION' ? pkg.licenseDeclared : 'N/A');
      
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO NOTHING`,
        [
          compId,
          sbomId,
          pkg.supplier || null,
          pkg.name || 'Unknown',
          pkg.versionInfo || null,
          purlRef ? purlRef.referenceLocator : null,
          null, // SPDX thường không chuẩn lưu cpe trực tiếp như cyclonedx, hoặc lưu trong externalRefs
          license
        ]
      );
    }

    // Insert Dependencies
    const relationships = payload.relationships || [];
    for (const rel of relationships) {
      if (['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType)) {
        if (validComponentIds.has(rel.spdxElementId) && validComponentIds.has(rel.relatedSpdxElement)) {
          await client.query(
            `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`,
            [sbomId, rel.spdxElementId, rel.relatedSpdxElement]
          );
        }
      } else if (['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType)) {
        if (validComponentIds.has(rel.relatedSpdxElement) && validComponentIds.has(rel.spdxElementId)) {
          await client.query(
            `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`,
            [sbomId, rel.relatedSpdxElement, rel.spdxElementId]
          );
        }
      }
    }
  }
  
  // 2. Parsing cho CycloneDX
  else if (payload.bomFormat === "CycloneDX" || payload.components) {
    const metadataObj = payload.metadata || {};
    sbomId = payload.serialNumber || sbomId;
    
    const authorsList = metadataObj.authors as Array<{ name?: string, email?: string }> | undefined;
    const parsedAuthors = authorsList?.map(a => `${a.name || ''} ${a.email ? `(${a.email})` : ''}`.trim()).join(', ') || 'N/A';
    
    // Tools
    let toolCompsStr = 'N/A';
    let toolServicesStr = 'N/A';
    const toolsObj = metadataObj.tools;
    if (Array.isArray(toolsObj)) {
      toolCompsStr = toolsObj.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
    } else if (toolsObj) {
      if (toolsObj.components) {
        toolCompsStr = toolsObj.components.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
      }
      if (toolsObj.services) {
        toolServicesStr = toolsObj.services.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
      }
    }

    // Insert Metadata
      await client.query(
        `INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO NOTHING`,
        [
          sbomId,
          parsedAuthors,
          metadataObj.timestamp || new Date().toISOString(),
          providedSystemId,
          toolCompsStr || 'N/A',
          toolServicesStr || 'N/A',
          'N/A'
        ]
      );

    // Insert Components
    const componentsList = payload.components || [];
    const validCdxComponentIds = new Set<string>();
    
    // Đôi khi CycloneDX có main component nằm ở metadata.component
    if (metadataObj.component && metadataObj.component['bom-ref']) {
      validCdxComponentIds.add(metadataObj.component['bom-ref']);
      const mainC = metadataObj.component;
      const licenses = mainC.licenses;
      const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO NOTHING`,
        [
          mainC['bom-ref'], sbomId, mainC.supplier?.name || null, mainC.name || 'Unknown',
          mainC.version || null, mainC.purl || null, mainC.cpe || null, licenseStr
        ]
      );
    }

    for (const c of componentsList) {
      const compId = c['bom-ref'] || uuidv4();
      validCdxComponentIds.add(compId);
      const licenses = c.licenses;
      const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
      
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO NOTHING`,
        [
          compId,
          sbomId,
          c.supplier?.name || null,
          c.name || 'Unknown',
          c.version || null,
          c.purl || null,
          c.cpe || null,
          licenseStr
        ]
      );
    }

    // Insert Dependencies
    const dependencies = payload.dependencies || [];
    for (const dep of dependencies) {
      if (validCdxComponentIds.has(dep.ref) && dep.dependsOn && Array.isArray(dep.dependsOn)) {
        for (const targetRef of dep.dependsOn) {
          if (validCdxComponentIds.has(targetRef)) {
            await client.query(
              `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref)
               VALUES ($1, $2, $3)`,
              [sbomId, dep.ref, targetRef]
            );
          }
        }
      }
    }
    
    // Insert Vulnerabilities có sẵn trong file CycloneDX (nếu có)
    const vulnerabilities = payload.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
      vulnerabilitiesInserted = true;
      for (const vuln of vulnerabilities) {
        const vulnId = vuln.id || 'UNKNOWN';
        const description = vuln.description || vuln.detail || '';
        let severity = 'Info';
        
        if (vuln.ratings && vuln.ratings.length > 0) {
          // Find highest severity or just take first
          severity = vuln.ratings[0].severity || severity;
        }
        
        const affects = vuln.affects || [];
        if (affects.length > 0) {
          for (const affect of affects) {
            await client.query(
              `INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
              [sbomId, null, null, null, null, vulnId, severity, null, null, vulnId, description, affect.ref]
            );
          }
        } else {
          await client.query(
            `INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
            [sbomId, null, null, null, null, vulnId, severity, null, null, vulnId, description, null]
          );
        }
      }
    }
  } else {
    throw new Error('Unsupported SBOM Format');
  }

  // 3. Tích hợp Grype Scanner nếu file Upload không chứa sẵn Vulnerabilities
  // Hoặc bạn có thể cho chạy luôn để update liên tục CVE mới. Ở đây chạy nếu chưa có.
  if (!vulnerabilitiesInserted) {
    console.log(`Bắt đầu quét lỗ hổng bằng Grype cho SBOM ID: ${sbomId}...`);
      const grypeResults = await scanSBOMWithGrype(payload);
    
    if (grypeResults && grypeResults.length > 0) {
      for (const vuln of grypeResults) {
        await client.query(
          `INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            sbomId,
            vuln.name,
            vuln.installed,
            vuln.fixed_in,
            vuln.package_type,
            vuln.vulnerability,
            vuln.severity,
            vuln.epss,
            vuln.risk,
            vuln.cve_id,
            vuln.description,
            vuln.affected_component_ref
          ]
        );
      }
      console.log(`Đã lưu ${grypeResults.length} lỗ hổng do Grype phát hiện.`);
    } else {
      console.log("Grype không tìm thấy lỗ hổng nào hoặc lỗi thực thi.");
    }
  }
  
  return sbomId;
};

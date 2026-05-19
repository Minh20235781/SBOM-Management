"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseAndSaveSBOM = void 0;
const uuid_1 = require("uuid");
const parseAndSaveSBOM = async (client, data) => {
    let sbomId = (0, uuid_1.v4)();
    // 1. Parsing cho SPDX
    if (data.spdxVersion || data.SPDXID) {
        sbomId = data.documentNamespace || data.SPDXID || sbomId;
        const creationInfo = data.creationInfo || {};
        const creators = creationInfo.creators;
        const toolComponentsStr = creators?.filter(c => c.startsWith('Tool:')).join(', ') || 'N/A';
        const authorsStr = creators?.filter(c => !c.startsWith('Tool:')).join(', ') || 'N/A';
        // Insert Metadata
        await client.query(`INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, tool_components, tool_services, lifecycle_phase)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (sbom_id) DO NOTHING`, [
            sbomId,
            authorsStr,
            creationInfo.created || new Date().toISOString(),
            toolComponentsStr,
            'N/A',
            'N/A'
        ]);
        // Insert Components
        const packages = data.packages || [];
        for (const pkg of packages) {
            const compId = pkg.SPDXID || (0, uuid_1.v4)();
            const externalRefs = pkg.externalRefs || [];
            const purlRef = externalRefs.find((ref) => ref.referenceType === 'purl');
            const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : (pkg.licenseDeclared !== 'NOASSERTION' ? pkg.licenseDeclared : 'N/A');
            await client.query(`INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO NOTHING`, [
                compId,
                sbomId,
                pkg.supplier || null,
                pkg.name || 'Unknown',
                pkg.versionInfo || null,
                purlRef ? purlRef.referenceLocator : null,
                null, // SPDX thường không chuẩn lưu cpe trực tiếp như cyclonedx, hoặc lưu trong externalRefs
                license
            ]);
        }
        // Insert Dependencies
        const relationships = data.relationships || [];
        for (const rel of relationships) {
            if (['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType)) {
                await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`, [sbomId, rel.spdxElementId, rel.relatedSpdxElement]);
            }
            else if (['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType)) {
                await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`, [sbomId, rel.relatedSpdxElement, rel.spdxElementId]);
            }
        }
        return sbomId;
    }
    // 2. Parsing cho CycloneDX
    if (data.bomFormat === "CycloneDX" || data.components) {
        const metadataObj = data.metadata || {};
        sbomId = data.serialNumber || sbomId;
        const authorsList = metadataObj.authors;
        const parsedAuthors = authorsList?.map(a => `${a.name || ''} ${a.email ? `(${a.email})` : ''}`.trim()).join(', ') || 'N/A';
        // Tools
        let toolCompsStr = 'N/A';
        let toolServicesStr = 'N/A';
        const toolsObj = metadataObj.tools;
        if (Array.isArray(toolsObj)) {
            toolCompsStr = toolsObj.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
        }
        else if (toolsObj) {
            if (toolsObj.components) {
                toolCompsStr = toolsObj.components.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
            }
            if (toolsObj.services) {
                toolServicesStr = toolsObj.services.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()).join(', ');
            }
        }
        // Insert Metadata
        await client.query(`INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, tool_components, tool_services, lifecycle_phase)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (sbom_id) DO NOTHING`, [
            sbomId,
            parsedAuthors,
            metadataObj.timestamp || new Date().toISOString(),
            toolCompsStr || 'N/A',
            toolServicesStr || 'N/A',
            'N/A'
        ]);
        // Insert Components
        const componentsList = data.components || [];
        for (const c of componentsList) {
            const compId = c['bom-ref'] || (0, uuid_1.v4)();
            const licenses = c.licenses;
            const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
            await client.query(`INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO NOTHING`, [
                compId,
                sbomId,
                c.supplier?.name || null,
                c.name || 'Unknown',
                c.version || null,
                c.purl || null,
                c.cpe || null,
                licenseStr
            ]);
        }
        // Insert Dependencies
        const dependencies = data.dependencies || [];
        for (const dep of dependencies) {
            if (dep.dependsOn && Array.isArray(dep.dependsOn)) {
                for (const targetRef of dep.dependsOn) {
                    await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref)
             VALUES ($1, $2, $3)`, [sbomId, dep.ref, targetRef]);
                }
            }
        }
        // Insert Vulnerabilities
        const vulnerabilities = data.vulnerabilities || [];
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
                    await client.query(`INSERT INTO vulnerability (sbom_id, cve_id, description, severity, affected_component_ref)
             VALUES ($1, $2, $3, $4, $5)`, [sbomId, vulnId, description, severity, affect.ref]);
                }
            }
            else {
                await client.query(`INSERT INTO vulnerability (sbom_id, cve_id, description, severity, affected_component_ref)
           VALUES ($1, $2, $3, $4, $5)`, [sbomId, vulnId, description, severity, null]);
            }
        }
        return sbomId;
    }
    throw new Error('Unsupported SBOM Format');
};
exports.parseAndSaveSBOM = parseAndSaveSBOM;

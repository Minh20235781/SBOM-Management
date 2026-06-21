"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseAndSaveSBOM = void 0;
const uuid_1 = require("uuid");
const crypto_1 = __importDefault(require("crypto"));
const grypeScannerService_1 = require("./grypeScannerService");
const joinNonEmpty = (items) => {
    const value = items.filter((item) => Boolean(item && item.trim())).join(', ');
    return value || null;
};
const normalizeText = (value) => {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    return trimmed || null;
};
const propertyValue = (properties, name) => {
    if (!Array.isArray(properties))
        return null;
    const found = properties.find((item) => item?.name === name);
    return normalizeText(found?.value);
};
const makeScopedComponentId = (sbomId, rawRef) => {
    const ref = String(rawRef || (0, uuid_1.v4)());
    const candidate = `${sbomId}::${ref}`;
    if (candidate.length <= 240)
        return candidate;
    const digest = crypto_1.default.createHash('sha256').update(candidate).digest('hex');
    const prefix = sbomId.length > 120 ? sbomId.slice(0, 120) : sbomId;
    return `${prefix}::${digest}`;
};
const clearExistingSbomDetails = async (client, sbomId) => {
    await client.query('DELETE FROM vulnerability WHERE sbom_id = $1', [sbomId]);
    await client.query('DELETE FROM dependency WHERE sbom_id = $1', [sbomId]);
    await client.query('DELETE FROM component WHERE sbom_id = $1', [sbomId]);
};
const parseAndSaveSBOM = async (client, data) => {
    let sbomId = (0, uuid_1.v4)();
    // Support wrapper payload: { sbom: <object>, system_id?: <int> }
    const payload = data && data.sbom ? data.sbom : data;
    const providedSystemId = data && (data.system_id || data.systemId) ? (data.system_id || data.systemId) : null;
    let vulnerabilitiesInserted = false;
    const componentLookupByRawRef = new Map();
    // 1. Parsing cho SPDX
    if (payload.spdxVersion || payload.SPDXID) {
        sbomId = payload.documentNamespace || payload.SPDXID || sbomId;
        await clearExistingSbomDetails(client, sbomId);
        const creationInfo = payload.creationInfo || {};
        const creators = creationInfo.creators;
        const toolComponentsStr = creators?.filter(c => c.startsWith('Tool:')).join(', ') || 'N/A';
        const authorsStr = creators?.filter(c => !c.startsWith('Tool:')).join(', ') || 'N/A';
        // Insert Metadata
        await client.query(`INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO UPDATE SET
          system_id = COALESCE(EXCLUDED.system_id, sbom_metadata.system_id),
          authors = COALESCE(EXCLUDED.authors, sbom_metadata.authors),
          tool_components = COALESCE(EXCLUDED.tool_components, sbom_metadata.tool_components),
          tool_services = COALESCE(EXCLUDED.tool_services, sbom_metadata.tool_services),
          lifecycle_phase = COALESCE(EXCLUDED.lifecycle_phase, sbom_metadata.lifecycle_phase)`, [
            sbomId,
            authorsStr,
            creationInfo.created || new Date().toISOString(),
            providedSystemId,
            toolComponentsStr,
            'N/A',
            'N/A'
        ]);
        // Insert Components
        const packages = payload.packages || [];
        const componentIdByRef = new Map();
        for (const pkg of packages) {
            const rawRef = pkg.SPDXID || (0, uuid_1.v4)();
            const compId = makeScopedComponentId(sbomId, rawRef);
            componentIdByRef.set(rawRef, compId);
            componentLookupByRawRef.set(rawRef, compId);
            const externalRefs = pkg.externalRefs || [];
            const purlRef = externalRefs.find((ref) => ref.referenceType === 'purl');
            const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : (pkg.licenseDeclared !== 'NOASSERTION' ? pkg.licenseDeclared : 'N/A');
            await client.query(`INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`, [
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
        const relationships = payload.relationships || [];
        for (const rel of relationships) {
            if (['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType)) {
                const sourceId = componentIdByRef.get(rel.spdxElementId);
                const targetId = componentIdByRef.get(rel.relatedSpdxElement);
                if (sourceId && targetId) {
                    await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`, [sbomId, sourceId, targetId]);
                }
            }
            else if (['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType)) {
                const sourceId = componentIdByRef.get(rel.relatedSpdxElement);
                const targetId = componentIdByRef.get(rel.spdxElementId);
                if (sourceId && targetId) {
                    await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`, [sbomId, sourceId, targetId]);
                }
            }
        }
    }
    // 2. Parsing cho CycloneDX
    else if (payload.bomFormat === "CycloneDX" || payload.components) {
        const metadataObj = payload.metadata || {};
        sbomId = payload.serialNumber || sbomId;
        await clearExistingSbomDetails(client, sbomId);
        const authorsList = metadataObj.authors;
        const parsedAuthors = joinNonEmpty(authorsList?.map(a => `${a.name || ''}${a.email ? ` (${a.email})` : ''}`.trim()) || [])
            ?? normalizeText(metadataObj.author)
            ?? normalizeText(metadataObj.creator)
            ?? normalizeText(payload.authors)
            ?? normalizeText(payload.author)
            ?? null;
        // Tools
        let toolCompsStr = null;
        let toolServicesStr = null;
        const toolsObj = metadataObj.tools;
        if (Array.isArray(toolsObj)) {
            toolCompsStr = joinNonEmpty(toolsObj.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
        }
        else if (toolsObj) {
            if (toolsObj.components) {
                toolCompsStr = joinNonEmpty(toolsObj.components.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
            }
            if (toolsObj.services) {
                toolServicesStr = joinNonEmpty(toolsObj.services.map((t) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
            }
        }
        // CycloneDX thường có thông tin này ở các chỗ khác nhau tùy generator, nên thử các fallback phổ biến.
        toolCompsStr =
            toolCompsStr
                ?? normalizeText(metadataObj.tool_components)
                ?? normalizeText(payload.tool_components)
                ?? normalizeText(payload.toolComponents)
                ?? null;
        toolServicesStr =
            toolServicesStr
                ?? normalizeText(metadataObj.tool_services)
                ?? normalizeText(payload.tool_services)
                ?? normalizeText(payload.toolServices)
                ?? (Array.isArray(payload.services)
                    ? joinNonEmpty(payload.services.map((s) => `${s.vendor || ''} ${s.name || ''} ${s.version || ''}`.trim()))
                    : null)
                ?? null;
        const lifecyclePhase = normalizeText(metadataObj.lifecycle_phase)
            ?? normalizeText(metadataObj.lifecyclePhase)
            ?? normalizeText(metadataObj.lifecycle?.phase)
            ?? normalizeText(payload.lifecycle_phase)
            ?? normalizeText(payload.lifecyclePhase)
            ?? normalizeText(payload.lifecycle?.phase)
            ?? propertyValue(metadataObj.properties, 'devops.lifecycle.phase')
            ?? propertyValue(payload.properties, 'devops.lifecycle.phase')
            ?? normalizeText(payload.lifecyle_phase)
            ?? null;
        // Insert Metadata
        await client.query(`INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO UPDATE SET
          system_id = COALESCE(EXCLUDED.system_id, sbom_metadata.system_id),
          authors = COALESCE(EXCLUDED.authors, sbom_metadata.authors),
          tool_components = COALESCE(EXCLUDED.tool_components, sbom_metadata.tool_components),
          tool_services = COALESCE(EXCLUDED.tool_services, sbom_metadata.tool_services),
          lifecycle_phase = COALESCE(EXCLUDED.lifecycle_phase, sbom_metadata.lifecycle_phase)`, [
            sbomId,
            parsedAuthors,
            metadataObj.timestamp || new Date().toISOString(),
            providedSystemId,
            toolCompsStr,
            toolServicesStr,
            lifecyclePhase
        ]);
        // Insert Components
        const componentsList = payload.components || [];
        const componentIdByRef = new Map();
        // Đôi khi CycloneDX có main component nằm ở metadata.component
        if (metadataObj.component && metadataObj.component['bom-ref']) {
            const mainC = metadataObj.component;
            const rawRef = mainC['bom-ref'];
            const compId = makeScopedComponentId(sbomId, rawRef);
            componentIdByRef.set(rawRef, compId);
            componentLookupByRawRef.set(rawRef, compId);
            const licenses = mainC.licenses;
            const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
            await client.query(`INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`, [
                compId, sbomId, mainC.supplier?.name || null, mainC.name || 'Unknown',
                mainC.version || null, mainC.purl || null, mainC.cpe || null, licenseStr
            ]);
        }
        for (const c of componentsList) {
            const rawRef = c['bom-ref'] || (0, uuid_1.v4)();
            const compId = makeScopedComponentId(sbomId, rawRef);
            componentIdByRef.set(rawRef, compId);
            componentLookupByRawRef.set(rawRef, compId);
            const licenses = c.licenses;
            const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
            await client.query(`INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`, [
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
        const dependencies = payload.dependencies || [];
        for (const dep of dependencies) {
            const sourceId = componentIdByRef.get(dep.ref);
            if (sourceId && dep.dependsOn && Array.isArray(dep.dependsOn)) {
                for (const targetRef of dep.dependsOn) {
                    const targetId = componentIdByRef.get(targetRef);
                    if (targetId) {
                        await client.query(`INSERT INTO dependency (sbom_id, component_ref, depends_on_ref)
               VALUES ($1, $2, $3)`, [sbomId, sourceId, targetId]);
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
                        const affectedComponentId = componentIdByRef.get(affect.ref) || null;
                        await client.query(`INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, [sbomId, null, null, null, null, vulnId, severity, null, null, vulnId, description, affectedComponentId]);
                    }
                }
                else {
                    await client.query(`INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, [sbomId, null, null, null, null, vulnId, severity, null, null, vulnId, description, null]);
                }
            }
        }
    }
    else {
        throw new Error('Unsupported SBOM Format');
    }
    // 3. Tích hợp Grype Scanner nếu file Upload không chứa sẵn Vulnerabilities
    // Hoặc bạn có thể cho chạy luôn để update liên tục CVE mới. Ở đây chạy nếu chưa có.
    if (!vulnerabilitiesInserted) {
        console.log(`Bắt đầu quét lỗ hổng bằng Grype cho SBOM ID: ${sbomId}...`);
        const grypeResults = await (0, grypeScannerService_1.scanSBOMWithGrype)(payload);
        if (grypeResults && grypeResults.length > 0) {
            for (const vuln of grypeResults) {
                const affectedComponentRef = vuln.affected_component_ref
                    ? componentLookupByRawRef.get(vuln.affected_component_ref) || null
                    : null;
                await client.query(`INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, [
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
                    affectedComponentRef
                ]);
            }
            console.log(`Đã lưu ${grypeResults.length} lỗ hổng do Grype phát hiện.`);
        }
        else {
            console.log("Grype không tìm thấy lỗ hổng nào hoặc lỗi thực thi.");
        }
    }
    if (providedSystemId) {
        await client.query('UPDATE system SET last_uploaded_at = CURRENT_TIMESTAMP WHERE system_id = $1', [providedSystemId]);
    }
    return sbomId;
};
exports.parseAndSaveSBOM = parseAndSaveSBOM;

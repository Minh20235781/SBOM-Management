import { PoolClient } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { scanSBOMWithGrype } from './grypeScannerService';

const joinNonEmpty = (items: Array<string | null | undefined>) => {
  const value = items.filter((item): item is string => Boolean(item && item.trim())).join(', ');
  return value || null;
};

const normalizeText = (value: unknown) => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
};

const stringifyOrNull = (value: unknown) => {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.length > 0 ? value.join(', ') : null;
  if (typeof value === 'object') return JSON.stringify(value);
  const text = String(value).trim();
  return text || null;
};

const jsonOrNull = (value: unknown) => {
  if (value === undefined || value === null) return null;
  return JSON.stringify(value);
};

const isSpdxPayload = (value: any) => {
  if (!value || typeof value !== 'object') return false;
  return Boolean(value.spdxVersion || value.SPDXID || value.documentNamespace || Array.isArray(value.packages));
};

const isCycloneDxPayload = (value: any) => {
  if (!value || typeof value !== 'object') return false;
  return value.bomFormat === 'CycloneDX' || Array.isArray(value.components);
};

const unwrapSbomPayload = (value: any): any => {
  if (!value) return value;
  if (Array.isArray(value)) {
    return value.length === 1 ? unwrapSbomPayload(value[0]) : value;
  }
  if (typeof value !== 'object') return value;
  if (isSpdxPayload(value) || isCycloneDxPayload(value)) return value;

  const wrapperKeys = [
    'sbom',
    'bom',
    'data',
    'document',
    'payload',
    'sbomData',
    'sbom_data',
    'sbomJson',
    'sbom_json',
    'rawSbom',
    'raw_sbom',
  ];

  for (const key of wrapperKeys) {
    if (value[key]) {
      const unwrapped = unwrapSbomPayload(value[key]);
      if (isSpdxPayload(unwrapped) || isCycloneDxPayload(unwrapped)) return unwrapped;
    }
  }

  return value;
};

const propertyValue = (properties: unknown, name: string) => {
  if (!Array.isArray(properties)) return null;
  const found = properties.find((item: any) => item?.name === name);
  return normalizeText(found?.value);
};

const makeScopedComponentId = (sbomId: string, rawRef: unknown) => {
  const ref = String(rawRef || uuidv4());
  const candidate = `${sbomId}::${ref}`;
  if (candidate.length <= 240) return candidate;
  const digest = crypto.createHash('sha256').update(candidate).digest('hex');
  const prefix = sbomId.length > 120 ? sbomId.slice(0, 120) : sbomId;
  return `${prefix}::${digest}`;
};

const clearExistingSbomDetails = async (client: PoolClient, sbomId: string) => {
  await client.query('DELETE FROM vulnerability WHERE sbom_id = $1', [sbomId]);
  await client.query('DELETE FROM dependency WHERE sbom_id = $1', [sbomId]);
  await client.query('DELETE FROM component WHERE sbom_id = $1', [sbomId]);
};

const clearExistingSpdxDetails = async (client: PoolClient, spdxDocumentId: string) => {
  await client.query('DELETE FROM spdx_document WHERE spdx_document_id = $1', [spdxDocumentId]);
};

export const parseAndSaveSBOM = async (client: PoolClient, data: any) => {
  let sbomId = uuidv4();
    // Support wrapper payload: { sbom: <object>, system_id?: <int> }
    const payload = unwrapSbomPayload(data && data.sbom ? data.sbom : data);
    const providedSystemId = data && (data.system_id || data.systemId) ? (data.system_id || data.systemId) : null;
    let vulnerabilitiesInserted = false;
    const componentLookupByRawRef = new Map<string, string>();
  
  // 1. Parsing cho SPDX
  if (isSpdxPayload(payload)) {
    sbomId = payload.documentNamespace || payload.SPDXID || sbomId;
    await clearExistingSbomDetails(client, sbomId);
    await clearExistingSpdxDetails(client, sbomId);

    const creationInfo = payload.creationInfo || {};
    const creators = creationInfo.creators as string[] | undefined;
    const toolComponentsStr = creators?.filter(c => c.startsWith('Tool:')).join(', ') || 'N/A';
    const authorsStr = creators?.filter(c => !c.startsWith('Tool:')).join(', ') || 'N/A';

    // Insert Metadata
      await client.query(
        `INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO UPDATE SET
          system_id = COALESCE(EXCLUDED.system_id, sbom_metadata.system_id),
          authors = COALESCE(EXCLUDED.authors, sbom_metadata.authors),
          tool_components = COALESCE(EXCLUDED.tool_components, sbom_metadata.tool_components),
          tool_services = COALESCE(EXCLUDED.tool_services, sbom_metadata.tool_services),
          lifecycle_phase = COALESCE(EXCLUDED.lifecycle_phase, sbom_metadata.lifecycle_phase)`,
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

    await client.query(
      `INSERT INTO spdx_document (
        spdx_document_id,
        system_id,
        spdx_version,
        data_license,
        spdx_id,
        name,
        document_namespace,
        document_describes,
        comment,
        created_timestamp,
        creators,
        creator_comment,
        license_list_version,
        raw_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`,
      [
        sbomId,
        providedSystemId,
        payload.spdxVersion || null,
        payload.dataLicense || null,
        payload.SPDXID || null,
        payload.name || null,
        payload.documentNamespace || null,
        stringifyOrNull(payload.documentDescribes),
        payload.comment || null,
        creationInfo.created || new Date().toISOString(),
        stringifyOrNull(creators),
        creationInfo.comment || null,
        creationInfo.licenseListVersion || null,
        jsonOrNull(payload)
      ]
    );

    const externalDocumentRefs = payload.externalDocumentRefs || [];
    for (const ref of externalDocumentRefs) {
      await client.query(
        `INSERT INTO spdx_external_document_ref (
          spdx_document_id,
          external_document_id,
          spdx_document_uri,
          checksum_algorithm,
          checksum_value
        )
        VALUES ($1, $2, $3, $4, $5)`,
        [
          sbomId,
          ref.externalDocumentId || null,
          ref.spdxDocument || null,
          ref.checksum?.algorithm || null,
          ref.checksum?.checksumValue || null
        ]
      );
    }

    // Insert Components
    const packages = payload.packages || [];
    const componentIdByRef = new Map<string, string>();
    for (const pkg of packages) {
      const rawRef = pkg.SPDXID || uuidv4();
      const compId = makeScopedComponentId(sbomId, rawRef);
      componentIdByRef.set(rawRef, compId);
      componentLookupByRawRef.set(rawRef, compId);
      const externalRefs = pkg.externalRefs || [];
      const purlRef = externalRefs.find((ref: any) => ref.referenceType === 'purl');
      const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : (pkg.licenseDeclared !== 'NOASSERTION' ? pkg.licenseDeclared : 'N/A');
      
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`,
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

      await client.query(
        `INSERT INTO spdx_package (
          package_id,
          spdx_document_id,
          spdx_id,
          name,
          version_info,
          supplier,
          originator,
          download_location,
          files_analyzed,
          verification_code,
          verification_code_excluded_files,
          checksums,
          homepage,
          source_info,
          license_concluded,
          license_declared,
          license_comments,
          copyright_text,
          summary,
          description,
          comment,
          primary_package_purpose,
          release_date,
          built_date,
          valid_until_date,
          raw_json
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26::jsonb)`,
        [
          compId,
          sbomId,
          rawRef,
          pkg.name || 'Unknown',
          pkg.versionInfo || null,
          pkg.supplier || null,
          pkg.originator || null,
          pkg.downloadLocation || null,
          typeof pkg.filesAnalyzed === 'boolean' ? pkg.filesAnalyzed : null,
          pkg.packageVerificationCode?.packageVerificationCodeValue || null,
          stringifyOrNull(pkg.packageVerificationCode?.packageVerificationCodeExcludedFiles),
          stringifyOrNull(pkg.checksums),
          pkg.homepage || null,
          pkg.sourceInfo || null,
          pkg.licenseConcluded || null,
          pkg.licenseDeclared || null,
          pkg.licenseComments || null,
          pkg.copyrightText || null,
          pkg.summary || null,
          pkg.description || null,
          pkg.comment || null,
          pkg.primaryPackagePurpose || null,
          pkg.releaseDate || null,
          pkg.builtDate || null,
          pkg.validUntilDate || null,
          jsonOrNull(pkg)
        ]
      );

      for (const extRef of externalRefs) {
        await client.query(
          `INSERT INTO spdx_package_external_ref (
            package_id,
            reference_category,
            reference_type,
            reference_locator,
            comment
          )
          VALUES ($1, $2, $3, $4, $5)`,
          [
            compId,
            extRef.referenceCategory || null,
            extRef.referenceType || null,
            extRef.referenceLocator || null,
            extRef.comment || null
          ]
        );
      }

      const attributionTexts = pkg.attributionTexts || [];
      for (const attributionText of attributionTexts) {
        await client.query(
          `INSERT INTO spdx_package_attribution (package_id, attribution_text)
           VALUES ($1, $2)`,
          [compId, String(attributionText)]
        );
      }
    }

    const files = payload.files || [];
    const fileIdByRef = new Map<string, string>();
    for (const file of files) {
      const rawRef = file.SPDXID || uuidv4();
      const fileId = makeScopedComponentId(sbomId, rawRef);
      fileIdByRef.set(rawRef, fileId);
      await client.query(
        `INSERT INTO spdx_file (
          file_id,
          spdx_document_id,
          spdx_id,
          file_name,
          file_types,
          checksums,
          license_concluded,
          license_info_in_files,
          license_comments,
          copyright_text,
          notice_text,
          contributors,
          comment,
          raw_json
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`,
        [
          fileId,
          sbomId,
          rawRef,
          file.fileName || 'Unknown',
          stringifyOrNull(file.fileTypes),
          stringifyOrNull(file.checksums),
          file.licenseConcluded || null,
          stringifyOrNull(file.licenseInfoInFiles),
          file.licenseComments || null,
          file.copyrightText || null,
          file.noticeText || null,
          stringifyOrNull(file.fileContributors),
          file.comment || null,
          jsonOrNull(file)
        ]
      );
    }

    const snippets = payload.snippets || [];
    for (const snippet of snippets) {
      const rawRef = snippet.SPDXID || uuidv4();
      const snippetId = makeScopedComponentId(sbomId, rawRef);
      const sourceFileRef = snippet.snippetFromFile;
      await client.query(
        `INSERT INTO spdx_snippet (
          snippet_id,
          spdx_document_id,
          spdx_id,
          snippet_from_file,
          name,
          byte_range_start,
          byte_range_end,
          line_range_start,
          line_range_end,
          license_concluded,
          license_info_in_snippets,
          license_comments,
          copyright_text,
          comment,
          raw_json
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb)`,
        [
          snippetId,
          sbomId,
          rawRef,
          sourceFileRef ? fileIdByRef.get(sourceFileRef) || null : null,
          snippet.name || null,
          snippet.ranges?.[0]?.startPointer?.offset ?? null,
          snippet.ranges?.[0]?.endPointer?.offset ?? null,
          snippet.ranges?.[0]?.startPointer?.lineNumber ?? null,
          snippet.ranges?.[0]?.endPointer?.lineNumber ?? null,
          snippet.licenseConcluded || null,
          stringifyOrNull(snippet.licenseInfoInSnippets),
          snippet.licenseComments || null,
          snippet.copyrightText || null,
          snippet.comment || null,
          jsonOrNull(snippet)
        ]
      );
    }

    // Insert Dependencies
    const relationships = payload.relationships || [];
    for (const rel of relationships) {
      await client.query(
        `INSERT INTO spdx_relationship (
          spdx_document_id,
          spdx_element_id,
          relationship_type,
          related_spdx_element,
          comment
        )
        VALUES ($1, $2, $3, $4, $5)`,
        [
          sbomId,
          rel.spdxElementId || null,
          rel.relationshipType || null,
          rel.relatedSpdxElement || null,
          rel.comment || null
        ]
      );

      if (['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType)) {
        const sourceId = componentIdByRef.get(rel.spdxElementId);
        const targetId = componentIdByRef.get(rel.relatedSpdxElement);
        if (sourceId && targetId) {
          await client.query(
            `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`,
            [sbomId, sourceId, targetId]
          );
        }
      } else if (['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType)) {
        const sourceId = componentIdByRef.get(rel.relatedSpdxElement);
        const targetId = componentIdByRef.get(rel.spdxElementId);
        if (sourceId && targetId) {
          await client.query(
            `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref) VALUES ($1, $2, $3)`,
            [sbomId, sourceId, targetId]
          );
        }
      }
    }

    const annotations = payload.annotations || [];
    for (const annotation of annotations) {
      await client.query(
        `INSERT INTO spdx_annotation (
          spdx_document_id,
          spdx_id,
          annotation_type,
          annotator,
          annotation_date,
          comment
        )
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          sbomId,
          annotation.SPDXID || annotation.spdxElementId || null,
          annotation.annotationType || null,
          annotation.annotator || null,
          annotation.annotationDate || null,
          annotation.comment || null
        ]
      );
    }

    const extractedLicensingInfos = payload.hasExtractedLicensingInfos || [];
    for (const licenseInfo of extractedLicensingInfos) {
      await client.query(
        `INSERT INTO spdx_extracted_licensing_info (
          spdx_document_id,
          license_id,
          extracted_text,
          name,
          see_alsos,
          comment
        )
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          sbomId,
          licenseInfo.licenseId || licenseInfo.licenseID || null,
          licenseInfo.extractedText || null,
          licenseInfo.name || null,
          stringifyOrNull(licenseInfo.seeAlsos),
          licenseInfo.comment || null
        ]
      );
    }
  }
  
  // 2. Parsing cho CycloneDX
  else if (isCycloneDxPayload(payload)) {
    const metadataObj = payload.metadata || {};
    sbomId = payload.serialNumber || sbomId;
    await clearExistingSbomDetails(client, sbomId);
    
    const authorsList = metadataObj.authors as Array<{ name?: string, email?: string }> | undefined;
    const parsedAuthors = joinNonEmpty(
      authorsList?.map(a => `${a.name || ''}${a.email ? ` (${a.email})` : ''}`.trim()) || []
    )
      ?? normalizeText((metadataObj as any).author)
      ?? normalizeText((metadataObj as any).creator)
      ?? normalizeText((payload as any).authors)
      ?? normalizeText((payload as any).author)
      ?? null;
    
    // Tools
    let toolCompsStr: string | null = null;
    let toolServicesStr: string | null = null;
    const toolsObj = metadataObj.tools;
    if (Array.isArray(toolsObj)) {
      toolCompsStr = joinNonEmpty(toolsObj.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
    } else if (toolsObj) {
      if (toolsObj.components) {
        toolCompsStr = joinNonEmpty(toolsObj.components.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
      }
      if (toolsObj.services) {
        toolServicesStr = joinNonEmpty(toolsObj.services.map((t: any) => `${t.vendor || ''} ${t.name || ''} ${t.version || ''}`.trim()));
      }
    }

    // CycloneDX thường có thông tin này ở các chỗ khác nhau tùy generator, nên thử các fallback phổ biến.
    toolCompsStr =
      toolCompsStr
      ?? normalizeText((metadataObj as any).tool_components)
      ?? normalizeText((payload as any).tool_components)
      ?? normalizeText((payload as any).toolComponents)
      ?? null;

    toolServicesStr =
      toolServicesStr
      ?? normalizeText((metadataObj as any).tool_services)
      ?? normalizeText((payload as any).tool_services)
      ?? normalizeText((payload as any).toolServices)
      ?? (Array.isArray((payload as any).services)
        ? joinNonEmpty((payload as any).services.map((s: any) => `${s.vendor || ''} ${s.name || ''} ${s.version || ''}`.trim()))
        : null)
      ?? null;

    const lifecyclePhase =
      normalizeText((metadataObj as any).lifecycle_phase)
      ?? normalizeText((metadataObj as any).lifecyclePhase)
      ?? normalizeText((metadataObj as any).lifecycle?.phase)
      ?? normalizeText((payload as any).lifecycle_phase)
      ?? normalizeText((payload as any).lifecyclePhase)
      ?? normalizeText((payload as any).lifecycle?.phase)
      ?? propertyValue((metadataObj as any).properties, 'devops.lifecycle.phase')
      ?? propertyValue((payload as any).properties, 'devops.lifecycle.phase')
      ?? normalizeText((payload as any).lifecyle_phase)
      ?? null;

    // Insert Metadata
      await client.query(
        `INSERT INTO sbom_metadata (sbom_id, authors, created_timestamp, system_id, tool_components, tool_services, lifecycle_phase)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (sbom_id) DO UPDATE SET
          system_id = COALESCE(EXCLUDED.system_id, sbom_metadata.system_id),
          authors = COALESCE(EXCLUDED.authors, sbom_metadata.authors),
          tool_components = COALESCE(EXCLUDED.tool_components, sbom_metadata.tool_components),
          tool_services = COALESCE(EXCLUDED.tool_services, sbom_metadata.tool_services),
          lifecycle_phase = COALESCE(EXCLUDED.lifecycle_phase, sbom_metadata.lifecycle_phase)`,
        [
          sbomId,
          parsedAuthors,
          metadataObj.timestamp || new Date().toISOString(),
          providedSystemId,
          toolCompsStr,
          toolServicesStr,
          lifecyclePhase
        ]
      );

    // Insert Components
    const componentsList = payload.components || [];
    const componentIdByRef = new Map<string, string>();
    
    // Đôi khi CycloneDX có main component nằm ở metadata.component
    if (metadataObj.component && metadataObj.component['bom-ref']) {
      const mainC = metadataObj.component;
      const rawRef = mainC['bom-ref'];
      const compId = makeScopedComponentId(sbomId, rawRef);
      componentIdByRef.set(rawRef, compId);
      componentLookupByRawRef.set(rawRef, compId);
      const licenses = mainC.licenses;
      const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`,
        [
          compId, sbomId, mainC.supplier?.name || null, mainC.name || 'Unknown',
          mainC.version || null, mainC.purl || null, mainC.cpe || null, licenseStr
        ]
      );
    }

    for (const c of componentsList) {
      const rawRef = c['bom-ref'] || uuidv4();
      const compId = makeScopedComponentId(sbomId, rawRef);
      componentIdByRef.set(rawRef, compId);
      componentLookupByRawRef.set(rawRef, compId);
      const licenses = c.licenses;
      const licenseStr = licenses?.[0]?.license?.id || licenses?.[0]?.license?.name || 'N/A';
      
      await client.query(
        `INSERT INTO component (component_id, sbom_id, supplier_name, name, version, purl, cpe, licenses)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (component_id) DO UPDATE SET
          sbom_id = EXCLUDED.sbom_id,
          supplier_name = EXCLUDED.supplier_name,
          name = EXCLUDED.name,
          version = EXCLUDED.version,
          purl = EXCLUDED.purl,
          cpe = EXCLUDED.cpe,
          licenses = EXCLUDED.licenses`,
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
      const sourceId = componentIdByRef.get(dep.ref);
      if (sourceId && dep.dependsOn && Array.isArray(dep.dependsOn)) {
        for (const targetRef of dep.dependsOn) {
          const targetId = componentIdByRef.get(targetRef);
          if (targetId) {
            await client.query(
              `INSERT INTO dependency (sbom_id, component_ref, depends_on_ref)
               VALUES ($1, $2, $3)`,
              [sbomId, sourceId, targetId]
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
            const affectedComponentId = componentIdByRef.get(affect.ref) || null;
            await client.query(
              `INSERT INTO vulnerability (sbom_id, name, installed, fixed_in, package_type, vulnerability, severity, epss, risk, cve_id, description, affected_component_ref)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
              [sbomId, null, null, null, null, vulnId, severity, null, null, vulnId, description, affectedComponentId]
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
        const affectedComponentRef = vuln.affected_component_ref
          ? componentLookupByRawRef.get(vuln.affected_component_ref) || null
          : null;
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
            affectedComponentRef
          ]
        );
      }
      console.log(`Đã lưu ${grypeResults.length} lỗ hổng do Grype phát hiện.`);
    } else {
      console.log("Grype không tìm thấy lỗ hổng nào hoặc lỗi thực thi.");
    }
  }

  if (providedSystemId) {
    await client.query(
      'UPDATE system SET last_uploaded_at = CURRENT_TIMESTAMP WHERE system_id = $1',
      [providedSystemId]
    );
  }
  
  return sbomId;
};

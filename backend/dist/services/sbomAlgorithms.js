"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.severityToRisk = exports.riskRank = exports.diffSboms = exports.normalizeSbomPayload = exports.sha256Json = exports.stableComponentKey = void 0;
const crypto_1 = __importDefault(require("crypto"));
const text = (value) => {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    return trimmed || null;
};
const inferEcosystem = (purl, type) => {
    if (purl?.startsWith('pkg:')) {
        const slash = purl.indexOf('/');
        return slash > 4 ? purl.slice(4, slash) : 'unknown';
    }
    if (type)
        return type.toLowerCase();
    return 'unknown';
};
const stableComponentKey = (component) => {
    const purl = text(component.purl);
    if (purl)
        return purl.toLowerCase();
    const name = text(component.name) || 'unknown';
    const version = text(component.version) || 'unknown';
    const ecosystem = text(component.ecosystem);
    if (ecosystem)
        return `${ecosystem}:${name}:${version}`.toLowerCase();
    const hashes = text(component.hashes);
    return `${name}:${version}:${hashes || 'no-hash'}`.toLowerCase();
};
exports.stableComponentKey = stableComponentKey;
const sha256Json = (value) => crypto_1.default.createHash('sha256').update(JSON.stringify(value)).digest('hex');
exports.sha256Json = sha256Json;
const componentComparable = (component) => ({
    name: component.name,
    version: component.version,
    purl: component.purl,
    licenses: component.licenses,
    hashes: component.hashes,
    supplier: component.supplier,
});
const normalizeSbomPayload = (payload) => {
    const sbom = payload && payload.sbom ? payload.sbom : payload;
    const componentsByRef = new Map();
    const dependencies = [];
    const vulnerabilities = [];
    let rootKey = null;
    if (sbom?.bomFormat === 'CycloneDX' || sbom?.components) {
        const addComponent = (raw) => {
            const ref = raw?.['bom-ref'] || raw?.bomRef || raw?.purl || `${raw?.name || 'unknown'}@${raw?.version || ''}`;
            const license = raw?.licenses?.[0]?.license?.id || raw?.licenses?.[0]?.license?.name || raw?.licenses || null;
            const hashes = Array.isArray(raw?.hashes)
                ? raw.hashes.map((h) => `${h.alg || h.algorithm}:${h.content || h.value}`).join(',')
                : text(raw?.hashes);
            const component = {
                componentId: ref,
                stableKey: '',
                name: raw?.name || 'Unknown',
                version: text(raw?.version),
                purl: text(raw?.purl),
                ecosystem: inferEcosystem(raw?.purl, raw?.type),
                supplier: text(raw?.supplier?.name || raw?.supplier),
                licenses: text(license),
                hashes,
            };
            component.stableKey = (0, exports.stableComponentKey)(component);
            componentsByRef.set(ref, component);
            componentsByRef.set(component.stableKey, component);
            return component;
        };
        if (sbom.metadata?.component) {
            rootKey = addComponent(sbom.metadata.component).stableKey;
        }
        for (const raw of sbom.components || [])
            addComponent(raw);
        for (const dep of sbom.dependencies || []) {
            const source = componentsByRef.get(dep.ref);
            for (const targetRef of dep.dependsOn || []) {
                const target = componentsByRef.get(targetRef);
                if (source && target) {
                    dependencies.push({ sourceKey: source.stableKey, targetKey: target.stableKey, relationship: 'DEPENDS_ON' });
                }
            }
        }
        for (const vuln of sbom.vulnerabilities || []) {
            const severity = vuln?.ratings?.[0]?.severity || vuln?.severity || null;
            const affects = vuln?.affects || [];
            if (affects.length === 0)
                vulnerabilities.push({ affectedKey: null, severity });
            for (const affect of affects) {
                vulnerabilities.push({ affectedKey: componentsByRef.get(affect.ref)?.stableKey || affect.ref || null, severity });
            }
        }
        return { components: uniqueComponents(componentsByRef), dependencies, vulnerabilities, rootKey, format: 'CycloneDX' };
    }
    if (sbom?.spdxVersion || sbom?.SPDXID) {
        for (const pkg of sbom.packages || []) {
            const purl = pkg.externalRefs?.find((ref) => ref.referenceType === 'purl')?.referenceLocator || null;
            const license = pkg.licenseConcluded !== 'NOASSERTION' ? pkg.licenseConcluded : pkg.licenseDeclared;
            const component = {
                componentId: pkg.SPDXID || pkg.name,
                stableKey: '',
                name: pkg.name || 'Unknown',
                version: text(pkg.versionInfo),
                purl,
                ecosystem: inferEcosystem(purl, null),
                supplier: text(pkg.supplier),
                licenses: text(license),
                hashes: Array.isArray(pkg.checksums) ? pkg.checksums.map((h) => `${h.algorithm}:${h.checksumValue}`).join(',') : null,
            };
            component.stableKey = (0, exports.stableComponentKey)(component);
            componentsByRef.set(component.componentId, component);
            componentsByRef.set(component.stableKey, component);
        }
        for (const rel of sbom.relationships || []) {
            const forward = ['DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'DESCRIBES', 'HAS_PREREQUISITE'].includes(rel.relationshipType);
            const reverse = ['DEPENDENCY_OF', 'CONTAINED_BY', 'DESCRIBED_BY', 'PREREQUISITE_FOR'].includes(rel.relationshipType);
            const source = componentsByRef.get(forward ? rel.spdxElementId : rel.relatedSpdxElement);
            const target = componentsByRef.get(forward ? rel.relatedSpdxElement : rel.spdxElementId);
            if ((forward || reverse) && source && target) {
                dependencies.push({ sourceKey: source.stableKey, targetKey: target.stableKey, relationship: 'DEPENDS_ON' });
            }
        }
        return { components: uniqueComponents(componentsByRef), dependencies, vulnerabilities, rootKey, format: 'SPDX' };
    }
    return { components: [], dependencies: [], vulnerabilities: [], rootKey, format: 'INTERNAL' };
};
exports.normalizeSbomPayload = normalizeSbomPayload;
const uniqueComponents = (componentsByRef) => {
    const byKey = new Map();
    for (const component of componentsByRef.values())
        byKey.set(component.stableKey, component);
    return [...byKey.values()];
};
const diffSboms = (previous, current) => {
    const previousComponents = new Map(previous.components.map(component => [component.stableKey, component]));
    const currentComponents = new Map(current.components.map(component => [component.stableKey, component]));
    const changeLogs = [];
    let added = 0;
    let updated = 0;
    let removed = 0;
    let unchanged = 0;
    for (const component of current.components) {
        const old = previousComponents.get(component.stableKey);
        if (!old) {
            added += 1;
            changeLogs.push({ changeType: 'ADDED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, currentValue: componentComparable(component) });
            continue;
        }
        if (JSON.stringify(componentComparable(old)) !== JSON.stringify(componentComparable(component))) {
            updated += 1;
            changeLogs.push({ changeType: 'UPDATED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, previousValue: componentComparable(old), currentValue: componentComparable(component) });
        }
        else {
            unchanged += 1;
            changeLogs.push({ changeType: 'UNCHANGED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name });
        }
    }
    for (const component of previous.components) {
        if (!currentComponents.has(component.stableKey)) {
            removed += 1;
            changeLogs.push({ changeType: 'REMOVED', entityType: 'COMPONENT', entityKey: component.stableKey, componentName: component.name, previousValue: componentComparable(component) });
        }
    }
    const previousDeps = new Set(previous.dependencies.map(dep => `${dep.sourceKey}->${dep.targetKey}`));
    const currentDeps = new Set(current.dependencies.map(dep => `${dep.sourceKey}->${dep.targetKey}`));
    for (const dep of currentDeps) {
        if (!previousDeps.has(dep))
            changeLogs.push({ changeType: 'ADDED', entityType: 'DEPENDENCY', entityKey: dep });
    }
    for (const dep of previousDeps) {
        if (!currentDeps.has(dep))
            changeLogs.push({ changeType: 'REMOVED', entityType: 'DEPENDENCY', entityKey: dep });
    }
    return {
        changeLogs,
        summary: { totalComponents: current.components.length, added, updated, removed, unchanged },
    };
};
exports.diffSboms = diffSboms;
const riskRank = (risk) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 })[risk];
exports.riskRank = riskRank;
const severityToRisk = (severities) => {
    const normalized = severities.map(severity => (severity || '').toLowerCase());
    if (normalized.includes('critical'))
        return 'CRITICAL';
    if (normalized.includes('high'))
        return 'HIGH';
    if (normalized.includes('medium'))
        return 'MEDIUM';
    return 'LOW';
};
exports.severityToRisk = severityToRisk;

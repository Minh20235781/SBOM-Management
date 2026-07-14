"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanSBOMWithGrype = exports.scanSBOMWithGrypeReport = void 0;
const child_process_1 = require("child_process");
const util_1 = __importDefault(require("util"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const uuid_1 = require("uuid");
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.GRYPE_TIMEOUT_MS || 120000);
const extractNumericEpss = (epssValue) => {
    if (typeof epssValue === 'number' && Number.isFinite(epssValue))
        return epssValue;
    if (typeof epssValue === 'string') {
        const parsed = Number.parseFloat(epssValue);
        return Number.isFinite(parsed) ? parsed : null;
    }
    if (Array.isArray(epssValue)) {
        for (const item of epssValue) {
            const extracted = extractNumericEpss(item);
            if (extracted !== null)
                return extracted;
        }
        return null;
    }
    if (epssValue && typeof epssValue === 'object')
        return extractNumericEpss(epssValue.epss);
    return null;
};
const scanSBOMWithGrypeReport = async (sbomData) => {
    const tempFilePath = path_1.default.join(os_1.default.tmpdir(), `sbom-${(0, uuid_1.v4)()}.json`);
    const scannedAt = new Date().toISOString();
    try {
        await promises_1.default.writeFile(tempFilePath, JSON.stringify(sbomData), 'utf8');
        const grypeBin = process.env.GRYPE_BIN || 'grype';
        const { stdout } = await execFilePromise(grypeBin, [`sbom:${tempFilePath}`, '-o', 'json', '-q'], { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER });
        const result = JSON.parse(stdout);
        const matches = Array.isArray(result?.matches) ? result.matches : [];
        const findings = matches.map((match) => {
            const artifact = match.artifact || {};
            const vulnerability = match.vulnerability || {};
            const fixVersions = Array.isArray(vulnerability.fix?.versions) ? vulnerability.fix.versions : [];
            return {
                name: artifact.name || null,
                installed: artifact.version || null,
                fixed_in: fixVersions[0] || null,
                package_type: artifact.type || null,
                vulnerability: vulnerability.id || 'UNKNOWN',
                cve_id: vulnerability.id || 'UNKNOWN',
                severity: vulnerability.severity || 'Unknown',
                epss: extractNumericEpss(vulnerability.epss ?? vulnerability.score),
                risk: vulnerability.risk || vulnerability.riskScore || null,
                description: vulnerability.description || match.relatedVulnerabilities?.[0]?.description || '',
                affected_component_ref: artifact.id || artifact.purl || null,
            };
        });
        return {
            scanner: 'Grype',
            scannerVersion: result?.descriptor?.version || null,
            status: 'COMPLETED',
            scannedAt,
            findingCount: findings.length,
            findings,
            error: null,
            note: findings.length
                ? 'CVE findings are produced by Grype from SBOM components; static source comparison does not independently prove exploitability.'
                : 'No vulnerability finding was returned by Grype for this SBOM.',
        };
    }
    catch (error) {
        const message = String(error?.stderr || error?.stdout || error?.message || 'Unknown Grype error').trim();
        console.error('Grype scan failed:', message);
        return {
            scanner: 'Grype',
            scannerVersion: null,
            status: 'FAILED',
            scannedAt,
            findingCount: 0,
            findings: [],
            error: message,
            note: 'The vulnerability scan failed. Zero findings must not be interpreted as zero vulnerabilities.',
        };
    }
    finally {
        try {
            await promises_1.default.unlink(tempFilePath);
        }
        catch {
            // Ignore cleanup errors for a temporary scan file.
        }
    }
};
exports.scanSBOMWithGrypeReport = scanSBOMWithGrypeReport;
const scanSBOMWithGrype = async (sbomData) => {
    const report = await (0, exports.scanSBOMWithGrypeReport)(sbomData);
    return report.findings;
};
exports.scanSBOMWithGrype = scanSBOMWithGrype;

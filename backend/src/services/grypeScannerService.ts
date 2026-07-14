import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';

const execFilePromise = util.promisify(execFile);
const MAX_BUFFER = 50 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.GRYPE_TIMEOUT_MS || 120000);

export type GrypeFinding = {
  name: string | null;
  installed: string | null;
  fixed_in: string | null;
  package_type: string | null;
  vulnerability: string;
  cve_id: string;
  severity: string;
  epss: number | null;
  risk: number | null;
  description: string;
  affected_component_ref: string | null;
};

export type GrypeScanReport = {
  scanner: 'Grype';
  scannerVersion: string | null;
  status: 'COMPLETED' | 'FAILED';
  scannedAt: string;
  findingCount: number;
  findings: GrypeFinding[];
  error: string | null;
  note: string;
};

const extractNumericEpss = (epssValue: any): number | null => {
  if (typeof epssValue === 'number' && Number.isFinite(epssValue)) return epssValue;
  if (typeof epssValue === 'string') {
    const parsed = Number.parseFloat(epssValue);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (Array.isArray(epssValue)) {
    for (const item of epssValue) {
      const extracted = extractNumericEpss(item);
      if (extracted !== null) return extracted;
    }
    return null;
  }
  if (epssValue && typeof epssValue === 'object') return extractNumericEpss(epssValue.epss);
  return null;
};

export const scanSBOMWithGrypeReport = async (sbomData: any): Promise<GrypeScanReport> => {
  const tempFilePath = path.join(os.tmpdir(), `sbom-${uuidv4()}.json`);
  const scannedAt = new Date().toISOString();

  try {
    await fs.writeFile(tempFilePath, JSON.stringify(sbomData), 'utf8');
    const grypeBin = process.env.GRYPE_BIN || 'grype';
    const { stdout } = await execFilePromise(
      grypeBin,
      [`sbom:${tempFilePath}`, '-o', 'json', '-q'],
      { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER }
    );
    const result = JSON.parse(stdout);
    const matches = Array.isArray(result?.matches) ? result.matches : [];
    const findings: GrypeFinding[] = matches.map((match: any) => {
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
  } catch (error: any) {
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
  } finally {
    try {
      await fs.unlink(tempFilePath);
    } catch {
      // Ignore cleanup errors for a temporary scan file.
    }
  }
};

export const scanSBOMWithGrype = async (sbomData: any): Promise<GrypeFinding[]> => {
  const report = await scanSBOMWithGrypeReport(sbomData);
  return report.findings;
};

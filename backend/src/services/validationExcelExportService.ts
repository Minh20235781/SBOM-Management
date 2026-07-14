import ExcelJS from 'exceljs';

const COLORS = {
  navy: 'FF1F4E78',
  lightBlue: 'FFD9EAF7',
  critical: 'FFF4CCCC',
  high: 'FFFCE5CD',
  medium: 'FFFFF2CC',
  low: 'FFD9EAD3',
  unknown: 'FFE7E6E6',
};

const cellValue = (input: unknown): string | number | boolean => {
  if (input === null || input === undefined) return '';
  if (typeof input === 'number' || typeof input === 'boolean') return input;
  return typeof input === 'object' ? JSON.stringify(input) : String(input);
};

const severityColor = (severity: unknown) => {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL': return COLORS.critical;
    case 'HIGH': return COLORS.high;
    case 'MEDIUM': return COLORS.medium;
    case 'LOW': return COLORS.low;
    default: return COLORS.unknown;
  }
};

const addSheet = (workbook: ExcelJS.Workbook, name: string, rows: Record<string, unknown>[]) => {
  const sheet = workbook.addWorksheet(name);
  const columns = [...new Set(rows.flatMap(row => Object.keys(row)))];
  sheet.columns = columns.map(key => {
    const contentWidth = rows.reduce((max, row) => Math.max(max, String(cellValue(row[key])).length), key.length);
    return { header: key, key, width: Math.min(60, Math.max(14, contentWidth + 2)) };
  });
  rows.forEach(row => sheet.addRow(columns.map(key => cellValue(row[key]))));
  sheet.views = [{ state: 'frozen', ySplit: 1 }];
  if (columns.length) sheet.autoFilter = { from: 'A1', to: `${sheet.getColumn(columns.length).letter}1` };

  const header = sheet.getRow(1);
  header.height = 28;
  header.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COLORS.navy } };
  header.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };

  const severityColumn = columns.findIndex(key => key.toLowerCase() === 'severity') + 1;
  sheet.eachRow((row, index) => {
    if (index === 1) return;
    row.alignment = { vertical: 'top', wrapText: true };
    if (index % 2 === 0) {
      row.eachCell(cell => {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF4F8FC' } };
      });
    }
    if (severityColumn > 0) {
      const severityCell = row.getCell(severityColumn);
      severityCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: severityColor(severityCell.value) } };
      severityCell.font = { bold: true };
    }
  });
  return sheet;
};

const countBySeverity = (findings: any[]) => {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  findings.forEach(finding => {
    const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
    counts[severity] = (counts[severity] || 0) + 1;
  });
  return counts;
};

export const validationExcelExportService = {
  generate: async (run: any) => {
    const analysis = run.analysis || {};
    const verification = run.verification_report || {};
    const report = run.test_report || {};
    const scan = analysis.vulnerabilityScan || {};
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    if (!run.test_report || !run.verification_report) {
      throw new Error('Run verification before exporting the Excel report.');
    }

    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'SBOM Management - Verification';
    workbook.created = new Date();
    workbook.properties.date1904 = false;

    addSheet(workbook, 'TongQuan', [{
      testCaseId: report.testCaseId,
      project: run.project_name,
      repository: run.github_url,
      applicationType: run.application_type,
      repositoryScope: run.repo_scope,
      architecture: run.architecture_type,
      result: report.result,
      verificationStatus: verification.status,
      trustLevel: verification.trustLevel,
      trustScore: verification.trustScore,
      sourceComponents: verification.sourceComponentCount,
      sbomComponents: verification.sbomComponentCount,
      matched: verification.matchedCount,
      missingInSbom: verification.missingCount,
      extraInSbom: verification.extraCount,
      versionMismatch: verification.versionMismatchCount,
      vulnerabilityScanner: scan.scanner || 'Grype',
      vulnerabilityScanStatus: scan.status || 'NOT_RUN',
      vulnerabilityFindings: scan.findingCount ?? findings.length,
      uniqueCve: new Set(findings.map((item: any) => item.cve_id).filter(Boolean)).size,
      embeddedVulnerabilitiesInInputSbom: analysis.embeddedVulnerabilityCount ?? 0,
      generatedAt: new Date().toISOString(),
    }]);

    const severityCounts = countBySeverity(findings);
    const uniquePackages = new Set(findings.map((item: any) => `${item.name || ''}@${item.installed || ''}`)).size;
    const fixedAvailable = findings.filter((item: any) => item.fixed_in).length;
    const epssAvailable = findings.filter((item: any) => item.epss !== null && item.epss !== undefined).length;
    addSheet(workbook, 'ThongKeCVE', [
      { metric: 'Scan status', value: scan.status || 'NOT_RUN', meaning: scan.error || scan.note || '' },
      { metric: 'Scanner', value: scan.scanner || 'Grype', meaning: scan.scannerVersion ? `Version ${scan.scannerVersion}` : 'Version not reported' },
      { metric: 'Scanned at', value: scan.scannedAt || '', meaning: 'Time when Grype analyzed the verified SBOM' },
      { metric: 'Vulnerability findings', value: scan.findingCount ?? findings.length, meaning: 'Number of CVE-package findings; not necessarily unique CVE count' },
      { metric: 'Unique CVE', value: new Set(findings.map((item: any) => item.cve_id).filter(Boolean)).size, meaning: 'Distinct CVE identifiers' },
      { metric: 'Affected package versions', value: uniquePackages, meaning: 'Distinct package@installed-version pairs' },
      { metric: 'CRITICAL', value: severityCounts.CRITICAL, meaning: 'Grype severity' },
      { metric: 'HIGH', value: severityCounts.HIGH, meaning: 'Grype severity' },
      { metric: 'MEDIUM', value: severityCounts.MEDIUM, meaning: 'Grype severity' },
      { metric: 'LOW', value: severityCounts.LOW, meaning: 'Grype severity' },
      { metric: 'UNKNOWN', value: severityCounts.UNKNOWN, meaning: 'Severity was not supplied' },
      { metric: 'Fix version available', value: `${fixedAvailable}/${findings.length}`, meaning: 'Finding includes at least one fixed version' },
      { metric: 'EPSS available', value: `${epssAvailable}/${findings.length}`, meaning: 'Grype supplied an EPSS-compatible numeric value' },
      { metric: 'Vulnerabilities embedded in input SBOM', value: analysis.embeddedVulnerabilityCount ?? 0, meaning: 'Count already present in the CycloneDX vulnerabilities array before this verification scan' },
      { metric: 'Verification boundary', value: 'ENRICHMENT', meaning: 'CVE findings are generated by Grype. Static source comparison verifies component inventory, not real-world exploitability.' },
    ]);

    const vulnerabilityRows = findings.map((finding: any) => ({
      cveId: finding.cve_id || finding.vulnerability,
      severity: finding.severity,
      package: finding.name,
      installedVersion: finding.installed,
      fixedVersion: finding.fixed_in || 'Not available',
      packageType: finding.package_type,
      epss: finding.epss ?? 'Not available',
      risk: finding.risk ?? 'Not available',
      affectedComponentRef: finding.affected_component_ref || 'Not available',
      description: finding.description || 'Not available',
      dataSource: 'Grype scan of verified SBOM',
    }));
    addSheet(workbook, 'CVEChiTiet', vulnerabilityRows.length ? vulnerabilityRows : [{
      cveId: '', severity: '', package: '', installedVersion: '', fixedVersion: '', packageType: '',
      epss: '', risk: '', affectedComponentRef: '', description: scan.error || scan.note || 'No CVE finding',
      dataSource: scan.status === 'FAILED' ? 'Grype scan failed' : 'Grype scan of verified SBOM',
    }]);

    const diffRows: Record<string, unknown>[] = [];
    (verification.MATCHED || []).forEach((component: string) => diffRows.push({ classification: 'MATCHED', component }));
    (verification.MISSING_IN_SBOM || []).forEach((component: string) => diffRows.push({ classification: 'MISSING_IN_SBOM', component }));
    (verification.EXTRA_IN_SBOM || []).forEach((component: string) => diffRows.push({ classification: 'EXTRA_IN_SBOM', component }));
    (verification.VERSION_MISMATCH || []).forEach((item: any) => diffRows.push({
      classification: 'VERSION_MISMATCH', ecosystem: item.ecosystem, component: item.component,
      sourceVersion: item.sourceVersion, sbomVersion: item.sbomVersion,
    }));
    addSheet(workbook, 'KiemChungSource', diffRows.length ? diffRows : [{ classification: 'NO_DIFFERENCE' }]);

    addSheet(workbook, 'PhanTichSource', [{
      analysisRunId: run.run_id,
      sourcePath: run.source_path,
      sbomPath: run.sbom_path,
      tool: analysis.toolInfo,
      analyzedAt: analysis.createdTimestamp,
      analysisDurationMs: analysis.analysisDurationMs,
      sbomSizeBytes: analysis.sbomSizeBytes,
      componentCount: analysis.componentCount,
      dependencyCount: analysis.dependencyCount,
      dependencyFileCount: analysis.dependencyFileCount,
      ecosystems: analysis.ecosystems,
      metadataInferredBySystem: analysis.inferredMetadata || null,
    }]);

    addSheet(workbook, 'TepPhuThuoc', (analysis.dependencyFiles || []).map((file: any) => ({
      name: file.name, path: file.path, sizeBytes: file.sizeBytes,
    })).concat((analysis.dependencyFiles || []).length ? [] : [{ name: 'No dependency file recorded' }]));

    addSheet(workbook, 'BangChung', Object.entries(report.evidence || {}).map(([key, entry]) => ({ evidence: key, value: entry })));
    addSheet(workbook, 'QuyTrinhKiemThu', [
      ...(report.preconditions || []).map((text: string, index: number) => ({ type: 'PRECONDITION', order: index + 1, description: text })),
      ...(report.steps || []).map((text: string, index: number) => ({ type: 'STEP', order: index + 1, description: text })),
      { type: 'EXPECTED_RESULT', order: '', description: report.expectedResult },
      { type: 'ACTUAL_RESULT', order: '', description: report.actualResult },
    ]);

    addSheet(workbook, 'ChuGiaiCVE', [
      { field: 'cveId', source: 'Grype', automatic: 'Yes', meaning: 'Vulnerability identifier returned for a package version', humanCheck: 'Confirm relevance for the deployed build and environment' },
      { field: 'severity', source: 'Grype vulnerability database', automatic: 'Yes', meaning: 'Severity label', humanCheck: 'Review business impact and deployment context' },
      { field: 'package / installedVersion', source: 'SBOM artifact matched by Grype', automatic: 'Yes', meaning: 'Affected component and detected version', humanCheck: 'Confirm that the component is shipped and used at runtime' },
      { field: 'fixedVersion', source: 'Grype vulnerability database', automatic: 'Conditional', meaning: 'First fixed version reported by Grype', humanCheck: 'Validate compatibility before upgrading' },
      { field: 'epss / risk', source: 'Grype output when available', automatic: 'Conditional', meaning: 'Optional prioritization signals', humanCheck: 'Blank means unavailable, not zero risk' },
      { field: 'affectedComponentRef', source: 'Grype artifact identifier', automatic: 'Conditional', meaning: 'Reference used to relate a finding to an SBOM component', humanCheck: 'Inspect unresolved or ambiguous references' },
      { field: 'CVSS vector / CISA KEV', source: 'Not collected by this report', automatic: 'No', meaning: 'Fields seen in the reference workbook but outside the current Grype mapping', humanCheck: 'Require an additional trusted data source before reporting' },
      { field: 'Static source verification', source: 'Application comparison logic', automatic: 'Yes', meaning: 'Compares source-derived inventory with SBOM inventory', humanCheck: 'Does not independently confirm that a CVE is exploitable' },
    ]);

    const buffer = Buffer.from(await workbook.xlsx.writeBuffer());
    const safeId = String(report.testCaseId || run.run_id).replace(/[^a-zA-Z0-9_.-]/g, '-');
    return { buffer, fileName: `${safeId}-verification-report.xlsx` };
  },
};

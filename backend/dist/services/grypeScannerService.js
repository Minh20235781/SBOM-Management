"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanSBOMWithGrype = void 0;
const child_process_1 = require("child_process");
const util_1 = __importDefault(require("util"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const uuid_1 = require("uuid");
const execFilePromise = util_1.default.promisify(child_process_1.execFile);
const extractNumericEpss = (epssValue) => {
    if (typeof epssValue === 'number' && Number.isFinite(epssValue)) {
        return epssValue;
    }
    if (typeof epssValue === 'string') {
        const parsed = Number.parseFloat(epssValue);
        return Number.isFinite(parsed) ? parsed : null;
    }
    if (Array.isArray(epssValue)) {
        for (const item of epssValue) {
            const extracted = extractNumericEpss(item);
            if (extracted !== null) {
                return extracted;
            }
        }
        return null;
    }
    if (epssValue && typeof epssValue === 'object') {
        return extractNumericEpss(epssValue.epss);
    }
    return null;
};
const scanSBOMWithGrype = async (sbomData) => {
    const tempId = (0, uuid_1.v4)();
    const tempFilePath = path_1.default.join(os_1.default.tmpdir(), `sbom-${tempId}.json`);
    try {
        // 1. Lưu SBOM ra file tạm
        await promises_1.default.writeFile(tempFilePath, JSON.stringify(sbomData), 'utf8');
        // 2. Chạy child_process gọi Grype CLI (quét file sbom và trả kết quả dạng JSON)
        // Ưu tiên đọc biến môi trường GRYPE_BIN để tránh lỗi PATH
        const grypeBin = process.env.GRYPE_BIN || 'grype';
        const { stdout } = await execFilePromise(grypeBin, [`sbom:${tempFilePath}`, '-o', 'json', '-q']);
        // 3. Phân tích kết quả JSON
        const result = JSON.parse(stdout);
        if (!result || !result.matches) {
            return [];
        }
        // 4. Map dữ liệu sang cấu trúc vulnerability của Backend
        const vulnerabilities = result.matches.map((match) => {
            let affectedRef = null;
            // Grype thường gán SBOM component id (bom-ref / SPDXID) vào artifact.id
            if (match.artifact && match.artifact.id) {
                affectedRef = match.artifact.id;
            }
            const artifact = match.artifact || {};
            const vulnInfo = match.vulnerability || {};
            const fixVersions = Array.isArray(vulnInfo.fix?.versions) ? vulnInfo.fix.versions : [];
            return {
                name: artifact.name || null,
                installed: artifact.version || null,
                fixed_in: fixVersions[0] || null,
                package_type: artifact.type || null,
                vulnerability: vulnInfo.id || 'UNKNOWN',
                cve_id: vulnInfo.id || 'UNKNOWN',
                severity: vulnInfo.severity || 'Unknown',
                epss: extractNumericEpss(vulnInfo.epss ?? vulnInfo.score),
                risk: vulnInfo.risk || vulnInfo.riskScore || null,
                // Lấy description ưu tiên từ vulnInfo, nếu không có lấy từ relatedVulnerabilities
                description: vulnInfo.description || match.relatedVulnerabilities?.[0]?.description || '',
                affected_component_ref: affectedRef,
            };
        });
        return vulnerabilities;
    }
    catch (error) {
        console.error('Lỗi khi quét bằng Grype:', error.message);
        // Trả về mảng rỗng thay vì ném lỗi để không làm sập tiến trình upload SBOM chung
        return [];
    }
    finally {
        // 5. Dọn dẹp file tạm
        try {
            await promises_1.default.unlink(tempFilePath);
        }
        catch (e) {
            console.error('Không thể xóa file SBOM tạm:', e);
        }
    }
};
exports.scanSBOMWithGrype = scanSBOMWithGrype;

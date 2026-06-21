"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.swaggerSpec = void 0;
const path_1 = __importDefault(require("path"));
const swagger_jsdoc_1 = __importDefault(require("swagger-jsdoc"));
const port = process.env.PORT || 5000;
const swaggerPath = (target) => path_1.default.resolve(process.cwd(), target).replace(/\\/g, '/');
exports.swaggerSpec = (0, swagger_jsdoc_1.default)({
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'SBOM Management API',
            version: '1.0.0',
            description: 'API documentation for SBOM Management System',
        },
        servers: [
            {
                url: `http://localhost:${port}`,
                description: 'Local development server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
            schemas: {
                User: {
                    type: 'object',
                    properties: {
                        user_id: { type: 'integer', example: 1 },
                        username: { type: 'string', example: 'developer' },
                        email: { type: 'string', format: 'email', example: 'developer@example.com' },
                        role: { type: 'string', example: 'DEVELOPER' },
                        created_at: { type: 'string', format: 'date-time' },
                    },
                },
                Project: {
                    type: 'object',
                    properties: {
                        system_id: { type: 'integer', example: 1 },
                        name: { type: 'string', example: 'SBOM Management' },
                        description: { type: 'string', nullable: true },
                        created_timestamp: { type: 'string', format: 'date-time' },
                        last_uploaded_at: { type: 'string', format: 'date-time', nullable: true },
                        sbom_count: { type: 'integer', example: 3 },
                    },
                },
                Repository: {
                    type: 'object',
                    properties: {
                        repo_url: { type: 'string', example: 'https://github.com/owner/repo.git' },
                        branch: { type: 'string', example: 'main' },
                        provider: { type: 'string', example: 'GITHUB_ACTIONS' },
                    },
                },
                SbomMetadata: {
                    type: 'object',
                    properties: {
                        sbom_id: { type: 'string', example: 'urn:uuid:demo' },
                        authors: { type: 'string', nullable: true },
                        created_timestamp: { type: 'string', format: 'date-time', nullable: true },
                        system_id: { type: 'integer', nullable: true },
                        tool_components: { type: 'string', nullable: true },
                        tool_services: { type: 'string', nullable: true },
                        lifecycle_phase: { type: 'string', nullable: true },
                    },
                },
                Component: {
                    type: 'object',
                    properties: {
                        component_id: { type: 'string', example: 'pkg:npm/express@5.2.1' },
                        sbom_id: { type: 'string' },
                        supplier_name: { type: 'string', nullable: true },
                        name: { type: 'string', example: 'express' },
                        version: { type: 'string', nullable: true, example: '5.2.1' },
                        purl: { type: 'string', nullable: true },
                        cpe: { type: 'string', nullable: true },
                        hashes: { type: 'string', nullable: true },
                        licenses: { type: 'string', nullable: true, example: 'MIT' },
                    },
                },
                Dependency: {
                    type: 'object',
                    properties: {
                        dependency_id: { type: 'integer', example: 1 },
                        sbom_id: { type: 'string' },
                        component_ref: { type: 'string' },
                        depends_on_ref: { type: 'string' },
                    },
                },
                Vulnerability: {
                    type: 'object',
                    properties: {
                        vuln_id: { type: 'integer', example: 1 },
                        sbom_id: { type: 'string' },
                        cve_id: { type: 'string', nullable: true, example: 'CVE-2024-0001' },
                        name: { type: 'string', nullable: true },
                        severity: { type: 'string', nullable: true, example: 'High' },
                        installed: { type: 'string', nullable: true },
                        fixed_in: { type: 'string', nullable: true },
                        risk: { type: 'string', nullable: true },
                        affected_component_ref: { type: 'string', nullable: true },
                    },
                },
                License: {
                    type: 'object',
                    properties: {
                        id: { type: 'string', example: 'MIT' },
                        name: { type: 'string', example: 'MIT License' },
                        component_id: { type: 'string' },
                    },
                },
                Pipeline: {
                    type: 'object',
                    properties: {
                        pipeline_id: { type: 'integer', example: 1 },
                        project_id: { type: 'integer', example: 1 },
                        name: { type: 'string', example: 'sbom-incremental-scan' },
                        provider: { type: 'string', example: 'GITHUB_ACTIONS' },
                        branch: { type: 'string', example: 'main' },
                        trigger_type: { type: 'string', example: 'PUSH' },
                        repo_url: { type: 'string', nullable: true },
                        latest_status: { type: 'string', nullable: true },
                    },
                },
                ApiError: {
                    type: 'object',
                    properties: {
                        error: { type: 'string', example: 'Invalid id' },
                    },
                },
            },
        },
        security: [{ bearerAuth: [] }],
    },
    apis: [
        swaggerPath('src/routes/**/*.ts'),
        swaggerPath('src/controllers/**/*.ts'),
        swaggerPath('dist/routes/**/*.js'),
        swaggerPath('dist/controllers/**/*.js'),
    ],
});

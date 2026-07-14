"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validationScenarioController = void 0;
const validationScenarioService_1 = require("../services/validationScenarioService");
const firstParam = (value) => Array.isArray(value) ? value[0] : value || '';
exports.validationScenarioController = {
    list: async (_req, res, next) => {
        try {
            res.json({
                scope: {
                    applicationType: 'Web Application',
                    repoScope: 'Single Repository',
                    currentSupport: 'This page validates repositories saved on projects in this system.',
                    extensionNote: 'Create a project pipeline with a repository URL to make it available here.',
                },
                repositories: await validationScenarioService_1.validationScenarioService.listCatalog(),
            });
        }
        catch (error) {
            next(error);
        }
    },
    analyze: async (req, res, next) => {
        try {
            res.status(201).json(await validationScenarioService_1.validationScenarioService.analyze(firstParam(req.params.scenarioId)));
        }
        catch (error) {
            next(error);
        }
    },
    getRun: async (req, res, next) => {
        try {
            res.json(await validationScenarioService_1.validationScenarioService.getRun(firstParam(req.params.runId)));
        }
        catch (error) {
            next(error);
        }
    },
    confirm: async (req, res, next) => {
        try {
            res.json(await validationScenarioService_1.validationScenarioService.confirm(firstParam(req.params.runId)));
        }
        catch (error) {
            next(error);
        }
    },
    generate: async (req, res, next) => {
        try {
            res.json(await validationScenarioService_1.validationScenarioService.generate(firstParam(req.params.runId)));
        }
        catch (error) {
            next(error);
        }
    },
    createFaulty: async (req, res, next) => {
        try {
            res.status(201).json(await validationScenarioService_1.validationScenarioService.createFaulty(firstParam(req.params.runId)));
        }
        catch (error) {
            next(error);
        }
    },
    verify: async (req, res, next) => {
        try {
            res.json(await validationScenarioService_1.validationScenarioService.verify(firstParam(req.params.runId), req.body?.useFaulty === true));
        }
        catch (error) {
            next(error);
        }
    },
    verifyUploaded: async (req, res, next) => {
        try {
            res.json(await validationScenarioService_1.validationScenarioService.verifyUploaded(firstParam(req.params.runId), req.body?.sbom, req.body?.fileName));
        }
        catch (error) {
            next(error);
        }
    },
    report: async (req, res, next) => {
        try {
            const report = await validationScenarioService_1.validationScenarioService.report(firstParam(req.params.runId));
            if (!report)
                return res.status(404).json({ error: 'No test report has been generated for this run.' });
            res.json(report);
        }
        catch (error) {
            next(error);
        }
    },
    exportExcel: async (req, res, next) => {
        try {
            const report = await validationScenarioService_1.validationScenarioService.exportExcel(firstParam(req.params.runId));
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            res.setHeader('Content-Disposition', `attachment; filename="${report.fileName}"`);
            res.send(report.buffer);
        }
        catch (error) {
            next(error);
        }
    },
};

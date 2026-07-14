import { NextFunction, Request, Response } from 'express';
import { validationScenarioService } from '../services/validationScenarioService';

const firstParam = (value: string | string[] | undefined) => Array.isArray(value) ? value[0] : value || '';

export const validationScenarioController = {
  list: async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.json({
        scope: {
          applicationType: 'Web Application',
          repoScope: 'Single Repository',
          currentSupport: 'This page validates repositories saved on projects in this system.',
          extensionNote: 'Create a project pipeline with a repository URL to make it available here.',
        },
        repositories: await validationScenarioService.listCatalog(),
      });
    } catch (error) {
      next(error);
    }
  },

  analyze: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.status(201).json(await validationScenarioService.analyze(firstParam(req.params.scenarioId)));
    } catch (error) {
      next(error);
    }
  },

  getRun: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await validationScenarioService.getRun(firstParam(req.params.runId)));
    } catch (error) {
      next(error);
    }
  },

  confirm: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await validationScenarioService.confirm(firstParam(req.params.runId)));
    } catch (error) {
      next(error);
    }
  },

  generate: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await validationScenarioService.generate(firstParam(req.params.runId)));
    } catch (error) {
      next(error);
    }
  },

  createFaulty: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.status(201).json(await validationScenarioService.createFaulty(firstParam(req.params.runId)));
    } catch (error) {
      next(error);
    }
  },

  verify: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await validationScenarioService.verify(firstParam(req.params.runId), req.body?.useFaulty === true));
    } catch (error) {
      next(error);
    }
  },

  verifyUploaded: async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await validationScenarioService.verifyUploaded(
        firstParam(req.params.runId),
        req.body?.sbom,
        req.body?.fileName
      ));
    } catch (error) {
      next(error);
    }
  },

  report: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const report = await validationScenarioService.report(firstParam(req.params.runId));
      if (!report) return res.status(404).json({ error: 'No test report has been generated for this run.' });
      res.json(report);
    } catch (error) {
      next(error);
    }
  },

  exportExcel: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const report = await validationScenarioService.exportExcel(firstParam(req.params.runId));
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${report.fileName}"`);
      res.send(report.buffer);
    } catch (error) {
      next(error);
    }
  },
};

import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import swaggerUi from 'swagger-ui-express';
import sbomRoutes from './routes/sbomRoutes';
import systemRoutes from './routes/systemRoutes';
import projectSbomRoutes from './routes/projectSbomRoutes';
import sbomSnapshotRoutes from './routes/sbomSnapshotRoutes';
import cicdRoutes from './routes/cicdRoutes';
import validationScenarioRoutes from './routes/validationScenarioRoutes';
import { swaggerSpec } from './config/swagger';
import { checkDbConnection, ensureCicdSchema, ensureCoreSchema, ensureSbomAlgorithmSchema, ensureSbomValidationScenarioSchema, ensureVulnerabilitySchema } from './config/db';
import { errorHandler } from './middlewares/errorMiddleware';

dotenv.config();

export const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use('/api/sboms', sbomRoutes);
app.use('/api/systems', systemRoutes);
app.use('/api/projects', projectSbomRoutes);
app.use('/api/sbom', sbomSnapshotRoutes);
app.use('/api', cicdRoutes);
app.use('/api/validation-scenarios', validationScenarioRoutes);

app.get('/', (req: Request, res: Response) => {
  res.send('SBOM Management Backend API is running...');
});

app.use(errorHandler);

const startServer = async () => {
  await checkDbConnection();
  await ensureCoreSchema();
  await ensureVulnerabilitySchema();
  await ensureSbomAlgorithmSchema();
  await ensureCicdSchema();
  await ensureSbomValidationScenarioSchema();
  app.listen(port, () => {
    console.log(`[server]: Server is running at http://localhost:${port}`);
  });
};

if (require.main === module) {
  startServer();
}

export default app;

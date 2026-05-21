import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import sbomRoutes from './routes/sbomRoutes';
import systemRoutes from './routes/systemRoutes';
import { checkDbConnection, ensureVulnerabilitySchema } from './config/db';
import { errorHandler } from './middlewares/errorMiddleware';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/api/sboms', sbomRoutes);
app.use('/api/systems', systemRoutes);

app.get('/', (req: Request, res: Response) => {
  res.send('SBOM Management Backend API is running...');
});

app.use(errorHandler);

const startServer = async () => {
  await checkDbConnection();
  await ensureVulnerabilitySchema();
  app.listen(port, () => {
    console.log(`[server]: Server is running at http://localhost:${port}`);
  });
};

startServer();
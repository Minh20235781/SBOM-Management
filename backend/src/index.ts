import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.get('/', (req: Request, res: Response) => {
  res.send('SBOM Management Backend API is running...');
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});
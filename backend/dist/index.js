"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const sbomRoutes_1 = __importDefault(require("./routes/sbomRoutes"));
const systemRoutes_1 = __importDefault(require("./routes/systemRoutes"));
const projectSbomRoutes_1 = __importDefault(require("./routes/projectSbomRoutes"));
const sbomSnapshotRoutes_1 = __importDefault(require("./routes/sbomSnapshotRoutes"));
const cicdRoutes_1 = __importDefault(require("./routes/cicdRoutes"));
const db_1 = require("./config/db");
const errorMiddleware_1 = require("./middlewares/errorMiddleware");
dotenv_1.default.config();
const app = (0, express_1.default)();
const port = process.env.PORT || 5000;
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '50mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '50mb' }));
app.use('/api/sboms', sbomRoutes_1.default);
app.use('/api/systems', systemRoutes_1.default);
app.use('/api/projects', projectSbomRoutes_1.default);
app.use('/api/sbom', sbomSnapshotRoutes_1.default);
app.use('/api', cicdRoutes_1.default);
app.get('/', (req, res) => {
    res.send('SBOM Management Backend API is running...');
});
app.use(errorMiddleware_1.errorHandler);
const startServer = async () => {
    await (0, db_1.checkDbConnection)();
    await (0, db_1.ensureVulnerabilitySchema)();
    await (0, db_1.ensureSbomAlgorithmSchema)();
    await (0, db_1.ensureCicdSchema)();
    app.listen(port, () => {
        console.log(`[server]: Server is running at http://localhost:${port}`);
    });
};
startServer();

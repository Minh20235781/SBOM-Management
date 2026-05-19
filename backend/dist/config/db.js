"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkDbConnection = exports.pool = void 0;
const pg_1 = require("pg");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
exports.pool = new pg_1.Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'sbom_db',
    password: process.env.DB_PASSWORD || 'secret',
    port: parseInt(process.env.DB_PORT || '5432', 10),
});
const checkDbConnection = async () => {
    try {
        const client = await exports.pool.connect();
        console.log('Successfully connected to the PostgreSQL database.');
        client.release();
    }
    catch (err) {
        console.error('Error connecting to PostgreSQL:', err);
        process.exit(1);
    }
};
exports.checkDbConnection = checkDbConnection;

import 'dotenv/config';
import path from 'node:path';
import { FileRecordStore } from '../issuer/records.js';
import { log } from '../logger.js';
import { createSorApp } from './app.js';

const port = Number(process.env.PORT) || 8082;
const file = path.resolve(process.env.SOR_DATA_FILE || 'data/records.json');
const apiToken = process.env.SOR_API_TOKEN || undefined;
if (!apiToken) log.warn('SOR_API_TOKEN is not set: the write API is disabled, only the sample records are served');

createSorApp({ store: new FileRecordStore(file), apiToken }).listen(port, () => log.info('record service started', { port, dataFile: file, writeApi: !!apiToken }));

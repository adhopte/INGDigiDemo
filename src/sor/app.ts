import { createHash, timingSafeEqual } from 'node:crypto';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { loadPortalUseCases } from '../issuer/portal.js';
import { RECORD_FIELDS, SAFE_ID, buildRecord, sorLookup, validatePortrait, validateRecord, type RecordStore } from '../issuer/records.js';

export interface SorOptions {
  store: RecordStore;
  /** Bearer token for writing / listing records. Without it the write API is disabled. */
  apiToken?: string | undefined;
}

const sha = (s: string) => createHash('sha256').update(s).digest();

/**
 * Standalone record service ("system of record") for the credential issuer. Same read contract as the WalletTester's SoR server:
 *   GET /<credential configuration id>/sor/<identifier>[?credential_identifier=<credential id>]
 * Serves the issuer portal's sample records plus records written through the token-protected API:
 *   PUT|GET|DELETE /records/<identifier>, GET /records.
 */
export function createSorApp(opts: SorOptions): Express {
  const { store, apiToken } = opts;
  const samples = loadPortalUseCases().flatMap((u) => u.users);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  app.use((req, res, next) => {
    res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    if (req.method === 'OPTIONS') return void res.sendStatus(204);
    next();
  });

  app.get('/healthz', (_req, res) => void res.json({ status: 'ok' }));
  app.get('/', (_req, res) => void res.json({
    service: 'IN Groupe record service (system of record) for the EU Wallet playground',
    contract: 'GET /<credentialConfigurationId>/sor/<identifier>?credential_identifier=<credentialId>',
    sampleRecords: samples.length,
    adminRecords: store.list().length,
    writeApi: apiToken ? 'enabled (Bearer token)' : 'disabled (set SOR_API_TOKEN)',
  }));

  // ---- read contract (the issuer) ----
  app.get('/:configId/sor/:identifier', (req, res) => {
    const identifier = String(req.params.identifier);
    const cred = typeof req.query.credential_identifier === 'string' ? req.query.credential_identifier : undefined;
    const found = sorLookup(store.get(identifier), samples, String(req.params.configId), identifier, cred);
    if (!found) return void res.status(404).type('text/plain').send('User not found by identifier');
    res.json(found);
  });

  // ---- write API (the admin console) ----
  const auth = (req: Request, res: Response, next: NextFunction) => {
    if (!apiToken) return void res.status(503).json({ error: 'write API disabled: SOR_API_TOKEN is not set' });
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '');
    if (!m || !timingSafeEqual(sha(m[1]!), sha(apiToken))) return void res.status(401).json({ error: 'unauthorized' });
    next();
  };

  app.get('/records', auth, (_req, res) => void res.json(store.list()));
  app.get('/records/:identifier', auth, (req, res) => {
    const rec = store.get(String(req.params.identifier));
    if (!rec) return void res.status(404).json({ error: 'not_found' });
    res.json(rec);
  });
  app.put('/records/:identifier', auth, (req, res) => {
    const identifier = String(req.params.identifier);
    const useCase = typeof req.body?.useCase === 'string' ? req.body.useCase : '';
    if (!SAFE_ID.test(identifier) || !RECORD_FIELDS[useCase]) return void res.status(400).json({ error: 'invalid_record' });
    const v = validateRecord(useCase, (req.body?.attributes ?? {}) as Record<string, unknown>);
    const pt = useCase === 'pid' ? validatePortrait(req.body?.portrait) : { ok: true as const, portrait: undefined };
    if (!v.ok || !pt.ok) return void res.status(422).json({ error: 'invalid_attributes', details: v.ok ? {} : v.errors, portrait: pt.ok ? undefined : 'invalid' });
    res.status(store.get(identifier) ? 200 : 201).json(store.put(buildRecord(useCase, v.attributes, pt.portrait, identifier)));
  });
  app.delete('/records/:identifier', auth, (req, res) => void res.sendStatus(store.delete(String(req.params.identifier)) ? 204 : 404));

  app.use((_req, res) => void res.status(404).type('text/plain').send('Not found'));
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => void res.status(500).json({ error: 'server_error' }));
  return app;
}

import express, { Router, type Request, type Response } from 'express';
import { log } from '../logger.js';
import type { Ctx } from '../rps/context.js';

const MAX_CREDENTIALS = 8;
const MAX_PORTRAIT = 900_000; // base64 chars
const ID = /^[A-Za-z0-9._-]{1,80}$/;
const CONFIG_ID = /^[A-Za-z0-9._:-]{1,120}$/;

const clean = (v: unknown): v is string => typeof v === 'string' && v.length <= 400 && !/[\u0000-\u001f<>]/.test(v);

/**
 * Issuance workspace: a three-step page (identity → credentials → offer) for the issuer's data API ("cases": one identity and
 * its credentials produce one credential offer). This router only checks and forwards; the issuer's service owns the data.
 */
export function labRouter(ctx: Ctx): Router {
  const { cfg, svc } = ctx;
  const r = Router();
  const base = cfg.issuer.sorApiBase;
  if (!base) return r;

  const call = async (path: string, init: RequestInit = {}): Promise<{ status: number; body: unknown }> => {
    try {
      const res = await svc.fetchImpl(`${base}${path}`, { ...init, headers: { accept: 'application/json', ...(init.body ? { 'content-type': 'application/json' } : {}) }, signal: AbortSignal.timeout(25_000) });
      const text = await res.text();
      let body: unknown;
      try { body = JSON.parse(text); } catch { body = { error: { message: `Unexpected answer (HTTP ${res.status})` } }; }
      return { status: res.status, body };
    } catch (e) {
      log.warn('issuance workspace: issuer data API unreachable', { error: e instanceof Error ? e.message : String(e) });
      return { status: 502, body: { error: { message: 'The issuer could not be reached.' } } };
    }
  };
  const send = (res: Response, out: { status: number; body: unknown }) => void res.status(out.status).set('Cache-Control', 'no-store').json(out.body);

  r.use('/demo-issuer', (_req, res, next) => { res.locals.skin = 'dashboard'; res.locals.basePath = ''; next(); });

  r.get('/demo-issuer', (_req, res) => res.render('issuer/lab', { title: res.locals.t('lab.title') }));

  const api = Router();
  api.use(express.json({ limit: '2mb' }));
  api.get('/presets', async (_req, res) => send(res, await call('/api/presets')));
  api.get('/configurations', async (req: Request, res) => {
    const lang = typeof req.query.locale === 'string' && /^[a-z]{2}$/.test(req.query.locale) ? req.query.locale : 'en';
    send(res, await call(`/api/configurations?locale=${lang}`));
  });
  api.post('/cases', async (req, res) => {
    const b = req.body as { identity?: Record<string, unknown>; credentials?: Array<Record<string, unknown>> } | undefined;
    const identity = b?.identity;
    const creds = b?.credentials;
    const bad = (m: string) => void res.status(422).json({ error: { message: m } });
    if (!identity || typeof identity !== 'object' || !Array.isArray(creds) || !creds.length || creds.length > MAX_CREDENTIALS) return bad('An identity and 1-8 credentials are required.');
    const id: Record<string, string> = {};
    for (const [k, v] of Object.entries(identity)) {
      if (k === 'portrait') { if (typeof v === 'string' && v) { if (v.length > MAX_PORTRAIT || !/^[A-Za-z0-9+/=]+$/.test(v)) return bad('The portrait is too large or not a JPEG image.'); id.portrait = v; } continue; }
      if (!/^[a-z_]{1,40}$/.test(k) || !clean(v)) return bad(`Invalid value for ${k}.`);
      if (v) id[k] = v;
    }
    const credentials: unknown[] = [];
    for (const c of creds) {
      if (typeof c?.credentialConfigurationId !== 'string' || !CONFIG_ID.test(c.credentialConfigurationId)) return bad('Invalid credential type.');
      const attrs: Record<string, string | number | boolean> = {};
      for (const [k, v] of Object.entries((c.attributes ?? {}) as Record<string, unknown>)) {
        if (!/^[a-z_0-9]{1,60}$/.test(k)) return bad(`Invalid attribute ${k}.`);
        if (typeof v === 'number' || typeof v === 'boolean') attrs[k] = v;
        else if (clean(v)) { if (v !== '') attrs[k] = v; } else return bad(`Invalid value for ${k}.`);
      }
      credentials.push({ credentialConfigurationId: c.credentialConfigurationId, attributes: attrs, ...(c.portraitFromIdentity === true ? { portraitFromIdentity: true } : {}) });
    }
    send(res, await call('/api/cases', { method: 'POST', body: JSON.stringify({ identity: id, credentials }) }));
  });
  api.get('/cases/:id', async (req, res) => (ID.test(String(req.params.id)) ? send(res, await call(`/api/cases/${encodeURIComponent(String(req.params.id))}`)) : void res.sendStatus(404)));
  api.post('/cases/:id/offer', async (req, res) => (ID.test(String(req.params.id)) ? send(res, await call(`/api/cases/${encodeURIComponent(String(req.params.id))}/offer`, { method: 'POST' })) : void res.sendStatus(404)));
  r.use('/demo-issuer/lab/api', api);
  return r;
}

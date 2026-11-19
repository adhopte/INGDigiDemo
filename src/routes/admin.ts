import { createHash, timingSafeEqual } from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { createIssuerProvider, type IssuedOffer } from '../issuer/provider.js';
import { loadPortalUseCases } from '../issuer/portal.js';
import { matchConfig } from '../issuer/remote.js';
import { RECORD_FIELDS, sorLookup, validatePortrait, validateRecord, type CustomRecord } from '../issuer/records.js';
import type { Ctx } from '../rps/context.js';
import { q } from '../rps/context.js';

const sha = (s: string) => createHash('sha256').update(s).digest();
const LOCK_AFTER = 5;
const LOCK_MS = 60_000;

/**
 * Machine-facing record service ("system of record") with the same contract as the WalletTester's SoR server:
 *   GET /sor/<credential configuration id>/sor/<identifier>[?credential_identifier=<credential id>]
 * It serves the issuer portal's sample records plus the records an admin entered. An issuer pointed at this service
 * (a SIGMA-side setting) fills credentials from these values. No session, no list endpoint.
 */
export function sorRouter(ctx: Ctx): Router {
  const { cfg, svc } = ctx;
  const r = Router();
  const samples = loadPortalUseCases();
  r.use((_req, res, next) => { res.set('Access-Control-Allow-Origin', '*').set('Cache-Control', 'no-store'); next(); });
  r.get('/:configId/sor/:identifier', async (req, res) => {
    const identifier = String(req.params.identifier);
    const found = sorLookup(await Promise.resolve(svc.records.get(identifier)).catch(() => undefined), samples.flatMap((u) => u.users), String(req.params.configId), identifier, q(req.query.credential_identifier));
    if (!found) return void res.status(404).type('text/plain').send('User not found by identifier');
    res.json(found);
  });
  return r;
}

/** Admin console of the issuer portal: a mock of a check against an authentic source. */
export function adminRouter(ctx: Ctx): Router {
  const { cfg, svc } = ctx;
  const r = Router();
  const samples = loadPortalUseCases();
  const ucOf = (id: unknown) => (id === 'birth-certificate' ? 'birth-certificate' : 'pid');
  const attOf = (uc: string) => cfg.attestations[uc === 'pid' ? 'pid' : 'birth_certificate']!;

  r.use('/demo-issuer/admin', (_req, res, next) => { res.locals.skin = 'dashboard'; res.locals.basePath = ''; next(); });
  const needAdmin = (req: Request, res: Response, next: NextFunction) => (req.session.admin ? next() : void res.redirect('/demo-issuer/admin/login'));

  r.get('/demo-issuer/admin/login', (req, res) => {
    if (req.session.admin) return void res.redirect('/demo-issuer/admin');
    res.render('issuer/admin-login', { title: res.locals.t('admin.login.title'), error: undefined });
  });

  r.post('/demo-issuer/admin/login', (req, res) => {
    const fails = req.session.adminFails ?? { n: 0, until: 0 };
    if (fails.until > Date.now()) return void res.status(429).render('issuer/admin-login', { title: res.locals.t('admin.login.title'), error: 'admin.login.locked' });
    const user = (q(req.body?.username) ?? '').trim().toLowerCase();
    const ok = user === 'admin' && timingSafeEqual(sha(q(req.body?.password) ?? ''), sha(cfg.adminPassword));
    if (!ok) {
      req.session.adminFails = { n: fails.n + 1, until: fails.n + 1 >= LOCK_AFTER ? Date.now() + LOCK_MS : 0 };
      if (fails.n + 1 >= LOCK_AFTER) req.session.adminFails.n = 0;
      return void res.status(401).render('issuer/admin-login', { title: res.locals.t('admin.login.title'), error: 'admin.login.failed' });
    }
    delete req.session.adminFails;
    req.session.admin = true;
    res.redirect('/demo-issuer/admin');
  });

  r.post('/demo-issuer/admin/logout', (req, res) => {
    delete req.session.admin;
    res.redirect('/demo-issuer');
  });

  const sampleValues = (uc: string) => samples.find((s) => s.id === uc)?.users[0]?.attributes ?? {};

  const renderAdmin = async (req: Request, res: Response, uc: string, values: Record<string, string>, errors: Record<string, string>, status = 200) => {
    let records: CustomRecord[] = [];
    let storeError = false;
    try { records = await svc.records.list(); } catch { storeError = true; } // standalone record service unreachable
    res.status(status).render('issuer/admin', {
      title: res.locals.t('admin.title'), uc, fields: RECORD_FIELDS[uc], values, errors, records, storeError,
      recordService: cfg.sor.url ?? `${cfg.publicBaseUrl}/sor`, standalone: !!cfg.sor.url, configId: attOf(uc).externalConfigurationId, mockMode: cfg.mockMode,
    });
  };

  r.get('/demo-issuer/admin', needAdmin, async (req, res) => {
    const uc = ucOf(req.query.uc);
    await renderAdmin(req, res, uc, sampleValues(uc), {});
  });

  /** The issuer creates the credential from the record: SIGMA's offer API (live) or the local demo issuer (mock mode). */
  const offerFor = async (rec: CustomRecord): Promise<IssuedOffer | undefined> => {
    const att = attOf(rec.useCase);
    if (cfg.mockMode) return createIssuerProvider({ ...cfg, issuer: { ...cfg.issuer, mode: 'local' } }, svc.local).createOffer(att.key, rec.attributes);
    const s = await svc.remote?.summary();
    if (!s?.reachable || !s.issuer || !matchConfig(att, s.configs)) return undefined;
    const external = createIssuerProvider(
      { ...cfg, issuer: { ...cfg.issuer, mode: 'external', fallbackLocal: false, external: { ...cfg.issuer.external, apiBaseUrl: cfg.issuer.external.apiBaseUrl ?? s.issuer } } },
      svc.local, svc.fetchImpl, svc.remote,
    );
    return external.createOffer(att.key, {}, { identifier: rec.identifier, credentialIdentifier: rec.credentialId });
  };

  const showOffer = async (req: Request, res: Response, rec: CustomRecord) => {
    const att = attOf(rec.useCase);
    try {
      const offer = await offerFor(rec);
      if (!offer) return void res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer/admin' });
      if (offer.id) req.session.offerIds = [...(req.session.offerIds ?? []).slice(-19), offer.id];
      res.render('offer', { title: res.locals.t(`att.${att.key}.name`), attestationKey: att.key, offer, returnTo: `/demo-issuer/admin?uc=${rec.useCase}`, canSimulate: cfg.mockMode, rp: undefined });
    } catch {
      res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer/admin' });
    }
  };

  r.post('/demo-issuer/admin/offer', needAdmin, async (req, res) => {
    const uc = ucOf(req.body?.uc);
    const v = validateRecord(uc, (req.body ?? {}) as Record<string, unknown>);
    const pt = uc === 'pid' ? validatePortrait(req.body?.portrait) : { ok: true as const, portrait: undefined };
    if (!v.ok || !pt.ok) {
      const values: Record<string, string> = {};
      for (const f of RECORD_FIELDS[uc]!) values[f.name] = q(req.body?.[f.name]) ?? '';
      if (pt.ok && pt.portrait) values.portrait = pt.portrait;
      return void (await renderAdmin(req, res, uc, values, { ...(v.ok ? {} : v.errors), ...(pt.ok ? {} : { portrait: 'admin.err.portrait' }) }, 422));
    }
    let rec: CustomRecord;
    try { rec = await svc.records.add(uc, v.attributes, pt.portrait); } catch { return void res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('admin.sor_unreachable'), retryHref: '/demo-issuer/admin' }); }
    await showOffer(req, res, rec);
  });

  r.post('/demo-issuer/admin/records/:id/offer', needAdmin, async (req, res) => {
    const rec = await Promise.resolve(svc.records.get(String(req.params.id))).catch(() => undefined);
    if (!rec) return void res.redirect('/demo-issuer/admin');
    await showOffer(req, res, rec);
  });

  r.post('/demo-issuer/admin/records/:id/delete', needAdmin, async (req, res) => {
    const rec = await Promise.resolve(svc.records.get(String(req.params.id))).catch(() => undefined);
    await Promise.resolve(svc.records.delete(String(req.params.id))).catch(() => undefined);
    res.redirect(`/demo-issuer/admin?uc=${rec?.useCase ?? 'pid'}`);
  });

  return r;
}

import { createHash, timingSafeEqual } from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { createIssuerProvider, type IssuedOffer } from '../issuer/provider.js';
import { SOR_LIST_PATH, SOR_USE_CASE_ID, loadPortalUseCases, parseUsers, type PortalUser } from '../issuer/portal.js';
import { matchConfig } from '../issuer/remote.js';
import { RECORD_FIELDS, matchRecords, validateRecord } from '../issuer/records.js';
import type { Ctx } from '../rps/context.js';
import { q } from '../rps/context.js';

const sha = (s: string) => createHash('sha256').update(s).digest();
const LOCK_AFTER = 5;
const LOCK_MS = 60_000;

/**
 * Admin console of the issuer portal: a mock of a check against an authentic source.
 * The SIGMA issuer issues only what its own record store holds, so the admin's input is MATCHED against those records
 * (the store's list is publicly readable) and the offer is created for the matching record.
 */
export function adminRouter(ctx: Ctx): Router {
  const { cfg, svc } = ctx;
  const r = Router();
  const samples = loadPortalUseCases();
    const ucOf = (id: unknown) => (id === 'birth-certificate' ? 'birth-certificate' : id === 'mdl' ? 'mdl' : 'pid');
  const ATT: Record<string, string> = { pid: 'pid', 'birth-certificate': 'birth_certificate', mdl: 'mdl' };
  const attOf = (uc: string) => cfg.attestations[ATT[uc] ?? 'pid']!;

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

  const sampleValues = (uc: string) => {
    const a = samples.find((s) => s.id === uc)?.users[0]?.attributes ?? {};
    return Object.fromEntries(Object.entries(a).filter(([k]) => RECORD_FIELDS[uc]!.some((f) => f.name === k)));
  };

  r.post('/demo-issuer/admin/reuse-policy', needAdmin, (req, res) => {
    svc.local.reusePolicy = q(req.body?.value) === 'off' ? 'off' : 'sigma';
    req.session.flash = svc.local.reusePolicy === 'off' ? 'admin.reuse.saved_off' : 'admin.reuse.saved_on';
    res.redirect('/demo-issuer/admin');
  });

  r.post('/demo-issuer/admin/batch-size', needAdmin, (req, res) => {
    const n = Number(q(req.body?.value));
    svc.local.batchSize = Number.isInteger(n) && n >= 1 && n <= 10 ? n : svc.local.batchSize;
    req.session.flash = 'admin.batch.saved';
    res.redirect('/demo-issuer/admin');
  });

  const renderForm = (res: Response, uc: string, values: Record<string, string>, errors: Record<string, string>, status = 200) =>
    void res.status(status).render('issuer/admin', { title: res.locals.t('admin.title'), uc, fields: RECORD_FIELDS[uc], values, errors, mockMode: cfg.mockMode, ucs: ['pid', 'birth-certificate', 'mdl'], reusePolicy: svc.local.reusePolicy, batchSize: svc.local.batchSize });

  r.get('/demo-issuer/admin', needAdmin, (req, res) => {
    const uc = ucOf(req.query.uc);
    renderForm(res, uc, sampleValues(uc), {});
  });

  /** The issuer's records for a use case: read live from its record store, or the saved copy of the sample records when it cannot be reached. */
  const authenticSource = async (uc: string): Promise<{ users: PortalUser[]; live: boolean }> => {
    const fallback = { users: samples.find((s) => s.id === uc)?.users ?? [], live: false };
    try {
      const s = await svc.remote?.summary();
      const base = s?.issuer ?? cfg.issuer.external.apiBaseUrl;
      if (!base) return fallback;
      const res = await svc.fetchImpl(`${base}${SOR_LIST_PATH}/${SOR_USE_CASE_ID[uc]}/sor/`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10_000) });
      if (!res.ok) return fallback;
      const users = parseUsers(await res.json());
      return users.length ? { users, live: true } : fallback;
    } catch {
      return fallback;
    }
  };

  /** SIGMA's offer API for the matched record; the local demo issuer only in mock mode (typed values). */
  const createOffer = async (uc: string, record: PortalUser, typed: Record<string, string>): Promise<IssuedOffer | undefined> => {
    const att = attOf(uc);
    if (cfg.mockMode) {
      const claims = Object.fromEntries(Object.entries(typed).map(([k, v]) => [k, v === 'True' ? true : v === 'False' ? false : v]));
      return createIssuerProvider({ ...cfg, issuer: { ...cfg.issuer, mode: 'local' } }, svc.local).createOffer(att.key, claims);
    }
    const s = await svc.remote?.summary();
    if (!s?.reachable || !s.issuer || !matchConfig(att, s.configs)) return undefined;
    const external = createIssuerProvider(
      { ...cfg, issuer: { ...cfg.issuer, mode: 'external', fallbackLocal: false, external: { ...cfg.issuer.external, apiBaseUrl: cfg.issuer.external.apiBaseUrl ?? s.issuer } } },
      svc.local, svc.fetchImpl, svc.remote,
    );
    return external.createOffer(att.key, {}, { identifier: record.identifier, credentialIdentifier: record.credentialId, ...(record.walletId ? { walletIdentifier: record.walletId } : {}) });
  };

  const showOffer = async (req: Request, res: Response, uc: string, record: PortalUser, typed: Record<string, string>) => {
    const att = attOf(uc);
    try {
      const offer = await createOffer(uc, record, typed);
      if (!offer) return void res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer/admin' });
      if (offer.id) req.session.offerIds = [...(req.session.offerIds ?? []).slice(-19), offer.id];
      res.render('offer', { title: res.locals.t(`att.${att.key}.name`), attestationKey: att.key, offer, returnTo: `/demo-issuer/admin?uc=${uc}`, canSimulate: cfg.mockMode, rp: undefined });
    } catch {
      res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer/admin' });
    }
  };

  /** What the admin typed, without the derived "over 18" flag (unless chosen explicitly). */
  const enteredValues = (uc: string, body: Record<string, unknown>, attributes: Record<string, string>) => {
    const e = { ...attributes };
    if (!(typeof body.age_over_18 === 'string' && body.age_over_18.trim())) delete e.age_over_18;
    return e;
  };

  r.post('/demo-issuer/admin/check', needAdmin, async (req, res) => {
    const uc = ucOf(req.body?.uc);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const v = validateRecord(uc, body);
    if (!v.ok) {
      const values: Record<string, string> = {};
      for (const f of RECORD_FIELDS[uc]!) values[f.name] = q(body[f.name]) ?? '';
      return renderForm(res, uc, values, v.errors, 422);
    }
    const typed = enteredValues(uc, body, v.attributes);
    if (cfg.mockMode) return void (await showOffer(req, res, uc, { identifier: 'typed', credentialId: 'typed', configurationId: '', attributes: v.attributes }, v.attributes));
    const source = await authenticSource(uc);
    const matches = matchRecords(source.users, typed);
    if (matches.length === 1) return void (await showOffer(req, res, uc, matches[0]!, typed));
    res.status(matches.length ? 200 : 404).render('issuer/admin-result', {
      title: res.locals.t('admin.result.title'), uc, matches, available: source.users, live: source.live, columns: ['given_name', 'family_name', 'birth_date'],
    });
  });

  /** Offer for one of several matching records (looked up again on the server, nothing is trusted from the client). */
  r.post('/demo-issuer/admin/pick', needAdmin, async (req, res) => {
    const uc = ucOf(req.body?.uc);
    const record = (await authenticSource(uc)).users.find((u) => u.identifier === q(req.body?.identifier));
    if (!record) return void res.redirect(`/demo-issuer/admin?uc=${uc}`);
    await showOffer(req, res, uc, record, {});
  });

  return r;
}

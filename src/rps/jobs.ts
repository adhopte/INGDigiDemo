import { randomBytes } from 'node:crypto';
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, q, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

/** The demo vacancies. `eqf` = the lowest EQF level the employer asks for (6 = Bachelor, 7 = Master). */
export const JOBS = [
  { id: 'j1', company: 'Northwind Labs', city: 'Berlin', eqf: 6 },
  { id: 'j2', company: 'Contoso Analytics', city: 'Paris', eqf: 7 },
  { id: 'j3', company: 'Helix Institute', city: 'Utrecht', eqf: 7 },
  { id: 'j4', company: 'Fabrikam Legal', city: 'Brussels', eqf: 7 },
  { id: 'j5', company: 'Tailspin Studio', city: 'Lisbon', eqf: 6 },
  { id: 'j6', company: 'Adventure Works', city: 'Madrid', eqf: 6 },
] as const;
const MAX_CV = 800_000; // bytes
const CV_TYPES: Record<string, string> = { pdf: 'application/pdf', txt: 'text/plain', md: 'text/plain', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };

/** Does the presented diploma meet the vacancy's level? (EQF level when shared, else the degree name). `undefined` = cannot tell. */
export function meetsLevel(diploma: Record<string, unknown>, minEqf: number): boolean | undefined {
  const eqf = Number(diploma.eqf_level);
  if (Number.isInteger(eqf) && eqf >= 1 && eqf <= 8) return eqf >= minEqf;
  const level = str(diploma.degree_level).toLowerCase();
  if (!level) return undefined;
  const byName = /\b(phd|doctor|doctorate)\b/.test(level) ? 8 : /\b(master|msc|llm|ma)\b/.test(level) ? 7 : /\b(bachelor|bsc|ba)\b/.test(level) ? 6 : undefined;
  return byName === undefined ? undefined : byName >= minEqf;
}

export function jobsRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'jobs'));

  const diploma = (req: Request) => claimsOfType(req.session, rp.id, 'diploma');
  const job = (id: unknown) => JOBS.find((j) => j.id === id);
  router.use((req, res, next) => { res.locals.loggedIn = !!diploma(req); res.locals.hasCv = !!req.session.cv; next(); });

  router.get('/', (req, res) => {
    const term = (q(req.query.q) ?? '').trim().toLowerCase().slice(0, 60);
    const t = res.locals.t as (k: string) => string;
    const jobs = JOBS.filter((j) => !term || `${t(`jobs.${j.id}.title`)} ${j.company} ${j.city}`.toLowerCase().includes(term));
    res.render('jobs/home', { title: 'Demo Jobs', jobs, term: q(req.query.q)?.slice(0, 60) ?? '' });
  });

  router.get('/job/:id', (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('error.not_found'), retryHref: `/${rp.id}/` });
    res.render('jobs/job', { title: res.locals.t(`jobs.${j.id}.title`), j });
  });

  // ---- step 1: the CV (kept in the session only; sent as the raw file body by the page's script)
  router.post('/cv', express.raw({ type: () => true, limit: MAX_CV }), (req: Request, res: Response) => {
    const name = decodeURIComponent(String(req.get('x-filename') ?? '')).replace(/[^\p{L}\p{N}._ -]/gu, '').slice(0, 80);
    const ext = name.split('.').pop()?.toLowerCase() ?? '';
    const body = req.body as Buffer;
    const okType = ext in CV_TYPES && Buffer.isBuffer(body) && body.length > 0 && body.length <= MAX_CV
      && (ext !== 'pdf' || body.subarray(0, 5).toString() === '%PDF-') && ((ext !== 'txt' && ext !== 'md') || !body.includes(0));
    if (!name || !okType) return void res.status(422).json({ error: 'invalid' });
    req.session.cv = { name, type: CV_TYPES[ext]!, size: body.length, data: body.toString('base64') };
    res.json({ name, size: body.length });
  });
  router.post('/cv/remove', (req, res) => { delete req.session.cv; res.redirect(q(req.body?.back)?.startsWith(`/${rp.id}/`) ? q(req.body?.back)! : `/${rp.id}/`); });
  router.get('/cv/download', (req, res) => {
    const cv = req.session.cv;
    if (!cv) return void res.sendStatus(404);
    res.set({ 'Content-Type': cv.type, 'Content-Disposition': `attachment; filename="${cv.name.replace(/["\\]/g, '_')}"`, 'Cache-Control': 'no-store' }).send(Buffer.from(cv.data, 'base64'));
  });

  router.get('/apply/:id', (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.redirect(`/${rp.id}/`);
    res.render('jobs/apply', { title: res.locals.t('jobs.apply.title', { job: res.locals.t(`jobs.${j.id}.title`) }), j, cv: req.session.cv ? { name: req.session.cv.name, size: req.session.cv.size } : undefined, maxKb: Math.round(MAX_CV / 1000) });
  });

  // ---- step 2: the diploma attestation, presented through the wallet
  router.get('/apply/:id/present', (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.redirect(`/${rp.id}/`);
    if (!req.session.cv) return void res.redirect(`/${rp.id}/apply/${j.id}`);
    res.redirect(`/${rp.id}/verify?p=diploma&returnTo=${encodeURIComponent(`/${rp.id}/application/${j.id}`)}`);
  });

  const guard = (req: Request, res: Response, next: NextFunction) => (diploma(req) ? next() : res.redirect(`/${rp.id}/`));
  router.get('/application/:id', guard, (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.redirect(`/${rp.id}/`);
    if (!req.session.cv) return void res.redirect(`/${rp.id}/apply/${j.id}`);
    const d = diploma(req)!;
    let app = (req.session.applications ?? []).find((a) => a.jobId === j.id);
    if (!app) {
      app = { jobId: j.id, ref: `JB-${randomBytes(3).toString('hex').toUpperCase()}`, at: new Date().toISOString() };
      req.session.applications = [...(req.session.applications ?? []), app].slice(-20);
    }
    res.render('jobs/application', { title: res.locals.t('jobs.done.title'), j, d, app, meets: meetsLevel(d, j.eqf), cv: { name: req.session.cv.name, size: req.session.cv.size } });
  });

  router.get('/applications', (req, res) => {
    const apps = (req.session.applications ?? []).map((a) => ({ ...a, j: job(a.jobId) })).filter((a) => a.j);
    res.render('jobs/applications', { title: res.locals.t('jobs.apps.title'), apps });
  });

  return router;
}

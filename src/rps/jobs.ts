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

  /** The account: created and signed in with the PID. */
  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const job = (id: unknown) => JOBS.find((j) => j.id === id);
  router.use((req, res, next) => { res.locals.loggedIn = !!pid(req); next(); });
  const guard = (req: Request, res: Response, next: NextFunction) => (pid(req) ? next() : res.redirect(`/${rp.id}/signup?next=${encodeURIComponent(req.originalUrl.startsWith(`/${rp.id}/`) ? req.originalUrl : `/${rp.id}/cv`)}`));
  const education = (req: Request) => req.session.cvEducation ?? [];
  /** The best level among the verified diplomas on the CV (EQF), for the requirement check. */
  const meets = (req: Request, minEqf: number): boolean | undefined => {
    const list = education(req);
    if (!list.length) return undefined;
    return list.some((e) => meetsLevel({ eqf_level: e.eqf, degree_level: e.level }, minEqf) === true);
  };
  const cvInfo = (req: Request) => (req.session.cv ? { name: req.session.cv.name, size: req.session.cv.size } : undefined);

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

  // ---- account creation / sign-in with the PID
  router.get('/signup', (req, res) => {
    const next = q(req.query.next);
    const to = next && next.startsWith(`/${rp.id}/`) && !next.includes('//') && !/[\\\r\n]/.test(next) ? next : `/${rp.id}/cv`;
    res.redirect(`/${rp.id}/verify?p=pid&returnTo=${encodeURIComponent(to)}`);
  });

  // ---- my CV: the profile (PID), the CV document, and the verified education
  router.get('/cv', guard, (req, res) => {
    res.render('jobs/cv', { title: res.locals.t('jobs.cv.title'), p: pid(req)!, cv: cvInfo(req), edu: education(req), maxKb: Math.round(MAX_CV / 1000) });
  });

  router.post('/cv', guard, express.raw({ type: () => true, limit: MAX_CV }), (req: Request, res: Response) => {
    const name = decodeURIComponent(String(req.get('x-filename') ?? '')).replace(/[^\p{L}\p{N}._ -]/gu, '').slice(0, 80);
    const ext = name.split('.').pop()?.toLowerCase() ?? '';
    const body = req.body as Buffer;
    const okType = ext in CV_TYPES && Buffer.isBuffer(body) && body.length > 0 && body.length <= MAX_CV
      && (ext !== 'pdf' || body.subarray(0, 5).toString() === '%PDF-') && ((ext !== 'txt' && ext !== 'md') || !body.includes(0));
    if (!name || !okType) return void res.status(422).json({ error: 'invalid' });
    req.session.cv = { name, type: CV_TYPES[ext]!, size: body.length, data: body.toString('base64') };
    res.json({ name, size: body.length });
  });
  router.post('/cv/remove', guard, (req, res) => { delete req.session.cv; res.redirect(`/${rp.id}/cv`); });
  router.get('/cv/download', guard, (req, res) => {
    const cv = req.session.cv;
    if (!cv) return void res.sendStatus(404);
    res.set({ 'Content-Type': cv.type, 'Content-Disposition': `attachment; filename="${cv.name.replace(/["\\]/g, '_')}"`, 'Cache-Control': 'no-store' }).send(Buffer.from(cv.data, 'base64'));
  });

  // the diploma attestation, presented through the wallet; once verified it becomes a verified attribute (education entry) of the CV
  router.get('/cv/diploma', guard, (_req, res) => res.redirect(`/${rp.id}/verify?p=diploma&returnTo=${encodeURIComponent(`/${rp.id}/cv/diploma/added`)}`));
  router.get('/cv/diploma/added', guard, (req, res) => {
    const d = claimsOfType(req.session, rp.id, 'diploma');
    if (!d) return void res.redirect(`/${rp.id}/cv`);
    const entry = { title: str(d.diploma_title), institution: str(d.institution_name), level: str(d.degree_level), eqf: str(d.eqf_level), awarded: str(d.awarding_date), programme: str(d.programme_id), at: new Date().toISOString() };
    const list = education(req);
    if (!list.some((e) => e.title === entry.title && e.institution === entry.institution && e.awarded === entry.awarded)) req.session.cvEducation = [...list, entry].slice(-10);
    req.session.flash = 'jobs.cv.diploma_added';
    res.redirect(`/${rp.id}/cv`);
  });
  router.post('/cv/education/remove', guard, (req, res) => {
    const i = Number(q(req.body?.i));
    req.session.cvEducation = education(req).filter((_, k) => k !== i);
    res.redirect(`/${rp.id}/cv`);
  });

  // ---- apply with the CV (profile + verified education)
  router.get('/apply/:id', guard, (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.redirect(`/${rp.id}/`);
    res.render('jobs/apply', { title: res.locals.t('jobs.apply.title', { job: res.locals.t(`jobs.${j.id}.title`) }), j, p: pid(req)!, cv: cvInfo(req), edu: education(req), meets: meets(req, j.eqf) });
  });
  router.post('/apply/:id', guard, (req, res) => {
    const j = job(req.params.id);
    if (!j) return void res.redirect(`/${rp.id}/`);
    if (!(req.session.applications ?? []).some((a) => a.jobId === j.id)) req.session.applications = [...(req.session.applications ?? []), { jobId: j.id, ref: `JB-${randomBytes(3).toString('hex').toUpperCase()}`, at: new Date().toISOString() }].slice(-20);
    res.redirect(`/${rp.id}/application/${j.id}`);
  });

  router.get('/application/:id', guard, (req, res) => {
    const j = job(req.params.id);
    const app = (req.session.applications ?? []).find((a) => a.jobId === req.params.id);
    if (!j || !app) return void res.redirect(`/${rp.id}/`);
    res.render('jobs/application', { title: res.locals.t('jobs.done.title'), j, p: pid(req)!, app, edu: education(req), meets: meets(req, j.eqf), cv: cvInfo(req) });
  });

  router.get('/applications', guard, (req, res) => {
    const apps = (req.session.applications ?? []).map((a) => ({ ...a, j: job(a.jobId) })).filter((a) => a.j);
    res.render('jobs/applications', { title: res.locals.t('jobs.apps.title'), apps });
  });

  return router;
}

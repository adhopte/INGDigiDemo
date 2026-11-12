import { randomInt } from 'node:crypto';
import { Router, type Request } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, q, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

export const PROGRAMMES = ['cs', 'law', 'bio', 'art'] as const;

export function universityRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'university'));

  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const bc = (req: Request) => claimsOfType(req.session, rp.id, 'birth_certificate');
  const norm = (v: unknown) => str(v).trim().toLowerCase();

  /** PID and birth certificate must describe the same person. */
  const identityMatches = (req: Request) => {
    const p = pid(req), b = bc(req);
    return !!p && !!b && norm(p.given_name) === norm(b.given_name) && norm(p.family_name) === norm(b.family_name) && str(p.birth_date) === str(b.birth_date);
  };

  router.get('/', (req, res) => res.render('university/home', { title: 'Demo University', enrolled: !!req.session.enrolment }));

  // multi-credential: one request for both; otherwise two requests in a row
  router.get('/start', (_req, res) => {
    const next = `/${rp.id}/documents`;
    res.redirect(ctx.cfg.multiCredential ? `/${rp.id}/verify?p=pid_bc&returnTo=${encodeURIComponent(next)}` : next);
  });

  router.get('/documents', (req, res) =>
    res.render('university/documents', { title: res.locals.t('uni.docs.title'), hasPid: !!pid(req), hasBc: !!bc(req), multi: ctx.cfg.multiCredential, mismatch: !!pid(req) && !!bc(req) && !identityMatches(req) }),
  );

  const needBoth = (req: Request) => !!pid(req) && !!bc(req) && identityMatches(req);

  router.get('/enrol', (req, res) => {
    if (!needBoth(req)) return void res.redirect(`/${rp.id}/documents`);
    const p = pid(req)!, b = bc(req)!;
    res.render('university/enrol', { title: res.locals.t('uni.enrol.title'), p, b, programmes: PROGRAMMES, errors: {}, values: {} });
  });

  router.post('/enrol', (req, res) => {
    if (!needBoth(req)) return void res.redirect(`/${rp.id}/documents`);
    const programme = q(req.body?.programme) ?? '';
    const email = (q(req.body?.email) ?? '').trim();
    const errors: Record<string, string> = {};
    if (!(PROGRAMMES as readonly string[]).includes(programme)) errors.programme = 'form.err.required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'form.err.email';
    if (q(req.body?.consent) !== 'yes') errors.consent = 'form.err.consent';
    if (Object.keys(errors).length) {
      return void res.status(422).render('university/enrol', { title: res.locals.t('uni.enrol.title'), p: pid(req)!, b: bc(req)!, programmes: PROGRAMMES, errors, values: { programme, email } });
    }
    req.session.enrolment = { studentNumber: `S${new Date().getFullYear()}${randomInt(10000, 99999)}`, programme, email, at: new Date().toISOString() };
    res.redirect(`/${rp.id}/confirmation`);
  });

  router.get('/confirmation', (req, res) => {
    const e = req.session.enrolment;
    const p = pid(req);
    if (!e || !p) return void res.redirect(`/${rp.id}/`);
    res.render('university/confirmation', { title: res.locals.t('uni.done.title'), e, p });
  });

  return router;
}

import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

/** The member's cover as shown by the insurer: valid when today lies within the card's validity (the end date; the start date when shared). */
export function coverStanding(c: Record<string, unknown>, now = new Date()): { valid: boolean; started: boolean; ended: boolean } {
  const d = (v: unknown) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v) ? new Date(`${v.slice(0, 10)}T00:00:00Z`) : undefined);
  const start = d(c.starting_date), end = d(c.ending_date);
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const started = !start || start <= today, ended = !!end && end < today;
  return { valid: started && !ended, started, ended };
}

export function insuranceRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'insurance'));

  const ehic = (req: Request) => claimsOfType(req.session, rp.id, 'ehic');
  const guard = (req: Request, res: Response, next: NextFunction) => (ehic(req) ? next() : res.redirect(`/${rp.id}/login`));
  router.use((req, res, next) => { res.locals.loggedIn = !!ehic(req); next(); });

  router.get('/', (_req, res) => res.render('insurance/home', { title: 'Demo Insure' }));
  router.get('/login', (_req, res) => res.redirect(`/${rp.id}/verify?p=ehic&returnTo=${encodeURIComponent(`/${rp.id}/account`)}`));

  router.get('/account', guard, (req, res) => {
    const c = ehic(req)!;
    const s = (c.subject && typeof c.subject === 'object' ? c.subject : {}) as Record<string, unknown>;
    const pan = str(c.personal_administrative_number);
    const authority = c.issuing_authority && typeof c.issuing_authority === 'object' ? str((c.issuing_authority as Record<string, unknown>).name) : str(c.issuing_authority);
    res.render('insurance/account', {
      title: res.locals.t('ins.account.title'),
      c, standing: coverStanding(c), name: `${str(s.given_name)} ${str(s.family_name)}`.trim(),
      member: pan ? `${pan.slice(0, 2)}••••••${pan.slice(-3)}` : '', authority,
    });
  });

  return router;
}

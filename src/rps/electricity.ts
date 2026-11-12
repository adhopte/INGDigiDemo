import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

export function electricityRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'electricity'));

  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const guard = (req: Request, res: Response, next: NextFunction) => (pid(req) ? next() : res.redirect(`/${rp.id}/login`));

  router.get('/', (req, res) => res.render('electricity/home', { title: 'Demo Power Co', loggedIn: !!pid(req) }));
  router.get('/login', (_req, res) => res.redirect(`/${rp.id}/verify?p=pid&returnTo=${encodeURIComponent(`/${rp.id}/account`)}`));

  router.get('/account', guard, (req, res) => {
    const c = pid(req)!;
    const seed = (str(c.family_name) + str(c.birth_date)).split('').reduce((a, ch) => (a * 33 + ch.charCodeAt(0)) >>> 0, 7);
    res.render('electricity/account', {
      title: res.locals.t('el.account.title'),
      c,
      contract: `PC-${String(seed % 1000000).padStart(6, '0')}`,
      meter: `EAN ${String(seed % 100000000).padStart(8, '0')}0001`,
      usage: [310, 295, 270, 240, 215, 205].map((v, i) => v + ((seed >> i) % 25)),
      invoice: 61 + (seed % 40),
    });
  });

  void ctx;
  return router;
}

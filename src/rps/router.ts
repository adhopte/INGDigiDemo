import { Router, type Request, type Response, type NextFunction } from 'express';
import type { AppConfig, RpConfig } from '../config.js';
import { redirectUriFor } from '../config.js';

/**
 * Per-RP router. Step 1 only exposes the RP home page; the OIDC callback and the
 * use-case flows are added in steps 2-5.
 */
export function rpRouter(config: AppConfig, rp: RpConfig): Router {
  const router = Router();

  router.use((_req: Request, res: Response, next: NextFunction) => {
    res.locals.rp = rp;
    res.locals.themeColor = rp.themeColor;
    res.locals.basePath = `/${rp.id}`;
    next();
  });

  router.get('/', (_req, res) =>
    res.render('rp-home', { title: rp.displayName, redirectUri: redirectUriFor(config, rp.id) }),
  );

  return router;
}

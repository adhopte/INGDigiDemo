import { Router, type NextFunction, type Request, type Response } from 'express';
import type { AppConfig, RpConfig } from '../config.js';
import { redirectUriFor } from '../config.js';
import { log } from '../logger.js';
import { AuthFlowError, beginAuth, completeAuth, peekPending } from '../oidc/flow.js';
import { mockClaimsFor } from '../mock/claims.js';

const q = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

/**
 * Per-RP router: generic auth endpoints (start / callback / mock wallet) shared by all four RPs.
 * Use-case flows are added on top in steps 4-5.
 */
export function rpRouter(config: AppConfig, rp: RpConfig): Router {
  const router = Router();

  router.use((_req: Request, res: Response, next: NextFunction) => {
    res.locals.rp = rp;
    res.locals.themeColor = rp.themeColor;
    res.locals.basePath = `/${rp.id}`;
    next();
  });

  router.get('/', (req, res) =>
    res.render('rp-home', {
      title: rp.displayName,
      redirectUri: redirectUriFor(config, rp.id),
      disclosed: req.session.disclosed?.[rp.id] ?? {},
    }),
  );

  /** Start a wallet presentation: GET /<rp>/auth/start?p=<presentation>&returnTo=/<rp>/... */
  router.get('/auth/start', async (req, res) => {
    const { redirectTo } = await beginAuth(config, rp, req.session, { presentation: q(req.query.p) ?? '', returnTo: req.query.returnTo });
    res.redirect(redirectTo);
  });

  /** Redirect URI registered on the Intermediary: <PUBLIC_BASE_URL>/<rp>/callback */
  router.get('/callback', async (req, res) => {
    const { returnTo } = await completeAuth(config, rp, req.session, req.originalUrl);
    res.redirect(returnTo);
  });

  // ---- Simulated wallet (MOCK_MODE only) ----
  if (config.mockMode) {
    router.get('/mock-wallet', (req, res) => {
      const state = q(req.query.state);
      const pending = peekPending(req.session, rp, state);
      if (!pending) throw new AuthFlowError('No pending request for this simulated wallet', 'bad_state');
      const presentation = rp.presentations[pending.presentation]!;
      res.render('mock-wallet', {
        title: 'Simulated wallet',
        state,
        presentation,
        claims: mockClaimsFor(rp, pending.presentation, presentation),
      });
    });

    router.post('/mock-wallet/approve', (req, res) => {
      const state = q(req.body?.state);
      if (!peekPending(req.session, rp, state)) throw new AuthFlowError('No pending request for this simulated wallet', 'bad_state');
      const code = `mock-${Math.random().toString(36).slice(2)}`;
      res.redirect(`/${rp.id}/callback?code=${code}&state=${encodeURIComponent(state!)}`);
    });

    router.post('/mock-wallet/decline', (req, res) => {
      const state = q(req.body?.state);
      if (!peekPending(req.session, rp, state)) throw new AuthFlowError('No pending request for this simulated wallet', 'bad_state');
      res.redirect(`/${rp.id}/callback?error=access_denied&state=${encodeURIComponent(state!)}`);
    });
  }

  // Auth errors become a friendly page scoped to this RP.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  router.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (!(err instanceof AuthFlowError)) return next(err);
    log.warn('auth flow error', { rp: rp.id, code: err.code, error: err.message });
    const status = err.code === 'provider_error' ? 200 : 400;
    res.status(status).render('error', { title: 'Wallet request failed', message: err.message, retryHref: `/${rp.id}/` });
  });

  return router;
}

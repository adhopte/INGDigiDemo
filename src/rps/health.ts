import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, str, type Ctx } from './context.js';
import { rpBase } from './common.js';
import { ehicFromHiid, hiidFromPid } from './health-data.js';
import { renderOffer } from './offer.js';

/**
 * Demo Health. Health ID and EHIC are issued only as mdoc (ISO 18013-5), so they work online (OpenID4VP) and offline (proximity). A new member signs in with the PID and gets a Health ID attestation derived from it; a returning member signs in with that
 * Health ID and gets the European Health Insurance Card (EHIC) derived from the Health ID.
 */
export function healthRouter(ctx: Ctx, rp: RpConfig): Router {
  const r = rpBase(ctx, rp, 'health');
  const router = Router();
  router.use(r);

  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const hiid = (req: Request) => claimsOfType(req.session, rp.id, 'hiid');
  const guard = (req: Request, res: Response, next: NextFunction) => (pid(req) || hiid(req) ? next() : res.redirect(`/${rp.id}/login`));
  router.use((req, res, next) => { res.locals.loggedIn = !!(pid(req) || hiid(req)); next(); });

  router.get('/', (_req, res) => res.render('health/home', { title: 'Demo Health' }));
  router.get('/login', (_req, res) => res.render('health/login', { title: res.locals.t('health.login.title') }));
  router.get('/login/pid', (_req, res) => res.redirect(`/${rp.id}/verify?p=pid&returnTo=${encodeURIComponent(`/${rp.id}/portal`)}`));
  router.get('/login/hiid', (_req, res) => res.redirect(`/${rp.id}/verify?p=hiid&returnTo=${encodeURIComponent(`/${rp.id}/portal`)}`));

  router.get('/portal', guard, (req, res) => {
    const h = hiid(req);
    const p = pid(req);
    const member = h
      ? { via: 'hiid' as const, given: str(h.matching_registered_given_name), family: str(h.matching_registered_family_name), born: str(h.matching_birth_date), id: str(h.health_insurance_id), country: str(h.affiliation_country), until: str(h.expiry_date) }
      : { via: 'pid' as const, given: str(p!.given_name), family: str(p!.family_name), born: str(p!.birth_date), id: '', country: str(p!.nationality), until: '' };
    res.render('health/portal', { title: res.locals.t('health.portal.title'), m: member, hasPid: !!p });
  });

  // Health ID: only for a member who signed in with the PID (it is derived from it)
  router.post('/attestation/hiid', guard, async (req, res) => {
    const p = pid(req);
    if (!p) return void res.sendStatus(403);
    await renderOffer(ctx, req, res, rp, 'hiid', hiidFromPid(p), `/${rp.id}/portal`, { format: 'mdoc' });
  });

  // EHIC: only for a member who signed in with the Health ID (it is derived from it)
  router.post('/attestation/ehic', guard, async (req, res) => {
    const h = hiid(req);
    if (!h) return void res.sendStatus(403);
    const { sd, mdoc } = ehicFromHiid(h);
    await renderOffer(ctx, req, res, rp, 'ehic', sd, `/${rp.id}/portal`, { format: 'mdoc', mdocClaims: mdoc });
  });

  return router;
}

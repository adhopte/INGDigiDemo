import { Router } from 'express';
import { deeplinkForOfferObject, qrDataUrl } from '../issuer/offer.js';
import { createIssuerProvider } from '../issuer/provider.js';
import { matchConfig } from '../issuer/remote.js';
import { PERSONAS, demoClaims, heldClaims, personaFor, redeemOffer } from '../mock/wallet.js';
import type { Ctx } from '../rps/context.js';
import { q } from '../rps/context.js';

const localPath = (v: unknown, fallback: string) => (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') && !v.includes('\\') && !/[\r\n]/.test(v) ? v : fallback);

/** Dashboard-level pages: the demo issuer console and (mock mode) the simulated wallet. */
export function extrasRouter(ctx: Ctx): Router {
  const { cfg, svc } = ctx;
  const r = Router();
  // The console always uses the LOCAL issuer so a real wallet can obtain demo PID / birth certificates.
  const localProvider = createIssuerProvider({ ...cfg, issuer: { ...cfg.issuer, mode: 'local' } }, svc.local);

  r.use((_req, res, next) => { res.locals.skin = 'dashboard'; res.locals.basePath = ''; next(); });

  r.get('/demo-issuer', async (_req, res) => {
    const s = await svc.remote?.summary();
    res.render('issuer/console', { title: res.locals.t('issuer.console.title'), personas: PERSONAS, types: ['pid', 'birth_certificate'], sigma: s?.reachable ? s : undefined });
  });

  /**
   * EXPERIMENTAL: a wallet-initiated credential offer for the real SIGMA PID (authorization_code grant at the issuer's PID realm).
   * It carries no secret and needs no issuer backend call; the wallet runs the authorization flow itself.
   */
  r.post('/demo-issuer/sigma-pid', async (_req, res) => {
    const s = await svc.remote?.summary();
    const att = cfg.attestations.pid;
    const rc = s?.reachable && att ? matchConfig(att, s.configs) : undefined;
    if (!s?.issuer || !rc) return void res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer' });
    const as = s.authorizationServers.find((a) => a.includes('/realms/')) ?? s.authorizationServers[0];
    const offerObject = { credential_issuer: s.issuer, credential_configuration_ids: [rc.id], grants: { authorization_code: { ...(as ? { authorization_server: as } : {}) } } };
    const deeplink = deeplinkForOfferObject(offerObject);
    const offer = { id: undefined, deeplink, qr: await qrDataUrl(deeplink), txCode: undefined, expiresAt: new Date(Date.now() + 10 * 60_000), provider: 'external' as const };
    res.render('offer', { title: res.locals.t('att.pid.name'), attestationKey: 'pid', offer, returnTo: '/demo-issuer', canSimulate: false, rp: undefined });
  });

  r.post('/demo-issuer/offer', async (req, res) => {
    const type = q(req.body?.type);
    if (type !== 'pid' && type !== 'birth_certificate') return void res.sendStatus(400);
    const offer = await localProvider.createOffer(type, demoClaims(type, personaFor(q(req.body?.persona))));
    if (offer.id) req.session.offerIds = [...(req.session.offerIds ?? []).slice(-19), offer.id];
    res.render('offer', { title: res.locals.t(`att.${type}.name`), attestationKey: type, offer, returnTo: '/demo-issuer', canSimulate: cfg.mockMode, rp: undefined });
  });

  if (cfg.mockMode) {
    r.get('/wallet', (req, res) =>
      res.render('wallet', { title: res.locals.t('wallet.title'), items: (req.session.wallet ?? []).map((c) => ({ c, claims: heldClaims(c) })) }),
    );
    r.post('/wallet/clear', (req, res) => { req.session.wallet = []; res.redirect('/wallet'); });

    r.post('/wallet-sim/redeem', async (req, res) => {
      try {
        await redeemOffer(svc.local, req.session, q(req.body?.offerId) ?? '', q(req.body?.txCode));
        req.session.flash = 'offer.simulated_done';
      } catch {
        req.session.flash = 'offer.simulated_failed';
      }
      res.redirect(localPath(req.body?.returnTo, '/wallet'));
    });
  }
  return r;
}

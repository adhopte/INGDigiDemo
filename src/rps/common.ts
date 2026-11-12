import { Router, type Request, type Response, type NextFunction } from 'express';
import type { RpConfig } from '../config.js';
import { qrDataUrl } from '../issuer/offer.js';
import { log } from '../logger.js';
import { PERSONAS, addDemoCredential, buildVpToken, heldClaims, heldCredential, respondToVerifier } from '../mock/wallet.js';
import { VpError } from '../verifier/service.js';
import { claimsOfType, q, safeReturnTo, type Ctx } from './context.js';

/** The verification flow shared by all four RPs: start → QR/deeplink page → wallet → finish. */
export function rpBase(ctx: Ctx, rp: RpConfig, skin: string): Router {
  const { cfg, svc } = ctx;
  const r = Router();

  r.use((_req: Request, res: Response, next: NextFunction) => {
    res.locals.rp = rp;
    res.locals.skin = skin;
    res.locals.basePath = `/${rp.id}`;
    res.locals.loggedIn = !!claimsOfType(_req.session, rp.id, 'pid');
    next();
  });

  const owns = (req: Request, id: string) => req.session.txIds?.includes(id) === true;

  // Start a presentation request, then show it at a stable, reload-safe URL.
  r.get('/verify', async (req, res) => {
    const key = q(req.query.p) ?? '';
    const tx = await svc.verifier.createTransaction(rp, key, safeReturnTo(rp, req.query.returnTo));
    req.session.txIds = [...(req.session.txIds ?? []).slice(-9), tx.id];
    res.redirect(`/${rp.id}/verify/${tx.id}`);
  });

  r.get('/verify/status/:id', (req, res) => {
    const id = String(req.params.id);
    const tx = owns(req, id) ? svc.verifier.get(id) : undefined;
    if (!tx) return void res.status(404).json({ status: 'unknown' });
    res.set('Cache-Control', 'no-store').json({ status: tx.status, error: tx.errorCode });
  });

  r.get('/verify/finish/:id', (req, res) => {
    const id = String(req.params.id);
    const tx = svc.verifier.get(id);
    if (!tx || tx.rpId !== rp.id) return void res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('verify.err.unknown'), retryHref: `/${rp.id}/` });
    if (!owns(req, id)) return void res.status(403).render('error', { title: res.locals.t('error.title'), message: res.locals.t('verify.err.other_browser'), retryHref: `/${rp.id}/` });
    const code = q(req.query.response_code);
    if (code && code !== tx.responseCode) return void res.status(400).render('error', { title: res.locals.t('error.title'), message: res.locals.t('verify.err.unknown'), retryHref: `/${rp.id}/` });

    if (tx.status === 'pending') return void res.redirect(`/${rp.id}/verify/${id}`);
    if (tx.status === 'failed' || tx.status === 'expired') {
      return void res.status(200).render('verify-failed', {
        title: res.locals.t('verify.failed.title'),
        code: tx.status === 'expired' ? 'expired' : tx.errorCode ?? 'bad_response',
        retryHref: `/${rp.id}/verify?p=${encodeURIComponent(tx.presentationKey)}&returnTo=${encodeURIComponent(tx.returnTo)}`,
      });
    }
    if (!tx.consumed && tx.result) {
      tx.consumed = true;
      req.session.disclosed = {
        ...req.session.disclosed,
        [rp.id]: { ...req.session.disclosed?.[rp.id], [tx.presentationKey]: { presentation: tx.presentationKey, byType: tx.result.byType, issuers: tx.result.issuers, at: new Date().toISOString(), mock: cfg.mockMode } },
      };
      log.info('verification bound to session', { rp: rp.id, presentation: tx.presentationKey });
    }
    res.redirect(tx.returnTo);
  });

  // ---- Simulated wallet (MOCK_MODE only) ----
  if (cfg.mockMode) {
    const walletPage = (req: Request, res: Response) => {
      const id = String(req.params.id);
      const tx = owns(req, id) ? svc.verifier.get(id) : undefined;
      if (!tx || tx.status !== 'pending') return void res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('verify.err.unknown'), retryHref: `/${rp.id}/` });
      const items = tx.reqs.map((rq) => {
        const held = heldCredential(req.session, rq.type);
        const values = held ? heldClaims(held) : {};
        return { type: rq.type, held: !!held, claims: rq.claims.map((c) => ({ name: c, value: values[c] })) };
      });
      res.render('mock-wallet', {
        title: res.locals.t('mockw.title'),
        tx, items, personas: PERSONAS,
        ready: items.every((i) => i.held),
        verifyUrl: `/${rp.id}/verify/${tx.id}`,
      });
    };
    r.get('/verify/wallet/:id', walletPage);

    r.post('/verify/wallet/:id/add', async (req, res) => {
      const id = String(req.params.id);
      const type = q(req.body?.type);
      if (!owns(req, id) || (type !== 'pid' && type !== 'birth_certificate')) return void res.sendStatus(400);
      await addDemoCredential(svc.local, cfg, req.session, type, q(req.body?.persona) ?? 'ie');
      res.redirect(`/${rp.id}/verify/wallet/${id}`);
    });

    const respond = (kind: 'share' | 'decline') => async (req: Request, res: Response) => {
      const id = String(req.params.id);
      const tx = owns(req, id) ? svc.verifier.get(id) : undefined;
      if (!tx || tx.status !== 'pending') return void res.sendStatus(400);
      try {
        await respondToVerifier(svc.verifier, tx, kind === 'share' ? { vp_token: await buildVpToken(req.session, tx, svc.verifier) } : { error: 'access_denied' });
      } catch (e) {
        if (!(e instanceof VpError)) throw e; // rejected by the verifier: tx is marked failed, finish page explains
      }
      res.redirect(`/${rp.id}/verify/finish/${id}?response_code=${tx.responseCode}`);
    };
    r.post('/verify/wallet/:id/share', respond('share'));
    r.post('/verify/wallet/:id/decline', respond('decline'));
  }

  // Stable page showing the QR code / deeplink for an existing transaction.
  r.get('/verify/:id', async (req, res) => {
    const id = String(req.params.id);
    const tx = owns(req, id) ? svc.verifier.get(id) : undefined;
    if (!tx) return void res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('verify.err.unknown'), retryHref: `/${rp.id}/` });
    if (tx.status !== 'pending') return void res.redirect(`/${rp.id}/verify/finish/${id}`);
    const link = svc.verifier.walletLink(tx);
    res.render('verify', {
      title: res.locals.t('verify.title'),
      tx, link, qr: await qrDataUrl(link),
      expiresAt: new Date(tx.expiresAt),
      statusUrl: `/${rp.id}/verify/status/${id}`,
      finishUrl: `/${rp.id}/verify/finish/${id}`,
      walletUrl: cfg.mockMode ? `/${rp.id}/verify/wallet/${id}` : undefined,
    });
  });

  r.post('/signout', (req, res) => {
    if (req.session.disclosed) delete req.session.disclosed[rp.id];
    req.session.flash = 'flash.signed_out';
    res.redirect(`/${rp.id}/`);
  });

  return r;
}

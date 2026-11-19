import { Router } from 'express';
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

  // Technical page: which credential does the wallet actually hold? One probe per credential type.
  const PROBES = [
    { key: 'probe_pid_mdoc', label: 'PID as mdoc – family_name', detail: 'docType eu.europa.ec.eudi.pid.1, element family_name (the SIGMA issuer’s PID)' },
    { key: 'probe_pid_mdoc_given', label: 'PID as mdoc – given_name', detail: 'element given_name' },
    { key: 'probe_pid_mdoc_birth_date', label: 'PID as mdoc – birth_date', detail: 'element birth_date' },
    { key: 'probe_pid_mdoc_birthdate', label: 'PID as mdoc – birthdate (SD-JWT spelling)', detail: 'element birthdate (no underscore), in case the issuer’s records use the SD-JWT name' },
    { key: 'probe_pid_sd_benin', label: 'PID as SD-JWT, Benin rulebook type', detail: 'vct https://credentials.benin.example/pid' },
    { key: 'probe_pid_sd_urn', label: 'PID as SD-JWT, ARF type', detail: 'vct urn:eudi:pid:1' },
    { key: 'probe_pid_sd_eu', label: 'PID as SD-JWT, EUDI reference type', detail: 'vct urn:eu.europa.ec.eudi:pid:1' },
    { key: 'probe_bc_sd', label: 'Birth certificate as SD-JWT', detail: 'vct urn:eudi:birth_certificate:1 (the SIGMA issuer’s birth certificate)' },
  ];
  r.get('/wallet-check', (req, res) => {
    res.render('wallet-check', {
      title: 'Wallet compatibility check',
      probes: PROBES.map((p) => ({ ...p, done: req.session.probes?.[p.key] })),
    });
  });

  r.get('/demo-issuer', async (_req, res) => {
    const s = await svc.remote?.summary();
    // credentials the connected SIGMA issuer offers AND that we know sample identifiers for
    const sigmaItems = s?.reachable
      ? Object.values(cfg.attestations).flatMap((a) => {
          const rc = matchConfig(a, s.configs);
          return rc && a.externalUsers.length ? [{ type: a.key, config: rc.id, users: a.externalUsers }] : [];
        })
      : [];
    res.render('issuer/console', { title: res.locals.t('issuer.console.title'), personas: PERSONAS, types: ['pid', 'birth_certificate'], sigmaItems });
  });

  /** A REAL pre-authorised offer from the SIGMA issuer's offer API for a known sample identifier. */
  r.post('/demo-issuer/sigma-offer', async (req, res) => {
    const s = await svc.remote?.summary();
    const att = cfg.attestations[q(req.body?.type) ?? ''];
    const rc = att && s?.reachable ? matchConfig(att, s.configs) : undefined;
    // a configured sample user, or identifiers typed in by hand (only the issuer knows which records exist)
    const SAFE = /^[A-Za-z0-9._:@-]{1,64}$/;
    const customId = (q(req.body?.customIdentifier) ?? '').trim();
    const customCred = (q(req.body?.customCredentialIdentifier) ?? '').trim();
    const sample = att?.externalUsers.find((u) => u.identifier === q(req.body?.identifier));
    const user: { identifier: string; credentialIdentifier?: string | undefined; walletIdentifier?: string | undefined; configurationId?: string | undefined } | undefined = customId ? (SAFE.test(customId) && (!customCred || SAFE.test(customCred)) ? { identifier: customId, credentialIdentifier: customCred || undefined } : undefined) : sample;
    // a sample may pin another configuration of the same issuer (it must exist in the issuer's catalogue)
    const pinnedOk = !user?.configurationId || !!s?.configs.some((c) => c.id === user.configurationId);
    if (!att || !rc || !user || !pinnedOk || !s?.issuer) return void res.status(400).render('error', { title: res.locals.t('error.title'), message: res.locals.t('error.generic'), retryHref: '/demo-issuer' });
    const external = createIssuerProvider(
      { ...cfg, issuer: { ...cfg.issuer, mode: 'external', fallbackLocal: false, external: { ...cfg.issuer.external, apiBaseUrl: cfg.issuer.external.apiBaseUrl ?? s.issuer } } },
      svc.local, svc.fetchImpl, svc.remote,
    );
    try {
      const offer = await external.createOffer(att.key, {}, { identifier: user.identifier, ...(user.credentialIdentifier ? { credentialIdentifier: user.credentialIdentifier } : {}), ...(user.walletIdentifier ? { walletIdentifier: user.walletIdentifier } : {}), ...(user.configurationId ? { configurationId: user.configurationId } : {}) });
      res.render('offer', { title: res.locals.t(`att.${att.key}.name`), attestationKey: att.key, offer, returnTo: '/demo-issuer', canSimulate: false, rp: undefined });
    } catch {
      res.status(502).render('error', { title: res.locals.t('error.title'), message: res.locals.t('dash.sigma.unreachable'), retryHref: '/demo-issuer' });
    }
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

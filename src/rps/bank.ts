import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { renderOffer } from './offer.js';
import { claimsOfType, demoIban, maskIban, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

const BANK_NAME = 'Demo Bank';
const BIC = 'DEMOBKXX';

export function bankRouter(ctx: Ctx, rp: RpConfig): Router {
  const r = rpBase(ctx, rp, 'bank');
  const router = Router();
  router.use(r);

  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const guard = (req: Request, res: Response, next: NextFunction) => (pid(req) ? next() : res.redirect(`/${rp.id}/login`));

  /** The customer record is derived from the verified PID (stateless demo). */
  const customer = (req: Request) => {
    const c = pid(req)!;
    const given = str(c.given_name), family = str(c.family_name), born = str(c.birthdate);
    return { claims: c, given, family, born, iban: demoIban(given, family, born) };
  };

  router.get('/', (req, res) => res.render('bank/home', { title: BANK_NAME, loggedIn: !!pid(req) }));

  // KYC with the PID: this is how the customer opens the account and signs in.
  router.get('/login', (_req, res) => res.redirect(`/${rp.id}/verify?p=pid&returnTo=${encodeURIComponent(`/${rp.id}/kyc`)}`));

  router.get('/kyc', guard, (req, res) => {
    const c = customer(req);
    const d = req.session.disclosed?.[rp.id]?.pid;
    res.render('bank/kyc', { title: res.locals.t('bank.kyc.title'), c, issuers: d?.issuers ?? [], mockData: d?.mock ?? false });
  });

  router.get('/account', guard, (req, res) => {
    const c = customer(req);
    res.render('bank/account', { title: res.locals.t('bank.account.title'), c, ibanMasked: maskIban(c.iban) });
  });

  router.post('/attestation/:key', guard, async (req, res) => {
    const key = String(req.params.key);
    if (key !== 'account' && key !== 'payment') return void res.sendStatus(404);
    const c = customer(req);
    const today = new Date();
    const plus2y = new Date(today.getFullYear() + 2, today.getMonth(), today.getDate());
    const claims =
      key === 'account'
        ? {
            given_name: c.given, family_name: c.family, birthdate: c.born,
            nationalities: (c.claims.nationalities as string[] | undefined) ?? [],
            account_number: c.iban, account_opened: today.toISOString().slice(0, 10), bank_name: BANK_NAME,
          }
        : { account_holder_name: `${c.given} ${c.family}`, iban: c.iban, bic: BIC, bank_name: BANK_NAME, valid_until: plus2y.toISOString().slice(0, 10) };
    await renderOffer(ctx, req, res, rp, key, claims, `/${rp.id}/account`);
  });

  return router;
}

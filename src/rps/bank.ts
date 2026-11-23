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
  const acct = (req: Request) => claimsOfType(req.session, rp.id, 'account');
  const guard = (req: Request, res: Response, next: NextFunction) => (pid(req) || acct(req) ? next() : res.redirect(`/${rp.id}/login`));

  /**
   * The customer. An existing customer signs in with the bank account attestation: its attributes (name, birth date, account number = IBAN)
   * are the bank's own record. A new customer opens the account with the PID (KYC), the IBAN being derived from it (stateless demo).
   */
  const customer = (req: Request) => {
    const a = acct(req);
    if (a) {
      const given = str(a.given_name), family = str(a.family_name), born = str(a.birth_date);
      return { via: 'account' as const, claims: a, given, family, born, iban: str(a.account_number), nationality: '', opened: str(a.account_opened) };
    }
    const c = pid(req)!;
    const given = str(c.given_name), family = str(c.family_name), born = str(c.birth_date);
    return { via: 'pid' as const, claims: c, given, family, born, iban: demoIban(given, family, born), nationality: str(c.nationality), opened: '' };
  };

  router.get('/', (req, res) => res.render('bank/home', { title: BANK_NAME, loggedIn: !!(pid(req) || acct(req)) }));

  // Two ways in: the bank account attestation (existing customer) or the PID (KYC, new customer).
  router.get('/login', (_req, res) => res.render('bank/login', { title: res.locals.t('bank.login.title') }));
  router.get('/login/pid', (_req, res) => res.redirect(`/${rp.id}/verify?p=pid&returnTo=${encodeURIComponent(`/${rp.id}/kyc`)}`));
  router.get('/login/account', (_req, res) => res.redirect(`/${rp.id}/verify?p=account&returnTo=${encodeURIComponent(`/${rp.id}/account`)}`));

  router.get('/kyc', (req, res, next) => (pid(req) ? next() : res.redirect(`/${rp.id}/${acct(req) ? 'account' : 'login'}`)), (req, res) => {
    const c = { ...customer(req), claims: pid(req)! }; // the KYC page shows the verified PID, whatever else the session holds
    const d = req.session.disclosed?.[rp.id]?.pid;
    res.render('bank/kyc', { title: res.locals.t('bank.kyc.title'), c, issuers: d?.issuers ?? [], mockData: d?.mock ?? false });
  });

  router.get('/account', guard, (req, res) => {
    const c = customer(req);
    res.render('bank/account', { title: res.locals.t('bank.account.title'), c, ibanMasked: maskIban(c.iban), via: c.via, hasPid: !!pid(req) });
  });

  router.post('/attestation/:key', guard, async (req, res) => {
    const key = String(req.params.key);
    if (key !== 'account' && key !== 'payment') return void res.sendStatus(404);
    // The payment attestation is only for customers who signed in with the bank account attestation (not the PID / KYC path).
    if (key === 'payment' && !acct(req)) return void res.sendStatus(403);
    const c = customer(req);
    const today = new Date();
    const plus2y = new Date(today.getFullYear() + 2, today.getMonth(), today.getDate());
    const claims =
      key === 'account'
        ? {
            given_name: c.given, family_name: c.family, birth_date: c.born,
            nationality: c.nationality,
            account_number: c.iban, account_opened: c.opened || today.toISOString().slice(0, 10), bank_name: BANK_NAME,
          }
        : { account_holder_name: `${c.given} ${c.family}`, iban: c.iban, bic: BIC, bank_name: BANK_NAME, valid_until: plus2y.toISOString().slice(0, 10) };
    await renderOffer(ctx, req, res, rp, key, claims, `/${rp.id}/account`);
  });

  return router;
}

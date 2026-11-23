import { randomBytes } from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, maskIban, q, str, type Ctx } from './context.js';
import { rpBase } from './common.js';

/** The fleet (demo prices per day). */
export const CARS = [
  { id: 'city', price: 29 },
  { id: 'family', price: 49 },
  { id: 'suv', price: 79 },
] as const;
const MAX_DAYS = 14;
const MIN_AGE = 21;

const parseDate = (v: string): Date | undefined => (/^\d{4}-\d{2}-\d{2}/.test(v) && !Number.isNaN(Date.parse(v.slice(0, 10))) ? new Date(`${v.slice(0, 10)}T00:00:00Z`) : undefined);
const yearsBetween = (from: Date, to: Date) => {
  let y = to.getUTCFullYear() - from.getUTCFullYear();
  if (to.getUTCMonth() < from.getUTCMonth() || (to.getUTCMonth() === from.getUTCMonth() && to.getUTCDate() < from.getUTCDate())) y--;
  return y;
};

/** What the rental desk checks on a driving licence. `undefined` = the attribute was not shared, so nothing is concluded. */
export function licenceChecks(c: Record<string, unknown>, now = new Date()) {
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const expiry = parseDate(str(c.expiry_date));
  const issued = parseDate(str(c.issue_date));
  const born = parseDate(str(c.birth_date));
  return {
    expiry,
    valid: expiry ? expiry >= today : undefined,
    experienced: issued ? yearsBetween(issued, today) >= 1 : undefined,
    ofAge: born ? yearsBetween(born, today) >= MIN_AGE : undefined,
  };
}

export function rentalRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'rental'));

  const lic = (req: Request) => claimsOfType(req.session, rp.id, 'mdl');
  router.use((req, res, next) => { res.locals.loggedIn = !!lic(req); next(); }); // the header shows "sign in" until a driving licence was presented
  const guard = (req: Request, res: Response, next: NextFunction) => (lic(req) ? next() : res.redirect(`/${rp.id}/login`));

  router.get('/', (_req, res) => res.render('rental/home', { title: 'Demo Drive', cars: CARS }));
  router.get('/login', (_req, res) => res.redirect(`/${rp.id}/verify?p=mdl&returnTo=${encodeURIComponent(`/${rp.id}/booking`)}`));

  const page = (req: Request, res: Response, extra: Record<string, unknown> = {}, status = 200) => {
    const c = lic(req)!;
    const k = licenceChecks(c);
    const eligible = k.valid !== false && k.experienced !== false && k.ofAge !== false;
    res.status(status).render('rental/booking', { title: res.locals.t('rental.book.title'), c, k, eligible, cars: CARS, maxDays: MAX_DAYS, minAge: MIN_AGE, error: undefined, ...extra });
  };
  router.get('/booking', guard, (req, res) => page(req, res));

  router.post('/book', guard, (req, res) => {
    const c = lic(req)!;
    const k = licenceChecks(c);
    const car = CARS.find((x) => x.id === q(req.body?.car));
    const days = Number(q(req.body?.days));
    if (k.valid === false || k.experienced === false || k.ofAge === false) return void page(req, res, { error: 'rental.err.ineligible' }, 403);
    if (!car || !Number.isInteger(days) || days < 1 || days > MAX_DAYS) return void page(req, res, { error: 'rental.err.choice' }, 422);
    const end = new Date(Date.now() + days * 86_400_000);
    if (k.expiry && k.expiry < end) return void page(req, res, { error: 'rental.err.ends_before' }, 422); // the licence must cover the whole rental
    // the booking is paid with the payment attestation: a fresh presentation is needed for every booking
    req.session.rentalBooking = { car: car.id, days, total: car.price * days, at: new Date().toISOString() };
    res.redirect(`/${rp.id}/verify?p=payment&returnTo=${encodeURIComponent(`/${rp.id}/confirmation`)}`);
  });

  router.get('/confirmation', guard, (req, res) => {
    const c = lic(req)!;
    const b = req.session.rentalBooking;
    const paid = req.session.disclosed?.[rp.id]?.payment;
    const pay = claimsOfType(req.session, rp.id, 'payment');
    if (b && (!pay || !paid || paid.at < b.at)) return void res.redirect(`/${rp.id}/booking`); // not paid yet
    if (b && pay) {
      const end = new Date(Date.now() + b.days * 86_400_000);
      req.session.rentalDone = {
        ...b, ref: `DR-${randomBytes(3).toString('hex').toUpperCase()}`, pickup: new Date().toISOString().slice(0, 10), back: end.toISOString().slice(0, 10),
        holder: str(pay.account_holder_name), ibanMasked: maskIban(str(pay.iban)), bank: str(pay.bank_name),
        driver: `${str(c.given_name)} ${str(c.family_name)}`.trim(), licence: str(c.document_number),
      };
      delete req.session.rentalBooking;
    }
    const d = req.session.rentalDone;
    if (!d) return void res.redirect(`/${rp.id}/booking`);
    res.render('rental/confirmation', { title: res.locals.t('rental.confirm.title'), c, d, car: CARS.find((x) => x.id === d.car) ?? CARS[0] });
  });

  return router;
}

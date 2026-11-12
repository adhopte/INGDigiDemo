import { randomInt } from 'node:crypto';
import { Router, type Request } from 'express';
import type { RpConfig } from '../config.js';
import { maskIban, claimsOfType, q, str, type Ctx } from './context.js';
import { rpBase } from './common.js';
import { PRODUCTS, SHIPPING, productById } from './shop-data.js';

export function eshopRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'eshop'));

  const cartLines = (req: Request) =>
    (req.session.cart ?? []).flatMap((i) => {
      const p = productById(i.id);
      return p ? [{ ...p, qty: i.qty, line: Math.round(p.price * i.qty * 100) / 100 }] : [];
    });
  const totals = (req: Request) => {
    const lines = cartLines(req);
    const sub = Math.round(lines.reduce((s, l) => s + l.line, 0) * 100) / 100;
    return { lines, sub, shipping: lines.length ? SHIPPING : 0, total: Math.round((sub + (lines.length ? SHIPPING : 0)) * 100) / 100 };
  };

  router.use((req, res, next) => {
    res.locals.cartCount = (req.session.cart ?? []).reduce((n, i) => n + i.qty, 0);
    next();
  });

  router.get('/', (_req, res) => res.render('eshop/home', { title: 'Demo eShop', products: PRODUCTS }));

  router.post('/cart/add', (req, res) => {
    const id = q(req.body?.id);
    if (!id || !productById(id)) return void res.sendStatus(400);
    const cart = [...(req.session.cart ?? [])];
    const line = cart.find((i) => i.id === id);
    if (line) line.qty = Math.min(line.qty + 1, 9);
    else cart.push({ id, qty: 1 });
    req.session.cart = cart;
    req.session.flash = 'eshop.flash.added';
    res.redirect(q(req.body?.back) === 'cart' ? `/${rp.id}/cart` : `/${rp.id}/#products`);
  });

  router.post('/cart/remove', (req, res) => {
    req.session.cart = (req.session.cart ?? []).filter((i) => i.id !== q(req.body?.id));
    res.redirect(`/${rp.id}/cart`);
  });

  router.get('/cart', (req, res) => res.render('eshop/cart', { title: res.locals.t('eshop.cart.title'), ...totals(req) }));

  // Payment: present the payment attestation issued by the bank, then confirm.
  router.get('/pay', (req, res) => {
    if (!(req.session.cart ?? []).length) return void res.redirect(`/${rp.id}/cart`);
    res.redirect(`/${rp.id}/verify?p=payment&returnTo=${encodeURIComponent(`/${rp.id}/order`)}`);
  });

  router.get('/order', (req, res) => {
    const pay = claimsOfType(req.session, rp.id, 'payment');
    if (!pay) return void res.redirect(`/${rp.id}/cart`);
    const t = totals(req);
    if (t.lines.length) {
      const holder = str(pay.account_holder_name);
      req.session.order = {
        number: `ES-${new Date().getFullYear()}-${randomInt(100000, 999999)}`,
        items: t.lines.map((l) => ({ id: l.id, qty: l.qty, unit: l.price })),
        total: t.total, holder, ibanMasked: maskIban(str(pay.iban)), at: new Date().toISOString(),
      };
      req.session.cart = [];
    }
    if (!req.session.order) return void res.redirect(`/${rp.id}/cart`);
    res.render('eshop/order', { title: res.locals.t('eshop.order.title'), order: req.session.order, products: PRODUCTS, bank: str(pay.bank_name) });
  });

  return router;
}

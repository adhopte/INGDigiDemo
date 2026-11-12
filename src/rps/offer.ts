import type { Request, Response } from 'express';
import type { RpConfig } from '../config.js';
import type { Claims } from '../sdjwt/index.js';
import type { Ctx } from './context.js';

/** Create a credential offer (local or external issuer, per configuration) and render the QR / deeplink page. */
export async function renderOffer(ctx: Ctx, req: Request, res: Response, rp: RpConfig | undefined, attestationKey: string, claims: Claims, returnTo: string) {
  const offer = await ctx.svc.issuer.createOffer(attestationKey, claims);
  if (offer.id) req.session.offerIds = [...(req.session.offerIds ?? []).slice(-19), offer.id];
  res.render('offer', {
    title: res.locals.t(`att.${attestationKey}.name`),
    attestationKey,
    offer,
    returnTo,
    canSimulate: ctx.cfg.mockMode && offer.provider === 'local' && !!offer.id,
    rp,
  });
}

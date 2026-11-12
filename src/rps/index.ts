import type { Router } from 'express';
import type { RpConfig } from '../config.js';
import { bankRouter } from './bank.js';
import type { Ctx } from './context.js';
import { electricityRouter } from './electricity.js';
import { eshopRouter } from './eshop.js';
import { universityRouter } from './university.js';

const factories: Record<string, (ctx: Ctx, rp: RpConfig) => Router> = {
  bank: bankRouter,
  eshop: eshopRouter,
  university: universityRouter,
  electricity: electricityRouter,
};

export function rpRouterFor(ctx: Ctx, rp: RpConfig): Router {
  const f = factories[rp.id];
  if (!f) throw new Error(`No implementation for RP "${rp.id}"`);
  return f(ctx, rp);
}

import type { AppConfig, RpConfig } from '../config.js';
import type { Services } from '../services.js';
import type { Claims } from '../sdjwt/index.js';
import type { SessionData } from 'express-session';

export interface Ctx {
  cfg: AppConfig;
  svc: Services;
}

export type SessionLike = Partial<SessionData>;

export const q = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

/** Only local paths inside the RP's own mount point (prevents open redirects). */
export function safeReturnTo(rp: Pick<RpConfig, 'id'>, value: unknown): string {
  const fallback = `/${rp.id}/`;
  if (typeof value !== 'string' || value.startsWith('//') || value.includes('\\') || /[\r\n]/.test(value)) return fallback;
  return value === `/${rp.id}` || value.startsWith(`/${rp.id}/`) || value.startsWith(`/${rp.id}?`) ? value : fallback;
}

/** Verified claims of a credential type disclosed to this RP in the current session (latest wins). */
export function claimsOfType(session: SessionLike, rpId: string, type: string): Claims | undefined {
  const all = Object.values(session.disclosed?.[rpId] ?? {}).sort((a, b) => a.at.localeCompare(b.at));
  let found: Claims | undefined;
  for (const d of all) if (d.byType[type]) found = d.byType[type];
  return found;
}

export const str = (v: unknown): string => (typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v));

/** Deterministic fake IBAN (not valid, clearly demo) derived from identity attributes. */
export function demoIban(given: string, family: string, birthdate: string): string {
  let h = 0;
  for (const ch of `${given}|${family}|${birthdate}`) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const digits = String(h).padStart(10, '0').slice(-10);
  return `XX00 DEMO ${digits.slice(0, 4)} ${digits.slice(4, 8)} ${digits.slice(8)}`;
}

export const maskIban = (iban: string) => {
  const c = iban.replace(/\s+/g, '');
  return `${c.slice(0, 4)} •••• •••• ${c.slice(-4)}`;
};

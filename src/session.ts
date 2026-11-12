import 'express-session';
import type { JWK } from 'jose';
import type { Claims } from './sdjwt/index.js';

export interface Disclosure {
  presentation: string;
  /** Verified claims per credential type key (e.g. pid, birth_certificate, payment). */
  byType: Record<string, Claims>;
  issuers: string[];
  at: string;
  mock: boolean;
}

/** Credential held by the SIMULATED wallet (mock mode only). */
export interface WalletCredential {
  id: string;
  typeKey: string;
  vct: string;
  credential: string;
  holderPrivateJwk: JWK;
  issuedAt: string;
}

export interface CartItem { id: string; qty: number }
export interface Order { number: string; items: { id: string; qty: number; unit: number }[]; total: number; holder: string; ibanMasked: string; at: string }
export interface Enrolment { studentNumber: string; programme: string; email: string; at: string }

declare module 'express-session' {
  interface SessionData {
    /** Verifier transactions started from this browser session. */
    txIds?: string[];
    /** Verified disclosures per RP id, per presentation key. */
    disclosed?: Record<string, Record<string, Disclosure>>;
    wallet?: WalletCredential[];
    /** Issuer offers created in this session (the simulated wallet may only redeem these). */
    offerIds?: string[];
    cart?: CartItem[];
    order?: Order;
    enrolment?: Enrolment;
    flash?: string;
  }
}

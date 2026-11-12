export type Claims = Record<string, unknown>;

/** State kept in the session between the authorization redirect and the callback. */
export interface PendingAuth {
  rpId: string;
  presentation: string;
  codeVerifier: string;
  nonce: string;
  returnTo: string;
  mock: boolean;
  startedAt: number;
}

export interface Disclosure {
  presentation: string;
  claims: Claims;
  /** Expected claims that the ID token did not contain. */
  missing: string[];
  at: string;
  mock: boolean;
}

declare module 'express-session' {
  interface SessionData {
    /** In-flight authorizations, keyed by OIDC `state`. */
    pending?: Record<string, PendingAuth>;
    /** Disclosed claims per RP id, per presentation key. */
    disclosed?: Record<string, Record<string, Disclosure>>;
  }
}

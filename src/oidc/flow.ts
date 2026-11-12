import type { Session, SessionData } from 'express-session';
import * as oidc from 'openid-client';
import { redirectUriFor, type AppConfig, type PresentationConfig, type RpConfig } from '../config.js';
import { log } from '../logger.js';
import { mockClaimsFor } from '../mock/claims.js';
import { getOidcConfig } from './client.js';
import type { Claims, Disclosure, PendingAuth } from './types.js';

const PENDING_TTL_MS = 10 * 60 * 1000;
const MAX_PENDING = 5;

export class AuthFlowError extends Error {
  constructor(
    message: string,
    public readonly code: 'bad_state' | 'expired' | 'provider_error' | 'validation_failed' | 'bad_request',
  ) {
    super(message);
  }
}

/** Only allow local paths inside the RP's own mount point (prevents open redirects). */
export function safeReturnTo(rp: Pick<RpConfig, 'id'>, value: unknown): string {
  const fallback = `/${rp.id}/`;
  if (typeof value !== 'string') return fallback;
  if (value.startsWith('//') || value.includes('\\') || /[\r\n]/.test(value)) return fallback;
  if (value !== `/${rp.id}` && !value.startsWith(`/${rp.id}/`) && !value.startsWith(`/${rp.id}?`)) return fallback;
  return value;
}

export interface BeginResult {
  redirectTo: string;
  state: string;
}

/** Start an authorization (code + PKCE S256 + state + nonce). Returns where to send the browser. */
export async function beginAuth(
  cfg: AppConfig,
  rp: RpConfig,
  session: Session & Partial<SessionData>,
  opts: { presentation: string; returnTo?: unknown },
): Promise<BeginResult> {
  const presentation = rp.presentations[opts.presentation];
  if (!presentation) throw new AuthFlowError(`Unknown presentation "${opts.presentation}"`, 'bad_request');

  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const codeVerifier = oidc.randomPKCECodeVerifier();

  const pending: PendingAuth = {
    rpId: rp.id,
    presentation: opts.presentation,
    codeVerifier,
    nonce,
    returnTo: safeReturnTo(rp, opts.returnTo),
    mock: cfg.mockMode,
    startedAt: Date.now(),
  };

  let redirectTo: string;
  if (cfg.mockMode) {
    // Same state/nonce/PKCE bookkeeping as live, but the "provider" is the local simulated wallet.
    redirectTo = `/${rp.id}/mock-wallet?state=${encodeURIComponent(state)}`;
  } else {
    const config = await getOidcConfig(cfg, rp);
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUriFor(cfg, rp.id),
      scope: presentation.scope,
      acr_values: presentation.acrValues,
      response_type: 'code',
      state,
      nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
    });
    redirectTo = url.href;
  }

  storePending(session, state, pending);
  log.info('auth started', { rp: rp.id, presentation: opts.presentation, mock: cfg.mockMode });
  return { redirectTo, state };
}

function storePending(session: Session & Partial<SessionData>, state: string, p: PendingAuth) {
  const now = Date.now();
  const all = Object.entries(session.pending ?? {}).filter(([, v]) => now - v.startedAt < PENDING_TTL_MS);
  all.sort((a, b) => a[1].startedAt - b[1].startedAt);
  while (all.length >= MAX_PENDING) all.shift();
  session.pending = Object.fromEntries([...all, [state, p]]);
}

/** Look up (without consuming) an in-flight authorization; used by the mock wallet page. */
export function peekPending(session: Session & Partial<SessionData>, rp: Pick<RpConfig, 'id'>, state: unknown): PendingAuth | undefined {
  if (typeof state !== 'string') return undefined;
  const p = session.pending?.[state];
  if (!p || p.rpId !== rp.id || Date.now() - p.startedAt > PENDING_TTL_MS) return undefined;
  return p;
}

/**
 * Exchange the code and validate the ID token. openid-client verifies the signature (JWKS from discovery),
 * `iss`, `aud`, `exp`, `nonce`, PKCE and `state`. Exported separately so it can be tested with a fake provider.
 */
export async function exchangeAndValidate(
  config: oidc.Configuration,
  currentUrl: URL,
  pending: Pick<PendingAuth, 'codeVerifier' | 'nonce'>,
  state: string,
): Promise<Claims> {
  try {
    const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: pending.codeVerifier,
      expectedNonce: pending.nonce,
      expectedState: state,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error('no ID token claims');
    return claims as unknown as Claims;
  } catch (err) {
    // Message only: never log the token response or any claim values.
    throw new AuthFlowError(`ID token / code validation failed: ${err instanceof Error ? err.message : 'unknown error'}`, 'validation_failed');
  }
}

/** Keep only what the presentation expects (plus `sub`), and report what is missing. */
export function selectClaims(all: Claims, presentation: Pick<PresentationConfig, 'claims'>): { claims: Claims; missing: string[] } {
  const claims: Claims = {};
  if (all.sub !== undefined) claims.sub = all.sub;
  const missing: string[] = [];
  for (const name of presentation.claims) {
    if (all[name] === undefined) missing.push(name);
    else claims[name] = all[name];
  }
  return { claims, missing };
}

/**
 * Handle the redirect back (live Intermediary or the mock wallet). `originalUrl` is the request path + query;
 * the absolute URL is rebuilt from PUBLIC_BASE_URL so it matches the registered redirect_uri behind Render's proxy.
 */
export async function completeAuth(
  cfg: AppConfig,
  rp: RpConfig,
  session: Session & Partial<SessionData>,
  originalUrl: string,
): Promise<{ disclosure: Disclosure; returnTo: string }> {
  const currentUrl = new URL(originalUrl, cfg.publicBaseUrl + '/');
  const redirectUri = new URL(redirectUriFor(cfg, rp.id));
  currentUrl.protocol = redirectUri.protocol;
  currentUrl.host = redirectUri.host;

  const state = currentUrl.searchParams.get('state');
  if (!state) throw new AuthFlowError('Missing state parameter', 'bad_state');
  const pending = session.pending?.[state];
  if (!pending || pending.rpId !== rp.id) throw new AuthFlowError('Unknown or already used state', 'bad_state');
  delete session.pending![state]; // single use, whatever happens next
  if (Date.now() - pending.startedAt > PENDING_TTL_MS) throw new AuthFlowError('Authorization expired, please retry', 'expired');

  const providerError = currentUrl.searchParams.get('error');
  if (providerError) {
    log.warn('auth refused by provider', { rp: rp.id, error: providerError });
    throw new AuthFlowError(
      providerError === 'access_denied' ? 'The wallet presentation was declined.' : `Provider returned an error: ${providerError}`,
      'provider_error',
    );
  }

  const presentation = rp.presentations[pending.presentation];
  if (!presentation) throw new AuthFlowError('Unknown presentation', 'bad_request');

  let raw: Claims;
  if (pending.mock) {
    if (!currentUrl.searchParams.get('code')?.startsWith('mock-')) throw new AuthFlowError('Invalid mock code', 'validation_failed');
    raw = mockClaimsFor(rp, pending.presentation, presentation);
  } else {
    const config = await getOidcConfig(cfg, rp);
    raw = await exchangeAndValidate(config, currentUrl, pending, state);
  }

  const { claims, missing } = selectClaims(raw, presentation);
  const disclosure: Disclosure = { presentation: pending.presentation, claims, missing, at: new Date().toISOString(), mock: pending.mock };
  session.disclosed = { ...session.disclosed, [rp.id]: { ...session.disclosed?.[rp.id], [pending.presentation]: disclosure } };

  // Claim NAMES only; values are personal data and are never logged.
  log.info('auth completed', { rp: rp.id, presentation: pending.presentation, mock: pending.mock, received: Object.keys(claims).length, missing });
  return { disclosure, returnTo: pending.returnTo };
}

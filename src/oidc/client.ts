import * as oidc from 'openid-client';
import type { AppConfig, RpConfig } from '../config.js';

const cache = new Map<string, Promise<oidc.Configuration>>();

/**
 * Per-RP openid-client Configuration (OIDC discovery against the Wallet Intermediary).
 * Cached per RP; a failed discovery is not cached so it can be retried.
 */
export function getOidcConfig(
  cfg: Pick<AppConfig, 'intermediaryIssuerUrl' | 'oidcClientAuth' | 'isProduction'>,
  rp: Pick<RpConfig, 'id' | 'clientId' | 'clientSecretEnv'>,
  env: Record<string, string | undefined> = process.env,
): Promise<oidc.Configuration> {
  const cached = cache.get(rp.id);
  if (cached) return cached;

  if (!cfg.intermediaryIssuerUrl) throw new Error('INTERMEDIARY_ISSUER_URL is not configured');
  const secret = env[rp.clientSecretEnv];
  if (!secret) throw new Error(`Missing client secret: env var ${rp.clientSecretEnv} is not set`);

  const issuer = new URL(cfg.intermediaryIssuerUrl);
  const auth = cfg.oidcClientAuth === 'post' ? oidc.ClientSecretPost(secret) : oidc.ClientSecretBasic(secret);
  // Plain-http issuers are tolerated outside production only (local test OPs).
  const execute = issuer.protocol === 'http:' && !cfg.isProduction ? [oidc.allowInsecureRequests] : undefined;

  const p = oidc.discovery(issuer, rp.clientId, undefined, auth, execute ? { execute } : undefined);
  cache.set(rp.id, p);
  p.catch(() => cache.delete(rp.id));
  return p;
}

export function clearOidcCache(): void {
  cache.clear();
}

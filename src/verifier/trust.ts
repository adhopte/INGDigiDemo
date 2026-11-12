import { X509Certificate } from 'node:crypto';
import { importJWK, type CryptoKey, type JWK } from 'jose';
import type { AppConfig } from '../config.js';
import type { LocalIssuer } from '../issuer/local/service.js';
import { SdJwtError, type IssuerKeyResolver } from '../sdjwt/index.js';

export class TrustError extends SdJwtError {}

/** Validate an x5c chain (leaf first) up to one of the configured trust anchors. No revocation checking. */
export function validateX5cChain(x5c: string[], trustedPem: string[], now = new Date()): X509Certificate {
  if (x5c.length === 0) throw new TrustError('Empty x5c');
  const chain = x5c.map((b64) => new X509Certificate(Buffer.from(b64, 'base64')));
  const roots = trustedPem.map((p) => new X509Certificate(p));
  if (roots.length === 0) throw new TrustError('No trust anchors configured (TRUSTED_CA_PEM)');
  for (const c of chain) if (now < new Date(c.validFrom) || now > new Date(c.validTo)) throw new TrustError('Certificate outside its validity period');
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i]!.checkIssued(chain[i + 1]!) || !chain[i]!.verify(chain[i + 1]!.publicKey)) throw new TrustError('Broken certificate chain');
  }
  const top = chain[chain.length - 1]!;
  const anchored = roots.some((r) => top.fingerprint256 === r.fingerprint256 || (top.checkIssued(r) && top.verify(r.publicKey)));
  if (!anchored) throw new TrustError('Certificate chain does not lead to a trusted root');
  return chain[0]!;
}

const isTrustedIssuer = (iss: string, trusted: string[]) => trusted.includes('*') || trusted.some((t) => iss === t || iss.startsWith(`${t}/`));

/** JWT VC Issuer Metadata URL: well-known segment inserted between host and path (SD-JWT VC spec). */
export function jwtVcIssuerMetadataUrls(iss: string): string[] {
  const u = new URL(iss);
  const path = u.pathname.replace(/\/+$/, '');
  return [`${u.origin}/.well-known/jwt-vc-issuer${path}`, `${iss.replace(/\/+$/, '')}/.well-known/jwt-vc-issuer`];
}

/**
 * Decides which key may verify a credential's issuer signature. Order:
 *  1. our own local issuer (always trusted, no network),
 *  2. x5c chain anchored in TRUSTED_CA_PEM,
 *  3. issuers listed in TRUSTED_ISSUERS, via their jwt-vc-issuer metadata (JWKS).
 */
export function createIssuerKeyResolver(cfg: AppConfig, local: LocalIssuer | undefined, fetchImpl: typeof fetch = fetch): IssuerKeyResolver {
  const cache = new Map<string, { jwks: JWK[]; exp: number }>();

  return async (header, payload) => {
    const iss = typeof payload.iss === 'string' ? payload.iss : '';
    if (!iss) throw new TrustError('Credential has no issuer');

    if (local && iss === local.issuerUrl) return (await importJWK(local.publicJwk, 'ES256')) as CryptoKey;

    if (header.x5c?.length) {
      const leaf = validateX5cChain(header.x5c, cfg.verifier.trustedCaPem);
      return (await importJWK(leaf.publicKey.export({ format: 'jwk' }) as JWK, 'ES256')) as CryptoKey;
    }

    if (!isTrustedIssuer(iss, cfg.verifier.trustedIssuers)) throw new TrustError(`Issuer ${new URL(iss).host} is not trusted`);
    const u = new URL(iss);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && !cfg.isProduction)) throw new TrustError('Issuer URL must be https');

    let entry = cache.get(iss);
    if (!entry || entry.exp < Date.now()) {
      let jwks: JWK[] | undefined;
      for (const url of jwtVcIssuerMetadataUrls(iss)) {
        try {
          const res = await fetchImpl(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
          if (!res.ok) continue;
          const meta = (await res.json()) as { issuer?: string; jwks?: { keys?: JWK[] } };
          if (meta.issuer === iss && meta.jwks?.keys?.length) { jwks = meta.jwks.keys; break; }
        } catch { /* try next */ }
      }
      if (!jwks) throw new TrustError('Could not obtain issuer keys');
      entry = { jwks, exp: Date.now() + 5 * 60_000 };
      cache.set(iss, entry);
    }
    const jwk = header.kid ? entry.jwks.find((k) => k.kid === header.kid) : entry.jwks.length === 1 ? entry.jwks[0] : undefined;
    if (!jwk) throw new TrustError('No matching issuer key');
    return (await importJWK(jwk, 'ES256')) as CryptoKey;
  };
}

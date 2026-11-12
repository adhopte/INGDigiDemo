import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { importJWK, type CryptoKey } from 'jose';
import type { AppConfig } from '../config.js';
import { log } from '../logger.js';

export interface VerifierIdentity {
  privateKey: CryptoKey | Uint8Array;
  /** base64 (not URL-safe) DER certificates, leaf first, as required for the x5c header. */
  x5c: string[];
  /** Full Client Identifier including the scheme prefix. */
  clientId: string;
  hostname: string;
  ephemeral: boolean;
}

const pemToDer = (pem: string): string[] =>
  [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => m[1]!.replace(/\s+/g, ''));

/**
 * Verifier identity used to sign OpenID4VP request objects (client_id scheme x509_san_dns).
 * Production: supply VERIFIER_SIGNING_KEY_JWK + VERIFIER_CERT_CHAIN_PEM (a certificate whose SAN dNSName is this site's host,
 * chained to a root the wallets trust). Otherwise a self-signed demo certificate is generated at startup – fine for
 * wallets/test setups that are configured to trust it, NOT for production wallets.
 */
export async function createVerifierIdentity(cfg: AppConfig): Promise<VerifierIdentity> {
  const hostname = new URL(cfg.publicBaseUrl).hostname;

  if (cfg.verifier.clientIdScheme === 'redirect_uri') {
    return { privateKey: new Uint8Array(), x5c: [], clientId: `redirect_uri:${cfg.publicBaseUrl}/vp/response`, hostname, ephemeral: false };
  }

  if (cfg.verifier.signingKeyJwk && cfg.verifier.certChainPem) {
    const jwk = JSON.parse(cfg.verifier.signingKeyJwk);
    const x5c = pemToDer(cfg.verifier.certChainPem);
    if (x5c.length === 0) throw new Error('VERIFIER_CERT_CHAIN_PEM contains no certificate');
    return { privateKey: await importJWK(jwk, 'ES256'), x5c, clientId: `x509_san_dns:${hostname}`, hostname, ephemeral: false };
  }

  if (cfg.isProduction) log.warn('Using a generated self-signed verifier certificate in production: set VERIFIER_SIGNING_KEY_JWK and VERIFIER_CERT_CHAIN_PEM');
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${hostname}, O=${cfg.brand.name} EU Wallet RP Playground (demo)`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    signingAlgorithm: alg,
    keys,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: hostname }], false)],
  });
  return { privateKey: keys.privateKey as CryptoKey, x5c: [Buffer.from(cert.rawData).toString('base64')], clientId: `x509_san_dns:${hostname}`, hostname, ephemeral: true };
}

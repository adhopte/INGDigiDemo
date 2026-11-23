import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import type { AppConfig } from '../../config.js';
import { log } from '../../logger.js';
import type { KeyMaterial } from './keys.js';

const pemToDer = (pem: string): string[] => [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => m[1]!.replace(/\s+/g, ''));
const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

/**
 * Certificate chain (base64 DER, leaf first) of the issuer's signing key for the `x5c` header of the credentials it issues. HAIP requires
 * it for SD-JWT VC and wallets verify / trust the issuer through it (SIGMA's credentials carry one).
 * ISSUER_CERT_CHAIN_PEM supplies a real chain whose leaf belongs to the signing key (e.g. signed by the SIGMA CA); otherwise a self-signed
 * demo certificate for this issuer's host is generated: it proves nothing to a wallet's trust list but gives the header the shape wallets expect.
 */
export async function createIssuerCertificate(cfg: AppConfig, keys: KeyMaterial): Promise<string[]> {
  if (cfg.issuer.certChainPem) {
    const chain = pemToDer(cfg.issuer.certChainPem);
    if (!chain.length) throw new Error('ISSUER_CERT_CHAIN_PEM contains no certificate');
    const leaf = new x509.X509Certificate(Buffer.from(chain[0]!, 'base64'));
    const jwk = (await crypto.subtle.exportKey('jwk', await leaf.publicKey.export())) as JsonWebKey;
    if (jwk.x !== keys.publicJwk.x || jwk.y !== keys.publicJwk.y) log.warn('ISSUER_CERT_CHAIN_PEM: the leaf certificate does not belong to the issuer signing key (credentials will not verify through x5c)');
    return chain;
  }
  const host = new URL(cfg.issuer.localIssuerUrl).hostname;
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: keys.publicJwk.x!, y: keys.publicJwk.y! }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '01',
    subject: `CN=${host}, O=${cfg.brand.name} ${cfg.brand.product} demo issuer (self-signed)`,
    issuer: `CN=${host}, O=${cfg.brand.name} ${cfg.brand.product} demo issuer (self-signed)`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 2 * 365 * 24 * 3600 * 1000),
    signingAlgorithm: ALG,
    publicKey,
    signingKey: keys.privateKey as CryptoKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(['1.0.18013.5.1.2'], false), // mdoc document signer (ISO 18013-5): readers look for it on the signing certificate
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }], false),
    ],
  });
  return [Buffer.from(cert.rawData).toString('base64')];
}

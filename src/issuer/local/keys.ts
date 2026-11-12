import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from 'jose';
import { createHash } from 'node:crypto';

export interface KeyMaterial {
  privateKey: CryptoKey | Uint8Array;
  publicJwk: JWK;
  kid: string;
}

const thumb = (jwk: JWK) => createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url').slice(0, 16);

/** Load an ES256 key from a private JWK (env secret) or generate an ephemeral one (regenerated on every restart). */
export async function loadOrGenerateKey(privateJwkJson?: string): Promise<KeyMaterial & { ephemeral: boolean }> {
  if (privateJwkJson) {
    const jwk = JSON.parse(privateJwkJson) as JWK;
    if (!jwk.d) throw new Error('Signing key JWK must be a private key (missing "d")');
    const privateKey = await importJWK(jwk, 'ES256');
    const { d: _d, ...pub } = jwk;
    void _d;
    const publicJwk: JWK = { ...pub, alg: 'ES256', use: 'sig' };
    return { privateKey, publicJwk, kid: jwk.kid ?? thumb(publicJwk), ephemeral: false };
  }
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(publicKey);
  const publicJwk: JWK = { ...pub, alg: 'ES256', use: 'sig' };
  return { privateKey, publicJwk, kid: thumb(publicJwk), ephemeral: true };
}

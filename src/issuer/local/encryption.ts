import { CompactEncrypt, importJWK, type JWK } from 'jose';

/** Credential Response encryption (OpenID4VCI 1.0 §8.3.1.2): what the local issuer advertises and supports. */
export const RESPONSE_ENCRYPTION = {
  alg_values_supported: ['ECDH-ES', 'RSA-OAEP-256'],
  enc_values_supported: ['A128GCM', 'A256GCM'],
  encryption_required: false, // optional: the simulated wallet and plain clients keep getting JSON
} as const;

export class EncryptionParamsError extends Error {}

export interface ResponseEncryptionParams { jwk: JWK; alg: string; enc: string; key: Awaited<ReturnType<typeof importJWK>> }

/** Validates the `credential_response_encryption` object of a Credential Request. Returns undefined when the wallet did not ask for encryption. */
export async function readEncryptionParams(raw: unknown): Promise<ResponseEncryptionParams | undefined> {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'object') throw new EncryptionParamsError('credential_response_encryption must be an object');
  const { jwk, alg, enc } = raw as { jwk?: unknown; alg?: unknown; enc?: unknown };
  if (typeof alg !== 'string' || !(RESPONSE_ENCRYPTION.alg_values_supported as readonly string[]).includes(alg)) throw new EncryptionParamsError(`alg must be one of ${RESPONSE_ENCRYPTION.alg_values_supported.join(', ')}`);
  if (typeof enc !== 'string' || !(RESPONSE_ENCRYPTION.enc_values_supported as readonly string[]).includes(enc)) throw new EncryptionParamsError(`enc must be one of ${RESPONSE_ENCRYPTION.enc_values_supported.join(', ')}`);
  if (!jwk || typeof jwk !== 'object' || (jwk as JWK).d !== undefined) throw new EncryptionParamsError('jwk must be a public key');
  let key;
  try {
    key = await importJWK(jwk as JWK, alg); // fails now (before anything is issued) when the key does not suit alg
  } catch {
    throw new EncryptionParamsError('jwk does not match alg');
  }
  return { jwk: jwk as JWK, alg, enc, key };
}

/** The Credential Response as a compact JWE addressed to the wallet's key. */
export async function encryptCredentialResponse(params: ResponseEncryptionParams, payload: unknown): Promise<string> {
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: params.alg, enc: params.enc, ...(params.jwk.kid ? { kid: params.jwk.kid } : {}) })
    .encrypt(params.key);
}

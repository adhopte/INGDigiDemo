import { CompactEncrypt, calculateJwkThumbprint, compactDecrypt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';

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

/** Keys of the issuer for encrypted Credential Requests (OpenID4VCI 1.0 §8.2.2): published in the metadata, private halves stay in memory. */
export const REQUEST_ENCRYPTION_ENC = ['A128GCM', 'A192GCM', 'A256GCM'] as const;

export class RequestEncryption {
  private constructor(private readonly keys: Array<{ jwk: JWK; privateKey: Awaited<ReturnType<typeof importJWK>> }>) {}

  private static cached: Promise<RequestEncryption> | undefined;

  /**
   * The same kinds of key the SIGMA issuer publishes (RSA-OAEP-256 4096-bit, then ECDH-ES P-384), plus ECDH-ES P-256 (the HAIP curve), in that order:
   * a wallet that only handles what SIGMA offers still finds a usable key. Generated once per process (RSA 4096 takes a moment), regenerated at
   * every start (wallets read the metadata per offer).
   */
  static generate(): Promise<RequestEncryption> {
    RequestEncryption.cached ??= (async () => {
      const keys: Array<{ jwk: JWK; privateKey: Awaited<ReturnType<typeof importJWK>> }> = [];
      for (const [alg, opts] of [['RSA-OAEP-256', { modulusLength: 4096 }], ['ECDH-ES', { crv: 'P-384' }], ['ECDH-ES', { crv: 'P-256' }]] as const) {
        const pair = await generateKeyPair(alg, { ...opts, extractable: true });
        const pub = await exportJWK(pair.publicKey);
        keys.push({ jwk: { ...pub, use: 'enc', alg, kid: (await calculateJwkThumbprint(pub)).slice(0, 16) }, privateKey: pair.privateKey });
      }
      return new RequestEncryption(keys);
    })();
    return RequestEncryption.cached;
  }

  /** The `credential_request_encryption` metadata object. */
  metadata() {
    return { jwks: { keys: this.keys.map((k) => k.jwk) }, enc_values_supported: [...REQUEST_ENCRYPTION_ENC], encryption_required: false };
  }

  /** Decrypts a compact JWE Credential Request and returns the JSON it carries. */
  async decrypt(jwe: string): Promise<Record<string, unknown>> {
    let header;
    try {
      header = decodeProtectedHeader(jwe);
    } catch {
      throw new EncryptionParamsError('the body is not a JWE');
    }
    // by kid; without one, by algorithm (and, for ECDH-ES, by the curve of the sender's ephemeral key)
    const epkCrv = (header.epk as { crv?: string } | undefined)?.crv;
    const key = this.keys.find((k) => (header.kid ? k.jwk.kid === header.kid : k.jwk.alg === header.alg && (!epkCrv || !k.jwk.crv || k.jwk.crv === epkCrv)));
    if (!key || key.jwk.alg !== header.alg) throw new EncryptionParamsError('the request is encrypted to a key this issuer does not have');
    if (!(REQUEST_ENCRYPTION_ENC as readonly string[]).includes(String(header.enc))) throw new EncryptionParamsError('unsupported enc');
    try {
      const { plaintext } = await compactDecrypt(jwe, key.privateKey, { keyManagementAlgorithms: [key.jwk.alg!], contentEncryptionAlgorithms: [...REQUEST_ENCRYPTION_ENC] });
      const body = JSON.parse(new TextDecoder().decode(plaintext));
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object');
      return body as Record<string, unknown>;
    } catch {
      throw new EncryptionParamsError('the request could not be decrypted');
    }
  }
}

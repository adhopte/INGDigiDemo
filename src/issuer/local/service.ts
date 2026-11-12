import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import type { AppConfig, AttestationConfig } from '../../config.js';
import { LOCALES, translator } from '../../i18n/index.js';
import { issueSdJwt, SD_JWT_TYP, type Claims } from '../../sdjwt/index.js';
import type { KeyMaterial } from './keys.js';

export const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const OFFER_TTL_MS = 10 * 60 * 1000;
const TOKEN_TTL_S = 300;
const NONCE_TTL_MS = 5 * 60 * 1000;
const MAX_TX_ATTEMPTS = 5;
const MAX_OFFERS = 5000; // in-memory store: bound memory under load

export class IssuerError extends Error {
  constructor(
    public readonly status: number,
    public readonly error: string,
    description: string,
    public readonly extra: Record<string, unknown> = {},
  ) {
    super(description);
  }
}

interface OfferRecord {
  id: string;
  code: string;
  attestation: AttestationConfig;
  claims: Claims;
  txCode: string | undefined;
  expiresAt: number;
  attempts: number;
  redeemed: boolean;
}

interface TokenRecord {
  attestation: AttestationConfig;
  claims: Claims;
  expiresAt: number;
}

export interface CreatedOffer {
  id: string;
  /** URL of the credential offer object (credential_offer_uri). */
  offerUri: string;
  txCode: string | undefined;
  expiresAt: Date;
}

/** In-memory OpenID4VCI issuer (pre-authorised code flow, SD-JWT VC, ES256). */
export class LocalIssuer {
  readonly issuerUrl: string;
  private offers = new Map<string, OfferRecord>();
  private codes = new Map<string, string>();
  private tokens = new Map<string, TokenRecord>();
  private nonces = new Map<string, number>();

  constructor(
    private readonly cfg: AppConfig,
    private readonly keys: KeyMaterial,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.issuerUrl = cfg.issuer.localIssuerUrl;
  }

  get publicJwk(): JWK {
    return { ...this.keys.publicJwk, kid: this.keys.kid };
  }

  private sweep() {
    const t = this.now();
    for (const [id, o] of this.offers) if (o.expiresAt < t) { this.offers.delete(id); this.codes.delete(o.code); }
    for (const [k, v] of this.tokens) if (v.expiresAt < t) this.tokens.delete(k);
    for (const [k, v] of this.nonces) if (v < t) this.nonces.delete(k);
  }

  // ------------------------------------------------------------- offers

  createOffer(attestationKey: string, claims: Claims): CreatedOffer {
    this.sweep();
    if (this.offers.size >= MAX_OFFERS) throw new IssuerError(503, 'temporarily_unavailable', 'Too many open offers');
    const attestation = this.cfg.attestations[attestationKey];
    if (!attestation) throw new Error(`Unknown attestation "${attestationKey}"`);
    const id = randomUUID();
    const code = randomBytes(24).toString('base64url');
    const txCode = this.cfg.issuer.txCode ? String(Math.floor(Math.random() * 10000)).padStart(4, '0') : undefined;
    const expiresAt = this.now() + OFFER_TTL_MS;
    this.offers.set(id, { id, code, attestation, claims, txCode, expiresAt, attempts: 0, redeemed: false });
    this.codes.set(code, id);
    return { id, offerUri: `${this.issuerUrl}/offers/${id}`, txCode, expiresAt: new Date(expiresAt) };
  }

  /** The Credential Offer object served at credential_offer_uri. */
  offerObject(id: string): Record<string, unknown> | undefined {
    this.sweep();
    const o = this.offers.get(id);
    if (!o || o.redeemed) return undefined;
    return {
      credential_issuer: this.issuerUrl,
      credential_configuration_ids: [o.attestation.credentialConfigurationId],
      grants: {
        [PRE_AUTH_GRANT]: {
          'pre-authorized_code': o.code,
          ...(o.txCode ? { tx_code: { input_mode: 'numeric', length: o.txCode.length, description: 'Enter the code shown on the web page' } } : {}),
        },
      },
    };
  }

  // ------------------------------------------------------------- token + nonce

  exchangePreAuthorizedCode(params: { grant_type?: string; 'pre-authorized_code'?: string; tx_code?: string }) {
    this.sweep();
    if (params.grant_type !== PRE_AUTH_GRANT) throw new IssuerError(400, 'unsupported_grant_type', 'Only the pre-authorized_code grant is supported');
    const code = params['pre-authorized_code'];
    const id = code ? this.codes.get(code) : undefined;
    const offer = id ? this.offers.get(id) : undefined;
    if (!offer || offer.redeemed) throw new IssuerError(400, 'invalid_grant', 'Unknown, expired or already used pre-authorized code');
    if (offer.txCode) {
      offer.attempts += 1;
      const given = Buffer.from(params.tx_code ?? '');
      const want = Buffer.from(offer.txCode);
      if (offer.attempts > MAX_TX_ATTEMPTS) {
        offer.redeemed = true;
        throw new IssuerError(400, 'invalid_grant', 'Too many attempts');
      }
      if (given.length !== want.length || !timingSafeEqual(given, want)) throw new IssuerError(400, 'invalid_grant', 'Invalid tx_code');
    }
    offer.redeemed = true; // single use
    const accessToken = randomBytes(32).toString('base64url');
    this.tokens.set(accessToken, { attestation: offer.attestation, claims: offer.claims, expiresAt: this.now() + TOKEN_TTL_S * 1000 });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL_S,
      c_nonce: this.newNonce(),
      c_nonce_expires_in: NONCE_TTL_MS / 1000,
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: offer.attestation.credentialConfigurationId }],
    };
  }

  newNonce(): string {
    const n = randomBytes(18).toString('base64url');
    this.nonces.set(n, this.now() + NONCE_TTL_MS);
    return n;
  }

  // ------------------------------------------------------------- credential

  async issueCredential(
    accessToken: string | undefined,
    body: { proof?: { proof_type?: string; jwt?: string }; proofs?: { jwt?: string[] }; credential_configuration_id?: string; vct?: string },
  ) {
    this.sweep();
    const grant = accessToken ? this.tokens.get(accessToken) : undefined;
    if (!grant) throw new IssuerError(401, 'invalid_token', 'Missing, unknown or expired access token');

    const wanted = body.credential_configuration_id;
    if (wanted && wanted !== grant.attestation.credentialConfigurationId) throw new IssuerError(400, 'unknown_credential_configuration', 'Not authorised for that credential configuration');
    if (!wanted && body.vct && body.vct !== grant.attestation.vct) throw new IssuerError(400, 'unsupported_credential_type', 'vct does not match the offer');

    const proofJwt = body.proofs?.jwt?.[0] ?? (body.proof?.proof_type === 'jwt' ? body.proof.jwt : undefined);
    if (!proofJwt) throw new IssuerError(400, 'invalid_proof', 'A jwt proof of possession is required', { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });

    const holderJwk = await this.verifyProof(proofJwt);
    this.tokens.delete(accessToken!); // one credential per offer

    const credential = await issueSdJwt({
      privateKey: this.keys.privateKey,
      kid: this.keys.kid,
      iss: this.issuerUrl,
      vct: grant.attestation.vct,
      claims: grant.claims,
      holderJwk,
    });
    return { credentials: [{ credential }], credential, c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 };
  }

  private async verifyProof(jwt: string): Promise<JWK> {
    const fail = (d: string) => new IssuerError(400, 'invalid_proof', d, { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });
    let header;
    try {
      header = decodeProtectedHeader(jwt);
    } catch {
      throw fail('Proof is not a JWT');
    }
    if (header.typ !== 'openid4vci-proof+jwt') throw fail('Proof typ must be openid4vci-proof+jwt');
    if (header.alg !== 'ES256') throw fail('Proof alg must be ES256');
    const jwk = header.jwk as JWK | undefined;
    if (!jwk || jwk.d) throw fail('Proof header must carry the public holder key as jwk');
    try {
      const key = await importJWK(jwk, 'ES256');
      const { payload } = await jwtVerify(jwt, key, { algorithms: ['ES256'], audience: this.issuerUrl, currentDate: new Date(this.now()) });
      const nonce = typeof payload.nonce === 'string' ? payload.nonce : '';
      const exp = this.nonces.get(nonce);
      if (!exp || exp < this.now()) throw new Error('unknown or expired nonce');
      this.nonces.delete(nonce);
    } catch (e) {
      throw fail(`Proof validation failed: ${(e as Error).message}`);
    }
    return jwk;
  }

  typeKeyForConfig(configurationId: string): string | undefined {
    return Object.values(this.cfg.attestations).find((a) => a.credentialConfigurationId === configurationId)?.key;
  }

  // ------------------------------------------------------------- metadata

  metadata(): Record<string, unknown> {
    const configs: Record<string, unknown> = {};
    for (const a of Object.values(this.cfg.attestations)) {
      const display = LOCALES.map((l) => ({ name: translator(l.code)(`att.${a.key}.name`), locale: l.code }));
      configs[a.credentialConfigurationId] = {
        format: SD_JWT_TYP,
        vct: a.vct,
        scope: a.credentialConfigurationId,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
        display,
        credential_metadata: {
          display,
          claims: a.claims.map((c) => ({ path: [c], display: LOCALES.map((l) => ({ name: translator(l.code)(`claim.${c}`), locale: l.code })) })),
        },
      };
    }
    return {
      credential_issuer: this.issuerUrl,
      authorization_servers: [this.issuerUrl],
      credential_endpoint: `${this.issuerUrl}/credential`,
      nonce_endpoint: `${this.issuerUrl}/nonce`,
      display: [{ name: `${this.cfg.brand.name} ${this.cfg.brand.product} – demo issuer`, locale: 'en' }],
      credential_configurations_supported: configs,
    };
  }

  authorizationServerMetadata(): Record<string, unknown> {
    return {
      issuer: this.issuerUrl,
      token_endpoint: `${this.issuerUrl}/token`,
      grant_types_supported: [PRE_AUTH_GRANT],
      'pre-authorized_grant_anonymous_access_supported': true,
      response_types_supported: ['token'],
      token_endpoint_auth_methods_supported: ['none'],
    };
  }

  jwtVcIssuerMetadata(): Record<string, unknown> {
    return { issuer: this.issuerUrl, jwks: { keys: [this.publicJwk] } };
  }
}

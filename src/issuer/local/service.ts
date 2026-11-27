import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, importJWK, importX509, jwtVerify, type JWK } from 'jose';
import type { AppConfig, AttestationConfig } from '../../config.js';
import { LOCALES, translator } from '../../i18n/index.js';
import { issueMdoc } from '../../mdoc/issue.js';
import { issueSdJwt, SD_JWT_TYP, type Claims } from '../../sdjwt/index.js';
import { createIssuerCertificate } from './certificate.js';
import { RESPONSE_ENCRYPTION, RequestEncryption } from './encryption.js';
import type { KeyMaterial } from './keys.js';

export const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
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
  /** Claims for the mdoc, when they differ from the SD-JWT ones (the element names of the mdoc namespace). */
  mdocClaims: Claims | undefined;
  format: 'sd-jwt' | 'mdoc' | 'both';
  txCode: string | undefined;
  expiresAt: number;
  attempts: number;
  redeemed: boolean;
}

interface TokenRecord {
  attestation: AttestationConfig;
  claims: Claims;
  mdocClaims: Claims | undefined;
  format: 'sd-jwt' | 'mdoc' | 'both';
  /** Formats of the offer not issued yet: the token is used up when none is left (an offer of both formats takes two requests). */
  remaining: Set<'sd-jwt' | 'mdoc'>;
  expiresAt: number;
  /** JWK thumbprint of the DPoP key the token is bound to (RFC 9449); undefined for a plain Bearer token. */
  jkt?: string | undefined;
}

/** DPoP proof algorithms accepted (and advertised): the same set the SIGMA issuer lists. */
export const DPOP_ALGS = ['ES256', 'RS256', 'RS384', 'RS512'];
/** Credentials per request (batch issuance, OpenID4VCI 1.0 §12.2.2): one per proof / attested key; the SIGMA issuer declares 10 as well. */
export const BATCH_SIZE = 10; // the maximum, and the default of ISSUER_BATCH_SIZE
const DPOP_WINDOW_S = 300;
// key attestation required, with no minimum levels: exactly what the SIGMA birth-certificate configuration (SD-JWT, jwk binding) declares and this wallet accepts
const PROOF_TYPE = { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: {} };

/** Configuration id of an attestation in a format: the SD-JWT one as configured, the mdoc one with a suffix. */
export const configIdOf = (a: AttestationConfig, format: 'sd-jwt' | 'mdoc' | 'both') => (format === 'mdoc' ? `${a.credentialConfigurationId}_mdoc` : a.credentialConfigurationId); // 'both' lists the SD-JWT one first;

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
  private dpopJti = new Map<string, number>(); // replay cache of DPoP proofs
  private nonces = new Map<string, number>();

  constructor(
    private readonly cfg: AppConfig,
    private readonly keys: KeyMaterial,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.issuerUrl = cfg.issuer.localIssuerUrl;
    this.reusePolicy = cfg.issuer.reusePolicy;
    this.batchSize = cfg.issuer.batchSize;
  }

  /** Credentials per request (1-10); starts from ISSUER_BATCH_SIZE, the admin can change it while running. */
  batchSize: number;

  /** Certificate chain of the signing key (base64 DER, leaf first) for the x5c header of issued credentials; set by init(). */
  x5c: string[] | undefined;

  /** Whether the metadata declares the credential reuse policy; starts from ISSUER_CREDENTIAL_REUSE, the admin can flip it while running. */
  reusePolicy: 'sigma' | 'off';

  /** Keys for encrypted Credential Requests; set by init(). Without them neither request nor response encryption is advertised (a HAIP wallet wants both or neither). */
  requestEncryption: RequestEncryption | undefined;

  async init(): Promise<this> {
    this.requestEncryption = await RequestEncryption.generate();
    this.x5c = await createIssuerCertificate(this.cfg, this.keys);
    return this;
  }

  get publicJwk(): JWK {
    return { ...this.keys.publicJwk, kid: this.keys.kid };
  }

  private sweep() {
    const t = this.now();
    for (const [id, o] of this.offers) if (o.expiresAt < t) { this.offers.delete(id); this.codes.delete(o.code); }
    for (const [k, v] of this.tokens) if (v.expiresAt < t) this.tokens.delete(k);
    for (const [k, v] of this.nonces) if (v < t) this.nonces.delete(k);
    for (const [k, v] of this.dpopJti) if (v < t) this.dpopJti.delete(k);
  }

  // ------------------------------------------------------------- offers

  createOffer(attestationKey: string, claims: Claims, format: 'sd-jwt' | 'mdoc' | 'both' = 'sd-jwt', mdocClaims?: Claims): CreatedOffer {
    this.sweep();
    if (this.offers.size >= MAX_OFFERS) throw new IssuerError(503, 'temporarily_unavailable', 'Too many open offers');
    const attestation = this.cfg.attestations[attestationKey];
    if (!attestation) throw new Error(`Unknown attestation "${attestationKey}"`);
    const noMdoc = !(attestation.mdoc && attestation.localMdoc), noSdJwt = !attestation.formats.includes('dc+sd-jwt');
    if (format === 'mdoc' ? noMdoc : format === 'both' ? noMdoc || noSdJwt : noSdJwt) throw new Error(`The local demo issuer does not issue "${attestationKey}" as ${format}`);
    const id = randomUUID();
    const code = randomBytes(24).toString('base64url');
    const txCode = this.cfg.issuer.txCode ? String(Math.floor(Math.random() * 10000)).padStart(4, '0') : undefined;
    const expiresAt = this.now() + this.cfg.issuer.offerTtlMinutes * 60_000;
    this.offers.set(id, { id, code, attestation, claims, mdocClaims, format, txCode, expiresAt, attempts: 0, redeemed: false });
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
      credential_configuration_ids: o.format === 'both' ? [configIdOf(o.attestation, 'sd-jwt'), configIdOf(o.attestation, 'mdoc')] : [configIdOf(o.attestation, o.format)],
      grants: {
        [PRE_AUTH_GRANT]: {
          'pre-authorized_code': o.code,
          ...(o.txCode ? { tx_code: { input_mode: 'numeric', length: o.txCode.length, description: 'Enter the code shown on the web page' } } : {}),
        },
      },
    };
  }

  // ------------------------------------------------------------- token + nonce

  /**
   * DPoP proof (RFC 9449) check. Returns the JWK thumbprint of the proof key. At the token endpoint (no access token) errors are 400, at the
   * credential endpoint (`accessToken` given) 401, as the RFC prescribes.
   */
  private async verifyDpop(proof: string, method: string, path: string, accessToken?: string): Promise<string> {
    const fail = (d: string) => new IssuerError(accessToken ? 401 : 400, 'invalid_dpop_proof', d);
    let header;
    try {
      header = decodeProtectedHeader(proof);
    } catch {
      throw fail('DPoP proof is not a JWT');
    }
    if (header.typ !== 'dpop+jwt') throw fail('DPoP proof typ must be dpop+jwt');
    if (typeof header.alg !== 'string' || !DPOP_ALGS.includes(header.alg)) throw fail(`DPoP proof alg must be one of ${DPOP_ALGS.join(', ')}`);
    const jwk = header.jwk as JWK | undefined;
    if (!jwk || jwk.d || (jwk as Record<string, unknown>).p) throw fail('DPoP proof header must carry the public key as jwk');
    let payload;
    try {
      ({ payload } = await jwtVerify(proof, await importJWK(jwk, header.alg), { algorithms: DPOP_ALGS, currentDate: new Date(this.now()) }));
    } catch (e) {
      throw fail(`DPoP proof validation failed: ${(e as Error).message}`);
    }
    if (payload.htm !== method) throw fail('DPoP htm does not match the request method');
    const htu = typeof payload.htu === 'string' ? payload.htu.split(/[?#]/)[0] : '';
    if (htu !== `${this.issuerUrl}${path}`) throw fail('DPoP htu does not match the request URL');
    if (typeof payload.iat !== 'number' || Math.abs(payload.iat - this.now() / 1000) > DPOP_WINDOW_S) throw fail('DPoP iat is not within the accepted window');
    if (typeof payload.jti !== 'string' || !payload.jti) throw fail('DPoP proof needs a jti');
    if (this.dpopJti.has(payload.jti)) throw fail('DPoP proof was already used');
    this.dpopJti.set(payload.jti, this.now() + 2 * DPOP_WINDOW_S * 1000);
    if (accessToken && payload.ath !== createHash('sha256').update(accessToken).digest('base64url')) throw fail('DPoP ath does not match the access token');
    return calculateJwkThumbprint(jwk);
  }

  /** `dpopProof`: value of the DPoP header. With it the token is sender-constrained (token_type DPoP); without, a plain Bearer token (simulated wallet). */
  async exchangePreAuthorizedCode(params: { grant_type?: string; 'pre-authorized_code'?: string; tx_code?: string }, dpopProof?: string) {
    this.sweep();
    if (params.grant_type !== PRE_AUTH_GRANT) throw new IssuerError(400, 'unsupported_grant_type', 'Only the pre-authorized_code grant is supported');
    const jkt = dpopProof ? await this.verifyDpop(dpopProof, 'POST', '/token') : undefined; // before the code is touched: a bad proof must not burn the offer
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
    this.tokens.set(accessToken, { attestation: offer.attestation, claims: offer.claims, mdocClaims: offer.mdocClaims, format: offer.format, remaining: new Set(offer.format === 'both' ? ['sd-jwt', 'mdoc'] : [offer.format]), expiresAt: this.now() + TOKEN_TTL_S * 1000, jkt });
    return {
      access_token: accessToken,
      token_type: jkt ? 'DPoP' : 'Bearer',
      expires_in: TOKEN_TTL_S,
      c_nonce: this.newNonce(),
      c_nonce_expires_in: NONCE_TTL_MS / 1000,
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
    body: { proof?: { proof_type?: string; jwt?: string; attestation?: string }; proofs?: { jwt?: string[]; attestation?: string[] }; credential_configuration_id?: string; vct?: string },
    auth: { scheme?: string; dpop?: string } = {},
  ) {
    this.sweep();
    const grant = accessToken ? this.tokens.get(accessToken) : undefined;
    if (!grant) throw new IssuerError(401, 'invalid_token', 'Missing, unknown or expired access token');
    if (grant.jkt) {
      // a sender-constrained token: DPoP scheme and a proof made with the same key, bound to this token (ath)
      if (auth.scheme?.toLowerCase() !== 'dpop' || !auth.dpop) throw new IssuerError(401, 'invalid_dpop_proof', 'This access token is DPoP-bound: use the DPoP scheme with a DPoP proof');
      if ((await this.verifyDpop(auth.dpop, 'POST', '/credential', accessToken)) !== grant.jkt) throw new IssuerError(401, 'invalid_dpop_proof', 'DPoP proof key differs from the key the token is bound to');
    }

    const wanted = body.credential_configuration_id;
    // which format is asked for: the mdoc configuration id, else the SD-JWT one (an offer of both formats is redeemed in two requests)
    const asked: 'sd-jwt' | 'mdoc' = wanted === configIdOf(grant.attestation, 'mdoc') ? 'mdoc' : 'sd-jwt';
    const allowed = grant.format === 'both' ? wanted === configIdOf(grant.attestation, 'sd-jwt') || asked === 'mdoc' : wanted === configIdOf(grant.attestation, grant.format);
    if (wanted && (!allowed || !grant.remaining.has(asked))) throw new IssuerError(400, 'unknown_credential_configuration', 'Not authorised for that credential configuration');
    const fmt: 'sd-jwt' | 'mdoc' = wanted ? asked : grant.format === 'mdoc' ? 'mdoc' : 'sd-jwt';
    if (!wanted && body.vct && body.vct !== grant.attestation.vct) throw new IssuerError(400, 'unsupported_credential_type', 'vct does not match the offer');

    const jwtProofs = body.proofs?.jwt ?? (body.proof?.proof_type === 'jwt' && body.proof.jwt ? [body.proof.jwt] : []);
    const attestationProofs = body.proofs?.attestation ?? (body.proof?.proof_type === 'attestation' && body.proof.attestation ? [body.proof.attestation] : []);
    if (!jwtProofs.length && !attestationProofs.length) throw new IssuerError(400, 'invalid_proof', 'A jwt or attestation proof is required', { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });

    // Verify EVERYTHING first (a batch shares one c_nonce, so nonces are consumed only once all proofs passed); nothing is issued or used up on failure.
    const holderJwks: JWK[] = [];
    const usedNonces = new Set<string>();
    const tooMany = () => new IssuerError(400, 'invalid_proof', `At most ${this.batchSize} credential${this.batchSize === 1 ? '' : 's'} per request`, { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });
    if (jwtProofs.length) {
      if (jwtProofs.length > this.batchSize) throw tooMany();
      for (const proof of jwtProofs) {
        const v = await this.verifyProof(proof);
        holderJwks.push(v.jwk);
        usedNonces.add(v.nonce);
      }
    } else {
      // an attestation proof stands for all the keys it attests: one credential per key
      const v = await this.verifyAttestationProof(attestationProofs[0]!);
      if (v.jwks.length > this.batchSize) throw tooMany();
      holderJwks.push(...v.jwks);
      usedNonces.add(v.nonce);
    }
    for (const n of usedNonces) this.nonces.delete(n);
    grant.remaining.delete(fmt);
    if (!grant.remaining.size) this.tokens.delete(accessToken!); // used up once everything offered was issued

    const m = grant.attestation.mdoc;
    const credentials = await Promise.all(holderJwks.map(async (holderJwk) => ({
      credential: fmt === 'mdoc' && m
        ? await issueMdoc({ privateKey: this.keys.privateKey as CryptoKey, x5c: this.x5c ?? [], docType: m.docType, namespace: m.namespace, elements: grant.mdocClaims ?? grant.claims, deviceJwk: holderJwk })
        : await issueSdJwt({ privateKey: this.keys.privateKey, kid: this.keys.kid, ...(this.x5c ? { x5c: this.x5c } : {}), iss: this.issuerUrl, vct: grant.attestation.vct, claims: grant.claims, holderJwk }),
    })));
    return { credentials, credential: credentials[0]!.credential, c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 };
  }

  private async verifyProof(jwt: string): Promise<{ jwk: JWK; nonce: string }> {
    const fail = (d: string) => new IssuerError(400, 'invalid_proof', d, { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });
    let header;
    try {
      header = decodeProtectedHeader(jwt);
    } catch {
      throw fail('Proof is not a JWT');
    }
    if (header.typ !== 'openid4vci-proof+jwt') throw fail('Proof typ must be openid4vci-proof+jwt');
    if (header.alg !== 'ES256') throw fail('Proof alg must be ES256');

    // Key attestation (OpenID4VCI 1.0, HAIP): a JWT of the wallet provider listing the attested keys. The proof is signed with one of them.
    // The wallet provider's trust chain is NOT evaluated (demo issuer); the attestation must be well-formed, unexpired, self-consistent and cover the proof key.
    let attested: JWK[] | undefined;
    if (header.key_attestation !== undefined) {
      if (typeof header.key_attestation !== 'string') throw fail('key_attestation must be a JWT string');
      attested = (await this.readKeyAttestation(header.key_attestation, fail)).keys;
    }

    // Which key signed the proof? The `jwk` header if present; otherwise (batch: several attested keys, header names none) the attested key whose
    // signature verifies.
    const explicit = header.jwk as JWK | undefined;
    const candidates: JWK[] = explicit ? [explicit] : attested ?? [];
    if (!candidates.length || candidates.some((c) => !c || c.d)) throw fail('Proof header must carry the public holder key as jwk (or a key_attestation listing it)');
    if (explicit && attested && !attested.some((k) => k.kty === explicit.kty && k.crv === explicit.crv && k.x === explicit.x && k.y === explicit.y)) throw fail('The proof key is not among the keys of the key attestation');
    let jwk: JWK | undefined;
    let nonce = '';
    let lastError: Error | undefined;
    for (const candidate of candidates) {
      try {
        const { payload } = await jwtVerify(jwt, await importJWK(candidate, 'ES256'), { algorithms: ['ES256'], audience: this.issuerUrl, currentDate: new Date(this.now()) });
        nonce = typeof payload.nonce === 'string' ? payload.nonce : '';
        const exp = this.nonces.get(nonce);
        if (!exp || exp < this.now()) throw new Error('unknown or expired nonce'); // consumed by the caller once every proof of the request passed
        jwk = candidate;
        break;
      } catch (e) {
        lastError = e as Error;
        if ((e as { code?: string }).code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') break; // a wrong key is worth another try, anything else is final
      }
    }
    if (!jwk) throw fail(`Proof validation failed: ${lastError?.message ?? 'no matching key'}`);
    return { jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JWK, nonce };
  }

  /**
   * Proof type `attestation` (OpenID4VCI 1.0 §8.2.1.3): the proof IS a key attestation JWT whose `nonce` is a c_nonce of this issuer.
   * One credential is issued per attested key. Same trust note as above: the wallet provider's chain is not evaluated.
   */
  private async verifyAttestationProof(att: string): Promise<{ jwks: JWK[]; nonce: string }> {
    const fail = (d: string) => new IssuerError(400, 'invalid_proof', d, { c_nonce: this.newNonce(), c_nonce_expires_in: NONCE_TTL_MS / 1000 });
    const { keys, nonce } = await this.readKeyAttestation(att, fail);
    const exp = nonce ? this.nonces.get(nonce) : undefined;
    if (!nonce || !exp || exp < this.now()) throw fail('The attestation proof needs a nonce claim holding a current c_nonce of this issuer');
    return { jwks: keys.map((k) => ({ kty: k.kty, crv: k.crv, x: k.x, y: k.y }) as JWK), nonce };
  }

  /** The attested public keys of a key attestation JWT; throws invalid_proof when it is malformed, expired or its signature does not verify. */
  private async readKeyAttestation(att: string, fail: (d: string) => IssuerError): Promise<{ keys: JWK[]; nonce: string | undefined }> {
    let h;
    let p;
    try {
      h = decodeProtectedHeader(att);
      p = decodeJwt(att);
    } catch {
      throw fail('key_attestation is not a JWT');
    }
    if (h.typ !== 'keyattestation+jwt' && h.typ !== 'key-attestation+jwt') throw fail('key_attestation typ must be keyattestation+jwt');
    const keys = (p as { attested_keys?: unknown }).attested_keys;
    if (!Array.isArray(keys) || !keys.length || keys.some((k) => !k || typeof k !== 'object' || (k as JWK).d)) throw fail('key_attestation has no usable attested_keys');
    if (typeof p.exp === 'number' && p.exp * 1000 < this.now()) throw fail('key_attestation has expired');
    if (Array.isArray(h.x5c) && typeof h.x5c[0] === 'string' && typeof h.alg === 'string') {
      try {
        const pem = `-----BEGIN CERTIFICATE-----\n${h.x5c[0].match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----`;
        await jwtVerify(att, await importX509(pem, h.alg), { algorithms: [h.alg], currentDate: new Date(this.now()) });
      } catch {
        throw fail('key_attestation signature does not verify against its own certificate');
      }
    }
    return { keys: keys as JWK[], nonce: typeof p.nonce === 'string' ? p.nonce : undefined };
  }

  typeKeyForConfig(configurationId: string): string | undefined {
    return Object.values(this.cfg.attestations).find((a) => a.credentialConfigurationId === configurationId || configIdOf(a, 'mdoc') === configurationId)?.key;
  }

  // ------------------------------------------------------------- metadata

  metadata(): Record<string, unknown> {
    const configs: Record<string, unknown> = {};
    for (const a of Object.values(this.cfg.attestations).filter((x) => x.formats.includes('dc+sd-jwt'))) {
      // an attestation that exists in two formats shows the format in its name, so the wallet's list tells the two apart
      const display = LOCALES.map((l) => ({ name: `${translator(l.code)(`att.${a.key}.name`)}${a.localMdoc ? ' (SD-JWT VC)' : ''}`, locale: l.code }));
      configs[a.credentialConfigurationId] = {
        format: SD_JWT_TYP,
        vct: a.vct,
        scope: a.credentialConfigurationId,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        // HAIP wallets refuse a jwt proof type without key_attestations_required (same levels as the SIGMA issuer: basic key storage / user authentication)
        // both proof types, like the SIGMA issuer: a jwt proof carrying a key attestation, or the attestation itself
        claims: a.claims.map((c) => ({ path: [c], display: LOCALES.map((l) => ({ name: translator(l.code)(`claim.${c}`), locale: l.code })) })), // older wallet versions read the claims here, newer ones from credential_metadata
        proof_types_supported: { attestation: PROOF_TYPE, jwt: PROOF_TYPE },
        display,
        credential_metadata: {
          display,
          claims: a.claims.map((c) => ({ path: [c], display: LOCALES.map((l) => ({ name: translator(l.code)(`claim.${c}`), locale: l.code })) })),
        },
      };
    }
    // the same attestations as ISO 18013-5 mdoc (the only format that can also be shared in proximity, wallet to reader)
    for (const a of Object.values(this.cfg.attestations).filter((x) => x.localMdoc && x.mdoc)) {
      const m = a.mdoc!;
      const display = LOCALES.map((l) => ({ name: `${translator(l.code)(`att.${a.key}.name`)} (mdoc)`, locale: l.code }));
      const claims = Object.values(m.elements).map((e) => ({ path: [m.namespace, e], display: LOCALES.map((l) => ({ name: translator(l.code)(`claim.${e}`), locale: l.code })) }));
      configs[configIdOf(a, 'mdoc')] = {
        format: 'mso_mdoc', doctype: m.docType, scope: configIdOf(a, 'mdoc'),
        cryptographic_binding_methods_supported: ['cose_key'], credential_signing_alg_values_supported: [-7],
        claims, proof_types_supported: { attestation: PROOF_TYPE, jwt: PROOF_TYPE }, display,
        credential_metadata: { display, claims },
      };
    }
    return {
      credential_issuer: this.issuerUrl,
      authorization_servers: [this.issuerUrl],
      credential_endpoint: `${this.issuerUrl}/credential`,
      nonce_endpoint: `${this.issuerUrl}/nonce`,
      // a HAIP wallet asks for several credentials per request (one per key, for unlinkable presentations) and refuses an issuer without this (IssuerDoesNotSupportBatchIssuance)
      // the spec only allows a batch size of 2 or more: with a limit of 1 batch issuance is simply not declared
      ...(this.batchSize >= 2 ? { batch_credential_issuance: { batch_size: this.batchSize } } : {}),
      // How the wallet may reuse the copies of a credential (ARF Annex II), same as the SIGMA issuer: without it a wallet treats every copy as
      // single-use, so the second presentation of the same attestation fails with NoMatchingDocuments
      ...(this.reusePolicy === 'sigma' ? { credential_reuse_policy: { id: 'arf_annex_ii', options: [{ details: ['per-relying-party', 'rotating-batch'], batch_size: 5, reissue_trigger_unused: 2, reissue_trigger_lifetime_left: 86400 }] } } : {}),
      // HAIP wallets require encrypted credential responses (else ResponseEncryptionRequiredByWalletButNotSupportedByIssuer) and, if responses
      // can be encrypted, also declared request encryption (else CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists)
      ...(this.requestEncryption ? { credential_request_encryption: this.requestEncryption.metadata(), credential_response_encryption: RESPONSE_ENCRYPTION } : {}),
      display: [{ name: `${[this.cfg.brand.name, this.cfg.brand.product].filter(Boolean).join(' ')} – demo issuer`, locale: 'en' }],
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
      token_endpoint_auth_methods_supported: ['none', 'attest_jwt_client_auth'], // wallet attestation headers (the SIGMA wallet sends them) are accepted and not enforced
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      // HAIP wallets require sender-constrained tokens: DPoP (RFC 9449) is supported on the token and credential endpoints, like the SIGMA issuer
      dpop_signing_alg_values_supported: DPOP_ALGS,
      client_attestation_signing_alg_values_supported: DPOP_ALGS,
      client_attestation_pop_signing_alg_values_supported: DPOP_ALGS,
    };
  }

  jwtVcIssuerMetadata(): Record<string, unknown> {
    return { issuer: this.issuerUrl, jwks: { keys: [this.publicJwk] } };
  }
}

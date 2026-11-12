import { randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, compactDecrypt, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import type { AppConfig, RpConfig } from '../config.js';
import { log } from '../logger.js';
import { SdJwtError, verifySdJwtPresentation, type Claims, type IssuerKeyResolver } from '../sdjwt/index.js';
import type { VerifierIdentity } from './identity.js';
import { buildDcql, buildPresentationDefinition, requestedCredentials, type RequestedCredential } from './query.js';
import { TrustError } from './trust.js';

const TX_TTL_MS = 10 * 60 * 1000;
const MAX_TRANSACTIONS = 5000; // in-memory store: bound memory under load
const SD_JWT_ALGS = { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] };

export type TxStatus = 'pending' | 'complete' | 'failed' | 'expired';
export type VerifyErrorCode = 'wallet_declined' | 'untrusted_issuer' | 'invalid_presentation' | 'missing_credential' | 'bad_response';

export interface TxResult {
  byType: Record<string, Claims>;
  issuers: string[];
}

export interface Transaction {
  id: string;
  rpId: string;
  rpName: string;
  presentationKey: string;
  reqs: RequestedCredential[];
  nonce: string;
  state: string;
  responseCode: string;
  returnTo: string;
  expiresAt: number;
  status: TxStatus;
  errorCode?: VerifyErrorCode;
  result?: TxResult;
  consumed: boolean;
  enc?: { privateKey: CryptoKey; publicJwk: JWK };
}

export class VpError extends Error {
  constructor(public readonly status: number, public readonly error: string, description: string) {
    super(description);
  }
}

export class Verifier {
  private txs = new Map<string, Transaction>();

  constructor(
    private readonly cfg: AppConfig,
    readonly identity: VerifierIdentity,
    private readonly resolveIssuerKey: IssuerKeyResolver,
    private readonly now: () => number = () => Date.now(),
  ) {}

  private sweep() {
    const t = this.now();
    for (const [id, tx] of this.txs) {
      if (tx.expiresAt < t - TX_TTL_MS) this.txs.delete(id);
      else if (tx.expiresAt < t && tx.status === 'pending') tx.status = 'expired';
    }
  }

  get(id: string): Transaction | undefined {
    this.sweep();
    return this.txs.get(id);
  }

  async createTransaction(rp: RpConfig, presentationKey: string, returnTo: string): Promise<Transaction> {
    const presentation = rp.presentations[presentationKey];
    if (!presentation) throw new VpError(400, 'invalid_request', `Unknown presentation "${presentationKey}"`);
    this.sweep();
    if (this.txs.size >= MAX_TRANSACTIONS) throw new VpError(503, 'temporarily_unavailable', 'Too many open requests, please retry shortly');
    const tx: Transaction = {
      id: randomUUID(),
      rpId: rp.id,
      rpName: rp.displayName,
      presentationKey,
      reqs: requestedCredentials(presentation, this.cfg.attestations),
      nonce: randomBytes(24).toString('base64url'),
      state: randomBytes(16).toString('base64url'),
      responseCode: randomBytes(16).toString('base64url'),
      returnTo,
      expiresAt: this.now() + TX_TTL_MS,
      status: 'pending',
      consumed: false,
    };
    if (this.cfg.verifier.responseMode === 'direct_post.jwt') {
      const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
      const pub = await exportJWK(publicKey);
      tx.enc = { privateKey, publicJwk: { ...pub, use: 'enc', alg: 'ECDH-ES', kid: tx.id } };
    }
    this.txs.set(tx.id, tx);
    log.info('vp transaction started', { rp: rp.id, presentation: presentationKey, types: tx.reqs.map((r) => r.type), scheme: this.cfg.verifier.clientIdScheme, mode: this.cfg.verifier.responseMode });
    return tx;
  }

  responseUri(tx: Transaction): string {
    return `${this.cfg.publicBaseUrl}/vp/response/${tx.id}`;
  }

  requestUri(tx: Transaction): string {
    return `${this.cfg.publicBaseUrl}/vp/request/${tx.id}`;
  }

  /** Authorization Request parameters (the content of the request object). */
  requestParams(tx: Transaction, walletNonce?: string): Record<string, unknown> {
    const v = this.cfg.verifier;
    const clientMetadata: Record<string, unknown> = {
      client_name: tx.rpName,
      vp_formats: { 'dc+sd-jwt': SD_JWT_ALGS, 'vc+sd-jwt': SD_JWT_ALGS },
      vp_formats_supported: { 'dc+sd-jwt': SD_JWT_ALGS, 'vc+sd-jwt': SD_JWT_ALGS },
    };
    if (tx.enc) {
      Object.assign(clientMetadata, {
        jwks: { keys: [tx.enc.publicJwk] },
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A128GCM',
      });
    }
    const params: Record<string, unknown> = {
      client_id: this.identity.clientId,
      response_type: 'vp_token',
      response_mode: v.responseMode,
      response_uri: this.responseUri(tx),
      nonce: tx.nonce,
      state: tx.state,
      client_metadata: clientMetadata,
    };
    if (v.queryLanguage === 'pex') params.presentation_definition = buildPresentationDefinition(tx.reqs, tx.id);
    else params.dcql_query = buildDcql(tx.reqs);
    if (walletNonce) params.wallet_nonce = walletNonce;
    return params;
  }

  /** Signed request object (x509_san_dns) – served at request_uri. */
  async signedRequestObject(tx: Transaction, walletNonce?: string): Promise<string> {
    const now = Math.floor(this.now() / 1000);
    return new SignJWT({ ...this.requestParams(tx, walletNonce), iss: this.identity.clientId, aud: 'https://self-issued.me/v2', iat: now, exp: now + 600 })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: this.identity.x5c })
      .sign(this.identity.privateKey);
  }

  /** The link/QR content that invokes the wallet. */
  walletLink(tx: Transaction): string {
    const base = this.cfg.verifier.deeplinkBase;
    const q = new URLSearchParams({ client_id: this.identity.clientId });
    if (this.cfg.verifier.clientIdScheme !== 'redirect_uri') {
      q.set('request_uri', this.requestUri(tx));
      q.set('request_uri_method', 'post');
    } else {
      // unsigned, by value (redirect_uri scheme)
      for (const [k, val] of Object.entries(this.requestParams(tx))) if (k !== 'client_id') q.set(k, typeof val === 'string' ? val : JSON.stringify(val));
    }
    return `${base}?${q.toString()}`;
  }

  private audiences(): string[] {
    const id = this.identity.clientId;
    return [id, id.slice(id.indexOf(':') + 1)];
  }

  private fail(tx: Transaction, code: VerifyErrorCode, detail: string): never {
    tx.status = 'failed';
    tx.errorCode = code;
    log.warn('vp response rejected', { rp: tx.rpId, code, detail });
    throw new VpError(400, code === 'wallet_declined' ? 'access_denied' : 'invalid_request', detail);
  }

  /** response_uri handler: validates what the wallet posted (direct_post or direct_post.jwt). */
  async handleResponse(id: string, body: Record<string, unknown>): Promise<{ redirect_uri: string }> {
    const tx = this.get(id);
    if (!tx || tx.status !== 'pending') throw new VpError(400, 'invalid_request', 'Unknown, expired or already completed request');

    let params = body;
    if (typeof body.response === 'string') {
      if (!tx.enc) this.fail(tx, 'bad_response', 'Encrypted response not expected');
      try {
        const { plaintext } = await compactDecrypt(body.response, tx.enc.privateKey);
        params = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
      } catch {
        this.fail(tx, 'bad_response', 'Could not decrypt response');
      }
    } else if (tx.enc) {
      this.fail(tx, 'bad_response', 'Response must be encrypted (direct_post.jwt)');
    }

    if (params.state !== tx.state) this.fail(tx, 'bad_response', 'state mismatch');
    if (typeof params.error === 'string') this.fail(tx, params.error === 'access_denied' ? 'wallet_declined' : 'bad_response', `Wallet error: ${params.error}`);

    let presented: string[];
    try {
      presented = extractPresentations(params.vp_token);
    } catch (e) {
      this.fail(tx, 'bad_response', (e as Error).message);
    }

    const verified: { iss: string; vct: string; claims: Claims }[] = [];
    const acceptedVcts = [...new Set(tx.reqs.flatMap((r) => r.attestation.acceptedVct))];
    for (const p of presented) {
      try {
        verified.push(await verifySdJwtPresentation(p, { resolveIssuerKey: this.resolveIssuerKey, acceptedVcts, aud: this.audiences(), nonce: tx.nonce, now: Math.floor(this.now() / 1000) }));
      } catch (e) {
        this.fail(tx, e instanceof TrustError ? 'untrusted_issuer' : e instanceof SdJwtError ? 'invalid_presentation' : 'bad_response', (e as Error).message);
      }
    }

    const byType: Record<string, Claims> = {};
    const issuers = new Set<string>();
    for (const req of tx.reqs) {
      const match = verified.find((v) => req.attestation.acceptedVct.includes(v.vct));
      if (!match) this.fail(tx, 'missing_credential', `No credential for type ${req.type}`);
      // Data minimisation: keep only what was asked for, even if the wallet disclosed more.
      byType[req.type] = Object.fromEntries(Object.entries(match.claims).filter(([k]) => req.claims.includes(k)));
      issuers.add(match.iss);
    }
    tx.result = { byType, issuers: [...issuers] };
    tx.status = 'complete';
    log.info('vp response accepted', { rp: tx.rpId, presentation: tx.presentationKey, types: Object.keys(byType), issuers: tx.result.issuers });
    return { redirect_uri: `${this.cfg.publicBaseUrl}/${tx.rpId}/verify/finish/${tx.id}?response_code=${tx.responseCode}` };
  }
}

/** vp_token may be a string, an array, or a DCQL object { id: [presentation, …] } – possibly JSON-encoded in a form field. */
export function extractPresentations(vpToken: unknown): string[] {
  let v = vpToken;
  if (typeof v === 'string' && /^\s*[[{]/.test(v)) {
    try {
      v = JSON.parse(v);
    } catch {
      throw new Error('vp_token is not valid JSON');
    }
  }
  const out: string[] = [];
  const walk = (x: unknown) => {
    if (typeof x === 'string') out.push(x);
    else if (Array.isArray(x)) x.forEach(walk);
    else if (x && typeof x === 'object') Object.values(x).forEach(walk);
  };
  walk(v);
  if (out.length === 0 || out.some((s) => !s.includes('~'))) throw new Error('vp_token carries no SD-JWT presentation');
  return out;
}

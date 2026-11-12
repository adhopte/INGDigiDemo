import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, decodeProtectedHeader, importJWK, jwtVerify, type CryptoKey, type JWK, type JWTHeaderParameters, type JWTPayload } from 'jose';

export type Claims = Record<string, unknown>;
type Key = CryptoKey | Uint8Array;

export const sha256b64u = (s: string): string => createHash('sha256').update(s, 'ascii').digest('base64url');
export const SD_JWT_TYP = 'dc+sd-jwt';
const ACCEPTED_TYP = new Set(['dc+sd-jwt', 'vc+sd-jwt']);

export class SdJwtError extends Error {}

// ---------------------------------------------------------------- issuance

export interface IssueOptions {
  privateKey: Key;
  kid?: string;
  x5c?: string[];
  iss: string;
  vct: string;
  claims: Claims;
  holderJwk?: JWK;
  ttlSec?: number;
  now?: number;
}

/** Issue an SD-JWT VC where every top-level claim is selectively disclosable. */
export async function issueSdJwt(o: IssueOptions): Promise<string> {
  const now = o.now ?? Math.floor(Date.now() / 1000);
  const disclosures: string[] = [];
  const digests: string[] = [];
  for (const [name, value] of Object.entries(o.claims)) {
    const d = Buffer.from(JSON.stringify([randomBytes(16).toString('base64url'), name, value])).toString('base64url');
    disclosures.push(d);
    digests.push(sha256b64u(d));
  }
  digests.sort(() => Math.random() - 0.5); // do not leak claim order
  const payload: JWTPayload = { iss: o.iss, iat: now, nbf: now, exp: now + (o.ttlSec ?? 365 * 24 * 3600), vct: o.vct, _sd: digests, _sd_alg: 'sha-256' };
  if (o.holderJwk) payload.cnf = { jwk: o.holderJwk };
  const header: JWTHeaderParameters = { alg: 'ES256', typ: SD_JWT_TYP };
  if (o.kid) header.kid = o.kid;
  if (o.x5c) header.x5c = o.x5c;
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(o.privateKey);
  return `${jwt}~${disclosures.join('~')}~`;
}

// ---------------------------------------------------------------- parsing

export interface SplitSdJwt {
  jwt: string;
  disclosures: string[];
  kbJwt: string | undefined;
}

export function splitSdJwt(compact: string): SplitSdJwt {
  const parts = compact.split('~');
  if (parts.length < 2 || !parts[0]) throw new SdJwtError('Not an SD-JWT (missing ~ separators)');
  const last = parts[parts.length - 1]!;
  return { jwt: parts[0], disclosures: parts.slice(1, -1), kbJwt: last === '' ? undefined : last };
}

type Disclosure = { name: string | undefined; value: unknown; raw: string };

function decodeDisclosure(raw: string): Disclosure {
  let arr: unknown;
  try {
    arr = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw new SdJwtError('Malformed disclosure');
  }
  if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3) || typeof arr[0] !== 'string') throw new SdJwtError('Malformed disclosure');
  if (arr.length === 3 && typeof arr[1] !== 'string') throw new SdJwtError('Malformed disclosure claim name');
  return { name: arr.length === 3 ? (arr[1] as string) : undefined, value: arr[arr.length - 1], raw };
}

/** Rebuild the full claim set from the issuer payload and the disclosures; rejects forged, duplicate or unused disclosures. */
export function resolveDisclosures(payload: Claims, disclosureList: string[]): Claims {
  if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') throw new SdJwtError('Unsupported _sd_alg');
  const byDigest = new Map<string, Disclosure>();
  for (const raw of disclosureList) {
    const digest = sha256b64u(raw);
    if (byDigest.has(digest)) throw new SdJwtError('Duplicate disclosure');
    byDigest.set(digest, decodeDisclosure(raw));
  }
  const used = new Set<string>();

  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) {
      return node.flatMap((el) => {
        if (el && typeof el === 'object' && !Array.isArray(el) && typeof (el as Claims)['...'] === 'string') {
          const digest = (el as Claims)['...'] as string;
          const d = byDigest.get(digest);
          if (!d) return []; // undisclosed array element
          if (d.name !== undefined) throw new SdJwtError('Array element disclosure must not have a name');
          used.add(digest);
          return [walk(d.value)];
        }
        return [walk(el)];
      });
    }
    if (node && typeof node === 'object') {
      const src = node as Claims;
      const out: Claims = {};
      for (const [k, v] of Object.entries(src)) if (k !== '_sd' && k !== '_sd_alg') out[k] = walk(v);
      const sd = src._sd;
      if (sd !== undefined) {
        if (!Array.isArray(sd)) throw new SdJwtError('_sd must be an array');
        for (const digest of sd) {
          const d = typeof digest === 'string' ? byDigest.get(digest) : undefined;
          if (!d) continue; // undisclosed claim (or decoy)
          if (d.name === undefined) throw new SdJwtError('Object disclosure must have a claim name');
          if (d.name in out || d.name === '_sd' || d.name === '...') throw new SdJwtError(`Disclosure clashes with claim "${d.name}"`);
          used.add(digest as string);
          out[d.name] = walk(d.value);
        }
      }
      return out;
    }
    return node;
  };

  const claims = walk(payload) as Claims;
  if (used.size !== byDigest.size) throw new SdJwtError('Disclosure not referenced by the signed payload');
  return claims;
}

// ---------------------------------------------------------------- holder side

export interface PresentOptions {
  credential: string;
  /** Top-level claim names to reveal. */
  reveal: string[];
  holderPrivateKey: Key;
  aud: string;
  nonce: string;
  now?: number;
}

/** Selective-disclosure presentation + key-binding JWT. */
export async function presentSdJwt(o: PresentOptions): Promise<string> {
  const { jwt, disclosures } = splitSdJwt(o.credential);
  const chosen = disclosures.filter((raw) => {
    const d = decodeDisclosure(raw);
    return d.name !== undefined && o.reveal.includes(d.name);
  });
  const base = `${jwt}~${chosen.join('~')}${chosen.length ? '~' : ''}`;
  const kb = await new SignJWT({ aud: o.aud, nonce: o.nonce, iat: o.now ?? Math.floor(Date.now() / 1000), sd_hash: sha256b64u(base) })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(o.holderPrivateKey);
  return base + kb;
}

// ---------------------------------------------------------------- verifier side

export type IssuerKeyResolver = (header: { alg?: string; kid?: string; x5c?: string[] }, payload: JWTPayload) => Promise<Key>;

export interface VerifyOptions {
  resolveIssuerKey: IssuerKeyResolver;
  /** Acceptable vct values; the credential must match one. */
  acceptedVcts: string[];
  /** Key-binding checks (required: bearer presentations are refused). Any listed audience is accepted. */
  aud: string | string[];
  nonce: string;
  now?: number;
  /** Max age of the KB-JWT in seconds. */
  maxKbAgeSec?: number;
}

export interface VerifiedCredential {
  iss: string;
  vct: string;
  claims: Claims;
}

export async function verifySdJwtPresentation(compact: string, o: VerifyOptions): Promise<VerifiedCredential> {
  const { jwt, disclosures, kbJwt } = splitSdJwt(compact);
  const now = o.now ?? Math.floor(Date.now() / 1000);

  let header;
  try {
    header = decodeProtectedHeader(jwt);
  } catch {
    throw new SdJwtError('Issuer JWT is not a valid JWT');
  }
  if (!header.typ || !ACCEPTED_TYP.has(header.typ)) throw new SdJwtError(`Unexpected issuer JWT typ "${header.typ ?? ''}"`);
  if (header.alg !== 'ES256') throw new SdJwtError(`Unsupported issuer algorithm "${header.alg ?? ''}"`);

  // Peek at the payload only to choose the key; nothing is trusted until the signature has been verified below.
  const unverified = JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as JWTPayload;
  const key = await o.resolveIssuerKey(header as { alg?: string; kid?: string; x5c?: string[] }, unverified);
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(jwt, key, { algorithms: ['ES256'], currentDate: new Date(now * 1000) }));
  } catch (e) {
    throw new SdJwtError(`Issuer signature / validity check failed: ${(e as Error).message}`);
  }
  if (typeof payload.iss !== 'string') throw new SdJwtError('Missing iss');
  if (typeof payload.vct !== 'string' || !o.acceptedVcts.includes(payload.vct)) throw new SdJwtError(`Credential type "${String(payload.vct)}" is not accepted`);

  const claims = resolveDisclosures(payload as Claims, disclosures);

  // Key binding is mandatory.
  const cnfJwk = (payload.cnf as { jwk?: JWK } | undefined)?.jwk;
  if (!cnfJwk) throw new SdJwtError('Credential has no holder binding (cnf.jwk)');
  if (!kbJwt) throw new SdJwtError('Presentation has no key-binding JWT');
  const holderKey = await importJWK(cnfJwk, 'ES256');
  let kb;
  try {
    kb = await jwtVerify(kbJwt, holderKey, { algorithms: ['ES256'], typ: 'kb+jwt', audience: o.aud, currentDate: new Date(now * 1000) });
  } catch (e) {
    throw new SdJwtError(`Key-binding JWT check failed: ${(e as Error).message}`);
  }
  if (kb.payload.nonce !== o.nonce) throw new SdJwtError('Key-binding nonce mismatch');
  if (typeof kb.payload.iat !== 'number' || Math.abs(now - kb.payload.iat) > (o.maxKbAgeSec ?? 300)) throw new SdJwtError('Key-binding JWT is not fresh');
  const signedPart = compact.slice(0, compact.length - kbJwt.length);
  if (kb.payload.sd_hash !== sha256b64u(signedPart)) throw new SdJwtError('Key-binding sd_hash mismatch');

  const { _sd, _sd_alg, cnf, iss, iat, nbf, exp, vct, ...rest } = claims as Claims;
  void _sd; void _sd_alg; void cnf; void iat; void nbf; void exp;
  return { iss: payload.iss, vct: payload.vct, claims: rest as Claims };
}

/** Decode the credential claims without verifying anything (used by the simulated wallet that just issued it). */
export function peekClaims(compact: string): Claims {
  const { jwt, disclosures } = splitSdJwt(compact);
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as Claims;
  const { _sd, _sd_alg, cnf, iss, iat, nbf, exp, vct, ...rest } = resolveDisclosures(payload, disclosures);
  void _sd; void _sd_alg; void cnf; void iss; void iat; void nbf; void exp; void vct;
  return rest;
}

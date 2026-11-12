/**
 * ISO 18013-5 mdoc (mso_mdoc) verification for OpenID4VP presentations: issuer signature + certificate chain,
 * per-element digests against the Mobile Security Object, validity, and the device signature over the
 * OpenID4VP SessionTranscript (replay protection, bound to client_id / nonce / response_uri / encryption key).
 */
import { createHash, createPublicKey, createVerify, X509Certificate, type KeyObject } from 'node:crypto';
import { Decoder, Encoder, Tag } from 'cbor-x';
import { SdJwtError, type Claims } from '../sdjwt/index.js';

const enc = new Encoder({ useRecords: false, mapsAsObjects: false });
const dec = new Decoder({ useRecords: false, mapsAsObjects: false });
const sha256 = (b: Uint8Array | Buffer) => createHash('sha256').update(b).digest();
const asBuf = (b: unknown): Buffer => {
  if (Buffer.isBuffer(b)) return b;
  if (b instanceof Uint8Array) return Buffer.from(b);
  throw new SdJwtError('mdoc: expected a byte string');
};
const asMap = (m: unknown, what: string): Map<unknown, unknown> => {
  if (m instanceof Map) return m;
  throw new SdJwtError(`mdoc: ${what} is not a map`);
};

export class MdocError extends SdJwtError {}

export interface MdocVerifyOptions {
  /** Expected document type, e.g. eu.europa.ec.eudi.pid.1 */
  docType: string;
  /** Validates the x5chain (DER certificates, leaf first); returns the trusted leaf. Throw to reject. */
  validateChain: (chain: Buffer[]) => X509Certificate;
  /** Candidate SessionTranscripts (already structured values) – the device signature must match one. */
  sessionTranscripts: unknown[];
  now?: Date;
}

export interface VerifiedMdoc {
  docType: string;
  /** namespace → element → value */
  elements: Record<string, Record<string, unknown>>;
  issuerSubject: string;
  matchedTranscript: number;
}

/** True when the string is base64url CBOR that looks like a DeviceResponse. */
export function looksLikeDeviceResponse(s: string): boolean {
  if (s.includes('~') || !/^[A-Za-z0-9_-]+={0,2}$/.test(s) || s.length < 20) return false;
  try {
    const m = dec.decode(Buffer.from(s, 'base64url'));
    return m instanceof Map && m.has('documents');
  } catch {
    return false;
  }
}

function coseKeyToKeyObject(k: Map<unknown, unknown>): KeyObject {
  const kty = k.get(1), crv = k.get(-1);
  if (kty !== 2 || crv !== 1) throw new MdocError('mdoc: only EC P-256 device keys are supported');
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: asBuf(k.get(-2)).toString('base64url'), y: asBuf(k.get(-3)).toString('base64url') }, format: 'jwk' });
}

/** Verify a COSE_Sign1 ES256 signature. */
function verifyCose1(protectedBstr: Buffer, payload: Buffer, signature: Buffer, key: KeyObject): boolean {
  const toBeSigned = Buffer.from(enc.encode(['Signature1', protectedBstr, Buffer.alloc(0), payload]));
  return createVerify('sha256').update(toBeSigned).verify({ key, dsaEncoding: 'ieee-p1363' }, signature);
}

const toDate = (v: unknown): Date | undefined => (v instanceof Date ? v : typeof v === 'string' ? new Date(v) : v instanceof Tag && typeof v.value === 'string' ? new Date(v.value) : undefined);

/** Convert decoded CBOR values (Maps, Tags, Buffers) to plain JSON-friendly values. */
export function plain(v: unknown): unknown {
  if (v instanceof Tag) return plain(v.value);
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (v instanceof Map) return Object.fromEntries([...v.entries()].map(([k, x]) => [String(k), plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (v instanceof Uint8Array) return Buffer.from(v).toString('base64url');
  return v;
}

export function verifyDeviceResponse(b64: string, o: MdocVerifyOptions): VerifiedMdoc {
  const now = o.now ?? new Date();
  let top: Map<unknown, unknown>;
  try {
    top = asMap(dec.decode(Buffer.from(b64, 'base64url')), 'DeviceResponse');
  } catch (e) {
    throw new MdocError(`mdoc: cannot decode DeviceResponse (${(e as Error).message})`);
  }
  const docs = top.get('documents');
  if (!Array.isArray(docs) || docs.length === 0) throw new MdocError('mdoc: no documents in DeviceResponse');
  const doc = docs.map((d) => asMap(d, 'document')).find((d) => d.get('docType') === o.docType);
  if (!doc) throw new MdocError(`mdoc: no document of type ${o.docType}`);

  // ---- issuer authentication
  const issuerSigned = asMap(doc.get('issuerSigned'), 'issuerSigned');
  const issuerAuth = issuerSigned.get('issuerAuth');
  if (!Array.isArray(issuerAuth) || issuerAuth.length !== 4) throw new MdocError('mdoc: malformed issuerAuth');
  const [protB, unprot, payloadB, sigB] = issuerAuth as [unknown, unknown, unknown, unknown];
  const protectedBytes = asBuf(protB);
  const alg = asMap(dec.decode(protectedBytes), 'protected header').get(1);
  if (alg !== -7) throw new MdocError('mdoc: unsupported issuer signature algorithm (ES256 only)');
  const x5 = asMap(unprot, 'unprotected header').get(33);
  const chain = (Array.isArray(x5) ? x5 : [x5]).filter(Boolean).map(asBuf);
  if (chain.length === 0) throw new MdocError('mdoc: issuerAuth carries no x5chain');
  const leaf = o.validateChain(chain);
  if (!verifyCose1(protectedBytes, asBuf(payloadB), asBuf(sigB), leaf.publicKey)) throw new MdocError('mdoc: issuer signature invalid');

  // ---- Mobile Security Object
  const msoTag = dec.decode(asBuf(payloadB));
  if (!(msoTag instanceof Tag) || msoTag.tag !== 24) throw new MdocError('mdoc: MSO is not tag 24');
  const mso = asMap(dec.decode(asBuf(msoTag.value)), 'MSO');
  if (mso.get('docType') !== o.docType) throw new MdocError('mdoc: MSO docType mismatch');
  if (mso.get('digestAlgorithm') !== 'SHA-256') throw new MdocError('mdoc: unsupported digestAlgorithm');
  const validity = asMap(mso.get('validityInfo'), 'validityInfo');
  const from = toDate(validity.get('validFrom')), until = toDate(validity.get('validUntil'));
  if (!from || !until || now < from || now > until) throw new MdocError('mdoc: outside validity period');

  // ---- disclosed elements vs. digests
  const valueDigests = asMap(mso.get('valueDigests'), 'valueDigests');
  const elements: Record<string, Record<string, unknown>> = {};
  const nameSpaces = issuerSigned.get('nameSpaces');
  for (const [ns, items] of asMap(nameSpaces, 'nameSpaces').entries()) {
    const digests = asMap(valueDigests.get(ns), `valueDigests[${String(ns)}]`);
    if (!Array.isArray(items)) throw new MdocError('mdoc: namespace is not an array');
    for (const item of items) {
      if (!(item instanceof Tag) || item.tag !== 24) throw new MdocError('mdoc: IssuerSignedItem is not tag 24');
      const parsed = asMap(dec.decode(asBuf(item.value)), 'IssuerSignedItem');
      const expected = digests.get(parsed.get('digestID'));
      const actual = sha256(Buffer.from(enc.encode(item)));
      if (!expected || !actual.equals(asBuf(expected))) throw new MdocError(`mdoc: digest mismatch for ${String(parsed.get('elementIdentifier'))}`);
      (elements[String(ns)] ??= {})[String(parsed.get('elementIdentifier'))] = plain(parsed.get('elementValue'));
    }
  }

  // ---- device authentication (proof of possession, bound to this transaction)
  const deviceSigned = asMap(doc.get('deviceSigned'), 'deviceSigned');
  const deviceKey = coseKeyToKeyObject(asMap(asMap(mso.get('deviceKeyInfo'), 'deviceKeyInfo').get('deviceKey'), 'deviceKey'));
  const deviceSig = asMap(deviceSigned.get('deviceAuth'), 'deviceAuth').get('deviceSignature');
  if (!Array.isArray(deviceSig) || deviceSig.length !== 4) throw new MdocError('mdoc: missing deviceSignature (deviceMac is not supported)');
  const devProtected = asBuf(deviceSig[0]);
  const devNs = deviceSigned.get('nameSpaces');
  let matched = -1;
  for (const [i, st] of o.sessionTranscripts.entries()) {
    const deviceAuthentication = ['DeviceAuthentication', st, o.docType, devNs];
    const payload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(deviceAuthentication)), 24)));
    if (verifyCose1(devProtected, payload, asBuf(deviceSig[3]), deviceKey)) { matched = i; break; }
  }
  if (matched < 0) throw new MdocError('mdoc: device signature does not match this transaction (nonce / client_id / response_uri / key binding)');

  return { docType: o.docType, elements, issuerSubject: leaf.subject.replace(/\n/g, ', '), matchedTranscript: matched };
}

/**
 * OpenID4VP SessionTranscript candidates. 1.0 form: [null, null, ["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, jwkThumbprint|null, responseUri]))]].
 * Variants tried: client_id with/without scheme prefix, encryption-key thumbprint present/absent.
 */
export function openId4VpSessionTranscripts(p: { clientId: string; nonce: string; responseUri: string; jwkThumbprint?: Buffer }): unknown[] {
  const ids = [p.clientId, p.clientId.slice(p.clientId.indexOf(':') + 1)];
  const thumbs: (Buffer | null)[] = p.jwkThumbprint ? [p.jwkThumbprint, null] : [null];
  const out: unknown[] = [];
  for (const id of ids) for (const t of thumbs) {
    out.push([null, null, ['OpenID4VPHandover', sha256(Buffer.from(enc.encode([id, p.nonce, t, p.responseUri])))]]);
  }
  return out;
}

/**
 * Map mdoc elements to the claim names used by the rest of the app (SD-JWT PID naming), using the attestation's
 * `mdoc.elements` map (internal claim → mdoc element). Addresses / places given as flat elements are folded into objects.
 */
export function normalizeMdocClaims(elements: Record<string, Record<string, unknown>>, namespace: string, map: Record<string, string>): Claims {
  const ns = elements[namespace] ?? {};
  const out: Claims = {};
  for (const [claim, element] of Object.entries(map)) if (ns[element] !== undefined) out[claim] = ns[element];
  if (typeof out.nationalities === 'string') out.nationalities = [out.nationalities];
  if (typeof out.place_of_birth === 'string') out.place_of_birth = { locality: out.place_of_birth };
  if (typeof out.address === 'string') out.address = { formatted: out.address };
  if (out.address === undefined && (ns.resident_city || ns.resident_street || ns.resident_country)) {
    out.address = { street_address: ns.resident_street, postal_code: ns.resident_postal_code, locality: ns.resident_city, country: ns.resident_country };
  }
  return out;
}

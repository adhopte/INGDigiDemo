import { createHash, randomBytes } from 'node:crypto';
import { Encoder, Tag } from 'cbor-x';

const enc = new Encoder({ useRecords: false, mapsAsObjects: false });
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest();

/** Elements whose value is a calendar date (ISO 18013-5: full-date, CBOR tag 1004). */
const DATE_ELEMENTS = new Set(['birth_date', 'issue_date', 'expiry_date', 'portrait_capture_date', 'issuance_date']);

/** Claim values → CBOR values: dates as full-date, the portrait (base64) as bytes, objects as maps. */
function toCbor(name: string, v: unknown): unknown {
  if (typeof v === 'string' && DATE_ELEMENTS.has(name) && /^\d{4}-\d{2}-\d{2}$/.test(v)) return new Tag(v, 1004);
  if (name === 'portrait' && typeof v === 'string') return Buffer.from(v, 'base64');
  if (Array.isArray(v)) return v.map((x) => toCbor(name, x));
  if (v && typeof v === 'object') return new Map(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, toCbor(k, x)]));
  return v;
}

const tdate = (d: Date) => new Tag(`${d.toISOString().slice(0, 19)}Z`, 0);

export interface IssueMdocOptions {
  /** ES256 signing key of the issuer (the leaf of x5c). */
  privateKey: CryptoKey;
  /** Certificate chain, base64 DER, leaf first. */
  x5c: string[];
  docType: string;
  namespace: string;
  elements: Record<string, unknown>;
  /** The holder's public key (EC P-256): the credential is bound to it as the mdoc device key. */
  deviceJwk: { x?: string; y?: string };
  now?: Date;
  validDays?: number;
}

/**
 * An ISO 18013-5 mdoc (IssuerSigned structure, base64url of its CBOR) as the OpenID4VCI `mso_mdoc` format carries it:
 * the elements, their digests in the Mobile Security Object, the device key, and the issuer's COSE_Sign1 over it with the certificate chain in x5chain.
 * The same document works online (OpenID4VP) and in proximity (the wallet adds the DeviceSigned part when it presents it).
 */
export async function issueMdoc(o: IssueMdocOptions): Promise<string> {
  const now = o.now ?? new Date();
  const items: Tag[] = [];
  const digests = new Map<number, Buffer>();
  let i = 0;
  for (const [name, value] of Object.entries(o.elements)) {
    if (value === undefined || value === null || value === '') continue;
    const item = new Tag(Buffer.from(enc.encode(new Map<string, unknown>([['digestID', i], ['random', randomBytes(16)], ['elementIdentifier', name], ['elementValue', toCbor(name, value)]]))), 24);
    digests.set(i, sha256(Buffer.from(enc.encode(item))));
    items.push(item);
    i++;
  }
  const mso = new Map<string, unknown>([
    ['version', '1.0'], ['digestAlgorithm', 'SHA-256'], ['docType', o.docType],
    ['valueDigests', new Map([[o.namespace, digests]])],
    ['deviceKeyInfo', new Map([['deviceKey', new Map<number, unknown>([[1, 2], [-1, 1], [-2, Buffer.from(o.deviceJwk.x ?? '', 'base64url')], [-3, Buffer.from(o.deviceJwk.y ?? '', 'base64url')]])]])],
    ['validityInfo', new Map<string, unknown>([['signed', tdate(now)], ['validFrom', tdate(now)], ['validUntil', tdate(new Date(now.getTime() + (o.validDays ?? 365) * 86_400_000))]])],
  ]);
  const protectedHdr = Buffer.from(enc.encode(new Map([[1, -7]])));
  const payload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(mso)), 24)));
  const toBeSigned = Buffer.from(enc.encode(['Signature1', protectedHdr, Buffer.alloc(0), payload]));
  const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, o.privateKey, toBeSigned)); // raw r||s, as COSE wants
  const chain = o.x5c.map((c) => Buffer.from(c, 'base64'));
  const issuerAuth = [protectedHdr, new Map([[33, chain.length === 1 ? chain[0]! : chain]]), payload, signature];
  return Buffer.from(enc.encode(new Map<string, unknown>([['nameSpaces', new Map([[o.namespace, items]])], ['issuerAuth', issuerAuth]]))).toString('base64url');
}

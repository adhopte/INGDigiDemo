import { createPrivateKey, createSign } from 'node:crypto';
import { Decoder, Encoder, Tag } from 'cbor-x';
import type { JWK } from 'jose';
import { plain } from '../mdoc/index.js';

const enc = new Encoder({ useRecords: false, mapsAsObjects: false });
const dec = new Decoder({ useRecords: false, mapsAsObjects: false });

const issuerSigned = (b64: string) => dec.decode(Buffer.from(b64, 'base64url')) as Map<string, any>;
const itemsOf = (b64: string, namespace: string): Tag[] => ((issuerSigned(b64).get('nameSpaces') as Map<string, Tag[]>).get(namespace) ?? []);
const itemMap = (t: Tag) => dec.decode(t.value as Uint8Array) as Map<string, unknown>;

/** The elements of a held mdoc (IssuerSigned) as plain values, without verifying anything: what the simulated wallet shows. */
export function peekMdoc(credential: string, namespace: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const t of itemsOf(credential, namespace)) { const m = itemMap(t); out[String(m.get('elementIdentifier'))] = plain(m.get('elementValue')); }
  return out;
}

/**
 * The wallet's answer for an mdoc: a DeviceResponse with only the requested elements, signed (DeviceAuthentication over the session
 * transcript of this transaction) with the holder key the credential is bound to.
 */
export function presentMdoc(o: { credential: string; holderPrivateJwk: JWK; docType: string; namespace: string; reveal: string[] | undefined; sessionTranscript: unknown }): string {
  const is = issuerSigned(o.credential);
  const items = itemsOf(o.credential, o.namespace).filter((t) => !o.reveal || o.reveal.includes(String(itemMap(t).get('elementIdentifier'))));
  const devNs = new Tag(Buffer.from(enc.encode(new Map())), 24);
  const protectedHdr = Buffer.from(enc.encode(new Map([[1, -7]])));
  const payload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(['DeviceAuthentication', o.sessionTranscript, o.docType, devNs])), 24)));
  const toBeSigned = Buffer.from(enc.encode(['Signature1', protectedHdr, Buffer.alloc(0), payload]));
  const signature = createSign('sha256').update(toBeSigned).sign({ key: createPrivateKey({ key: o.holderPrivateJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' });
  const doc = new Map<string, unknown>([
    ['docType', o.docType],
    ['issuerSigned', new Map<string, unknown>([['nameSpaces', new Map([[o.namespace, items]])], ['issuerAuth', is.get('issuerAuth')]])],
    ['deviceSigned', new Map<string, unknown>([['nameSpaces', devNs], ['deviceAuth', new Map([['deviceSignature', [protectedHdr, new Map(), null, signature]]])]])],
  ]);
  return Buffer.from(enc.encode(new Map<string, unknown>([['version', '1.0'], ['documents', [doc]], ['status', 0]]))).toString('base64url');
}

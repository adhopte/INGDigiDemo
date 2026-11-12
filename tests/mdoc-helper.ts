import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { Encoder, Tag } from 'cbor-x';

const enc = new Encoder({ useRecords: false, mapsAsObjects: false });
const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

export async function makeCa(name = 'Test PID CA') {
  const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: `CN=${name}`, notBefore: new Date(Date.now() - 3600_000), notAfter: new Date(Date.now() + 86400_000), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, undefined, true)] });
  return { cert, keys };
}

export async function makeDsc(ca: Awaited<ReturnType<typeof makeCa>>) {
  const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: '02', subject: 'CN=Test DS', issuer: ca.cert.subject, publicKey: keys.publicKey, signingKey: ca.keys.privateKey, notBefore: new Date(Date.now() - 3600_000), notAfter: new Date(Date.now() + 86400_000), signingAlgorithm: alg, extensions: [new x509.BasicConstraintsExtension(false, undefined, true)] });
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  const { createPrivateKey } = await import('node:crypto');
  return { cert, privateKey: createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }) };
}

const sign = (priv: KeyObject, protectedBstr: Buffer, payload: Buffer) =>
  createSign('sha256').update(Buffer.from(enc.encode(['Signature1', protectedBstr, Buffer.alloc(0), payload]))).sign({ key: priv, dsaEncoding: 'ieee-p1363' });

export interface BuildOptions {
  docType?: string;
  namespace?: string;
  elements: Record<string, unknown>;
  dsc: Awaited<ReturnType<typeof makeDsc>>;
  sessionTranscript: unknown;
  tamper?: boolean;
  validUntil?: Date;
}

/** Builds a base64url DeviceResponse like a wallet would. */
export function buildDeviceResponse(o: BuildOptions): string {
  const docType = o.docType ?? 'eu.europa.ec.eudi.pid.1';
  const ns = o.namespace ?? docType;
  const device = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = device.publicKey.export({ format: 'jwk' }) as { x: string; y: string };

  const items: Tag[] = [];
  const digests = new Map<number, Buffer>();
  Object.entries(o.elements).forEach(([name, value], i) => {
    const item = new Tag(Buffer.from(enc.encode(new Map<string, unknown>([['digestID', i], ['random', randomBytes(16)], ['elementIdentifier', name], ['elementValue', value]]))), 24);
    digests.set(i, createHash('sha256').update(Buffer.from(enc.encode(item))).digest());
    items.push(o.tamper && i === 0 ? new Tag(Buffer.from(enc.encode(new Map<string, unknown>([['digestID', i], ['random', randomBytes(16)], ['elementIdentifier', name], ['elementValue', 'FORGED']]))), 24) : item);
  });

  const now = new Date();
  const mso = new Map<string, unknown>([
    ['version', '1.0'], ['digestAlgorithm', 'SHA-256'], ['docType', docType],
    ['valueDigests', new Map([[ns, digests]])],
    ['deviceKeyInfo', new Map([['deviceKey', new Map<number, unknown>([[1, 2], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]])]])],
    ['validityInfo', new Map<string, unknown>([['signed', now.toISOString()], ['validFrom', new Date(now.getTime() - 60_000).toISOString()], ['validUntil', (o.validUntil ?? new Date(now.getTime() + 3600_000)).toISOString()]])],
  ]);
  const protectedHdr = Buffer.from(enc.encode(new Map([[1, -7]])));
  const payload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(mso)), 24)));
  const issuerAuth = [protectedHdr, new Map([[33, Buffer.from(o.dsc.cert.rawData)]]), payload, sign(o.dsc.privateKey, protectedHdr, payload)];

  const devNs = new Tag(Buffer.from(enc.encode(new Map())), 24);
  const devPayload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(['DeviceAuthentication', o.sessionTranscript, docType, devNs])), 24)));
  const devSig = sign(device.privateKey, protectedHdr, devPayload);

  const doc = new Map<string, unknown>([
    ['docType', docType],
    ['issuerSigned', new Map<string, unknown>([['nameSpaces', new Map([[ns, items]])], ['issuerAuth', issuerAuth]])],
    ['deviceSigned', new Map<string, unknown>([['nameSpaces', devNs], ['deviceAuth', new Map([['deviceSignature', [protectedHdr, new Map(), null, devSig]]])]])],
  ]);
  return Buffer.from(enc.encode(new Map<string, unknown>([['version', '1.0'], ['documents', [doc]], ['status', 0]]))).toString('base64url');
}

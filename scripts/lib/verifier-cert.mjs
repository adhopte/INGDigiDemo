// Helpers to create the verifier identity (ES256 key + X.509 chain) used to sign OpenID4VP request objects.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash } from 'node:crypto';

const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const gen = () => crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
const privateJwk = async (keys, kid) => ({ ...(await crypto.subtle.exportKey('jwk', keys.privateKey)), alg: 'ES256', use: 'sig', ...(kid ? { kid } : {}) });
const pem = (c) => c.toString('pem');
const envPem = (...certs) => certs.map(pem).join('').replace(/\r?\n/g, '\\n');
export const x509HashClientId = (cert) => `x509_hash:${createHash('sha256').update(Buffer.from(cert.rawData)).digest('base64url')}`;

/** Demo PKI: a root CA (to be added to the wallet's trust anchors) and a leaf certificate for `host` signed by it. */
export async function generateDemoPki(host, { org = 'IN Groupe (demo verifier)', days = 365 } = {}) {
  const now = Date.now();
  const caKeys = await gen();
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01', name: `CN=${org} Demo Root CA, O=${org}`, notBefore: new Date(now - 3600_000), notAfter: new Date(now + 5 * 365 * 86400_000),
    signingAlgorithm: alg, keys: caKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)],
  });
  const leafKeys = await gen();
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '02', subject: `CN=${host}, O=${org}`, issuer: ca.subject, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey,
    notBefore: new Date(now - 3600_000), notAfter: new Date(now + days * 86400_000), signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }], false),
    ],
  });
  return {
    caPem: pem(ca), leafPem: pem(leaf), chainPem: pem(leaf) + pem(ca), leaf, ca,
    keyJwk: await privateJwk(leafKeys),
    env: { VERIFIER_SIGNING_KEY_JWK: JSON.stringify(await privateJwk(leafKeys)), VERIFIER_CERT_CHAIN_PEM: envPem(leaf, ca) },
    clientIds: { x509_hash: x509HashClientId(leaf), x509_san_dns: `x509_san_dns:${host}` },
  };
}

/** Key + PKCS#10 certificate signing request, to be signed by a CA the wallet trusts (e.g. the IN Groupe / SIGMA PKI). */
export async function generateCsr(host, { org = 'IN Groupe' } = {}) {
  const keys = await gen();
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${host}, O=${org}`, keys, signingAlgorithm: alg,
    extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }], false)],
  });
  return { csrPem: csr.toString('pem'), keyJwk: await privateJwk(keys), keyEnv: JSON.stringify(await privateJwk(keys)) };
}

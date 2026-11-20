import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { X509Certificate } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair, importPKCS8, importX509, jwtVerify, type JWK } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { respondToVerifier } from '../src/mock/wallet.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { presentSdJwt } from '../src/sdjwt/index.js';
import { createServices } from '../src/services.js';
import { sdJwtShape } from '../src/verifier/service.js';
import { validateX5cChain } from '../src/verifier/trust.js';
import { generateIssuerCsr, requestText } from '../scripts/lib/issuer-csr.mjs';
import { testConfig } from './helpers.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
async function walletProvider() {
  const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=Test Wallet Provider', notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: ALG, keys });
  const pkcs8 = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----`;
  return { x5c: Buffer.from(cert.rawData).toString('base64'), key: await importPKCS8(pkcs8, 'ES256') };
}

type DcqlCredential = { id: string; format: string; meta?: { vct_values?: string[] }; claims?: Array<{ path: Array<string | null> }> };

/** What a wallet's DCQL matcher does for an SD-JWT VC: format, vct, and that every requested claim is available (signed or disclosable). */
function matches(credential: string, q: DcqlCredential): { ok: boolean; why: string } {
  const [jwt, ...disclosures] = credential.split('~');
  const header = JSON.parse(Buffer.from(jwt!.split('.')[0]!, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(jwt!.split('.')[1]!, 'base64url').toString());
  if (q.format !== 'dc+sd-jwt' || header.typ !== 'dc+sd-jwt') return { ok: false, why: `format ${header.typ} vs ${q.format}` };
  if (q.meta?.vct_values && !q.meta.vct_values.includes(payload.vct)) return { ok: false, why: `vct ${payload.vct}` };
  const available = new Set<string>(Object.keys(payload).filter((k) => !['_sd', '_sd_alg'].includes(k)));
  for (const d of disclosures.filter(Boolean)) available.add(JSON.parse(Buffer.from(d, 'base64url').toString())[1]);
  for (const c of q.claims ?? []) if (c.path.length !== 1 || !available.has(String(c.path[0]))) return { ok: false, why: `claim ${JSON.stringify(c.path)} missing` };
  return { ok: true, why: '' };
}

/** The wallet side of issuance: all `n` copies in one request, as the SIGMA wallet asks for (batch of 10). */
async function receiveBatch(n: number, env: Record<string, string> = {}) {
  const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri', PUBLIC_BASE_URL: 'https://rp.example.test', ...env });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  const o = svc.local.createOffer('payment', { account_holder_name: 'Mathieu Ahouandjinou', iban: 'XX00 DEMO 1142 5751 10', bic: 'DEMOBKXX', bank_name: 'Demo Bank', valid_until: '2028-11-20' });
  const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
  const token = (await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] })).body.access_token as string;
  const holders = await Promise.all(Array.from({ length: n }, async () => { const p = await generateKeyPair('ES256', { extractable: true }); return { priv: p.privateKey, jwk: await exportJWK(p.publicKey) as JWK }; }));
  const wp = await walletProvider();
  const nonce = (await request(app).post('/issuer/nonce')).body.c_nonce as string;
  const att = await new SignJWT({ attested_keys: holders.map((h) => h.jwk), nonce, key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'] }).setProtectedHeader({ alg: 'ES256', typ: 'keyattestation+jwt', x5c: [wp.x5c] }).setIssuedAt().sign(wp.key);
  const res = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${token}`).send({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { attestation: [att] } });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return { cfg, svc, copies: (res.body.credentials as Array<{ credential: string }>).map((c, i) => ({ credential: c.credential, holder: holders[i]! })) };
}

describe('every copy of a payment attestation batch against the eShop request (local issuer + local verifier)', () => {
  it('each of the 10 copies matches the eShop DCQL query, in the compact link and in the full request, and is accepted when presented', async () => {
    const { cfg, svc, copies } = await receiveBatch(10);
    expect(copies).toHaveLength(10);
    expect(new Set(copies.map((c) => c.credential)).size).toBe(10);
    const eshop = cfg.rps.find((r) => r.id === 'eshop')!;
    for (const [i, copy] of copies.entries()) {
      const tx = await svc.verifier.createTransaction(eshop, 'payment', '/eshop/');
      const compact = JSON.parse(new URL(svc.verifier.walletLink(tx, true)).searchParams.get('dcql_query')!) as { credentials: DcqlCredential[] };
      const full = svc.verifier.requestParams(tx).dcql_query as { credentials: DcqlCredential[] };
      for (const q of [compact, full]) {
        expect(q.credentials).toHaveLength(1);
        expect(matches(copy.credential, q.credentials[0]!), `copy ${i}`).toEqual({ ok: true, why: '' });
      }
      const claims = compact.credentials[0]!.claims!.map((c) => String(c.path[0]));
      const vp = await presentSdJwt({ credential: copy.credential, reveal: claims, holderPrivateKey: copy.holder.priv, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
      await respondToVerifier(svc.verifier, tx, { vp_token: { [compact.credentials[0]!.id]: [vp] } });
      expect(tx.status, `copy ${i}`).toBe('complete');
      expect(tx.result!.byType.payment).toMatchObject({ iban: 'XX00 DEMO 1142 5751 10', account_holder_name: 'Mathieu Ahouandjinou', bic: 'DEMOBKXX', bank_name: 'Demo Bank', valid_until: '2028-11-20' });
      expect(tx.result!.issuers).toEqual(['https://rp.example.test/issuer']);
    }
  });

  it('a different copy for each eShop transaction, and the same copy again also works (reuse is the wallet\'s policy, not the verifier\'s)', async () => {
    const { cfg, svc, copies } = await receiveBatch(3);
    const eshop = cfg.rps.find((r) => r.id === 'eshop')!;
    for (const copy of [copies[0]!, copies[0]!, copies[1]!]) {
      const tx = await svc.verifier.createTransaction(eshop, 'payment', '/eshop/');
      const vp = await presentSdJwt({ credential: copy.credential, reveal: ['account_holder_name', 'iban', 'bic', 'bank_name', 'valid_until'], holderPrivateKey: copy.holder.priv, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
      await respondToVerifier(svc.verifier, tx, { vp_token: { payment: [vp] } });
      expect(tx.status).toBe('complete');
    }
  });

  it('the Android probes (our own credentials, one variable at a time) ask what they say and are accepted when answered', async () => {
    const { cfg, svc, copies } = await receiveBatch(2);
    const bank = cfg.rps.find((r) => r.id === 'bank')!;
    const expectations: Record<string, { claims: string[]; vct: string[] }> = {
      probe_payment_all: { claims: ['account_holder_name', 'iban', 'bic', 'bank_name', 'valid_until'], vct: ['urn:eudi:demo:payment-attestation:1'] },
      probe_payment_iban: { claims: ['iban'], vct: ['urn:eudi:demo:payment-attestation:1'] },
      probe_payment_multivct: { claims: ['iban'], vct: ['urn:eudi:pid:1', 'urn:eudi:demo:payment-attestation:1'] },
    };
    for (const [key, want] of Object.entries(expectations)) {
      const tx = await svc.verifier.createTransaction(bank, key, '/wallet-check');
      const dcql = JSON.parse(new URL(svc.verifier.walletLink(tx, true)).searchParams.get('dcql_query')!) as { credentials: DcqlCredential[] };
      expect(dcql.credentials, key).toHaveLength(1);
      expect(dcql.credentials[0]!.meta!.vct_values, key).toEqual(want.vct);
      expect(dcql.credentials[0]!.claims!.map((c) => c.path[0]), key).toEqual(want.claims);
      expect(matches(copies[0]!.credential, { ...dcql.credentials[0]!, meta: { vct_values: ['urn:eudi:demo:payment-attestation:1'] } }).ok, key).toBe(true); // the credential has all of it
      const vp = await presentSdJwt({ credential: copies[0]!.credential, reveal: want.claims, holderPrivateKey: copies[0]!.holder.priv, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
      await respondToVerifier(svc.verifier, tx, { vp_token: { [dcql.credentials[0]!.id]: [vp] } });
      expect(tx.status, key).toBe('complete');
    }
  });

  it('the diagnostics record the shape of a presented SD-JWT (names and kinds, no values), to compare issuers', async () => {
    const { cfg, svc, copies } = await receiveBatch(1);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'eshop')!, 'payment', '/eshop/');
    const vp = await presentSdJwt({ credential: copies[0]!.credential, reveal: ['account_holder_name', 'iban', 'bic', 'bank_name', 'valid_until'], holderPrivateKey: copies[0]!.holder.priv, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
    await respondToVerifier(svc.verifier, tx, { vp_token: { payment: [vp] } });
    const ev = svc.verifier.diagnostics().find((e) => e.event === 'response_accepted') as unknown as { shapes: Array<Record<string, any>> };
    expect(ev.shapes).toHaveLength(1);
    const shape = ev.shapes[0]!;
    expect(shape.header).toEqual({ alg: 'ES256', typ: 'dc+sd-jwt', kid: 'string', x5c: 'array(1)' }); // x5c like SIGMA's credentials
    expect(Object.keys(shape.payload).sort()).toEqual(['_sd', '_sd_alg', 'cnf', 'exp', 'iat', 'iss', 'vct']);
    expect(shape.payload.iss).toBe('https://rp.example.test/…'); // path stripped
    expect(shape.payload.vct).toBe('urn:eudi:demo:payment-attestation:1');
    expect(shape.signedClaims).toBe(5); // five selectively disclosable claims (digests in _sd)
    expect(shape.disclosedNow.sort()).toEqual(['account_holder_name', 'bank_name', 'bic', 'iban', 'valid_until']);
    expect(shape.keyBinding).toBe(true);
    expect(JSON.stringify(ev)).not.toContain('XX00 DEMO'); // never a value
    expect(sdJwtShape('garbage')).toBeUndefined();
  });

  it('every issued credential carries the issuer certificate (x5c), valid for this host and verifying the credential like a wallet would check it', async () => {
    const { svc, copies } = await receiveBatch(2);
    for (const copy of copies) {
      const [jwt] = copy.credential.split('~');
      const header = JSON.parse(Buffer.from(jwt!.split('.')[0]!, 'base64url').toString());
      expect(header.x5c).toHaveLength(1);
      expect(header.kid).toBe(svc.local.publicJwk.kid);
      const cert = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
      expect(cert.subject).toContain('CN=rp.example.test');
      expect(cert.checkHost('rp.example.test')).toBe('rp.example.test');
      expect(cert.verify(cert.publicKey)).toBe(true); // self-signed by the issuer key
      expect(new Date(cert.validFrom).getTime()).toBeLessThan(Date.now());
      expect(new Date(cert.validTo).getTime()).toBeGreaterThan(Date.now() + 300 * 24 * 3600 * 1000);
      expect(cert.publicKey.export({ format: 'jwk' })).toMatchObject({ x: svc.local.publicJwk.x, y: svc.local.publicJwk.y });
      // the credential's signature verifies with the certificate's key, as a wallet doing x5c validation would
      const key = await importX509(cert.toString(), 'ES256');
      const { payload } = await jwtVerify(jwt!, key, { algorithms: ['ES256'] });
      expect(payload.iss).toBe('https://rp.example.test/issuer');
      expect(payload).not.toHaveProperty('nbf');
    }
  });

  it('ISSUER_CERT_CHAIN_PEM supplies a real chain, used as given', async () => {
    const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const mk = (cn: string) => x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '02', name: `CN=${cn}`, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: ALG, keys });
    const leaf = await mk('SIGMA signed leaf');
    const root = await mk('SIGMA root');
    const pem = `${leaf.toString('pem')}\n${root.toString('pem')}`.replace(/\n/g, '\\n'); // as a one-line environment variable
    const cfg = testConfig({ MOCK_MODE: 'false', ISSUER_CERT_CHAIN_PEM: pem });
    const svc = await createServices(cfg);
    expect(svc.local.x5c).toEqual([Buffer.from(leaf.rawData).toString('base64'), Buffer.from(root.rawData).toString('base64')]);
  });

  it('the certificate request for SIGMA: valid CSR for a persistent key; once a CA signs it, the issuer\'s credentials verify through that chain', async () => {
    const r = await generateIssuerCsr('https://rp.example.test/issuer/');
    expect(r.issuerUrl).toBe('https://rp.example.test/issuer');
    const csr = new x509.Pkcs10CertificateRequest(r.csrPem);
    expect(await csr.verify()).toBe(true); // proof of possession
    expect(csr.subject).toBe('CN=rp.example.test, O=IN Groupe');
    const san = new x509.SubjectAlternativeNameExtension(csr.getExtension('2.5.29.17')!.rawData);
    expect(san.names.items.map((n) => `${n.type}:${n.value}`)).toEqual(['dns:rp.example.test', 'url:https://rp.example.test/issuer']);
    expect(new x509.KeyUsagesExtension(csr.getExtension('2.5.29.15')!.rawData).usages).toBe(x509.KeyUsageFlags.digitalSignature);
    const text = requestText(r);
    expect(text).toContain('rp.example.test');
    expect(text).toContain(r.publicKeySha256);
    expect(text).toContain('ISSUER_CERT_CHAIN_PEM');
    await expect(generateIssuerCsr('http://insecure.example/issuer')).rejects.toThrow('https');
    // a CA with its own naming rules: the exact subject and its name in the message
    const eudi = await generateIssuerCsr('https://rp.example.test/issuer', { subject: 'CN=IN Groupe SIGMA demo issuer, O=IN Groupe, C=UT', ca: 'the EUDI test CA' });
    const eudiCsr = new x509.Pkcs10CertificateRequest(eudi.csrPem);
    expect(await eudiCsr.verify()).toBe(true);
    expect(eudiCsr.subject).toBe('CN=IN Groupe SIGMA demo issuer, O=IN Groupe, C=UT');
    expect(new x509.SubjectAlternativeNameExtension(eudiCsr.getExtension('2.5.29.17')!.rawData).names.items.map((n) => n.value)).toEqual(['rp.example.test', 'https://rp.example.test/issuer']); // the SANs stay
    expect(requestText(eudi)).toContain('have the EUDI test CA sign');
    expect(requestText(eudi)).toContain('C=UT');

    // the CA (SIGMA) signs the request ...
    const caKeys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=SIGMA test root CA', notBefore: new Date(Date.now() - 3600_000), notAfter: new Date(Date.now() + 5 * 365 * 86400_000), signingAlgorithm: ALG, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true)] });
    const leaf = await x509.X509CertificateGenerator.create({ serialNumber: '02', subject: csr.subject, issuer: ca.subject, publicKey: csr.publicKey, signingKey: caKeys.privateKey, notBefore: new Date(Date.now() - 3600_000), notAfter: new Date(Date.now() + 365 * 86400_000), signingAlgorithm: ALG, extensions: [new x509.BasicConstraintsExtension(false, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true), san] });
    const chainEnv = `${leaf.toString('pem')}${ca.toString('pem')}`.replace(/\r?\n/g, '\\n');
    // ... and the two environment values go to the service: the key from the request, the returned chain
    const { svc, copies } = await receiveBatch(2, { ISSUER_SIGNING_KEY_JWK: r.keyEnv, ISSUER_CERT_CHAIN_PEM: chainEnv });
    expect(svc.local.publicJwk.kid).toBe(r.kid);
    for (const copy of copies) {
      const [jwt] = copy.credential.split('~');
      const header = JSON.parse(Buffer.from(jwt!.split('.')[0]!, 'base64url').toString());
      expect(header.x5c).toEqual([Buffer.from(leaf.rawData).toString('base64'), Buffer.from(ca.rawData).toString('base64')]);
      const trusted = validateX5cChain(header.x5c, [ca.toString('pem')]); // what a wallet with the CA in its trust list does
      expect(trusted.checkHost('rp.example.test')).toBe('rp.example.test');
      const { payload } = await jwtVerify(jwt!, await importX509(trusted.toString(), 'ES256'), { algorithms: ['ES256'] });
      expect(payload.iss).toBe('https://rp.example.test/issuer');
      expect(new URL(payload.iss as string).hostname).toBe('rp.example.test'); // matches the dNSName SAN
    }
    expect(svc.local.x5c).toHaveLength(2);
  });
});

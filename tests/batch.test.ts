import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { SignJWT, compactDecrypt, exportJWK, generateKeyPair, importPKCS8, type JWK } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { BATCH_SIZE, PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
async function walletProvider() {
  const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=Test Wallet Provider', notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: ALG, keys });
  const pkcs8 = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----`;
  return { x5c: Buffer.from(cert.rawData).toString('base64'), key: await importPKCS8(pkcs8, 'ES256') };
}
const attest = async (wp: Awaited<ReturnType<typeof walletProvider>>, claims: Record<string, unknown>) =>
  new SignJWT({ key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'], ...claims }).setProtectedHeader({ alg: 'ES256', typ: 'keyattestation+jwt', x5c: [wp.x5c] }).setIssuedAt().sign(wp.key);

async function setup() {
  const cfg = testConfig({ MOCK_MODE: 'false' });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  const o = svc.local.createOffer('account', { account_holder_name: 'Lena Demo', iban: 'DE02120300000000202051', bic: 'BYLADEM1001' });
  const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
  const token = (await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] })).body.access_token as string;
  const newKeys = async (n: number) => Promise.all(Array.from({ length: n }, async () => { const p = await generateKeyPair('ES256', { extractable: true }); return { priv: p.privateKey, jwk: await exportJWK(p.publicKey) }; }));
  const nonce = async () => (await request(app).post('/issuer/nonce')).body.c_nonce as string;
  const send = (proofs: unknown, extra: Record<string, unknown> = {}) =>
    request(app).post('/issuer/credential').set('Authorization', `Bearer ${token}`).send({ credential_configuration_id: offer.credential_configuration_ids[0], proofs, ...extra });
  const jwtProof = async (k: { priv: CryptoKey; jwk: JWK }, nonceValue: string, att?: string, aud = offer.credential_issuer as string) =>
    new SignJWT({ nonce: nonceValue }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', ...(att ? { key_attestation: att } : { jwk: k.jwk }) }).setAudience(aud).setIssuedAt().sign(k.priv);
  const cnfOf = (cred: string) => JSON.parse(Buffer.from(cred.split('~')[0]!.split('.')[1]!, 'base64url').toString()).cnf.jwk as JWK;
  return { app, svc, newKeys, nonce, send, jwtProof, cnfOf };
}

describe('batch issuance (HAIP wallets ask for several credentials per request)', () => {
  it('is declared in the issuer metadata', async () => {
    const { app } = await setup();
    const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body;
    expect(meta.batch_credential_issuance).toEqual({ batch_size: 10 });
    expect(BATCH_SIZE).toBe(10);
  });

  it('issues one credential per jwt proof, all sharing one c_nonce, each bound to its own key', async () => {
    const t = await setup();
    const keys = await t.newKeys(3);
    const wp = await walletProvider();
    const att = await attest(wp, { attested_keys: keys.map((k) => k.jwk) });
    const n = await t.nonce();
    const res = await t.send({ jwt: await Promise.all(keys.map((k) => t.jwtProof(k, n, att))) });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.credentials).toHaveLength(3);
    const cnfs = res.body.credentials.map((c: { credential: string }) => t.cnfOf(c.credential));
    expect(cnfs.map((j: JWK) => j.x)).toEqual(keys.map((k) => k.jwk.x));
    expect(new Set(res.body.credentials.map((c: { credential: string }) => c.credential)).size).toBe(3); // distinct credentials
    // the shared nonce is used up afterwards, the offer too
    expect((await t.send({ jwt: [await t.jwtProof(keys[0]!, n, att)] })).status).toBe(401);
  });

  it('an attestation proof covering several keys yields one credential per attested key', async () => {
    const t = await setup();
    const keys = await t.newKeys(4);
    const att = await attest(await walletProvider(), { attested_keys: keys.map((k) => k.jwk), nonce: await t.nonce() });
    const res = await t.send({ attestation: [att] });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.credentials.map((c: { credential: string }) => t.cnfOf(c.credential).x)).toEqual(keys.map((k) => k.jwk.x));
  });

  it('a single proof still gives exactly one credential (plus the legacy top-level field)', async () => {
    const t = await setup();
    const [k] = await t.newKeys(1);
    const res = await t.send({ jwt: [await t.jwtProof(k!, await t.nonce())] });
    expect(res.status).toBe(200);
    expect(res.body.credentials).toHaveLength(1);
    expect(res.body.credential).toBe(res.body.credentials[0].credential);
  });

  it('refuses more than the batch size, and a bad proof in a batch, without using up the offer or the nonce', async () => {
    const t = await setup();
    const keys = await t.newKeys(BATCH_SIZE + 1);
    const wp = await walletProvider();
    const att = await attest(wp, { attested_keys: keys.map((k) => k.jwk) });
    const n = await t.nonce();
    const tooMany = await t.send({ jwt: await Promise.all(keys.map((k) => t.jwtProof(k, n, att))) });
    expect(tooMany.status).toBe(400);
    expect(tooMany.body.error_description).toContain(`At most ${BATCH_SIZE}`);
    const tooManyAtt = await t.send({ attestation: [await attest(wp, { attested_keys: keys.map((k) => k.jwk), nonce: await t.nonce() })] });
    expect(tooManyAtt.status).toBe(400);
    // one good proof and one with the wrong audience
    const two = await t.newKeys(2);
    const attTwo = await attest(wp, { attested_keys: two.map((k) => k.jwk) });
    const bad = await t.send({ jwt: [await t.jwtProof(two[0]!, n, attTwo), await t.jwtProof(two[1]!, n, attTwo, 'https://evil.example')] });
    expect(bad.status).toBe(400);
    expect(bad.body.credentials).toBeUndefined();
    // nothing was consumed: the same nonce and the same token still work for a correct batch
    const ok = await t.send({ jwt: [await t.jwtProof(two[0]!, n, attTwo), await t.jwtProof(two[1]!, n, attTwo)] });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.credentials).toHaveLength(2);
  });

  it('a batch can come back encrypted', async () => {
    const t = await setup();
    const keys = await t.newKeys(3);
    const wallet = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const att = await attest(await walletProvider(), { attested_keys: keys.map((k) => k.jwk), nonce: await t.nonce() });
    const res = await t.send({ attestation: [att] }, { credential_response_encryption: { jwk: await exportJWK(wallet.publicKey), alg: 'ECDH-ES', enc: 'A128GCM' } })
      .buffer(true).parse((r, cb) => { let d = ''; r.on('data', (c: Buffer) => (d += c)); r.on('end', () => cb(null, d)); });
    expect(res.status).toBe(200);
    const { plaintext } = await compactDecrypt(res.body as string, wallet.privateKey);
    expect(JSON.parse(new TextDecoder().decode(plaintext)).credentials).toHaveLength(3);
  });
});

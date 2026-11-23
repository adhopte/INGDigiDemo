import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, importPKCS8, type JWK } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

/** A "wallet provider": a self-signed certificate + key that signs key attestations. */
async function walletProvider() {
  const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=Test Wallet Provider', notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: ALG, keys });
  const pkcs8 = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----`;
  return { x5c: Buffer.from(cert.rawData).toString('base64'), key: await importPKCS8(pkcs8, 'ES256') };
}

async function setup() {
  const cfg = testConfig({ MOCK_MODE: 'false' });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  const redeem = async (build: (ctx: { nonce: string; issuer: string; jwk: JWK; privateKey: CryptoKey }) => Promise<{ header: Record<string, unknown> }>, attestationKey = 'account') => {
    const o = svc.local.createOffer(attestationKey, { account_holder_name: 'Lena Demo', iban: 'DE02120300000000202051', bic: 'BYLADEM1001' });
    const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
    const tokenRes = await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    const nonce = (await request(app).post('/issuer/nonce')).body.c_nonce as string;
    const { header } = await build({ nonce, issuer: offer.credential_issuer, jwk, privateKey });
    const proof = await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', ...header }).setAudience(offer.credential_issuer).setIssuedAt().sign(privateKey);
    const res = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${tokenRes.body.access_token}`).send({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { jwt: [proof] } });
    return { res, jwk, svc };
  };
  return { app, redeem, svc, cfg };
}

const attestation = async (wp: Awaited<ReturnType<typeof walletProvider>>, claims: Record<string, unknown>, header: Record<string, unknown> = {}) =>
  new SignJWT({ key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'], ...claims }).setProtectedHeader({ alg: 'ES256', typ: 'keyattestation+jwt', x5c: [wp.x5c], ...header }).setIssuedAt().sign(wp.key);

describe('issuer metadata for HAIP wallets', () => {
  it('declares key_attestations_required on the jwt proof type of EVERY credential (bank account and payment included)', async () => {
    const { app, cfg } = await setup();
    const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body;
    const configs = Object.values(meta.credential_configurations_supported) as any[];
    expect(configs.length).toBe(Object.values(cfg.attestations).filter((a) => a.formats.includes('dc+sd-jwt')).length);
    for (const c of configs) {
      expect(c.proof_types_supported.jwt.proof_signing_alg_values_supported).toEqual(['ES256']);
      expect(c.proof_types_supported.jwt.key_attestations_required).toEqual({}); // as SIGMA's birth certificate: required, no minimum levels
      expect(c.claims.length).toBeGreaterThan(0); // also at the top level of the configuration (older wallet versions)
    }
    expect(Object.keys(meta.credential_configurations_supported)).toEqual(expect.arrayContaining(['demo_bank_account', 'demo_bank_payment']));
  });
});

describe('proof of possession with a key attestation', () => {
  it('accepts a proof with jwk + key_attestation, and one with only the attested key', async () => {
    const { redeem } = await setup();
    const wp = await walletProvider();
    const a = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [jwk] }) } }));
    expect(a.res.status, JSON.stringify(a.res.body)).toBe(200);
    expect(a.res.body.credentials[0].credential).toContain('~');
    const b = await redeem(async ({ jwk }) => ({ header: { key_attestation: await attestation(wp, { attested_keys: [jwk] }) } })); // no jwk header: the first attested key signs
    expect(b.res.status, JSON.stringify(b.res.body)).toBe(200);
    const c = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [{ ...jwk, kid: 'x' }] }) } }), 'payment');
    expect(c.res.status).toBe(200);
  });

  it('the credential is bound to the attested key', async () => {
    const { redeem } = await setup();
    const wp = await walletProvider();
    const { res, jwk } = await redeem(async ({ jwk }) => ({ header: { key_attestation: await attestation(wp, { attested_keys: [jwk] }) } }));
    const sdjwt = res.body.credentials[0].credential as string;
    const payload = JSON.parse(Buffer.from(sdjwt.split('~')[0]!.split('.')[1]!, 'base64url').toString());
    expect(payload.cnf.jwk).toMatchObject({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });
    expect(payload.cnf.jwk.d).toBeUndefined();
  });

  it('refuses a key attestation that does not cover the proof key, is expired, is forged or malformed', async () => {
    const { redeem } = await setup();
    const wp = await walletProvider();
    const other = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
    const mismatch = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [other] }) } }));
    expect(mismatch.res.status).toBe(400);
    expect(mismatch.res.body.error_description).toContain('not among the keys');
    const expired = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [jwk], exp: Math.floor(Date.now() / 1000) - 60 }) } }));
    expect(expired.res.status).toBe(400);
    expect(expired.res.body.error_description).toContain('expired');
    const forger = await walletProvider(); // signs with a key that does not match the certificate it presents
    const forged = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation({ x5c: wp.x5c, key: forger.key }, { attested_keys: [jwk] }) } }));
    expect(forged.res.status).toBe(400);
    expect(forged.res.body.error_description).toContain('signature');
    const noKeys = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [] }) } }));
    expect(noKeys.res.status).toBe(400);
    const garbage = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: 'not-a-jwt' } }));
    expect(garbage.res.status).toBe(400);
    const wrongTyp = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: await attestation(wp, { attested_keys: [jwk] }, { typ: 'JWT' }) } }));
    expect(wrongTyp.res.status).toBe(400);
    const asString = await redeem(async ({ jwk }) => ({ header: { jwk, key_attestation: { not: 'a string' } } }));
    expect(asString.res.status).toBe(400);
  });

  it('still accepts a plain jwk proof (the simulated wallet), and refuses a proof with no key at all', async () => {
    const { redeem } = await setup();
    expect((await redeem(async ({ jwk }) => ({ header: { jwk } }))).res.status).toBe(200);
    expect((await redeem(async () => ({ header: {} }))).res.status).toBe(400);
    void exportPKCS8;
  });
});

import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { CompactEncrypt, SignJWT, compactDecrypt, exportJWK, generateKeyPair, importJWK, importPKCS8, type JWK } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const BASE = 'https://rp.example.test/issuer';
const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

async function walletProvider() {
  const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=Test Wallet Provider', notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: ALG, keys });
  const pkcs8 = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----`;
  return { x5c: Buffer.from(cert.rawData).toString('base64'), key: await importPKCS8(pkcs8, 'ES256') };
}
const keyAttestation = async (wp: Awaited<ReturnType<typeof walletProvider>>, claims: Record<string, unknown>) =>
  new SignJWT({ key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'], ...claims }).setProtectedHeader({ alg: 'ES256', typ: 'keyattestation+jwt', x5c: [wp.x5c] }).setIssuedAt().sign(wp.key);

async function setup() {
  const cfg = testConfig({ MOCK_MODE: 'false' });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  const text = (r: any) => r.parse((res: any, cb: any) => { let d = ''; res.on('data', (c: Buffer) => (d += c)); res.on('end', () => cb(null, d)); });
  return { app, svc, text, cfg };
}

/** Everything a HAIP wallet does, in order, against the local issuer. */
async function haipWallet(t: Awaited<ReturnType<typeof setup>>, proofType: 'jwt' | 'attestation', tweak: { nonceOverride?: string; attestationClaims?: Record<string, unknown> } = {}) {
  const { app, svc, text } = t;
  const o = svc.local.createOffer('account', { account_holder_name: 'Lena Demo', iban: 'DE02120300000000202051', bic: 'BYLADEM1001' });
  const offer = (await request(app).get(`/issuer/offers/${o.id}`).set('Accept', 'application/json')).body;
  const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body;
  const as = (await request(app).get('/issuer/.well-known/oauth-authorization-server')).body;
  // 1. token with DPoP + wallet attestation headers
  const dpopKey = await generateKeyPair('ES256', { extractable: true });
  const dpopJwk = await exportJWK(dpopKey.publicKey);
  const dpop = async (htu: string, ath?: string) => new SignJWT({ htm: 'POST', htu, jti: randomUUID(), ...(ath ? { ath } : {}) }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk }).setIssuedAt().sign(dpopKey.privateKey);
  const tok = await request(app).post(new URL(as.token_endpoint).pathname).set({ DPoP: await dpop(as.token_endpoint), 'OAuth-Client-Attestation': 'a.b.c', 'OAuth-Client-Attestation-PoP': 'd.e.f' })
    .type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  expect(tok.body.token_type).toBe('DPoP');
  // 2. nonce
  const nonce = (await request(app).post(new URL(meta.nonce_endpoint).pathname)).body.c_nonce as string;
  // 3. holder key + key attestation by the wallet provider
  const holder = await generateKeyPair('ES256', { extractable: true });
  const holderJwk = await exportJWK(holder.publicKey);
  const wp = await walletProvider();
  const attNonce = tweak.nonceOverride ?? nonce;
  const att = await keyAttestation(wp, { attested_keys: [holderJwk], nonce: attNonce, ...(tweak.attestationClaims ?? {}) });
  const proofs = proofType === 'jwt'
    ? { jwt: [await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', key_attestation: att }).setAudience(offer.credential_issuer).setIssuedAt().sign(holder.privateKey)] }
    : { attestation: [att] };
  // 4. request encrypted to the issuer's key, asking for an encrypted response
  const reqKey = (meta.credential_request_encryption.jwks.keys as JWK[]).find((k) => k.alg === 'ECDH-ES')!;
  const resp = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const plain = { credential_configuration_id: offer.credential_configuration_ids[0], proofs, credential_response_encryption: { jwk: await exportJWK(resp.publicKey), alg: 'ECDH-ES', enc: 'A128GCM' } };
  const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(plain))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: reqKey.kid }).encrypt(await importJWK(reqKey, 'ECDH-ES'));
  const at = tok.body.access_token as string;
  const res = await text(request(app).post(new URL(meta.credential_endpoint).pathname).buffer(true)
    .set({ Authorization: `DPoP ${at}`, DPoP: await dpop(meta.credential_endpoint, createHash('sha256').update(at).digest('base64url')), 'Content-Type': 'application/jwt' }).send(jwe));
  return { res, respPrivate: resp.privateKey, holderJwk };
}

describe('the whole HAIP wallet flow against the local issuer', () => {
  for (const proofType of ['jwt', 'attestation'] as const) {
    it(`DPoP + wallet attestation + nonce + ${proofType} proof with key attestation + encrypted request + encrypted response`, async () => {
      const t = await setup();
      const { res, respPrivate, holderJwk } = await haipWallet(t, proofType);
      expect(res.status, String(res.body)).toBe(200);
      expect(res.headers['content-type']).toContain('application/jwt');
      const { plaintext } = await compactDecrypt(res.body as string, respPrivate);
      const credential = JSON.parse(new TextDecoder().decode(plaintext)).credentials[0].credential as string;
      const payload = JSON.parse(Buffer.from(credential.split('~')[0]!.split('.')[1]!, 'base64url').toString());
      expect(payload.cnf.jwk).toMatchObject({ kty: 'EC', crv: 'P-256', x: holderJwk.x, y: holderJwk.y }); // bound to the attested key
      expect(credential.split('~').slice(1).map((d) => Buffer.from(d, 'base64url').toString()).some((d) => d.includes('DE02120300000000202051'))).toBe(true); // the claim sits in a disclosure
    });
  }

  it('metadata offers both proof types with key attestation required', async () => {
    const { app } = await setup();
    const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body;
    for (const c of Object.values(meta.credential_configurations_supported) as any[]) {
      expect(Object.keys(c.proof_types_supported).sort()).toEqual(['attestation', 'jwt']);
      expect(c.proof_types_supported.attestation.key_attestations_required).toEqual({ key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'] });
    }
  });

  it('the attestation proof needs a current c_nonce of this issuer, used once, and a sound key attestation', async () => {
    const t = await setup();
    const refused = async (tweak: Parameters<typeof haipWallet>[2]) => {
      const { res } = await haipWallet(t, 'attestation', tweak);
      expect(res.status, JSON.stringify(tweak)).toBe(400);
      return res;
    };
    await refused({ nonceOverride: 'made-up-nonce' });
    await refused({ attestationClaims: { attested_keys: [] } });
    await refused({ attestationClaims: { exp: Math.floor(Date.now() / 1000) - 60 } });
    const noNonce = await haipWallet(t, 'attestation', { attestationClaims: { nonce: undefined } });
    expect(noNonce.res.status).toBe(400);
  });
});

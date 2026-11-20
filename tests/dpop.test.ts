import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const BASE = 'https://rp.example.test/issuer';

async function setup() {
  const cfg = testConfig({ MOCK_MODE: 'false' });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  const dpopKey = async (alg: 'ES256' | 'RS256' = 'ES256') => {
    const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
    return { alg, jwk: await exportJWK(publicKey), privateKey };
  };
  const proofWith = async (k: Awaited<ReturnType<typeof dpopKey>>, over: { htm?: string; htu?: string; ath?: string; iat?: number; jti?: string; typ?: string } = {}) =>
    new SignJWT({ htm: over.htm ?? 'POST', htu: over.htu ?? '', jti: over.jti ?? randomUUID(), ...(over.ath ? { ath: over.ath } : {}) })
      .setProtectedHeader({ typ: over.typ ?? 'dpop+jwt', alg: k.alg, jwk: k.jwk }).setIssuedAt(over.iat ?? Math.floor(Date.now() / 1000)).sign(k.privateKey);
  const ath = (t: string) => createHash('sha256').update(t).digest('base64url');
  const newOffer = () => {
    const o = svc.local.createOffer('account', { account_holder_name: 'Lena Demo', iban: 'DE02120300000000202051', bic: 'BYLADEM1001' });
    return request(app).get(`/issuer/offers/${o.id}`).then((r) => r.body);
  };
  const credential = async (token: string, headers: Record<string, string>) => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const nonce = (await request(app).post('/issuer/nonce')).body.c_nonce as string;
    const proof = await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(publicKey) }).setAudience(BASE).setIssuedAt().sign(privateKey);
    void token;
    return (conf: string) => request(app).post('/issuer/credential').set(headers).send({ credential_configuration_id: conf, proofs: { jwt: [proof] } });
  };
  return { app, svc, dpopKey, proofWith, ath, newOffer, credential };
}

describe('DPoP (RFC 9449) on the local issuer', () => {
  it('is advertised in the authorization-server metadata, like the SIGMA issuer', async () => {
    const { app } = await setup();
    const as = (await request(app).get('/issuer/.well-known/oauth-authorization-server')).body;
    expect(as.dpop_signing_alg_values_supported).toEqual(['ES256', 'RS256', 'RS384', 'RS512']);
    expect(as.client_attestation_signing_alg_values_supported).toContain('ES256');
    expect(as.client_attestation_pop_signing_alg_values_supported).toContain('ES256');
    expect(as.token_endpoint_auth_methods_supported).toContain('attest_jwt_client_auth');
  });

  it('full flow: DPoP-bound token, credential request with DPoP scheme + proof (ES256 and RS256 keys)', async () => {
    const t = await setup();
    for (const alg of ['ES256', 'RS256'] as const) {
      const offer = await t.newOffer();
      const k = await t.dpopKey(alg);
      const tok = await request(t.app).post('/issuer/token').set('DPoP', await t.proofWith(k, { htu: `${BASE}/token` })).type('form')
        .send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
      expect(tok.status, JSON.stringify(tok.body)).toBe(200);
      expect(tok.body.token_type).toBe('DPoP');
      const send = await t.credential(tok.body.access_token, { Authorization: `DPoP ${tok.body.access_token}`, DPoP: await t.proofWith(k, { htu: `${BASE}/credential`, ath: t.ath(tok.body.access_token) }) });
      const res = await send(offer.credential_configuration_ids[0]);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.credentials[0].credential).toContain('~');
    }
  });

  it('without a DPoP header the token is a plain Bearer token (simulated wallet, simple clients)', async () => {
    const t = await setup();
    const offer = await t.newOffer();
    const tok = await request(t.app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
    expect(tok.body.token_type).toBe('Bearer');
    const send = await t.credential(tok.body.access_token, { Authorization: `Bearer ${tok.body.access_token}` });
    expect((await send(offer.credential_configuration_ids[0])).status).toBe(200);
  });

  it('refuses a bound token used without, or with the wrong, DPoP proof — and keeps it usable afterwards', async () => {
    const t = await setup();
    const offer = await t.newOffer();
    const k = await t.dpopKey();
    const tok = (await request(t.app).post('/issuer/token').set('DPoP', await t.proofWith(k, { htu: `${BASE}/token` })).type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] })).body.access_token as string;
    const conf = offer.credential_configuration_ids[0];
    const attempt = async (headers: Record<string, string>) => (await t.credential(tok, headers))(conf);
    const good = async (over = {}) => ({ Authorization: `DPoP ${tok}`, DPoP: await t.proofWith(k, { htu: `${BASE}/credential`, ath: t.ath(tok), ...over }) });
    const other = await t.dpopKey();
    const cases: Array<[string, Record<string, string>]> = [
      ['bearer scheme', { Authorization: `Bearer ${tok}` }],
      ['dpop scheme without proof', { Authorization: `DPoP ${tok}` }],
      ['proof by another key', { Authorization: `DPoP ${tok}`, DPoP: await t.proofWith(other, { htu: `${BASE}/credential`, ath: t.ath(tok) }) }],
      ['wrong ath', await good({ ath: t.ath('other-token') })],
      ['no ath', await good({ ath: undefined })],
      ['wrong htu (token endpoint)', await good({ htu: `${BASE}/token` })],
      ['wrong htm', await good({ htm: 'GET' })],
      ['stale iat', await good({ iat: Math.floor(Date.now() / 1000) - 3600 })],
      ['wrong typ', await good({ typ: 'JWT' })],
    ];
    for (const [name, h] of cases) {
      const r = await attempt(h);
      expect(r.status, name).toBe(401);
      expect(r.body.error, name).toBe('invalid_dpop_proof');
    }
    // not consumed: a correct request still succeeds ...
    const h = await good();
    expect((await attempt(h)).status).toBe(200);
  });

  it('a DPoP proof cannot be replayed', async () => {
    const t = await setup();
    const k = await t.dpopKey();
    const proof = await t.proofWith(k, { htu: `${BASE}/token`, jti: 'fixed-jti' });
    const o1 = await t.newOffer();
    const first = await request(t.app).post('/issuer/token').set('DPoP', proof).type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': o1.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
    expect(first.status).toBe(200);
    const o2 = await t.newOffer();
    const replay = await request(t.app).post('/issuer/token').set('DPoP', proof).type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': o2.grants[PRE_AUTH_GRANT]['pre-authorized_code'] });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_dpop_proof');
  });

  it('a bad DPoP proof at the token endpoint is refused BEFORE the pre-authorized code is used up', async () => {
    const t = await setup();
    const offer = await t.newOffer();
    const code = offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'];
    const k = await t.dpopKey();
    const send = (dpop?: string) => request(t.app).post('/issuer/token').set(dpop ? { DPoP: dpop } : {}).type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code });
    for (const bad of [await t.proofWith(k, { htu: 'https://evil.example/token' }), await t.proofWith(k, { htu: `${BASE}/token`, typ: 'JWT' }), 'garbage']) {
      const r = await send(bad);
      expect(r.status).toBe(400);
      expect(r.body.error).toBe('invalid_dpop_proof');
    }
    expect((await send(await t.proofWith(k, { htu: `${BASE}/token` }))).status).toBe(200); // the code was still there
  });
});

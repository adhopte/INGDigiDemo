import 'reflect-metadata';
import { CompactEncrypt, SignJWT, compactDecrypt, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

async function setup() {
  const cfg = testConfig({ MOCK_MODE: 'false' });
  const svc = await createServices(cfg);
  const app = createApp(cfg, svc);
  /** Token once, then any number of credential attempts (each with a fresh nonce-bound proof). */
  const session = async (attestationKey = 'account') => {
    const o = svc.local.createOffer(attestationKey, { account_holder_name: 'Lena Demo', iban: 'DE02120300000000202051', bic: 'BYLADEM1001' });
    const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
    const token = (await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] })).body.access_token as string;
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    const attempt = async (extra: Record<string, unknown>) => {
      const nonce = (await request(app).post('/issuer/nonce')).body.c_nonce as string;
      const proof = await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk }).setAudience(offer.credential_issuer).setIssuedAt().sign(privateKey);
      return request(app).post('/issuer/credential').set('Authorization', `Bearer ${token}`).buffer(true).parse((res, cb) => { let d = ''; res.on('data', (c: Buffer) => (d += c)); res.on('end', () => cb(null, d)); })
        .send({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { jwt: [proof] }, ...extra });
    };
    /** Like attempt, but the caller turns the plain request into the body to send (a compact JWE for an encrypted request). */
    const attemptRaw = async (make: (plain: Record<string, unknown>) => Promise<string>) => {
      const nonce = (await request(app).post('/issuer/nonce')).body.c_nonce as string;
      const proof = await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk }).setAudience(offer.credential_issuer).setIssuedAt().sign(privateKey);
      const jwe = await make({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { jwt: [proof] } });
      return request(app).post('/issuer/credential').set('Authorization', `Bearer ${token}`).set('Content-Type', 'application/jwt').buffer(true).parse((res, cb) => { let d = ''; res.on('data', (c: Buffer) => (d += c)); res.on('end', () => cb(null, d)); }).send(jwe);
    };
    return { attempt, attemptRaw };
  };
  return { app, session };
}

describe('credential response encryption (HAIP wallets)', () => {
  it('is declared in the issuer metadata, together with request encryption (a HAIP wallet insists on both)', async () => {
    const { app } = await setup();
    const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body;
    expect(meta.credential_response_encryption).toEqual({ alg_values_supported: ['ECDH-ES', 'RSA-OAEP-256'], enc_values_supported: ['A128GCM', 'A256GCM'], encryption_required: false });
    const req = meta.credential_request_encryption;
    expect(req.encryption_required).toBe(false);
    expect(req.enc_values_supported).toEqual(['A128GCM', 'A192GCM', 'A256GCM']);
    expect(req.jwks.keys.map((k: JWK) => [k.kty, k.alg, k.use])).toEqual([['EC', 'ECDH-ES', 'enc'], ['RSA', 'RSA-OAEP-256', 'enc']]);
    for (const k of req.jwks.keys) { expect(k.kid).toMatch(/^[A-Za-z0-9_-]{16}$/); expect(k.d).toBeUndefined(); expect(k.p).toBeUndefined(); }
  });

  it('answers with a JWE the wallet can decrypt when it asks for encryption (ECDH-ES P-256 + A128GCM)', async () => {
    const { session } = await setup();
    const { attempt } = await session();
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: 'wallet-1' };
    const res = await attempt({ credential_response_encryption: { jwk, alg: 'ECDH-ES', enc: 'A128GCM' } });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/jwt');
    expect(String(res.body).split('.')).toHaveLength(5); // compact JWE
    const { plaintext, protectedHeader } = await compactDecrypt(res.body as string, privateKey);
    expect(protectedHeader).toMatchObject({ alg: 'ECDH-ES', enc: 'A128GCM', kid: 'wallet-1' });
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    expect(payload.credentials[0].credential).toContain('~');
    expect(String(res.body)).not.toContain('~'); // nothing readable on the wire
  });

  it('supports RSA-OAEP-256 with A256GCM', async () => {
    const { session } = await setup();
    const { attempt } = await session('payment');
    const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256', { modulusLength: 2048, extractable: true });
    const res = await attempt({ credential_response_encryption: { jwk: await exportJWK(publicKey), alg: 'RSA-OAEP-256', enc: 'A256GCM' } });
    expect(res.status).toBe(200);
    const { plaintext } = await compactDecrypt(res.body as string, privateKey);
    expect(JSON.parse(new TextDecoder().decode(plaintext)).credentials).toHaveLength(1);
  });

  it('without the request parameter the response stays plain JSON (simulated wallet, plain clients)', async () => {
    const { session } = await setup();
    const res = await (await session()).attempt({});
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(JSON.parse(res.body as string).credentials[0].credential).toContain('~');
  });

  it('refuses unsupported or unusable parameters BEFORE issuing, so the offer is not consumed', async () => {
    const { session } = await setup();
    const { attempt } = await session();
    const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const jwk = await exportJWK(publicKey);
    const bad = async (p: unknown) => {
      const r = await attempt({ credential_response_encryption: p });
      expect(r.status, JSON.stringify(p)).toBe(400);
      expect(JSON.parse(r.body as string).error).toBe('invalid_encryption_parameters');
    };
    await bad({ jwk, alg: 'A128KW', enc: 'A128GCM' });
    await bad({ jwk, alg: 'ECDH-ES', enc: 'A128CBC-HS256' });
    await bad({ jwk: { ...jwk, d: 'secret' }, alg: 'ECDH-ES', enc: 'A128GCM' });
    await bad({ jwk, alg: 'RSA-OAEP-256', enc: 'A128GCM' }); // an EC key cannot serve RSA
    await bad({ alg: 'ECDH-ES', enc: 'A128GCM' });
    await bad('nope');
    // the same access token still works afterwards: nothing was issued
    const ok = await attempt({});
    expect(ok.status).toBe(200);
  });

  it('accepts a Credential Request encrypted to the issuer key (EC and RSA), and answers encrypted when asked', async () => {
    const { app, session } = await setup();
    const keys = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).body.credential_request_encryption.jwks.keys as JWK[];
    for (const [alg, enc] of [['ECDH-ES', 'A128GCM'], ['RSA-OAEP-256', 'A256GCM']] as const) {
      const { attemptRaw } = await session();
      const issuerKey = keys.find((k) => k.alg === alg)!;
      const wallet = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
      const res = await attemptRaw(async (plain) => new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ ...plain, credential_response_encryption: { jwk: await exportJWK(wallet.publicKey), alg: 'ECDH-ES', enc: 'A128GCM' } })))
        .setProtectedHeader({ alg, enc, kid: issuerKey.kid }).encrypt(await importJWK(issuerKey, alg)));
      expect(res.status, alg).toBe(200);
      expect(res.headers['content-type']).toContain('application/jwt');
      const { plaintext } = await compactDecrypt(res.body as string, wallet.privateKey);
      expect(JSON.parse(new TextDecoder().decode(plaintext)).credentials[0].credential).toContain('~');
    }
  });

  it('an encrypted request without response encryption gets a plain response; bad JWEs are refused without consuming the offer', async () => {
    const { app, session } = await setup();
    const issuerKey = ((await request(app).get('/issuer/.well-known/openid-credential-issuer')).body.credential_request_encryption.jwks.keys as JWK[])[0]!;
    const encryptFor = async (plain: unknown, key: JWK, alg: string, enc = 'A128GCM', kid: string | undefined = key.kid) =>
      new CompactEncrypt(new TextEncoder().encode(JSON.stringify(plain))).setProtectedHeader({ alg, enc, ...(kid ? { kid } : {}) }).encrypt(await importJWK(key, alg));
    const { attemptRaw } = await session();
    const refused = async (make: (plain: unknown) => Promise<string> | string) => {
      const r = await attemptRaw(async (p) => make(p));
      expect(r.status).toBe(400);
      expect(JSON.parse(r.body as string).error).toBe('invalid_credential_request');
    };
    await refused(() => 'not.a.jwe');
    await refused(async (p) => encryptFor(p, (await (async () => { const o = await exportJWK((await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true })).publicKey); return o; })()), 'ECDH-ES', 'A128GCM', 'unknown-kid')); // encrypted to a key this issuer does not have
    await refused((p) => encryptFor(p, issuerKey, 'ECDH-ES', 'A128CBC-HS256' as string)); // enc not supported
    const ok = await attemptRaw((p) => encryptFor(p, issuerKey, 'ECDH-ES')); // the very same access token still works
    expect(ok.status).toBe(200);
    expect(ok.headers['content-type']).toContain('application/json');
    expect(JSON.parse(ok.body as string).credentials[0].credential).toContain('~');
  });
});

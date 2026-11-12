import { SignJWT, exportJWK, generateKeyPair, importJWK, compactDecrypt, CompactEncrypt } from 'jose';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { presentSdJwt, verifySdJwtPresentation } from '../src/sdjwt/index.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

async function boot(env: Record<string, string> = {}) {
  const cfg = testConfig(env);
  const svc = await createServices(cfg);
  return { cfg, svc, app: createApp(cfg, svc) };
}

/** What a real wallet app does, over HTTP: fetch offer, token, nonce-bound proof, credential. */
async function walletRedeem(app: Parameters<typeof request>[0], offerPath: string, txCode?: string) {
  const offer = (await request(app).get(offerPath)).body;
  const grant = offer.grants[PRE_AUTH_GRANT];
  const tokenRes = await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': grant['pre-authorized_code'], ...(txCode ? { tx_code: txCode } : {}) });
  if (tokenRes.status !== 200) return { tokenRes };
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const { body: n } = await request(app).post('/issuer/nonce');
  const proof = await new SignJWT({ nonce: n.c_nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk }).setAudience(offer.credential_issuer).setIssuedAt().sign(privateKey);
  const credRes = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${tokenRes.body.access_token}`).send({ credential_configuration_id: offer.credential_configuration_ids[0], proofs: { jwt: [proof] } });
  return { tokenRes, credRes, privateKey, offer };
}

describe('platform basics', () => {
  it('healthz, security headers, no x-powered-by', async () => {
    const { app } = await boot();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    const home = await request(app).get('/');
    expect(home.headers['content-security-policy']).toContain("script-src 'self'");
    expect(home.headers['content-security-policy']).not.toContain('unsafe-inline');
    expect(home.headers['x-powered-by']).toBeUndefined();
  });

  it('selects language from ?lang, cookie and Accept-Language, falling back to English', async () => {
    const { app } = await boot();
    const mt = await request(app).get('/?lang=mt');
    expect(mt.text).toContain('<html lang="mt">');
    expect([mt.headers['set-cookie']].flat().join(';')).toContain('lang=mt');
    expect((await request(app).get('/').set('Accept-Language', 'de-DE,de;q=0.9,en;q=0.5')).text).toContain('<html lang="de">');
    expect((await request(app).get('/').set('Cookie', 'lang=sv')).text).toContain('<html lang="sv">');
    expect((await request(app).get('/?lang=xx')).text).toContain('<html lang="en">');
    expect((await request(app).get('/').set('Accept-Language', 'ja')).text).toContain('<html lang="en">');
  });

  it('dashboard lists the four RPs and the language switcher offers all eight languages', async () => {
    const { app } = await boot();
    const t = (await request(app).get('/')).text;
    for (const n of ['Demo Bank', 'Demo eShop', 'Demo University', 'Demo Power Co']) expect(t).toContain(n);
    for (const c of ['en', 'fr', 'es', 'nl', 'de', 'da', 'mt', 'sv']) expect(t).toContain(`hreflang="${c}"`);
  });

  it('mock banner and simulated wallet exist only in MOCK_MODE', async () => {
    const mock = await boot();
    expect((await request(mock.app).get('/')).text).toContain('mock-banner');
    expect((await request(mock.app).get('/wallet')).status).toBe(200);
    const live = await boot({ MOCK_MODE: 'false' });
    expect((await request(live.app).get('/')).text).not.toContain('mock-banner');
    expect((await request(live.app).get('/wallet')).status).toBe(404);
  });
});

describe('diagnostics and caching', () => {
  it('/vp/diagnostics exists only when enabled and records wallet metadata and rejections without claim values', async () => {
    const off = await boot({ DIAGNOSTICS_ENDPOINT: 'false' });
    expect((await request(off.app).get('/vp/diagnostics')).status).toBe(404);
    const { app, svc, cfg } = await boot();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    await request(app).post(`/vp/request/${tx.id}`).type('form').send({ wallet_metadata: JSON.stringify({ vp_formats_supported: { mso_mdoc: {} } }) });
    await request(app).post(`/vp/response/${tx.id}`).type('form').send({ vp_token: 'junk', state: 'x' });
    const d = (await request(app).get('/vp/diagnostics')).body.events;
    expect(d.map((e: any) => e.event)).toEqual(['response_rejected', 'wallet_fetched_request']);
    expect(d[1].walletMetadata).toContain('mso_mdoc');
    expect(d[0].detail).toBeTruthy();
  });

  it('static assets are revalidated and asset URLs carry a build version', async () => {
    const { app } = await boot();
    const css = await request(app).get('/css/base.css');
    expect(css.headers['cache-control']).toBe('public, max-age=0, must-revalidate');
    expect((await request(app).get('/fonts/inter-latin-wght-normal.woff2')).headers['cache-control']).toContain('max-age=604800');
    const home = (await request(app).get('/')).text;
    expect(home).toMatch(/\/css\/base\.css\?v=[A-Za-z0-9]+/);
    expect(home).toMatch(/\/img\/in-groupe-logo\.svg\?v=[A-Za-z0-9]+/);
  });
});

describe('OpenID4VCI issuer over HTTP', () => {
  it('serves issuer, authorization-server and JWT VC issuer metadata', async () => {
    const { app, cfg } = await boot();
    const md = (await request(app).get('/.well-known/openid-credential-issuer/issuer')).body;
    expect(md.credential_issuer).toBe('https://rp.example.test/issuer');
    expect(md.credential_endpoint).toBe('https://rp.example.test/issuer/credential');
    expect(Object.keys(md.credential_configurations_supported).sort()).toEqual(Object.values(cfg.attestations).map((a) => a.credentialConfigurationId).sort());
    expect(md.credential_configurations_supported.demo_bank_payment.format).toBe('dc+sd-jwt');
    const as = (await request(app).get('/.well-known/oauth-authorization-server/issuer')).body;
    expect(as['pre-authorized_grant_anonymous_access_supported']).toBe(true);
    expect((await request(app).get('/issuer/.well-known/openid-credential-issuer')).status).toBe(200);
    expect((await request(app).get('/.well-known/jwt-vc-issuer/issuer')).body.jwks.keys).toHaveLength(1);
  });

  it('pre-authorised code flow: wallet gets an SD-JWT VC the verifier accepts; the code is single use', async () => {
    const { app, svc, cfg } = await boot();
    const o = svc.local.createOffer('payment', { account_holder_name: 'Test Holder', iban: 'XX00 DEMO 0000 0000 01', bic: 'DEMOBKXX', bank_name: 'Demo Bank', valid_until: '2028-01-01' });
    const r = await walletRedeem(app, `/issuer/offers/${o.id}`);
    expect(r.credRes!.status).toBe(200);
    const credential = r.credRes!.body.credentials[0].credential as string;

    const tx = await svc.verifier.createTransaction(cfg.rps.find((x) => x.id === 'eshop')!, 'payment', '/eshop/');
    const vp = await presentSdJwt({ credential, reveal: ['iban', 'account_holder_name'], holderPrivateKey: r.privateKey!, aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    const { createIssuerKeyResolver } = await import('../src/verifier/trust.js');
    const v = await verifySdJwtPresentation(vp, { resolveIssuerKey: createIssuerKeyResolver(cfg, svc.local), acceptedVcts: cfg.attestations.payment!.acceptedVct, aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    expect(v.claims).toEqual({ iban: 'XX00 DEMO 0000 0000 01', account_holder_name: 'Test Holder' });

    // offer object is gone once redeemed; replaying the code fails
    expect((await request(app).get(`/issuer/offers/${o.id}`)).status).toBe(404);
  });

  it('rejects a reused code, missing/invalid proof, bad token and wrong tx_code', async () => {
    const { app, svc } = await boot({ ISSUER_TX_CODE: 'true' });
    const o = svc.local.createOffer('account', { given_name: 'A' });
    const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
    const grant = offer.grants[PRE_AUTH_GRANT];
    expect(grant.tx_code.length).toBe(4);
    const code = grant['pre-authorized_code'];

    const wrong = await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, tx_code: '0000x' });
    expect(wrong.status).toBe(400); expect(wrong.body.error).toBe('invalid_grant');
    const ok = await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, tx_code: o.txCode });
    expect(ok.status).toBe(200);
    const reuse = await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, tx_code: o.txCode });
    expect(reuse.status).toBe(400);

    const noProof = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${ok.body.access_token}`).send({});
    expect(noProof.status).toBe(400); expect(noProof.body.error).toBe('invalid_proof'); expect(noProof.body.c_nonce).toBeTruthy();
    const badProof = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${ok.body.access_token}`).send({ proof: { proof_type: 'jwt', jwt: 'a.b.c' } });
    expect(badProof.status).toBe(400); expect(badProof.body.error).toBe('invalid_proof');
    expect((await request(app).post('/issuer/credential').set('Authorization', 'Bearer nope').send({})).status).toBe(401);
    expect((await request(app).post('/issuer/token').type('form').send({ grant_type: 'password' })).body.error).toBe('unsupported_grant_type');
  });

  it('proof with a replayed nonce or wrong audience is refused', async () => {
    const { app, svc } = await boot();
    const mk = async (aud: string, nonce: string) => {
      const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
      return new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(publicKey) }).setAudience(aud).setIssuedAt().sign(privateKey);
    };
    const tok = async () => {
      const o = svc.local.createOffer('account', { given_name: 'A' });
      const offer = (await request(app).get(`/issuer/offers/${o.id}`)).body;
      return (await request(app).post('/issuer/token').type('form').send({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'] })).body;
    };
    const t1 = await tok();
    const wrongAud = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${t1.access_token}`).send({ proofs: { jwt: [await mk('https://other.example', t1.c_nonce)] } });
    expect(wrongAud.status).toBe(400);
    const t2 = await tok();
    const badNonce = await request(app).post('/issuer/credential').set('Authorization', `Bearer ${t2.access_token}`).send({ proofs: { jwt: [await mk('https://rp.example.test/issuer', 'made-up')] } });
    expect(badNonce.status).toBe(400);
  });
});

describe('OpenID4VP verifier over HTTP (what a wallet calls)', () => {
  it.each(['direct_post', 'direct_post.jwt'])('request_uri → signed request object → response_uri (%s)', async (mode) => {
    const { app, svc, cfg } = await boot({ VP_RESPONSE_MODE: mode });
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    // issue a PID via the local issuer first
    const o = svc.local.createOffer('pid', { given_name: 'Lena', family_name: 'Demo', birth_date: '1990-01-01', birth_place: 'Köln', nationality: 'DE', resident_address: 'Weg 1, Köln', issuing_country: 'DE' });
    const r = await walletRedeem(app, `/issuer/offers/${o.id}`);
    const credential = r.credRes!.body.credential as string;

    const tx = await svc.verifier.createTransaction(rp, 'pid', '/bank/kyc');
    const reqRes = await request(app).post(`/vp/request/${tx.id}`).type('form').send({ wallet_nonce: 'abc' });
    expect(reqRes.status).toBe(200);
    expect(reqRes.headers['content-type']).toContain('application/oauth-authz-req+jwt');
    const claims = JSON.parse(Buffer.from(reqRes.text.split('.')[1]!, 'base64url').toString());
    expect(claims.nonce).toBe(tx.nonce); expect(claims.wallet_nonce).toBe('abc'); expect(claims.response_mode).toBe(mode);

    const vp = await presentSdJwt({ credential, reveal: claims.dcql_query.credentials[0].claims.map((c: any) => c.path[0]), holderPrivateKey: r.privateKey!, aud: claims.client_id, nonce: claims.nonce });
    const body = { vp_token: { pid: [vp] }, state: claims.state };
    let post;
    if (mode === 'direct_post.jwt') {
      const enc = await importJWK(claims.client_metadata.jwks.keys[0], 'ECDH-ES');
      const response = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(body))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: claims.client_metadata.jwks.keys[0].kid }).encrypt(enc);
      post = await request(app).post(`/vp/response/${tx.id}`).type('form').send({ response });
      // plain (unencrypted) responses are refused in this mode
      const tx2 = await svc.verifier.createTransaction(rp, 'pid', '/');
      expect((await request(app).post(`/vp/response/${tx2.id}`).type('form').send({ vp_token: JSON.stringify(body.vp_token), state: tx2.state })).status).toBe(400);
    } else {
      post = await request(app).post(`/vp/response/${tx.id}`).type('form').send({ vp_token: JSON.stringify(body.vp_token), state: body.state });
    }
    expect(post.status).toBe(200);
    expect(post.body.redirect_uri).toContain(`/bank/verify/finish/${tx.id}?response_code=`);
    expect(tx.status).toBe('complete');
    expect(tx.result!.byType.pid!.given_name).toBe('Lena');
    void compactDecrypt;
  });

  it('returns 404 for unknown request ids and 400 for malformed responses', async () => {
    const { app, svc, cfg } = await boot();
    expect((await request(app).get('/vp/request/nope')).status).toBe(404);
    expect((await request(app).post('/vp/response/nope').type('form').send({ vp_token: 'x' })).status).toBe(400);
    const tx = await svc.verifier.createTransaction(cfg.rps[0]!, 'pid', '/');
    const bad = await request(app).post(`/vp/response/${tx.id}`).type('form').send({ vp_token: 'not-an-sdjwt', state: tx.state });
    expect(bad.status).toBe(400);
    expect(tx.status).toBe('failed');
  });

  it('encrypted wallet error response (HAIP default) marks the transaction as declined', async () => {
    const { svc, cfg } = await boot();
    const tx = await svc.verifier.createTransaction(cfg.rps[0]!, 'pid', '/');
    const { respondToVerifier } = await import('../src/mock/wallet.js');
    await expect(respondToVerifier(svc.verifier, tx, { error: 'access_denied' })).rejects.toThrow();
    expect(tx.errorCode).toBe('wallet_declined');
  });

  it('wallet error response (access_denied) marks the transaction as declined', async () => {
    const { app, svc, cfg } = await boot({ VP_RESPONSE_MODE: 'direct_post' });
    const tx = await svc.verifier.createTransaction(cfg.rps[0]!, 'pid', '/');
    const res = await request(app).post(`/vp/response/${tx.id}`).type('form').send({ error: 'access_denied', state: tx.state });
    expect(res.status).toBe(400);
    expect(tx.errorCode).toBe('wallet_declined');
  });
});

describe('RP flows in the browser session', () => {
  it('bank login starts a verification bound to the session; other sessions cannot see it', async () => {
    const { app } = await boot();
    const a = request.agent(app);
    const login = await a.get('/bank/login');
    expect(login.status).toBe(302);
    const start = await a.get(login.headers.location!); // /bank/verify?p=pid… creates the transaction and redirects to its page
    expect(start.status).toBe(302);
    const verify = await a.get(start.headers.location!);
    expect(verify.status).toBe(200);
    expect(verify.text).toContain('openid4vp://authorize?client_id=x509_hash%3A');
    expect(verify.text).toContain('data:image/png;base64');
    expect(verify.text).toContain('alt="QR code for the wallet presentation request');
    const id = /\/verify\/([0-9a-f-]{36})/.exec(start.headers.location!)![1]!;
    expect((await a.get(`/bank/verify/status/${id}`)).body.status).toBe('pending');
    expect((await request(app).get(`/bank/verify/status/${id}`)).status).toBe(404); // another browser
    expect((await request(app).get(`/bank/verify/finish/${id}`)).status).toBe(403);
  });

  it('protected pages redirect to the wallet login; open redirects are refused', async () => {
    const { app } = await boot();
    expect((await request(app).get('/bank/account')).headers.location).toBe('/bank/login');
    expect((await request(app).get('/electricity/account')).headers.location).toBe('/electricity/login');
    expect((await request(app).get('/eshop/order')).headers.location).toBe('/eshop/cart');
    expect((await request(app).get('/university/enrol')).headers.location).toBe('/university/documents');
    const a = request.agent(app);
    const r = await a.get('/bank/verify?p=pid&returnTo=//evil.example');
    expect(r.status).toBe(302);
    const { safeReturnTo } = await import('../src/rps/context.js');
    expect(safeReturnTo({ id: 'bank' }, '//evil.example')).toBe('/bank/');
    expect(safeReturnTo({ id: 'bank' }, 'https://evil.example')).toBe('/bank/');
    expect(safeReturnTo({ id: 'bank' }, '/eshop/')).toBe('/bank/');
    expect(safeReturnTo({ id: 'bank' }, '/bank/kyc')).toBe('/bank/kyc');
  });

  it('university requests PID and BC separately, or together with MULTI_CREDENTIAL', async () => {
    const two = await boot();
    expect((await request(two.app).get('/university/start')).headers.location).toBe('/university/documents');
    const one = await boot({ MULTI_CREDENTIAL: 'true' });
    expect((await request(one.app).get('/university/start')).headers.location).toContain('/university/verify?p=pid_bc');
  });

  it('unknown presentation is a 400, not a crash', async () => {
    const { app } = await boot();
    const r = await request(app).get('/bank/verify?p=nope');
    expect(r.status).toBe(400); // friendly error page, no stack trace or internals leaked
    expect(r.text).not.toContain('Unknown presentation');
  });
});

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

describe('redirect_uri client identifier (unsigned, by value)', () => {
  it('client_id equals the response_uri, the link is QR-sized, and a presentation verifies end to end', async () => {
    const { app, svc, cfg } = await boot({ VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    const o = svc.local.createOffer('pid', { given_name: 'Lena', family_name: 'Demo', birth_date: '1990-01-01', birth_place: 'Köln', nationality: 'DE', resident_address: 'Weg 1', issuing_country: 'DE' });
    const r = await walletRedeem(app, `/issuer/offers/${o.id}`);
    for (const pres of ['pid', 'pid_any_sd']) {
      const tx = await svc.verifier.createTransaction(rp, pres, '/bank/');
      expect(svc.verifier.clientIdFor(tx)).toBe(`redirect_uri:${svc.verifier.responseUri(tx)}`);
      const link = new URL(svc.verifier.walletLink(tx));
      expect(link.searchParams.get('client_id')).toBe(svc.verifier.clientIdFor(tx));
      expect(link.searchParams.get('response_uri')).toBe(svc.verifier.responseUri(tx));
      expect(link.searchParams.get('request_uri')).toBeNull();
      expect(JSON.parse(link.searchParams.get('dcql_query')!).credentials.map((c: any) => c.format)).toEqual(pres === 'pid' ? ['mso_mdoc', 'dc+sd-jwt'] : ['dc+sd-jwt']); // mdoc preferred + SD-JWT for the simulated wallet; the pid_any_sd probe is SD-JWT only
      expect(svc.verifier.walletLink(tx).length).toBeLessThan(2400); // both formats: still fits a QR code (the phone-camera QR / button are the easy paths)
      expect((await request(app).get(`/vp/request/${tx.id}`)).status).toBe(404); // nothing to fetch: not signed, by value
      const vp = await presentSdJwt({ credential: r.credRes!.body.credential, reveal: ['given_name', 'family_name', 'birth_date'], holderPrivateKey: r.privateKey!, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
      const body = { vp_token: JSON.stringify({ pid: [vp] }), state: tx.state };
      const { respondToVerifier } = await import('../src/mock/wallet.js');
      await respondToVerifier(svc.verifier, tx, { vp_token: { pid: [vp] } });
      expect(tx.status).toBe('complete');
      void body;
    }
  });
});

describe('same-device vs cross-device response (redirect_uri scheme)', () => {
  it('a QR scanned on another screen gets no redirect; the button on this device does; a stranger browser sees a friendly page', async () => {
    const { app, svc, cfg } = await boot({ VP_CLIENT_ID_SCHEME: 'redirect_uri', MOCK_MODE: 'false', VP_RESPONSE_MODE: 'direct_post' });
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    const o = svc.local.createOffer('pid', { given_name: 'Lena', family_name: 'Demo', birth_date: '1990-01-01', birth_place: 'Köln', nationality: 'DE', resident_address: 'Weg 1', issuing_country: 'DE' });
    const r = await walletRedeem(app, `/issuer/offers/${o.id}`);
    const present = async (state: (tx: { state: string }) => string) => {
      const tx = await svc.verifier.createTransaction(rp, 'pid', '/bank/');
      const vp = await presentSdJwt({ credential: r.credRes!.body.credential, reveal: ['given_name', 'family_name', 'birth_date'], holderPrivateKey: r.privateKey!, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
      const post = await request(app).post(`/vp/response/${tx.id}`).type('form').send({ vp_token: JSON.stringify({ pid: [vp] }), state: state(tx) });
      return { tx, post };
    };
    // cross-device (QR): the link carries the plain state, the wallet posts it back, nothing to open afterwards
    const cross = await present((t) => t.state);
    expect(cross.post.status, JSON.stringify(cross.post.body)).toBe(200);
    expect(cross.post.body).toEqual({});
    expect(svc.verifier.diagnostics().find((e) => e.event === 'response_accepted')!.device).toBe('cross-device (no redirect_uri returned)');
    // same-device (button): marker in state, the wallet is told where to go next
    const tx0 = await svc.verifier.createTransaction(rp, 'pid', '/bank/');
    expect(new URL(svc.verifier.walletLink(tx0, true)).searchParams.get('state')).toBe(`${tx0.state}.sd`);
    expect(new URL(svc.verifier.walletLink(tx0)).searchParams.get('state')).toBe(tx0.state);
    const same = await present((t) => `${t.state}.sd`);
    expect(same.post.status).toBe(200);
    expect(same.post.body.redirect_uri).toContain(`/bank/verify/finish/${same.tx.id}?response_code=`);
    // anything else is still a state mismatch
    expect((await present((t) => `${t.state}.x`)).post.status).toBe(400);
    // The wallet opens the follow-up page in ITS browser (not the one that started the flow). Without the code: refused.
    expect((await request(app).get(`/bank/verify/finish/${same.tx.id}`)).status).toBe(403);
    expect((await request(app).get(`/bank/verify/finish/${same.tx.id}?response_code=wrong`)).status).toBe(403);
    // With the code it continues there: the result is bound to that browser and it lands on the page the flow was heading to.
    const walletBrowser = request.agent(app);
    const landed = await walletBrowser.get(`/bank/verify/finish/${same.tx.id}?response_code=${same.tx.responseCode}`);
    expect(landed.status).toBe(302);
    expect(landed.headers.location).toBe('/bank/');
    expect((await request(app).get('/bank/kyc')).status).not.toBe(200); // a browser without the result cannot see the page
    expect((await walletBrowser.get('/bank/kyc')).status).toBe(200); // verified PID is available in this browser
    // ... but only once: a second browser with the same code just sees the friendly page
    expect((await request(app).get(`/bank/verify/finish/${same.tx.id}?response_code=${same.tx.responseCode}`)).text).toContain('Verification complete');
  });
});

describe('verifier certificate (what a wallet trust evaluation sees)', () => {
  it('a generated PKI configures the service; its chain validates against the generated root; /vp/verifier reports it', async () => {
    const { generateDemoPki } = await import('../scripts/lib/verifier-cert.mjs');
    const { validateX5cChain } = await import('../src/verifier/trust.js');
    const host = 'rp.example.test';
    const pki = await generateDemoPki(host);
    for (const scheme of ['x509_hash', 'x509_san_dns']) {
      const { app, svc, cfg } = await boot({ ...pki.env, VP_CLIENT_ID_SCHEME: scheme });
      expect(svc.verifier.identity.ephemeral).toBe(false);
      expect(svc.verifier.identity.clientId).toBe(pki.clientIds[scheme as 'x509_hash']);
      const tx = await svc.verifier.createTransaction(cfg.rps[0]!, 'pid', '/');
      const jwt = (await request(app).post(`/vp/request/${tx.id}`).type('form').send({})).text;
      const header = JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString());
      expect(header.x5c).toHaveLength(2); // leaf + root
      const leaf = validateX5cChain(header.x5c, [pki.caPem]); // what the wallet does with its trust anchors
      expect(leaf.subject).toContain(host);
      expect(leaf.subjectAltName).toContain(`DNS:${host}`);
      const info = (await request(app).get('/vp/verifier')).body;
      expect(info.self_signed_ephemeral).toBe(false);
      expect(info.x509_hash_client_id).toBe(pki.clientIds.x509_hash);
      expect(info.chain_pem).toHaveLength(2);
    }
    // an unrelated root does not validate the chain (the failure your wallet reported, in miniature)
    const other = await generateDemoPki(host);
    expect(() => validateX5cChain([Buffer.from(pki.leaf.rawData).toString('base64')], [other.caPem])).toThrow(/trusted root/);
    // default (no key configured) is self-signed and says so
    const dflt = await boot();
    const body = (await request(dflt.app).get('/vp/verifier')).body;
    expect(body.self_signed_ephemeral).toBe(true);
    expect(body.note).toMatch(/no wallet will trust/);
  });

  it('generates a CSR for a CA to sign', async () => {
    const { generateCsr } = await import('../scripts/lib/verifier-cert.mjs');
    const r = await generateCsr('rp.example.test');
    expect(r.csrPem).toContain('BEGIN CERTIFICATE REQUEST');
    expect(JSON.parse(r.keyEnv).d).toBeTruthy();
  });
});

describe('QR fallback for long links', () => {
  it('a payload too large for any QR code yields undefined (link-only page), normal ones render', async () => {
    const { qrDataUrlOrUndefined } = await import('../src/issuer/offer.js');
    expect(await qrDataUrlOrUndefined('x'.repeat(4000))).toBeUndefined();
    expect(await qrDataUrlOrUndefined('openid4vp://authorize?x=1')).toMatch(/^data:image\/svg\+xml/); // vector: stays sharp at any size
    // the combined university request now fits as well
    const { app } = await boot({ VP_CLIENT_ID_SCHEME: 'redirect_uri', MULTI_CREDENTIAL: 'true' });
    const a = request.agent(app);
    const loc = (await a.get('/university/verify?p=pid_bc&returnTo=/university/documents')).headers.location!;
    const page = (await a.get(loc)).text;
    expect(page).toContain('openid4vp://authorize?');
    expect(page).not.toContain('too large for a QR code');
  });
});

describe('phone-camera hand-off and QR scannability', () => {
  it('by-value link stays well under the dense-QR range; /verify/open/:id is public and shows the wallet button', async () => {
    const { app, svc, cfg } = await boot({ VP_CLIENT_ID_SCHEME: 'redirect_uri', VP_BY_VALUE_FORMATS: 'mso_mdoc' });
    for (const [rp, p] of [['bank', 'pid'], ['electricity', 'pid'], ['university', 'pid'], ['university', 'bc'], ['eshop', 'payment']] as const) {
      const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === rp)!, p, '/');
      expect(svc.verifier.walletLink(tx).length, `${rp}/${p}`).toBeLessThan(1700);
      // the wallet shows this as the relying party (unsigned requests carry no certificate name)
      expect(JSON.parse(new URL(svc.verifier.walletLink(tx)).searchParams.get('client_metadata')!).client_name, `${rp}/${p}`).toBe(tx.rpName);
    }
    const a = request.agent(app);
    const loc = (await a.get('/bank/verify?p=pid&returnTo=/bank/kyc')).headers.location!;
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(loc)![1]!;
    const page = (await a.get(loc)).text;
    expect(page).not.toContain('Scanning not working?');
    expect((page.match(/data:image\/svg\+xml/g) ?? []).length).toBe(1); // one QR code only (400px)
    expect(page).toContain('width="400"');
    const open = await request(app).get(`/bank/verify/open/${id}`); // no session cookie: a different device
    expect(open.status).toBe(200);
    expect(open.text).toContain('openid4vp://authorize?');
    expect((await request(app).get('/bank/verify/open/nope')).status).toBe(404);
    expect((await request(app).get(`/eshop/verify/open/${id}`)).status).toBe(404); // wrong RP
  });
});

describe('QR scan test page', () => {
  it('shows the same request in four forms, including a scheme-only link', async () => {
    const { app } = await boot({ VP_CLIENT_ID_SCHEME: 'redirect_uri', MOCK_MODE: 'false' });
    const page = (await request(app).get('/qr-test')).text;
    for (const k of ['A', 'B', 'C', 'D']) expect(page).toContain(`${k} – `);
    expect(page).toContain('haip-vp://authorize?');
    expect(page).toContain('openid4vp://authorize?client_id=qr-test');
    expect((page.match(/data:image\/svg\+xml/g) ?? []).length).toBeGreaterThanOrEqual(4);
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
    expect(d.map((e: any) => e.event)).toEqual(['wallet_response_posted', 'response_rejected', 'wallet_fetched_request']);
    expect(d[2].walletMetadata).toContain('mso_mdoc');
    expect(d[1].detail).toBeTruthy();
    expect(d[0]).toMatchObject({ status: 400, fields: ['vp_token', 'state'] }); // the POST itself is noted, with the names of the fields (never their content)
    expect(JSON.stringify(d[0])).not.toContain('junk');
  });

  it('static assets are revalidated and asset URLs carry a build version', async () => {
    const { app } = await boot();
    const css = await request(app).get('/css/base.css');
    expect(css.headers['cache-control']).toBe('public, max-age=0, must-revalidate');
    expect((await request(app).get('/fonts/inter-latin-wght-normal.woff2')).headers['cache-control']).toContain('max-age=604800');
    const home = (await request(app).get('/')).text;
    expect(home).toMatch(/\/css\/base\.css\?v=[A-Za-z0-9]+/);
    expect(home).toMatch(/\/img\/in-groupe-portal-logo\.png\?v=[A-Za-z0-9]+/);
  });
});

describe('OpenID4VCI issuer over HTTP', () => {
  it('serves issuer, authorization-server and JWT VC issuer metadata', async () => {
    const { app, cfg } = await boot();
    const md = (await request(app).get('/.well-known/openid-credential-issuer/issuer')).body;
    expect(md.credential_issuer).toBe('https://rp.example.test/issuer');
    expect(md.credential_endpoint).toBe('https://rp.example.test/issuer/credential');
    expect(Object.keys(md.credential_configurations_supported).sort()).toEqual(Object.values(cfg.attestations).filter((a) => a.formats.includes('dc+sd-jwt')).flatMap((a) => [a.credentialConfigurationId, ...(a.localMdoc ? [`${a.credentialConfigurationId}_mdoc`] : [])]).sort()); // the mdoc-only driving licence is issued by SIGMA only
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
    const vp = await presentSdJwt({ credential, reveal: ['iban', 'account_holder_name'], holderPrivateKey: r.privateKey!, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
    const { createIssuerKeyResolver } = await import('../src/verifier/trust.js');
    const v = await verifySdJwtPresentation(vp, { resolveIssuerKey: createIssuerKeyResolver(cfg, svc.local), acceptedVcts: cfg.attestations.payment!.acceptedVct, aud: svc.verifier.clientIdFor(tx), nonce: tx.nonce });
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

    const vp = await presentSdJwt({ credential, reveal: claims.dcql_query.credentials.find((c: any) => c.format === 'dc+sd-jwt').claims.map((c: any) => c.path[0]), holderPrivateKey: r.privateKey!, aud: claims.client_id, nonce: claims.nonce });
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

/** The simulated wallet page as { credential title: { claim label: value } }. */
function heldCredentials(html: string): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const section of html.split('<section class="panel"').slice(1)) {
    const title = /<h2[^>]*>([^<]+)<\/h2>/.exec(section)![1]!;
    out[title] = Object.fromEntries([...section.matchAll(/<dt>([^<]+)<\/dt>\s*<dd>([^<]*)<\/dd>/g)].map((m) => [m[1]!, m[2]!]));
  }
  return out;
}

describe('bank: PID for the KYC, the bank account attestation for later sign-ins', () => {
  /** Runs a verification on the simulated wallet and finishes it in the same browser session. */
  const presentVia = async (a: ReturnType<typeof request.agent>, path: string, add?: { type: 'pid'; persona: string }) => {
    const loc = (await a.get(path)).headers.location!;
    const verifyPath = (await a.get(loc)).headers.location!;
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
    if (add) await a.post(`/bank/verify/wallet/${id}/add`).type('form').send(add);
    const done = await a.post(`/bank/verify/wallet/${id}/share`);
    return (await a.get(done.headers.location!)).headers.location; // where the flow continues
  };
  const receive = async (a: ReturnType<typeof request.agent>, key: 'account' | 'payment') => {
    const offer = await a.post(`/bank/attestation/${key}`);
    expect(offer.status).toBe(200);
    const offerId = /name="offerId" value="([^"]+)"/.exec(offer.text)![1]!;
    await a.post('/wallet-sim/redeem').type('form').send({ offerId, returnTo: '/wallet' });
  };

  it('KYC with the PID, download the account attestation, sign out, sign in with the attestation, get a payment attestation made from its attributes', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    // 1. new customer: the PID (KYC); the account page says how the customer got in
    expect(await presentVia(a, '/bank/login/pid', { type: 'pid', persona: 'fr' })).toBe('/bank/kyc');
    expect((await a.get('/bank/kyc')).status).toBe(200);
    const viaPid = (await a.get('/bank/account')).text;
    expect(viaPid).toContain('Signed in with your PID');
    expect(viaPid).not.toContain('action="/bank/attestation/payment"'); // the payment attestation is not offered after the KYC sign-in
    expect((await a.post('/bank/attestation/payment')).status).toBe(403);
    await receive(a, 'account'); // the bank account attestation into the (simulated) wallet
    await a.post('/bank/signout');
    expect((await a.get('/bank/account')).headers.location).toBe('/bank/login');
    // 2. existing customer: the bank account attestation, no PID presented
    expect(await presentVia(a, '/bank/login/account')).toBe('/bank/account');
    const viaAccount = await a.get('/bank/account');
    expect(viaAccount.status).toBe(200);
    expect(viaAccount.text).toContain('Signed in with your bank account attestation');
    expect(viaAccount.text).toContain('action="/bank/attestation/payment"');
    expect(viaAccount.text).toContain('prepared from the attributes of your bank account attestation');
    expect((await a.get('/bank/kyc')).headers.location).toBe('/bank/account'); // the KYC page belongs to the PID path
    // 3. the payment attestation carries what the account attestation said
    await receive(a, 'payment');
    const held = heldCredentials((await a.get('/wallet')).text);
    const account = held['Bank account attestation']!;
    const payment = held['Payment attestation']!;
    expect(account['Account number']).toMatch(/^[A-Z]{2}\d{2}/);
    expect(payment['IBAN']).toBe(account['Account number']); // the IBAN is the account attestation's account number
    expect(payment['Account holder']).toBe(`${account['Given name']} ${account['Family name']}`); // so is the name
    expect(payment['Bank']).toBe(account['Bank']);
  });

  it('the sign-in with the bank account attestation asks for the account attestation (and not the PID)', async () => {
    const { app, svc, cfg } = await boot({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'account', '/bank/account');
    const link = new URL(svc.verifier.walletLink(tx, true));
    const q = JSON.parse(link.searchParams.get('dcql_query')!) as { credentials: Array<{ id: string; format: string; meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
    expect(q.credentials).toHaveLength(1);
    expect(q.credentials[0]).toMatchObject({ id: 'account', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:demo:bank-account:1'] } });
    expect(q.credentials[0]!.claims.map((c) => c.path[0])).toEqual(['given_name', 'family_name', 'birth_date', 'account_number']); // compact: fits a QR code
    expect(link.searchParams.get('verifier_info')).toBeNull(); // the registration certificate does not cover it
    expect(svc.verifier.walletLink(tx).length).toBeLessThan(1700);
    void app;
  });
});

describe('RP flows in the browser session', () => {
  it('bank login starts a verification bound to the session; other sessions cannot see it', async () => {
    const { app } = await boot();
    const a = request.agent(app);
    const chooser = await a.get('/bank/login'); // two ways in: bank account attestation (existing customer) or PID (new customer)
    expect(chooser.status).toBe(200);
    expect(chooser.text).toContain('href="/bank/login/account"');
    expect(chooser.text).toContain('href="/bank/login/pid"');
    const login = await a.get('/bank/login/pid');
    expect(login.status).toBe(302);
    expect(login.headers.location).toBe('/bank/verify?p=pid&returnTo=%2Fbank%2Fkyc');
    expect((await a.get('/bank/login/account')).headers.location).toBe('/bank/verify?p=account&returnTo=%2Fbank%2Faccount');
    const start = await a.get(login.headers.location!); // /bank/verify?p=pid… creates the transaction and redirects to its page
    expect(start.status).toBe(302);
    const verify = await a.get(start.headers.location!);
    expect(verify.status).toBe(200);
    expect(verify.text).toContain('openid4vp://authorize?client_id=x509_hash%3A');
    expect(verify.text).toContain('data:image/svg+xml;base64');
    expect(verify.text).toContain('alt="QR code for the wallet presentation request');
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(start.headers.location!)![1]!;
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
    const rs = await request(app).post('/university/restart'); // start over (e.g. PID and birth certificate of different people)
    expect(rs.status).toBe(302);
    expect(rs.headers.location).toBe('/university/documents');
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

  it('university: a PID and birth certificate of different people only block enrolment when UNIVERSITY_REQUIRE_MATCH is on', async () => {
    for (const strict of [false, true]) {
      const { app } = await boot({ MOCK_MODE: 'true', UNIVERSITY_REQUIRE_MATCH: String(strict) });
      const a = request.agent(app);
      const present = async (p: 'pid' | 'bc', type: 'pid' | 'birth_certificate', persona: string) => {
        const loc = (await a.get(`/university/verify?p=${p}&returnTo=/university/documents`)).headers.location!;
        const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(loc)![1]!;
        await a.post(`/university/verify/wallet/${id}/add`).type('form').send({ type, persona });
        await a.get((await a.post(`/university/verify/wallet/${id}/share`)).headers.location!); // the finish page records the verified claims
      };
      await present('pid', 'pid', 'fr');
      await present('bc', 'birth_certificate', 'de'); // a different person
      const docs = (await a.get('/university/documents')).text;
      const enrol = await a.get('/university/enrol');
      if (strict) {
        expect(docs).toContain('do not match');
        expect(docs).not.toContain('/university/enrol');
        expect(enrol.headers.location).toBe('/university/documents');
      } else {
        expect(docs).toContain('The check is switched off');
        expect(docs).toContain('/university/enrol');
        expect(enrol.status).toBe(200);
      }
    }
  });

  it('unknown presentation is a 400, not a crash', async () => {
    const { app } = await boot();
    const r = await request(app).get('/bank/verify?p=nope');
    expect(r.status).toBe(400); // friendly error page, no stack trace or internals leaked
    expect(r.text).not.toContain('Unknown presentation');
  });
});

describe('Demo Drive (car rental): mobile driving licence', () => {
  it('requests only the mDL (mdoc by value in live mode, SD-JWT too in mock mode) and the checks follow the licence', async () => {
    const { svc, cfg } = await boot({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'rental')!, 'mdl', '/rental/booking');
    const q = JSON.parse(new URL(svc.verifier.walletLink(tx)).searchParams.get('dcql_query')!);
    // mdoc (the SIGMA licence) or SD-JWT (the one issued by the local backup issuer): two alternatives
    expect(q.credentials.map((c: any) => c.format).sort()).toEqual(['dc+sd-jwt', 'mso_mdoc']);
    const mdoc = q.credentials.find((c: any) => c.format === 'mso_mdoc');
    expect(mdoc).toMatchObject({ meta: { doctype_value: 'org.iso.18013.5.1.mDL' } });
    expect(mdoc.claims.map((c: any) => c.path)).toContainEqual(['org.iso.18013.5.1', 'document_number']);
    const { licenceChecks } = await import('../src/rps/rental.js');
    const now = new Date('2026-11-23T00:00:00Z');
    expect(licenceChecks({ expiry_date: '2032-03-01', issue_date: '2022-03-01', birth_date: '1990-01-01' }, now)).toMatchObject({ valid: true, experienced: true, ofAge: true });
    expect(licenceChecks({ expiry_date: '2025-03-01', issue_date: '2026-06-01', birth_date: '2010-01-01' }, now)).toMatchObject({ valid: false, experienced: false, ofAge: false });
    expect(licenceChecks({}, now)).toMatchObject({ valid: undefined, experienced: undefined, ofAge: undefined });
  });

  it('sign in with a demo licence, pick a car, pay with the payment attestation; nothing is possible without them', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    expect((await a.get('/rental/booking')).headers.location).toBe('/rental/login');
    expect((await a.post('/rental/book').type('form').send({ car: 'city', days: '2' })).headers.location).toBe('/rental/login');
    expect((await a.get('/rental/confirmation')).headers.location).toBe('/rental/login');
    expect((await a.get('/rental/')).text).toContain('Demo Drive');
    // the wallet holds a payment attestation (the bank issues it after a sign-in with the bank account attestation)
    const present = async (rp: string, path: string, add?: { type: string; persona: string }) => {
      const verifyPath = (await a.get((await a.get(path)).headers.location!)).headers.location!;
      const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
      if (add) await a.post(`/${rp}/verify/wallet/${id}/add`).type('form').send(add);
      const done = await a.post(`/${rp}/verify/wallet/${id}/share`);
      return (await a.get(done.headers.location!)).headers.location;
    };
    const receive = async (key: string) => {
      const offer = await a.post(`/bank/attestation/${key}`);
      const offerId = /name="offerId" value="([^"]+)"/.exec(offer.text)![1]!;
      await a.post('/wallet-sim/redeem').type('form').send({ offerId, returnTo: '/wallet' });
    };
    await present('bank', '/bank/login/pid', { type: 'pid', persona: 'fr' });
    await receive('account'); await a.post('/bank/signout');
    await present('bank', '/bank/login/account');
    await receive('payment');
    // sign in with the licence
    expect(await present('rental', '/rental/login', { type: 'mdl', persona: 'fr' })).toBe('/rental/booking');
    const page = await a.get('/rental/booking');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Licence is valid');
    expect(page.text).toContain('Camille');
    expect((await a.post('/rental/book').type('form').send({ car: 'nope', days: '2' })).status).toBe(422);
    expect((await a.post('/rental/book').type('form').send({ car: 'city', days: '99' })).status).toBe(422);
    expect((await a.get('/rental/confirmation')).headers.location).toBe('/rental/booking'); // nothing booked yet
    // booking → payment request → confirmation
    const book = await a.post('/rental/book').type('form').send({ car: 'suv', days: '3' });
    expect(book.headers.location).toBe('/rental/verify?p=payment&returnTo=%2Frental%2Fconfirmation');
    expect((await a.get('/rental/confirmation')).headers.location).toBe('/rental/booking'); // not paid yet
    const verifyPath = (await a.get(book.headers.location!)).headers.location!;
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
    const done = await a.post(`/rental/verify/wallet/${id}/share`);
    expect((await a.get(done.headers.location!)).headers.location).toBe('/rental/confirmation');
    const ok = await a.get('/rental/confirmation');
    expect(ok.status).toBe(200);
    expect(ok.text).toMatch(/DR-[0-9A-F]{6}/);
    expect(ok.text).toContain('237'); // 3 days x 79
    expect(ok.text).toMatch(/XX00 •••• •••• \d{4}/); // paid with the payment attestation
    expect((await a.get('/rental/confirmation')).status).toBe(200); // a reload shows the same confirmation
    // a second booking needs a fresh payment presentation
    await a.post('/rental/book').type('form').send({ car: 'city', days: '1' });
    expect((await a.get('/rental/confirmation')).headers.location).toBe('/rental/booking');
  });
});

describe('wording and validity (customer feedback)', () => {
  it('the term SIGMA does not appear in what the customer sees', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    for (const lang of ['en', 'fr', 'de', 'es', 'nl', 'da', 'sv', 'mt']) {
      for (const path of ['/', '/demo-issuer', '/bank/', '/rental/', '/wallet-check']) {
        const html = (await request(app).get(`${path}?lang=${lang}`)).text.replace(/https?:\/\/\S+/g, '');
        expect(html, `${lang} ${path}`).not.toMatch(/SIGMA/i);
      }
    }
    const meta = (await request(app).get('/issuer/.well-known/openid-credential-issuer')).text;
    expect(meta).not.toMatch(/SIGMA/i); // the wallet shows the issuer's display name
  });

  it('offers and presentation requests stay valid longer (60 / 30 minutes, configurable)', async () => {
    const { svc, cfg } = await boot({ MOCK_MODE: 'true' });
    expect(cfg.issuer.offerTtlMinutes).toBe(60);
    expect(cfg.verifier.requestTtlMinutes).toBe(30);
    const o = svc.local.createOffer('account', { given_name: 'A' });
    expect(Math.round((o.expiresAt.getTime() - Date.now()) / 60_000)).toBe(60);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    expect(Math.round((tx.expiresAt - Date.now()) / 60_000)).toBe(30);
    const custom = await boot({ MOCK_MODE: 'true', ISSUER_OFFER_TTL_MINUTES: '120', VP_REQUEST_TTL_MINUTES: '45' });
    expect(custom.cfg.issuer.offerTtlMinutes).toBe(120);
    expect(custom.cfg.verifier.requestTtlMinutes).toBe(45);
  });

  it('Demo Drive: no name comparison and no account holder name, only the account reference', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    const present = async (rp: string, path: string, add?: { type: string; persona: string }) => {
      const verifyPath = (await a.get((await a.get(path)).headers.location!)).headers.location!;
      const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
      if (add) await a.post(`/${rp}/verify/wallet/${id}/add`).type('form').send(add);
      const done = await a.post(`/${rp}/verify/wallet/${id}/share`);
      return (await a.get(done.headers.location!)).headers.location;
    };
    const receive = async (key: string) => {
      const offer = await a.post(`/bank/attestation/${key}`);
      await a.post('/wallet-sim/redeem').type('form').send({ offerId: /name="offerId" value="([^"]+)"/.exec(offer.text)![1]!, returnTo: '/wallet' });
    };
    await present('bank', '/bank/login/pid', { type: 'pid', persona: 'de' }); // bank customer Lukas Demo
    await receive('account'); await a.post('/bank/signout');
    await present('bank', '/bank/login/account'); await receive('payment');
    await present('rental', '/rental/login', { type: 'mdl', persona: 'fr' }); // driver Camille Demo: another name, no warning
    const book = await a.post('/rental/book').type('form').send({ car: 'city', days: '2' });
    const vp = (await a.get(book.headers.location!)).headers.location!;
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(vp)![1]!;
    await a.get((await a.post(`/rental/verify/wallet/${id}/share`)).headers.location!);
    const ok = await a.get('/rental/confirmation');
    expect(ok.status).toBe(200);
    expect(ok.text).toMatch(/DR-[0-9A-F]{6}/);
    expect(ok.text).not.toContain('Names do not match');
    expect(ok.text).not.toContain('Lukas'); // the payment account holder's name is not shown
    expect(ok.text).toMatch(/XX00 •••• •••• \d{4}/); // only the account reference
  });
});

describe('offer pages do not expose the local issuer', () => {
  it('a bank attestation offer says nothing about a local demo issuer', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    const loc = (await a.get('/bank/login/pid')).headers.location!;
    const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec((await a.get(loc)).headers.location!)![1]!;
    await a.post(`/bank/verify/wallet/${id}/add`).type('form').send({ type: 'pid', persona: 'fr' });
    await a.get((await a.post(`/bank/verify/wallet/${id}/share`)).headers.location!);
    const offer = await a.post('/bank/attestation/account');
    expect(offer.status).toBe(200);
    expect(offer.text).not.toMatch(/local demo issuer|does not offer this attestation/i);
  });
});

describe('Demo University: Student ID attestation and the examination page', () => {
  it('a new student enrols with PID + birth certificate, gets a Student ID; a returning student signs in with it and registers for an exam', async () => {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    const present = async (path: string, add?: { type: string; persona: string }) => {
      const first = (await a.get(path)).headers.location!;
      const verifyPath = path.includes('/verify?') ? first : (await a.get(first)).headers.location!;
      const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
      if (add) await a.post(`/university/verify/wallet/${id}/add`).type('form').send(add);
      const done = await a.post(`/university/verify/wallet/${id}/share`);
      return (await a.get(done.headers.location!)).headers.location;
    };
    // nothing without the Student ID
    expect((await a.get('/university/exams')).headers.location).toBe('/university/login');
    expect((await a.post('/university/attestation/studentid')).headers.location).toBe('/university/'); // only after the enrolment
    // 1. enrol with PID + birth certificate
    await present('/university/verify?p=pid&returnTo=/university/documents', { type: 'pid', persona: 'fr' });
    await present('/university/verify?p=bc&returnTo=/university/documents', { type: 'birth_certificate', persona: 'fr' });
    expect((await a.post('/university/enrol').type('form').send({ programme: 'cs', email: 'camille@example.org', consent: 'yes' })).headers.location).toBe('/university/confirmation');
    const done = await a.get('/university/confirmation');
    expect(done.text).toContain('Get Student ID attestation');
    // 2. the Student ID attestation
    const offer = await a.post('/university/attestation/studentid');
    expect(offer.status).toBe(200);
    expect(offer.text).not.toMatch(/local demo issuer/i);
    const offerId = /name="offerId" value="([^"]+)"/.exec(offer.text)![1]!;
    await a.post('/wallet-sim/redeem').type('form').send({ offerId, returnTo: '/wallet' });
    const held = heldCredentials((await a.get('/wallet')).text)['Student ID']!;
    expect(held['Student number']).toMatch(/^S\d{4}\d{5}$/);
    expect(held['Institution']).toBe('Demo University');
    expect(held['Enrolment status']).toBeTruthy();
    // 3. returning student: sign out, sign in with the Student ID only
    await a.post('/university/signout');
    expect((await a.get('/university/exams')).headers.location).toBe('/university/login');
    expect(await present('/university/login')).toBe('/university/exams');
    const exams = await a.get('/university/exams');
    expect(exams.status).toBe(200);
    expect(exams.text).toContain('Signed in with your Student ID.');
    expect(exams.text).toContain('Enrolled and valid');
    expect(exams.text).toContain('Algorithms and Data Structures');
    expect((await a.post('/university/exams/register').type('form').send({ exam: 'e2' })).headers.location).toBe('/university/exams');
    expect((await a.get('/university/exams')).text).toContain('Registered');
    expect((await a.post('/university/exams/register').type('form').send({ exam: 'nope' })).status).toBe(400);
  });

  it('the standing check: enrolled and within validity', async () => {
    const { studentStanding } = await import('../src/rps/university.js');
    const now = new Date('2026-11-25T10:00:00Z');
    expect(studentStanding({ enrollment_status: 'active', valid_until: '2027-09-30' }, now)).toEqual({ active: true, current: true, ok: true });
    expect(studentStanding({ enrollment_status: 'active', valid_until: '2026-09-30' }, now).ok).toBe(false); // expired
    expect(studentStanding({ enrollment_status: 'suspended', valid_until: '2027-09-30' }, now)).toMatchObject({ active: false, ok: false });
    expect(studentStanding({ valid_until: '2026-11-25' }, now).ok).toBe(true); // valid through the whole last day
    expect(studentStanding({}, now).ok).toBe(true); // nothing shared: nothing concluded
  });

  it('the Student ID request is by SD-JWT with the rulebook vct, and the local issuer declares it', async () => {
    const { svc, cfg } = await boot({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'university')!, 'studentid', '/university/exams');
    const link = new URL(svc.verifier.walletLink(tx));
    const q = JSON.parse(link.searchParams.get('dcql_query')!);
    expect(q.credentials).toHaveLength(1);
    expect(q.credentials[0]).toMatchObject({ format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:studentid:1', 'urn:eudi:studentid:de:1'] } });
    expect(svc.verifier.walletLink(tx).length).toBeLessThan(1700);
    const md = (svc.local.metadata() as any).credential_configurations_supported.demo_student_id;
    expect(md).toMatchObject({ format: 'dc+sd-jwt', vct: 'urn:eudi:studentid:1' });
    expect(md.claims.map((c: any) => c.path[0])).toEqual(expect.arrayContaining(['student_id', 'institution_name', 'enrollment_status', 'valid_until', 'academic_year']));
  });
});

describe('Diploma attestation and the job portal (Demo Jobs)', () => {
  /** Enrol, get the Student ID and sign in with it (simulated wallet), as a returning student. */
  async function studentSession() {
    const { app } = await boot({ MOCK_MODE: 'true' });
    const a = request.agent(app);
    const present = async (rp: string, path: string, add?: { type: string; persona: string }) => {
      const first = (await a.get(path)).headers.location!;
      const verifyPath = path.includes('/verify?') ? first : (await a.get(first)).headers.location!;
      const id = /\/verify\/([A-Za-z0-9_-]{16})/.exec(verifyPath)![1]!;
      if (add) await a.post(`/${rp}/verify/wallet/${id}/add`).type('form').send(add);
      return (await a.get((await a.post(`/${rp}/verify/wallet/${id}/share`)).headers.location!)).headers.location;
    };
    const redeem = async (offerHtml: string) => a.post('/wallet-sim/redeem').type('form').send({ offerId: /name="offerId" value="([^"]+)"/.exec(offerHtml)![1]!, returnTo: '/wallet' });
    await present('university', '/university/verify?p=pid&returnTo=/university/documents', { type: 'pid', persona: 'fr' });
    await present('university', '/university/verify?p=bc&returnTo=/university/documents', { type: 'birth_certificate', persona: 'fr' });
    await a.post('/university/enrol').type('form').send({ programme: 'law', email: 'c@example.org', consent: 'yes' });
    await redeem((await a.post('/university/attestation/studentid')).text);
    await a.post('/university/signout');
    expect(await present('university', '/university/login')).toBe('/university/exams');
    return { a, present, redeem, app };
  }

  it('after the Student ID sign-in the student downloads a diploma attestation (DC4EU-DE higher education diploma)', async () => {
    const { a, redeem } = await studentSession();
    expect((await a.get('/university/exams')).text).toContain('Get my diploma');
    const page = await a.get('/university/diploma');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Master of Laws');
    expect((await a.post('/university/attestation/diploma').type('form').send({ dob: 'x' })).status).toBe(422); // a date is needed
    expect((await a.post('/university/attestation/diploma').type('form').send({ dob: '2999-01-01' })).status).toBe(422);
    const offer = await a.post('/university/attestation/diploma').type('form').send({ dob: '1992-04-17' });
    expect(offer.status).toBe(200);
    await redeem(offer.text);
    const held = heldCredentials((await a.get('/wallet')).text)['Higher Education Diploma']!;
    expect(held['Diploma title']).toBe('Master of Laws');
    expect(held['Institution']).toBe('Demo University');
    expect(held['EQF level']).toBe('7');
    expect(held['Degree level']).toBe('Master');
    expect(held['Programme identifier']).toBe('DEMO-LLM-LAW');
    expect((await request((await boot({ MOCK_MODE: 'true' })).app).get('/university/diploma')).headers.location).toBe('/university/login'); // only after the Student ID sign-in
  });

  it('job portal: the account is created with the PID; the diploma, once verified, is added to the CV as an attribute; the application shows it', async () => {
    const { a, present, redeem } = await studentSession();
    await redeem((await a.post('/university/attestation/diploma').type('form').send({ dob: '1992-04-17' })).text);
    expect((await a.get('/jobs/')).text).toContain('Create account with your PID');
    expect((await a.get('/jobs/?q=paris')).text).toContain('Data Scientist');
    expect((await a.get('/jobs/job/j2')).text).toContain('Apply with EU Wallet');
    expect((await a.get('/jobs/job/zzz')).status).toBe(404);
    // nothing without the account: everything goes to the PID sign-up and comes back
    expect((await a.get('/jobs/cv')).headers.location).toBe('/jobs/signup?next=%2Fjobs%2Fcv');
    expect((await a.get('/jobs/apply/j2')).headers.location).toBe('/jobs/signup?next=%2Fjobs%2Fapply%2Fj2');
    expect((await a.get('/jobs/signup?next=//evil.test')).headers.location).toBe('/jobs/verify?p=pid&returnTo=%2Fjobs%2Fcv'); // only local paths
    expect(await present('jobs', '/jobs/signup?next=/jobs/apply/j2')).toBe('/jobs/apply/j2');
    // no verified diploma yet
    const review = await a.get('/jobs/apply/j2');
    expect(review.status).toBe(200);
    expect(review.text).toContain('No verified diploma on your CV yet.');
    expect(review.text).toContain('Verified with your PID');
    // the CV document: wrong types and sizes are refused, a PDF is kept (session only) and can be downloaded again
    expect((await a.post('/jobs/cv').set('X-Filename', 'evil.exe').set('Content-Type', 'application/octet-stream').send(Buffer.from('MZ'))).status).toBe(422);
    expect((await a.post('/jobs/cv').set('X-Filename', 'cv.pdf').set('Content-Type', 'application/octet-stream').send(Buffer.from('not a pdf'))).status).toBe(422);
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF');
    const up = await a.post('/jobs/cv').set('X-Filename', encodeURIComponent('Camille CV.pdf')).set('Content-Type', 'application/octet-stream').send(pdf);
    expect(up.body).toMatchObject({ name: 'Camille CV.pdf', size: pdf.length });
    const dl = await a.get('/jobs/cv/download').buffer(true).parse((res, cb) => { const c: Buffer[] = []; res.on('data', (d: Buffer) => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); });
    expect(dl.headers['content-disposition']).toContain('attachment');
    expect(Buffer.from(dl.body as Buffer).equals(pdf)).toBe(true);
    // the diploma: presented through the wallet, then added to the CV as a verified attribute
    expect((await a.get('/jobs/cv')).text).not.toContain('Master of Laws');
    expect(await present('jobs', '/jobs/cv/diploma')).toBe('/jobs/cv/diploma/added');
    expect((await a.get('/jobs/cv/diploma/added')).headers.location).toBe('/jobs/cv');
    const cv = await a.get('/jobs/cv');
    expect(cv.text).toContain('Master of Laws');
    expect(cv.text).toContain('Verified by your diploma attestation');
    expect(cv.text).toContain('Diploma verified and added to your CV.');
    await a.get('/jobs/cv/diploma/added'); // presenting it again does not duplicate the entry
    expect(((await a.get('/jobs/cv')).text.match(/Verified by your diploma attestation/g) ?? []).length).toBe(1);
    // apply: the review shows the verified education and the requirement check; then send
    const ready = await a.get('/jobs/apply/j2');
    expect(ready.text).toContain('Master of Laws');
    expect(ready.text).toContain('Meets the requirement'); // EQF 7 for a job asking Master or higher
    expect((await a.post('/jobs/apply/j2')).headers.location).toBe('/jobs/application/j2');
    const done = await a.get('/jobs/application/j2');
    expect(done.text).toMatch(/JB-[0-9A-F]{6}/);
    expect(done.text).toContain('Education (verified)');
    expect(done.text).toContain('Camille CV.pdf');
    expect((await a.get('/jobs/applications')).text).toContain('Data Scientist');
    expect((await a.get('/jobs/application/j9')).headers.location).toBe('/jobs/');
    // the education entry can be removed again; without it the requirement is not met
    await a.post('/jobs/cv/education/remove').type('form').send({ i: '0' });
    expect((await a.get('/jobs/cv')).text).not.toContain('Master of Laws');
    expect((await request((await boot({ MOCK_MODE: 'true' })).app).get('/jobs/application/j2')).headers.location).toContain('/jobs/signup');
  });

  it('the level check, and the requested claims stay QR-sized', async () => {
    const { meetsLevel } = await import('../src/rps/jobs.js');
    expect(meetsLevel({ eqf_level: 7 }, 7)).toBe(true);
    expect(meetsLevel({ eqf_level: '6' }, 7)).toBe(false);
    expect(meetsLevel({ degree_level: 'Master' }, 7)).toBe(true);
    expect(meetsLevel({ degree_level: 'Bachelor' }, 7)).toBe(false);
    expect(meetsLevel({}, 6)).toBeUndefined();
    const { svc, cfg } = await boot({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const pidTx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'jobs')!, 'pid', '/jobs/cv');
    expect(JSON.parse(new URL(svc.verifier.walletLink(pidTx)).searchParams.get('dcql_query')!).credentials.map((c: any) => c.format)).toEqual(['mso_mdoc']); // the account: the PID (mdoc)
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'jobs')!, 'diploma', '/jobs/cv/diploma/added');
    const link = svc.verifier.walletLink(tx);
    expect(JSON.parse(new URL(link).searchParams.get('dcql_query')!).credentials[0].meta.vct_values).toEqual(['urn:dc4eu-de:hed:de:1']);
    expect(link.length).toBeLessThan(1700);
    const md = (svc.local.metadata() as any).credential_configurations_supported.demo_diploma;
    expect(md).toMatchObject({ format: 'dc+sd-jwt', vct: 'urn:dc4eu-de:hed:de:1' });
  });
});

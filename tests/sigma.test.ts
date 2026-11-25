import { readFileSync } from 'node:fs';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { matchConfig, missingClaims, parseIssuerMetadata, RemoteIssuerMetadata } from '../src/issuer/remote.js';
import { createServices } from '../src/services.js';
import { requestedCredentials } from '../src/verifier/query.js';
import { testConfig } from './helpers.js';

/** Snapshot of https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer (trimmed). */
const META = JSON.parse(readFileSync(new URL('./fixtures/sigma-issuer-metadata.json', import.meta.url), 'utf8'));
const META_URL = 'https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer';
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
const fetchMeta = (async (url: string) => (url === META_URL ? json(META) : new Response('nope', { status: 404 }))) as unknown as typeof fetch;

describe('SIGMA issuer catalogue vs. what the RPs request', () => {
  const cfg = testConfig({ MOCK_MODE: 'false', TRUST_ANY_ISSUER: 'true' });
  const parsed = parseIssuerMetadata(META);

  it('parses the four real credential configurations', () => {
    expect(parsed.issuer).toBe('https://issuer.sigma.prep.smartid.nuagein.io');
    expect(parsed.configs.map((c) => c.id).sort()).toEqual(['eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', 'eu.europa.ec.eudi.pid_mdoc', 'eu.europa.ec.eudi.pid_mdoc_emrtd', 'org.iso.18013.5.1.mDL']);
    expect(parsed.authorizationServers).toContain('https://idp-pid.sigma.prep.smartid.nuagein.io/realms/pid-haip');
  });

  it('maps PID → mdoc config and birth certificate → SD-JWT config; account/payment are not offered', () => {
    expect(matchConfig(cfg.attestations.pid!, parsed.configs)?.id).toBe('eu.europa.ec.eudi.pid_mdoc'); // preferred over the eMRTD variant
    expect(matchConfig(cfg.attestations.birth_certificate!, parsed.configs)).toMatchObject({ id: 'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', format: 'dc+sd-jwt', vct: 'urn:eudi:birth_certificate:1' });
    expect(matchConfig(cfg.attestations.account!, parsed.configs)).toBeUndefined();
    expect(matchConfig(cfg.attestations.payment!, parsed.configs)).toBeUndefined();
  });

  it('every claim every RP requests (full and minimum set) exists in the issuer catalogue', () => {
    for (const rp of cfg.rps) for (const [pk, pres] of Object.entries(rp.presentations)) {
      for (const req of requestedCredentials(pres, cfg.attestations)) {
        const rc = matchConfig(req.attestation, parsed.configs);
        if (!rc) continue; // payment: issued by the bank, not SIGMA
        expect(missingClaims(req.attestation, rc, req.claims), `${rp.id}/${pk}/${req.type}`).toEqual([]);
        expect(missingClaims(req.attestation, rc, req.minClaims), `${rp.id}/${pk}/${req.type} min`).toEqual([]);
      }
    }
  });

  it('requests the PID as mdoc and the birth certificate as SD-JWT with the issuer\'s vct', async () => {
    const svc = await createServices(cfg);
    const uni = cfg.rps.find((r) => r.id === 'university')!;
    const q = (svc.verifier.requestParams(await svc.verifier.createTransaction(uni, 'pid_bc', '/')) as any).dcql_query;
    expect(q.credentials.find((c: any) => c.id === 'pid_mdoc').meta.doctype_value).toBe('eu.europa.ec.eudi.pid.1');
    expect(q.credentials.find((c: any) => c.id === 'birth_certificate').meta.vct_values).toContain('urn:eudi:birth_certificate:1');
    // live by-value mode (QR): PID mdoc only; the simulated wallet (mock) keeps SD-JWT
    expect(cfg.verifier.byValueFormats).toEqual(['mso_mdoc']);
    expect(testConfig({ MOCK_MODE: 'true' }).verifier.byValueFormats).toEqual(['mso_mdoc', 'dc+sd-jwt']); // mock: real wallets still get the mdoc PID, the simulated wallet its SD-JWT
    const bv = await createServices(testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' }));
    const link = new URL(bv.verifier.walletLink(await bv.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/')));
    expect(JSON.parse(link.searchParams.get('dcql_query')!).credentials.map((c: any) => c.format)).toEqual(['mso_mdoc']);
    expect(bv.verifier.walletLink(await bv.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/')).length).toBeLessThan(1700);
  });
});

describe('console: offers through the SIGMA offer API', () => {
  it('POSTs the chosen sample user to /offer and shows deeplink and the 6-digit tx code', async () => {
    const cfg = testConfig({ ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', MOCK_MODE: 'false' });
    const calls: any[] = [];
    const f = (async (url: string, init?: RequestInit) => {
      if (url === META_URL) return json(META);
      calls.push({ url, body: JSON.parse(String(init?.body)) });
      return json({ uri: 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.sigma.prep.smartid.nuagein.io%22%7D', tx_code: '246810', qr_code: 'x', authorization_code: 'y' });
    }) as unknown as typeof fetch;
    const svc = await createServices(cfg, f);
    const app = createApp(cfg, svc);
    const res = await request(app).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-002' });
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://issuer.sigma.prep.smartid.nuagein.io/offer');
    expect(calls[0].body).toMatchObject({ identifier: 'user-pid-mdoc-002', authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'eu.europa.ec.eudi.pid_mdoc', credential_identifiers: ['credential_id_2_mdoc'] }] }); // the PID needs its credential identifier too, or the issuer produces an empty credential
    expect(res.text).toContain('246810'); // the code the wallet asks for
    expect(res.text).toContain('Pre-authorised code'); // shown like the WalletTester does
    expect(res.text).toContain('openid-credential-offer://');
    expect(res.text).toContain('data:image/png');
    // identifiers typed by hand are passed through (validated); unsafe input is refused
    const custom = await request(app).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-001', customIdentifier: 'my-user_9', customCredentialIdentifier: 'cred.1' });
    expect(custom.status).toBe(200);
    expect(calls[1].body).toMatchObject({ identifier: 'my-user_9', authorization_details: [{ credential_identifiers: ['cred.1'] }] });
    for (const bad of ['a b', '../x', 'x'.repeat(65), '<script>']) expect((await request(app).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', customIdentifier: bad })).status, bad).toBe(400);
    expect(calls).toHaveLength(2);
    // API failure: error page, no crash
    const bad = await createServices(cfg, (async (url: string) => (url === META_URL ? json(META) : new Response('x', { status: 500 }))) as unknown as typeof fetch);
    expect((await request(createApp(cfg, bad)).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-001' })).status).toBe(502);
  });
});

describe('wallet compatibility check (probe ladder)', () => {
  it('each probe requests exactly one credential type, one claim', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false' });
    const svc = await createServices(cfg);
    const bank = cfg.rps.find((r) => r.id === 'bank')!;
    const q = async (k: string) => (svc.verifier.requestParams(await svc.verifier.createTransaction(bank, k, '/')) as any).dcql_query;
    const mdoc = await q('probe_pid_mdoc');
    expect(mdoc.credentials).toHaveLength(1);
    expect(mdoc.credentials[0]).toMatchObject({ format: 'mso_mdoc', meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' }, claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'family_name'] }] });
    for (const [k, vct] of [['probe_pid_sd_benin', 'https://credentials.benin.example/pid'], ['probe_pid_sd_urn', 'urn:eudi:pid:1'], ['probe_pid_sd_eu', 'urn:eu.europa.ec.eudi:pid:1'], ['probe_bc_sd', 'urn:eudi:birth_certificate:1']] as const) {
      const d = await q(k);
      expect(d.credentials, k).toHaveLength(1);
      expect(d.credentials[0], k).toMatchObject({ format: 'dc+sd-jwt', meta: { vct_values: [vct] }, claims: [{ path: ['family_name'] }] });
    }
  });

  it('page lists the probes; an answered probe is verified, recorded and shown as done', async () => {
    const { addDemoCredential, buildVpToken, respondToVerifier } = await import('../src/mock/wallet.js');
    const cfg = testConfig({ MOCK_MODE: 'true' });
    const svc = await createServices(cfg);
    const app = createApp(cfg, svc);
    const a = request.agent(app);
    const page = (await a.get('/wallet-check')).text;
    for (const label of ['PID as mdoc', 'PID as SD-JWT, Benin rulebook type', 'Birth certificate as SD-JWT']) expect(page).toContain(label);
    const loc = (await a.get('/bank/verify?p=probe_pid_sd_benin')).headers.location!;
    const id = loc.split('/').pop()!;
    const tx = svc.verifier.get(id)!;
    const session: Record<string, any> = {};
    await addDemoCredential(svc.local, cfg, session, 'pid', 'fr');
    await respondToVerifier(svc.verifier, tx, { vp_token: await buildVpToken(session, tx, svc.verifier) });
    expect(tx.result!.byType.pid).toEqual({ family_name: 'Demo' });
    const fin = await a.get(`/bank/verify/finish/${id}?response_code=${tx.responseCode}`);
    expect(fin.headers.location).toBe('/wallet-check');
    expect((await a.get('/wallet-check')).text).toContain('answered by the wallet');
    // a probe never creates a bank login
    expect((await a.get('/bank/account')).headers.location).toBe('/bank/login');
  });
});

describe('connecting the attestation issuer to the SIGMA URL', () => {
  const env = { ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', MOCK_MODE: 'true' };

  it('derives the metadata URL from the base URL and caches the fetch; unreachable is reported, not fatal', async () => {
    const cfg = testConfig(env);
    expect(cfg.issuer.metadataUrl).toBe(META_URL);
    let calls = 0;
    const remote = new RemoteIssuerMetadata(cfg, (async (u: string) => { calls++; return fetchMeta(u); }) as unknown as typeof fetch);
    expect((await remote.summary())?.reachable).toBe(true);
    await remote.summary();
    expect(calls).toBe(1);
    const down = new RemoteIssuerMetadata(cfg, (async () => new Response('x', { status: 503 })) as unknown as typeof fetch);
    expect(await down.summary()).toMatchObject({ reachable: false, error: 'HTTP 503' });
    expect(testConfig({ MOCK_MODE: 'true' }).issuer.metadataUrl).toBeUndefined();
  });

  it('bank attestations are not offered by SIGMA, so they fall back to the local demo issuer (and say so)', async () => {
    const cfg = testConfig(env);
    const svc = await createServices(cfg, fetchMeta);
    for (const key of ['account', 'payment']) {
      const offer = await svc.issuer.createOffer(key, { x: 1 });
      expect(offer).toMatchObject({ provider: 'local', fallback: true });
      expect(offer.deeplink).toContain('credential_offer=');
    }
    const off = await createServices(testConfig({ ...env, ISSUER_FALLBACK_LOCAL: 'false' }), fetchMeta);
    await expect(off.issuer.createOffer('account', {})).rejects.toThrow(); // no fallback: the external API has nothing to issue
  });

  it('an attestation the SIGMA issuer does offer goes to the external API with SIGMA\'s own configuration id', async () => {
    const cfg = testConfig({ ...env, ISSUER_EXTERNAL_AUTH: 'bearer', ISSUER_API_TOKEN: 't' });
    let body: any;
    let target = '';
    const f = (async (url: string, init?: RequestInit) => {
      if (url === META_URL) return json(META);
      target = url;
      body = JSON.parse(String(init?.body));
      return json({ uri: 'openid-credential-offer://?credential_offer=%7B%7D', tx_code: '593296', qr_code: 'x', authorization_code: 'y' });
    }) as unknown as typeof fetch;
    const svc = await createServices(cfg, f);
    const offer = await svc.issuer.createOffer('birth_certificate', {});
    expect(offer).toMatchObject({ provider: 'external', txCode: '593296' });
    expect(target).toBe('https://issuer.sigma.prep.smartid.nuagein.io/offer');
    expect(body.authorization_details[0].credential_configuration_id).toBe('eu.europa.ec.eudi.birth_certificate_vc_sd_jwt');
    expect(body.identifier).toBe('user-bc-sd-jwt-001');
    expect(offer.fallback).toBeUndefined();
  });

  it('the landing page is free of issuer sections; the console creates offers', async () => {
    const cfg = testConfig(env);
    const svc = await createServices(cfg, fetchMeta);
    const app = createApp(cfg, svc);
    const home = (await request(app).get('/')).text;
    // the landing page shows neither the connected issuer's catalogue nor a local-issuer section, and never the term SIGMA
    expect(home).not.toMatch(/SIGMA/i);
    expect(home).not.toContain('Local demo issuer');
    expect(home).not.toContain('eu.europa.ec.eudi.pid_mdoc');
    // issuer portal: use-case selection -> sample records -> create the offer (SIGMA offer API)
    const portalPage = (await request(app).get('/demo-issuer')).text;
    expect(portalPage).toContain('Use case selection');
    expect(portalPage).toContain('value="pid"');
    expect(portalPage).toContain('value="birth-certificate"');
    expect(portalPage).toContain('Use other identifiers');
    expect((await request(app).get('/demo-issuer/go?useCase=pid')).headers.location).toBe('/demo-issuer/use-case/pid');
    expect((await request(app).get('/demo-issuer/go?useCase=nope')).headers.location).toBe('/demo-issuer');
    const pidPage = (await request(app).get('/demo-issuer/use-case/pid')).text;
    expect(pidPage).toContain('user-pid-mdoc-001');
    expect(pidPage).toContain('Mathieu');
    expect(pidPage).toContain('data:image/jpeg;base64,'); // portrait
    expect(pidPage).toContain('Create offer');
    const bcPage = (await request(app).get('/demo-issuer/use-case/birth-certificate')).text;
    expect(bcPage).toContain('user-bc-sd-jwt-002');
    expect((await request(app).get('/demo-issuer/use-case/unknown')).headers.location).toBe('/demo-issuer');
    expect((await request(app).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'not-configured' })).status).toBe(400);
    // no metadata URL configured: no panel, no SIGMA button
    const plain = createApp(testConfig({ MOCK_MODE: 'true' }), await createServices(testConfig({ MOCK_MODE: 'true' })));
    expect((await request(plain).post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-001' })).status).toBe(400);
  });
});

describe('issuer portal sample data', () => {
  it('matches the sample users configured in rps.json and shows the same person on matching PID / birth certificate', async () => {
    const { loadPortalUseCases } = await import('../src/issuer/portal.js');
    const { loadConfig } = await import('../src/config.js');
    const cfg = loadConfig({});
    const ucs = loadPortalUseCases();
    for (const uc of ucs) {
      const configured = cfg.attestations[uc.attestation]!.externalUsers.map((u) => `${u.identifier}|${u.credentialIdentifier}`).sort();
      expect(uc.users.map((u) => `${u.identifier}|${u.credentialId}`).sort(), uc.id).toEqual(configured);
    }
    const pid = ucs.find((u) => u.id === 'pid')!.users[0]!, bc = ucs.find((u) => u.id === 'birth-certificate')!.users[0]!;
    expect([pid.attributes.given_name, pid.attributes.family_name, pid.attributes.birth_date]).toEqual([bc.attributes.given_name, bc.attributes.family_name, bc.attributes.birth_date]);
  });
});

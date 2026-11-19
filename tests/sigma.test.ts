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

  it('parses the three real credential configurations', () => {
    expect(parsed.issuer).toBe('https://issuer.sigma.prep.smartid.nuagein.io');
    expect(parsed.configs.map((c) => c.id).sort()).toEqual(['eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', 'eu.europa.ec.eudi.pid_mdoc', 'eu.europa.ec.eudi.pid_mdoc_emrtd']);
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
    expect(bv.verifier.walletLink(await bv.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/')).length).toBeLessThan(1400);
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
      expect(offer.deeplink).toContain('credential_offer_uri=');
    }
    const off = await createServices(testConfig({ ...env, ISSUER_FALLBACK_LOCAL: 'false' }), fetchMeta);
    await expect(off.issuer.createOffer('account', {})).rejects.toThrow(); // no fallback: the external API has nothing to issue
  });

  it('an attestation the SIGMA issuer does offer goes to the external API with SIGMA\'s own configuration id', async () => {
    const cfg = testConfig({ ...env, ISSUER_EXTERNAL_AUTH: 'bearer', ISSUER_API_TOKEN: 't' });
    let body: any;
    const f = (async (url: string, init?: RequestInit) => {
      if (url === META_URL) return json(META);
      body = JSON.parse(String(init?.body));
      return json({ credential_offer_uri: 'https://issuer.sigma.prep.smartid.nuagein.io/offers/abc' });
    }) as unknown as typeof fetch;
    const svc = await createServices(cfg, f);
    const offer = await svc.issuer.createOffer('birth_certificate', { given_name: 'A' });
    expect(offer.provider).toBe('external');
    expect(body.credential_configuration_id).toBe('eu.europa.ec.eudi.birth_certificate_vc_sd_jwt');
    expect(offer.fallback).toBeUndefined();
  });

  it('the dashboard lists SIGMA\'s catalogue and what is local; the console builds an authorization-code PID offer', async () => {
    const cfg = testConfig(env);
    const svc = await createServices(cfg, fetchMeta);
    const app = createApp(cfg, svc);
    const home = (await request(app).get('/')).text;
    expect(home).toContain('Connected SIGMA issuer');
    expect(home).toContain('eu.europa.ec.eudi.pid_mdoc');
    expect(home).toContain('eu.europa.ec.eudi.birth_certificate_vc_sd_jwt');
    expect(home).toContain('Not offered by SIGMA');
    const res = await request(app).post('/demo-issuer/sigma-pid');
    expect(res.status).toBe(200);
    const link = /href="(openid-credential-offer:\/\/[^"]+)"/.exec(res.text)![1]!.replace(/&amp;/g, '&');
    const offer = JSON.parse(new URL(link).searchParams.get('credential_offer')!);
    expect(offer).toEqual({
      credential_issuer: 'https://issuer.sigma.prep.smartid.nuagein.io',
      credential_configuration_ids: ['eu.europa.ec.eudi.pid_mdoc'],
      grants: { authorization_code: { authorization_server: 'https://idp-pid.sigma.prep.smartid.nuagein.io/realms/pid-haip' } },
    });
    // no metadata URL configured: no panel, no SIGMA button
    const plain = createApp(testConfig({ MOCK_MODE: 'true' }), await createServices(testConfig({ MOCK_MODE: 'true' })));
    expect((await request(plain).get('/')).text).not.toContain('Connected SIGMA issuer');
    expect((await request(plain).post('/demo-issuer/sigma-pid')).status).toBe(404);
  });
});

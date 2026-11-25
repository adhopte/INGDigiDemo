import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const SOR = 'https://issuer-mock.sigma.prep.smartid.nuagein.io/mock-sor';
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });

async function setup(env: Record<string, string> = {}) {
  const cfg = testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_SOR_API_BASE: SOR, ...env });
  const calls: Array<{ url: string; method: string; body?: any }> = [];
  const f = (async (url: string, init?: RequestInit) => {
    if (url.endsWith('/.well-known/openid-credential-issuer')) return json({ credential_issuer: 'https://issuer.sigma.prep.smartid.nuagein.io', credential_configurations_supported: {} });
    calls.push({ url, method: init?.method ?? 'GET', ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
    if (url === `${SOR}/api/presets`) return json({ presets: [{ id: 'alex', name: 'Alex Morgan', identity: { given_name: 'Alex' }, credentials: [] }] });
    if (url.startsWith(`${SOR}/api/configurations`)) return json({ configurations: [{ id: 'eu.europa.ec.eudi.pid_mdoc', name: 'Digital Identity', format: 'mso_mdoc', fields: [] }] });
    if (url === `${SOR}/api/cases` && init?.method === 'POST') return json({ case: { identifier: 'mock-1', credentials: [], offer: { uri: 'openid-credential-offer://?x', tx_code: '123456' } } }, 201);
    if (url.startsWith(`${SOR}/api/cases/mock-1/offer`)) return json({ case: { identifier: 'mock-1', offer: { uri: 'openid-credential-offer://?y', tx_code: '654321' } } });
    if (url === `${SOR}/api/cases/mock-1`) return json({ case: { identifier: 'mock-1' } });
    return json({ error: { message: 'unexpected' } }, 404);
  }) as unknown as typeof fetch;
  const svc = await createServices(cfg, f);
  return { app: createApp(cfg, svc), cfg, calls };
}

describe('issuance workspace (identity → credentials → offer)', () => {
  it('derives the data API from the issuer host, and can be switched off', async () => {
    expect(testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_SOR_API_BASE: undefined as unknown as string }).issuer.sorApiBase).toBe(SOR);
    expect(testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_SOR_API_BASE: 'off' }).issuer.sorApiBase).toBeUndefined();
    expect(testConfig({ MOCK_MODE: 'true', ISSUER_SOR_API_BASE: SOR }).issuer.sorApiBase).toBeUndefined(); // mock mode: the simulated issuer
  });

  it('/demo-issuer is the three-step workspace, translated, without the old sample-record portal', async () => {
    const { app } = await setup();
    const page = await request(app).get('/demo-issuer');
    expect(page.status).toBe(200);
    expect(page.text).toContain('id="lab-root"');
    expect(page.text).toContain('/js/lab.js');
    expect(page.text).toContain('Continue to credentials');
    expect(page.text).not.toMatch(/SIGMA/i);
    const fr = await request(app).get('/demo-issuer?lang=fr');
    expect(fr.text).toContain('Continuer vers les attestations');
    expect((await request(app).get('/js/lab.js')).status).toBe(200);
  });

  it('forwards presets, configurations (with the language) and case creation; checks what it forwards', async () => {
    const { app, calls } = await setup();
    expect((await request(app).get('/demo-issuer/lab/api/presets')).body.presets[0].name).toBe('Alex Morgan');
    await request(app).get('/demo-issuer/lab/api/configurations?locale=fr');
    expect(calls.some((c) => c.url === `${SOR}/api/configurations?locale=fr`)).toBe(true);
    await request(app).get('/demo-issuer/lab/api/configurations?locale=../x');
    expect(calls.some((c) => c.url === `${SOR}/api/configurations?locale=en`)).toBe(true); // an odd locale falls back to en
    const ok = await request(app).post('/demo-issuer/lab/api/cases').send({
      identity: { given_name: 'Alex', family_name: 'Morgan', birth_date: '1994-06-15', evil: undefined, portrait: 'QUJD' },
      credentials: [{ credentialConfigurationId: 'eu.europa.ec.eudi.pid_mdoc', attributes: { expiry_date: '2032-01-01', height: 178, over: true, empty: '' }, portraitFromIdentity: true, extra: 'dropped' }],
    });
    expect(ok.status).toBe(201);
    expect(ok.body.case.offer.tx_code).toBe('123456');
    const sent = calls.find((c) => c.url === `${SOR}/api/cases`)!.body;
    expect(sent).toEqual({ identity: { given_name: 'Alex', family_name: 'Morgan', birth_date: '1994-06-15', portrait: 'QUJD' }, credentials: [{ credentialConfigurationId: 'eu.europa.ec.eudi.pid_mdoc', attributes: { expiry_date: '2032-01-01', height: 178, over: true }, portraitFromIdentity: true }] });
    for (const bad of [
      {}, { identity: {}, credentials: [] }, { identity: { given_name: '<b>' }, credentials: [{ credentialConfigurationId: 'x' }] },
      { identity: { a: 'b' }, credentials: [{ credentialConfigurationId: '../etc' }] }, { identity: { portrait: '<img>' }, credentials: [{ credentialConfigurationId: 'x' }] },
      { identity: {}, credentials: [{ credentialConfigurationId: 'x', attributes: { 'Bad Key': 1 } }] },
    ]) expect((await request(app).post('/demo-issuer/lab/api/cases').send(bad)).status, JSON.stringify(bad)).toBe(422);
    expect(calls.filter((c) => c.url === `${SOR}/api/cases`)).toHaveLength(1); // nothing invalid reached the issuer
  });

  it('regenerates an offer and reads a case; refuses odd ids; reports an unreachable issuer', async () => {
    const { app } = await setup();
    expect((await request(app).post('/demo-issuer/lab/api/cases/mock-1/offer')).body.case.offer.tx_code).toBe('654321');
    expect((await request(app).get('/demo-issuer/lab/api/cases/mock-1')).body.case.identifier).toBe('mock-1');
    expect((await request(app).get('/demo-issuer/lab/api/cases/..%2Fadmin')).status).toBe(404);
    const down = testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_SOR_API_BASE: SOR });
    const svc = await createServices(down, (async () => { throw new Error('offline'); }) as unknown as typeof fetch);
    const r = await request(createApp(down, svc)).get('/demo-issuer/lab/api/presets');
    expect(r.status).toBe(502);
    expect(r.body.error.message).toMatch(/could not be reached/);
  });

  it('without the data API the old portal stays', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_SOR_API_BASE: 'off' });
    const app = createApp(cfg, await createServices(cfg, (async () => json({})) as unknown as typeof fetch));
    expect((await request(app).get('/demo-issuer')).text).not.toContain('id="lab-root"');
    expect((await request(app).post('/demo-issuer/lab/api/cases').send({})).status).toBe(404);
  });
});

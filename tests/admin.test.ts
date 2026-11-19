import { readFileSync } from 'node:fs';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { validateRecord } from '../src/issuer/records.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const META = JSON.parse(readFileSync(new URL('./fixtures/sigma-issuer-metadata.json', import.meta.url), 'utf8'));
const META_URL = 'https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer';
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });

async function setup(env: Record<string, string> = {}) {
  const cfg = testConfig({ ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', MOCK_MODE: 'false', ...env });
  const calls: any[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    if (url === META_URL) return json(META);
    calls.push({ url, body: JSON.parse(String(init?.body)) });
    return json({ uri: 'openid-credential-offer://?credential_offer=%7B%7D', tx_code: '135790', authorization_code: 'abc' });
  }) as unknown as typeof fetch;
  const svc = await createServices(cfg, f);
  const app = createApp(cfg, svc);
  return { app, svc, calls, agent: request.agent(app) };
}

const PID_FORM = { uc: 'pid', given_name: 'Amina', family_name: 'Koffi', birth_date: '1990-05-17', nationality: 'BJ', gender: '2' };

describe('admin console (mock of an authentic source)', () => {
  it('validates attributes and derives age_over_18', () => {
    expect(validateRecord('pid', PID_FORM)).toMatchObject({ ok: true, attributes: { given_name: 'Amina', age_over_18: 'True' } });
    expect(validateRecord('pid', { ...PID_FORM, birth_date: '2099-01-01' })).toMatchObject({ ok: true, attributes: { age_over_18: 'False' } });
    expect(validateRecord('pid', { ...PID_FORM, given_name: '' })).toMatchObject({ ok: false, errors: { given_name: 'admin.err.required' } });
    expect(validateRecord('pid', { ...PID_FORM, birth_date: '17/05/1990' })).toMatchObject({ ok: false, errors: { birth_date: 'admin.err.date' } });
    expect(validateRecord('pid', { ...PID_FORM, gender: '7' })).toMatchObject({ ok: false, errors: { gender: 'admin.err.choice' } });
    expect(validateRecord('pid', { ...PID_FORM, family_name: '<script>' })).toMatchObject({ ok: false, errors: { family_name: 'admin.err.chars' } });
    const r = validateRecord('pid', { ...PID_FORM, evil: 'x' });
    expect(r.ok && 'evil' in r.attributes).toBe(false); // unknown fields are dropped
  });

  it('is closed to normal users and opens with the admin password', async () => {
    const { agent } = await setup();
    expect((await agent.get('/demo-issuer/admin')).headers.location).toBe('/demo-issuer/admin/login');
    expect((await agent.post('/demo-issuer/admin/offer').type('form').send(PID_FORM)).headers.location).toBe('/demo-issuer/admin/login');
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'wrong' })).status).toBe(401);
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'root', password: 'Admin123' })).status).toBe(401);
    const ok = await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
    expect(ok.status).toBe(302);
    const page = await agent.get('/demo-issuer/admin');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Authentic source (admin)');
    expect(page.text).toContain('name="given_name"');
    expect(page.text).toContain('value="Mathieu"'); // pre-filled from the first sample record
    expect((await agent.post('/demo-issuer/admin/logout')).status).toBe(302);
    expect((await agent.get('/demo-issuer/admin')).headers.location).toBe('/demo-issuer/admin/login');
  });

  it('locks sign-in after repeated failures; the password is configurable', async () => {
    const { agent } = await setup({ ADMIN_PASSWORD: 'S3cret!' });
    for (let i = 0; i < 5; i++) await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'nope' });
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'S3cret!' })).status).toBe(429);
    const fresh = (await setup({ ADMIN_PASSWORD: 'S3cret!' })).agent;
    expect((await fresh.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' })).status).toBe(401);
    expect((await fresh.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'S3cret!' })).status).toBe(302);
  });

  it('saves the record and creates the SIGMA offer for its identifier; the record service serves it', async () => {
    const { agent, calls, app } = await setup();
    await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
    const bad = await agent.post('/demo-issuer/admin/offer').type('form').send({ ...PID_FORM, given_name: '' });
    expect(bad.status).toBe(422);
    expect(bad.text).toContain('This field is required.');
    expect(calls).toHaveLength(0);
    const res = await agent.post('/demo-issuer/admin/offer').type('form').send(PID_FORM);
    expect(res.status).toBe(200);
    expect(res.text).toContain('135790'); // transaction code
    expect(res.text).toContain('Pre-authorised code');
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://issuer.sigma.prep.smartid.nuagein.io/offer');
    const sent = calls[0].body;
    expect(sent.identifier).toMatch(/^custom-pid-[0-9a-f]{8}$/);
    expect(sent.authorization_details[0]).toMatchObject({ credential_configuration_id: 'eu.europa.ec.eudi.pid_mdoc', credential_identifiers: ['custom_pid_mdoc'] });
    // the record service (same contract as the WalletTester's SoR) answers for it, and only for the right credential id / configuration
    const sor = await request(app).get(`/sor/eu.europa.ec.eudi.pid_mdoc/sor/${sent.identifier}?credential_identifier=custom_pid_mdoc`);
    expect(sor.status).toBe(200);
    expect(sor.body.identifier).toBe(sent.identifier);
    expect(sor.body.attributes).toContainEqual({ name: 'given_name', value: 'Amina' });
    expect(sor.body.attributes).toContainEqual({ name: 'age_over_18', value: 'True' });
    expect((await request(app).get(`/sor/eu.europa.ec.eudi.pid_mdoc/sor/${sent.identifier}?credential_identifier=other`)).status).toBe(404);
    expect((await request(app).get(`/sor/eu.europa.ec.eudi.birth_certificate_vc_sd_jwt/sor/${sent.identifier}`)).status).toBe(404);
    // sample records are served too, with their portrait
    const sample = await request(app).get('/sor/eu.europa.ec.eudi.pid_mdoc/sor/user-pid-mdoc-001?credential_identifier=credential_id_1_mdoc');
    expect(sample.status).toBe(200);
    expect(sample.body.attributes.some((a: any) => a.name === 'portrait')).toBe(true);
    expect((await request(app).get('/sor/eu.europa.ec.eudi.pid_mdoc/sor/')).status).toBe(404); // no list endpoint
    // listed on the admin page; offer again, then delete
    const page = await agent.get('/demo-issuer/admin');
    expect(page.text).toContain(sent.identifier);
    expect((await agent.post(`/demo-issuer/admin/records/${sent.identifier}/offer`)).status).toBe(200);
    expect(calls).toHaveLength(2);
    await agent.post(`/demo-issuer/admin/records/${sent.identifier}/delete`);
    expect((await request(app).get(`/sor/eu.europa.ec.eudi.pid_mdoc/sor/${sent.identifier}`)).status).toBe(404);
  });

  it('birth certificate uses its own configuration', async () => {
    const { agent, calls } = await setup();
    await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
    const res = await agent.post('/demo-issuer/admin/offer').type('form').send({ uc: 'birth-certificate', given_name: 'Amina', family_name: 'Koffi', birth_date: '1990-05-17', birth_place: 'Cotonou' });
    expect(res.status).toBe(200);
    expect(calls[0].body.identifier).toMatch(/^custom-bc-/);
    expect(calls[0].body.authorization_details[0]).toMatchObject({ credential_configuration_id: 'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', credential_identifiers: ['custom_birth_certificate'] });
  });

  it('normal users still create offers from the sample records', async () => {
    const { agent, calls } = await setup();
    expect((await agent.get('/demo-issuer')).text).toContain('Admin: enter records manually');
    const res = await agent.post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-001' });
    expect(res.status).toBe(200);
    expect(calls[0].body.identifier).toBe('user-pid-mdoc-001');
  });
});

describe('admin console in mock mode', () => {
  it('issues the entered values through the local demo issuer', async () => {
    const cfg = testConfig({ MOCK_MODE: 'true' });
    const svc = await createServices(cfg);
    const agent = request.agent(createApp(cfg, svc));
    await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
    const res = await agent.post('/demo-issuer/admin/offer').type('form').send(PID_FORM);
    expect(res.status).toBe(200);
    expect(res.text).toContain('openid-credential-offer://');
    expect(res.text).not.toContain('SIGMA issuer fills'); // no record-service note in mock mode
  });
});

import { readFileSync } from 'node:fs';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { matchRecords, validateRecord } from '../src/issuer/records.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const META = JSON.parse(readFileSync(new URL('./fixtures/sigma-issuer-metadata.json', import.meta.url), 'utf8'));
const META_URL = 'https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer';
const ISSUER = 'https://issuer.sigma.prep.smartid.nuagein.io';
const PID_LIST_URL = `${ISSUER}/api/in-person-portal-sor/oid_pid_inp_uc1/sor/`;
const MDL_LIST_URL = `${ISSUER}/api/in-person-portal-sor/oid_mdl_uc1/sor/`;
const BC_LIST_URL = `${ISSUER}/api/in-person-portal-sor/oid_birth_certificate_sd_jwt_uc1/sor/`;
const file = (n: string) => readFileSync(new URL(`../config/portal/${n}`, import.meta.url), 'utf8');
const json = (b: unknown, status = 200) => new Response(typeof b === 'string' ? b : JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });

async function setup(opts: { env?: Record<string, string>; pidList?: () => Response } = {}) {
  const cfg = testConfig({ ISSUER_MODE: 'external', ISSUER_API_BASE_URL: ISSUER, MOCK_MODE: 'false', ...opts.env });
  const offers: any[] = [];
  const fetched: string[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    if (url === META_URL) return json(META);
    if (url === PID_LIST_URL) { fetched.push(url); return opts.pidList ? opts.pidList() : json(file('user_pid_claims.json')); }
    if (url === MDL_LIST_URL) { fetched.push(url); return json(file('mdl_claims.json')); }
    if (url === BC_LIST_URL) { fetched.push(url); return json(file('birth_certificate_claims_sd_jwt.json')); }
    offers.push(JSON.parse(String(init?.body)));
    return json({ uri: 'openid-credential-offer://?credential_offer=%7B%7D', tx_code: '135790', authorization_code: 'abc' });
  }) as unknown as typeof fetch;
  const svc = await createServices(cfg, f);
  const agent = request.agent(createApp(cfg, svc));
  return { agent, offers, fetched, svc };
}
const login = (a: ReturnType<typeof request.agent>) => a.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });

const MATHIEU = { uc: 'pid', given_name: 'Mathieu', family_name: 'Ahouandjinou', birth_date: '1988-07-21', nationality: 'BJ', gender: '1' };

describe('record validation and matching', () => {
  it('validates attributes and derives age_over_18', () => {
    expect(validateRecord('pid', MATHIEU)).toMatchObject({ ok: true, attributes: { given_name: 'Mathieu', age_over_18: 'True' } });
    expect(validateRecord('pid', { ...MATHIEU, given_name: '' })).toMatchObject({ ok: false, errors: { given_name: 'admin.err.required' } });
    expect(validateRecord('pid', { ...MATHIEU, birth_date: '21/07/1988' })).toMatchObject({ ok: false, errors: { birth_date: 'admin.err.date' } });
    expect(validateRecord('pid', { ...MATHIEU, gender: '7' })).toMatchObject({ ok: false, errors: { gender: 'admin.err.choice' } });
    expect(validateRecord('pid', { ...MATHIEU, family_name: '<script>' })).toMatchObject({ ok: false, errors: { family_name: 'admin.err.chars' } });
    const r = validateRecord('pid', { ...MATHIEU, evil: 'x' });
    expect(r.ok && 'evil' in r.attributes).toBe(false);
  });

  it('matches case- and accent-insensitively, and never on an empty entry', () => {
    const recs = [{ attributes: { given_name: 'Mathieu', family_name: 'Ahouandjinou', birth_date: '1988-07-21' } }, { attributes: { given_name: 'Estelle', family_name: 'Houngbedji', birth_date: '2010-11-23' } }];
    expect(matchRecords(recs, { given_name: 'MATHIEU', family_name: ' ahouandjinou ' })).toHaveLength(1);
    expect(matchRecords(recs, { given_name: 'Éstelle', birth_date: '2010-11-23' })).toHaveLength(1);
    expect(matchRecords(recs, { given_name: 'Mathieu', birth_date: '2010-11-23' })).toHaveLength(0);
    expect(matchRecords(recs, { nationality: 'BJ' })).toHaveLength(0); // attribute the record does not have
    expect(matchRecords(recs, {})).toEqual([]);
  });
});

describe('admin console (mock of an authentic source check)', () => {
  it('is closed to normal users and opens with the admin password', async () => {
    const { agent } = await setup();
    expect((await agent.get('/demo-issuer/admin')).headers.location).toBe('/demo-issuer/admin/login');
    expect((await agent.post('/demo-issuer/admin/check').type('form').send(MATHIEU)).headers.location).toBe('/demo-issuer/admin/login');
    expect((await agent.post('/demo-issuer/admin/pick').type('form').send({ uc: 'pid', identifier: 'user-pid-mdoc-001' })).headers.location).toBe('/demo-issuer/admin/login');
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'wrong' })).status).toBe(401);
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'root', password: 'Admin123' })).status).toBe(401);
    expect((await login(agent)).status).toBe(302);
    const page = await agent.get('/demo-issuer/admin');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Authentic source (admin)');
    expect(page.text).toContain('value="Mathieu"'); // pre-filled from the first sample record
    expect(page.text).toContain('checked against those records');
    expect((await agent.post('/demo-issuer/admin/logout')).status).toBe(302);
    expect((await agent.get('/demo-issuer/admin')).headers.location).toBe('/demo-issuer/admin/login');
  });

  it('locks sign-in after repeated failures; the password is configurable', async () => {
    const { agent } = await setup({ env: { ADMIN_PASSWORD: 'S3cret!' } });
    for (let i = 0; i < 5; i++) await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'nope' });
    expect((await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'S3cret!' })).status).toBe(429);
    const fresh = (await setup({ env: { ADMIN_PASSWORD: 'S3cret!' } })).agent;
    expect((await login(fresh)).status).toBe(401);
    expect((await fresh.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'S3cret!' })).status).toBe(302);
  });

  it('a single matching record in the issuer\'s record store gets its SIGMA offer', async () => {
    const { agent, offers, fetched } = await setup();
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send(MATHIEU);
    expect(res.status).toBe(200);
    expect(res.text).toContain('135790');
    expect(fetched).toEqual([PID_LIST_URL]); // read live
    expect(offers).toHaveLength(1);
    expect(offers[0]).toMatchObject({ identifier: 'user-pid-mdoc-001', authorization_details: [{ credential_configuration_id: 'eu.europa.ec.eudi.pid_mdoc', credential_identifiers: ['credential_id_1_mdoc'] }] });
    // only the required fields, different case: still the same person
    const loose = await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'pid', given_name: 'mathieu', family_name: 'AHOUANDJINOU', birth_date: '1988-07-21' });
    expect(loose.status).toBe(200);
    expect(offers[1].identifier).toBe('user-pid-mdoc-001');
    // the second sample person
    await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'pid', given_name: 'Estelle', family_name: 'Houngbedji', birth_date: '2010-11-23' });
    expect(offers[2]).toMatchObject({ identifier: 'user-pid-mdoc-002', authorization_details: [{ credential_identifiers: ['credential_id_2_mdoc'] }] });
  });

  it('birth certificate uses its own configuration and record list', async () => {
    const { agent, offers, fetched } = await setup();
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'birth-certificate', given_name: 'Mathieu', family_name: 'Ahouandjinou', birth_date: '1988-07-21', birth_place: 'Cotonou' });
    expect(res.status).toBe(200);
    expect(fetched).toEqual([BC_LIST_URL]);
    expect(offers[0]).toMatchObject({ identifier: 'user-bc-sd-jwt-001', authorization_details: [{ credential_configuration_id: 'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', credential_identifiers: ['birth_certificate_full_data'] }] });
  });

  it('shows "no record" with the available records, and creates no offer, when nothing matches', async () => {
    const { agent, offers } = await setup();
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send({ ...MATHIEU, birth_date: '1999-01-01' });
    expect(res.status).toBe(404);
    expect(res.text).toContain('No record in the authentic source matches');
    expect(res.text).toContain('user-pid-mdoc-002'); // lists what exists
    expect(offers).toHaveLength(0);
    // validation errors come back on the form, before any lookup
    const bad = await agent.post('/demo-issuer/admin/check').type('form').send({ ...MATHIEU, given_name: '' });
    expect(bad.status).toBe(422);
    expect(bad.text).toContain('This field is required.');
  });

  it('several matches: lists them and issues for the chosen one (looked up again on the server)', async () => {
    const dup = JSON.parse(file('user_pid_claims.json'));
    dup.push({ ...JSON.parse(JSON.stringify(dup[0])), identifier: 'user-pid-mdoc-009', credentialId: 'credential_id_9_mdoc' });
    const { agent, offers } = await setup({ pidList: () => json(dup) });
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send(MATHIEU);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Several records match');
    expect(res.text).toContain('user-pid-mdoc-009');
    expect(offers).toHaveLength(0);
    expect((await agent.post('/demo-issuer/admin/pick').type('form').send({ uc: 'pid', identifier: 'user-pid-mdoc-009' })).status).toBe(200);
    expect(offers[0]).toMatchObject({ identifier: 'user-pid-mdoc-009', authorization_details: [{ credential_identifiers: ['credential_id_9_mdoc'] }] });
    expect((await agent.post('/demo-issuer/admin/pick').type('form').send({ uc: 'pid', identifier: 'ghost' })).headers.location).toBe('/demo-issuer/admin?uc=pid');
    expect(offers).toHaveLength(1);
  });

  it('falls back to the saved copy of the sample records when the issuer\'s list cannot be read', async () => {
    const { agent, offers } = await setup({ pidList: () => new Response('x', { status: 500 }) });
    await login(agent);
    expect((await agent.post('/demo-issuer/admin/check').type('form').send(MATHIEU)).status).toBe(200);
    expect(offers[0].identifier).toBe('user-pid-mdoc-001');
    const none = await agent.post('/demo-issuer/admin/check').type('form').send({ ...MATHIEU, given_name: 'Nobody' });
    expect(none.text).toContain('saved copy of its sample records');
  });

  it('normal users still create offers from the sample records', async () => {
    const { agent, offers } = await setup();
    expect((await agent.get('/demo-issuer')).text).toContain('Admin: enter records manually');
    expect((await agent.post('/demo-issuer/sigma-offer').type('form').send({ type: 'pid', identifier: 'user-pid-mdoc-001' })).status).toBe(200);
    expect(offers[0].identifier).toBe('user-pid-mdoc-001');
  });
});

describe('admin console in mock mode', () => {
  it('issues the typed values through the local demo issuer (no SIGMA)', async () => {
    const cfg = testConfig({ MOCK_MODE: 'true' });
    const agent = request.agent(createApp(cfg, await createServices(cfg)));
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send({ ...MATHIEU, given_name: 'Amina', family_name: 'Koffi' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('openid-credential-offer://');
  });
});

describe('mobile driving licence (mDL, mdoc) from the SIGMA issuer', () => {
  it('portal: lists the three sample records and creates an offer for the chosen one (config id, credential id, wallet id)', async () => {
    const { agent, offers } = await setup();
    const home = await agent.get('/demo-issuer');
    expect(home.text).toContain('Mobile driving licence (mDL)');
    const page = await agent.get('/demo-issuer/use-case/mdl');
    expect(page.status).toBe(200);
    for (const n of ['Sophie', 'Marco', 'Lena']) expect(page.text).toContain(n);
    expect((await agent.post('/demo-issuer/sigma-offer').type('form').send({ type: 'mdl', identifier: 'user-002' })).status).toBe(200);
    expect(offers[0]).toMatchObject({ identifier: 'user-002', walletIdentifier: 'w-002', authorization_details: [{ credential_configuration_id: 'org.iso.18013.5.1.mDL', credential_identifiers: ['driving-license'] }] });
  });

  it('admin: typed attributes are matched against the record store, then the offer is created for the record', async () => {
    const { agent, offers, fetched } = await setup();
    await login(agent);
    const form = await agent.get('/demo-issuer/admin?uc=mdl');
    expect(form.text).toContain('value="Sophie"'); // pre-filled from the first sample record
    const res = await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'mdl', given_name: 'Marco', family_name: 'ROSSI', birth_date: '1985-08-22', document_number: 'DL87654321', age_over_18: 'True' });
    expect(res.status).toBe(200);
    expect(fetched).toContain(MDL_LIST_URL);
    expect(offers[0]).toMatchObject({ identifier: 'user-002', authorization_details: [{ credential_configuration_id: 'org.iso.18013.5.1.mDL' }] });
    const none = await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'mdl', given_name: 'Nobody', family_name: 'Here', birth_date: '1980-01-01' });
    expect(none.status).toBe(404);
  });

  it('the SIGMA record layout (booleans, numbers, driving privileges) is read faithfully', async () => {
    const { parseUsers } = await import('../src/issuer/portal.js');
    const users = parseUsers(JSON.parse(file('mdl_claims.json')));
    expect(users).toHaveLength(3);
    expect(users[0]!.attributes).toMatchObject({ age_over_18: 'True', sex: '2', height: '168' });
    expect(users[1]!.attributes.driving_privileges).toContain('vehicle_category_code');
    expect(users[0]!.portrait).toBeTruthy();
  });

  it('mock mode: the local demo issuer issues a demo driving licence as SD-JWT (for the simulated wallet)', async () => {
    const cfg = testConfig({ MOCK_MODE: 'true' });
    const agent = request.agent(createApp(cfg, await createServices(cfg)));
    await login(agent);
    const res = await agent.post('/demo-issuer/admin/check').type('form').send({ uc: 'mdl', given_name: 'Amina', family_name: 'Koffi', birth_date: '1990-01-01' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('openid-credential-offer://');
  });
});

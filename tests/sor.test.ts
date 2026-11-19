import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { readFileSync as read } from 'node:fs';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { afterAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { FileRecordStore, RecordStore } from '../src/issuer/records.js';
import { createServices } from '../src/services.js';
import { createSorApp } from '../src/sor/app.js';
import { testConfig } from './helpers.js';

const TOKEN = 'test-token-123';
const AUTH = { Authorization: `Bearer ${TOKEN}` };
const PID = { useCase: 'pid', attributes: { given_name: 'Amina', family_name: 'Koffi', birth_date: '1990-05-17' } };
const JPEG_B64 = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 16]), Buffer.from('JFIF fake body')]).toString('base64');
const tmp = mkdtempSync(path.join(os.tmpdir(), 'sor-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe('standalone record service', () => {
  it('serves the sample records with the WalletTester SoR contract', async () => {
    const app = createSorApp({ store: new RecordStore() });
    const ok = await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/user-pid-mdoc-001?credential_identifier=credential_id_1_mdoc');
    expect(ok.status).toBe(200);
    expect(ok.body.identifier).toBe('user-pid-mdoc-001');
    expect(ok.body.attributes).toContainEqual({ name: 'given_name', value: 'Mathieu' });
    expect(ok.body).not.toHaveProperty('credentialId'); // internal fields are not exposed
    expect((await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/user-pid-mdoc-001')).status).toBe(200); // credential id optional
    expect((await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/user-pid-mdoc-001?credential_identifier=nope')).status).toBe(404);
    expect((await request(app).get('/eu.europa.ec.eudi.birth_certificate_vc_sd_jwt/sor/user-pid-mdoc-001')).status).toBe(404); // wrong configuration
    expect((await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/unknown')).text).toBe('User not found by identifier');
    expect((await request(app).get('/healthz')).body).toEqual({ status: 'ok' });
  });

  it('write API: disabled without a token, closed without the right token, validated', async () => {
    const off = createSorApp({ store: new RecordStore() });
    expect((await request(off).put('/records/custom-pid-aaaa1111').send(PID)).status).toBe(503);
    const app = createSorApp({ store: new RecordStore(), apiToken: TOKEN });
    expect((await request(app).put('/records/custom-pid-aaaa1111').send(PID)).status).toBe(401);
    expect((await request(app).put('/records/custom-pid-aaaa1111').set('Authorization', 'Bearer wrong').send(PID)).status).toBe(401);
    expect((await request(app).get('/records')).status).toBe(401);
    expect((await request(app).put('/records/bad id!').set(AUTH).send(PID)).status).toBe(400);
    expect((await request(app).put('/records/custom-pid-aaaa1111').set(AUTH).send({ ...PID, useCase: 'nope' })).status).toBe(400);
    expect((await request(app).put('/records/custom-pid-aaaa1111').set(AUTH).send({ useCase: 'pid', attributes: { given_name: '' } })).status).toBe(422);
    expect((await request(app).put('/records/custom-pid-aaaa1111').set(AUTH).send({ ...PID, portrait: 'AAAA' })).status).toBe(422);
    const created = await request(app).put('/records/custom-pid-aaaa1111').set(AUTH).send({ ...PID, portrait: JPEG_B64 });
    expect(created.status).toBe(201);
    expect((await request(app).put('/records/custom-pid-aaaa1111').set(AUTH).send(PID)).status).toBe(200); // upsert
    const read = await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/custom-pid-aaaa1111?credential_identifier=custom_pid_mdoc'); // the issuer needs no token
    expect(read.status).toBe(200);
    expect(read.body.attributes).toContainEqual({ name: 'age_over_18', value: 'True' });
    expect((await request(app).get('/records').set(AUTH)).body).toHaveLength(1);
    expect((await request(app).delete('/records/custom-pid-aaaa1111').set(AUTH)).status).toBe(204);
    expect((await request(app).get('/eu.europa.ec.eudi.pid_mdoc/sor/custom-pid-aaaa1111')).status).toBe(404);
    expect((await request(app).delete('/records/custom-pid-aaaa1111').set(AUTH)).status).toBe(404);
  });

  it('keeps records in a file across restarts', async () => {
    const file = path.join(tmp, 'sub', 'records.json');
    await request(createSorApp({ store: new FileRecordStore(file), apiToken: TOKEN })).put('/records/custom-bc-bbbb2222').set(AUTH).send({ useCase: 'birth-certificate', attributes: { given_name: 'A', family_name: 'B', birth_date: '2000-01-01' } });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toHaveLength(1);
    const restarted = createSorApp({ store: new FileRecordStore(file), apiToken: TOKEN });
    expect((await request(restarted).get('/eu.europa.ec.eudi.birth_certificate_vc_sd_jwt/sor/custom-bc-bbbb2222?credential_identifier=custom_birth_certificate')).status).toBe(200);
  });
});

describe('admin console writing to the standalone service', () => {
  it('saves the record in the service, creates the SIGMA offer, and the issuer-side read works', async () => {
    const server = createSorApp({ store: new RecordStore(), apiToken: TOKEN }).listen(0);
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const META = JSON.parse(read(new URL('./fixtures/sigma-issuer-metadata.json', import.meta.url), 'utf8'));
      const calls: any[] = [];
      const f = (async (url: string, init?: RequestInit) => {
        if (url.startsWith(base)) return fetch(url, init); // the real record service
        if (url === 'https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer') return new Response(JSON.stringify(META), { headers: { 'content-type': 'application/json' } });
        calls.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ uri: 'openid-credential-offer://?credential_offer=%7B%7D', tx_code: '424242' }), { headers: { 'content-type': 'application/json' } });
      }) as unknown as typeof fetch;
      const cfg = testConfig({ ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', MOCK_MODE: 'false', SOR_URL: `${base}/`, SOR_API_TOKEN: TOKEN });
      expect(cfg.sor.url).toBe(base);
      const agent = request.agent(createApp(cfg, await createServices(cfg, f)));
      await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
      const res = await agent.post('/demo-issuer/admin/offer').type('form').send({ uc: 'pid', given_name: 'Amina', family_name: 'Koffi', birth_date: '1990-05-17', portrait: JPEG_B64, via: 'sigma' });
      expect(res.status).toBe(200);
      expect(res.text).toContain('424242');
      const id = calls[0].identifier as string;
      // what the SIGMA issuer would now fetch from the service
      const sor = await fetch(`${base}/eu.europa.ec.eudi.pid_mdoc/sor/${id}?credential_identifier=custom_pid_mdoc`);
      expect(sor.status).toBe(200);
      const body = (await sor.json()) as any;
      expect(body.attributes).toContainEqual({ name: 'given_name', value: 'Amina' });
      expect(body.attributes).toContainEqual({ name: 'portrait', value: JPEG_B64 });
      // the admin page lists it (read back from the service) and shows the service address for the SIGMA team
      const page = await agent.get('/demo-issuer/admin');
      expect(page.text).toContain(id);
      expect(page.text).toContain(`${base}/eu.europa.ec.eudi.pid_mdoc/sor/`);
      expect((await agent.post(`/demo-issuer/admin/records/${id}/offer`).type('form').send({ via: 'sigma' })).status).toBe(200);
      await agent.post(`/demo-issuer/admin/records/${id}/delete`);
      expect((await fetch(`${base}/eu.europa.ec.eudi.pid_mdoc/sor/${id}`)).status).toBe(404);
    } finally { server.close(); }
  });

  it('shows an error instead of crashing when the service is unreachable or the token is wrong', async () => {
    const server = createSorApp({ store: new RecordStore(), apiToken: TOKEN }).listen(0);
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const cfg = testConfig({ MOCK_MODE: 'true', SOR_URL: base, SOR_API_TOKEN: 'wrong-token' });
      const agent = request.agent(createApp(cfg, await createServices(cfg)));
      await agent.post('/demo-issuer/admin/login').type('form').send({ username: 'admin', password: 'Admin123' });
      const bad = await agent.post('/demo-issuer/admin/offer').type('form').send({ uc: 'pid', given_name: 'A', family_name: 'B', birth_date: '1990-01-01' });
      expect(bad.status).toBe(502);
      expect(bad.text).toContain('record service could not be reached');
      expect((await agent.get('/demo-issuer/admin')).text).toContain('Saved records cannot be shown');
    } finally { server.close(); }
  });
});

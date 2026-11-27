import request from 'supertest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { Decoder, Tag } from 'cbor-x';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const dec = new Decoder({ useRecords: false, mapsAsObjects: false });

async function setup(env: Record<string, string> = {}) {
  const cfg = testConfig({ MOCK_MODE: 'false', ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.sigma.prep.smartid.nuagein.io', ISSUER_PORTAL_SOURCE: 'local', ...env });
  const svc = await createServices(cfg, (async () => new Response('{}', { status: 200 })) as unknown as typeof fetch);
  return { app: createApp(cfg, svc), svc, cfg };
}

describe('issuance workspace on the LOCAL issuer (temporary, while the external issuer is under maintenance)', () => {
  it('serves presets and configurations itself, in the visitor\'s language', async () => {
    const { app } = await setup();
    expect((await request(app).get('/demo-issuer')).text).toContain('id="lab-root"');
    const presets = (await request(app).get('/demo-issuer/lab/api/presets')).body.presets;
    expect(presets.map((p: any) => p.name)).toEqual(['Alex Morgan', 'Éléonore Lefèvre', 'Sahy Rabari']);
    const en = (await request(app).get('/demo-issuer/lab/api/configurations?locale=en')).body.configurations;
    expect(en.map((c: any) => c.id).sort()).toEqual(['eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', 'eu.europa.ec.eudi.pid_mdoc', 'org.iso.18013.5.1.mDL']);
    const fr = (await request(app).get('/demo-issuer/lab/api/configurations?locale=fr')).body.configurations;
    expect(fr.find((c: any) => c.id === 'eu.europa.ec.eudi.pid_mdoc').fields.find((f: any) => f.name === 'family_name').label).toBe('Nom');
  });

  it('one case = one pre-authorised offer with a 6-digit code for PID (mdoc), driving licence (mdoc) and birth certificate (SD-JWT); the wallet redeems each with the same token', async () => {
    const { app, svc } = await setup();
    const alex = (await request(app).get('/demo-issuer/lab/api/presets')).body.presets[0];
    const res = await request(app).post('/demo-issuer/lab/api/cases').send({
      identity: alex.identity,
      credentials: alex.credentials.map((c: any) => ({ credentialConfigurationId: c.credentialConfigurationId, attributes: c.attributes, ...(c.portraitFromIdentity ? { portraitFromIdentity: true } : {}) })),
    });
    expect(res.status).toBe(201);
    const rec = res.body.case;
    expect(rec.identifier).toMatch(/^local-[0-9a-f]{24}$/);
    expect(rec.offer.tx_code).toMatch(/^\d{6}$/);
    expect(rec.offer.uri).toMatch(/^openid-credential-offer:\/\//);
    expect(Buffer.from(rec.offer.qr_code, 'base64').subarray(1, 4).toString()).toBe('PNG');
    expect(rec.credentials).toHaveLength(3);
    const offer = JSON.parse(decodeURIComponent(rec.offer.uri.split('credential_offer=')[1]));
    expect(offer.credential_issuer).toBe(svc.local.issuerUrl);
    expect(offer.credential_configuration_ids).toEqual(['demo_pid_mdoc', 'demo_mdl_mdoc', 'demo_birth_certificate']);
    const grant = offer.grants[PRE_AUTH_GRANT];
    expect(grant.tx_code).toMatchObject({ input_mode: 'numeric', length: 6 });
    // the wallet: token (with the code), then one credential request per configuration
    await expect(svc.local.exchangePreAuthorizedCode({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': grant['pre-authorized_code'], tx_code: '000000' === rec.offer.tx_code ? '111111' : '000000' })).rejects.toThrow(/tx_code/);
    const token = await svc.local.exchangePreAuthorizedCode({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': grant['pre-authorized_code'], tx_code: rec.offer.tx_code });
    const get = async (configId: string) => {
      const kp = await generateKeyPair('ES256', { extractable: true });
      const proof = await new SignJWT({ nonce: svc.local.newNonce() }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(kp.publicKey) }).setAudience(svc.local.issuerUrl).setIssuedAt().sign(kp.privateKey);
      return (await svc.local.issueCredential(token.access_token, { credential_configuration_id: configId, proofs: { jwt: [proof] } })).credentials[0]!.credential;
    };
    const elements = (b64: string, ns: string) => Object.fromEntries(((dec.decode(Buffer.from(b64, 'base64url')) as Map<string, any>).get('nameSpaces') as Map<string, Tag[]>).get(ns)!.map((t) => { const m = dec.decode(t.value) as Map<string, any>; return [m.get('elementIdentifier'), m.get('elementValue')]; }));
    const pid = elements(await get('demo_pid_mdoc'), 'eu.europa.ec.eudi.pid.1');
    expect(pid).toMatchObject({ family_name: 'Morgan', given_name: 'Alex', nationality: ['PL'], issuing_country: 'PL', age_over_18: true });
    expect(pid.portrait).toBeInstanceOf(Uint8Array); // the portrait as bytes
    expect(pid.birth_date).toBeInstanceOf(Tag);
    const mdl = elements(await get('demo_mdl_mdoc'), 'org.iso.18013.5.1');
    expect(mdl).toMatchObject({ family_name: 'Morgan', document_number: 'AA12345', un_distinguishing_sign: 'PL', height: 178, age_over_21: true });
    expect(mdl.driving_privileges[0].get('vehicle_category_code')).toBe('B'); // "B" becomes the structured list
    const bc = await get('demo_birth_certificate');
    const disclosed = Object.fromEntries(bc.split('~').slice(1, -1).map((d) => { const a = JSON.parse(Buffer.from(d, 'base64url').toString()); return [a[1], a[2]]; }));
    expect(disclosed).toMatchObject({ birth_record_reference: 'AA123456789', family_name: 'Morgan', birth_city: 'Łódź' });
    await expect(get('demo_birth_certificate')).rejects.toThrow(); // used up once all three were issued
    // diagnostics and a fresh offer for the same case
    expect((await request(app).get(`/demo-issuer/lab/api/cases/${rec.identifier}`)).body.case.credentials[1].attributes.document_number).toBe('AA12345');
    const again = await request(app).post(`/demo-issuer/lab/api/cases/${rec.identifier}/offer`);
    expect(again.status).toBe(200);
    expect(again.body.case.offer.uri).not.toBe(rec.offer.uri);
    expect((await request(app).get('/demo-issuer/lab/api/cases/local-unknown')).status).toBe(404);
  });

  it('refuses a credential it does not issue, and ISSUER_PORTAL_SOURCE=sigma hands the workspace back to the external issuer\'s data API', async () => {
    const { app } = await setup();
    const r = await request(app).post('/demo-issuer/lab/api/cases').send({ identity: { given_name: 'A' }, credentials: [{ credentialConfigurationId: 'eu.europa.ec.eudi.pid_mdoc_emrtd', attributes: {} }] });
    expect(r.status).toBe(422);
    const back = await setup({ ISSUER_PORTAL_SOURCE: 'sigma', ISSUER_SOR_API_BASE: 'https://issuer-mock.example.test/mock-sor' });
    expect((await request(back.app).get('/demo-issuer')).text).toContain('id="lab-root"'); // the proxy variant (not reachable here)
    expect((await request(back.app).get('/demo-issuer/lab/api/presets')).status).toBe(200); // fetch stub answers {}
    expect(back.cfg.issuer.portalSource).toBe('sigma');
  });
});

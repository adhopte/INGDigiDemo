import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { createServices } from '../src/services.js';
import { parseRegistrationCert, registrationCovers } from '../src/verifier/registration.js';
import { testConfig } from './helpers.js';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
/** A registration certificate shaped like the EUDI registrar's (rc-wrp+jwt); the signature is a placeholder. */
const regCert = (over: Record<string, unknown> = {}, header: Record<string, unknown> = {}) =>
  `${b64({ alg: 'ES256', typ: 'rc-wrp+jwt', ...header })}.${b64({ name: 'Demo Bank (IN Groupe)', purpose: [{ lang: 'en', value: 'Know-your-customer check' }], country: 'FR', sub: 'LEIXG-TESTBANK0000000001', registry_uri: 'https://registry.example/', iat: 1786691316, ...over })}.c2ln`;

describe('registration certificate (verifier_info)', () => {
  it('reads name, purpose and subject; flags problems; never throws', () => {
    expect(parseRegistrationCert(undefined)).toBeUndefined();
    expect(parseRegistrationCert('   ')).toBeUndefined();
    const ok = parseRegistrationCert(regCert());
    expect(ok).toMatchObject({ ok: true, info: { name: 'Demo Bank (IN Groupe)', purposes: ['Know-your-customer check'], subject: 'LEIXG-TESTBANK0000000001', type: 'rc-wrp+jwt', expired: false }, warnings: [] });
    // pasted with line breaks and quotes (environment variable)
    const jwt = regCert();
    expect(parseRegistrationCert(`"${jwt.slice(0, 40)}\n${jwt.slice(40)}"`)).toMatchObject({ ok: true, jwt });
    expect(parseRegistrationCert(regCert({ exp: 1000 }), Date.now())).toMatchObject({ ok: true, info: { expired: true }, warnings: ['the certificate has expired'] });
    expect(parseRegistrationCert(regCert({ name: undefined }, { typ: 'JWT' }))).toMatchObject({ ok: true, warnings: expect.arrayContaining(['header typ is "JWT", expected "rc-wrp+jwt"', 'no "name": the wallet has nothing to display']) });
    expect(parseRegistrationCert('not-a-jwt')).toMatchObject({ ok: false });
    expect(parseRegistrationCert('a.b.c')).toMatchObject({ ok: false, error: 'header or payload is not valid JSON' });
  });

  it('is sent as verifier_info in the signed request: global default, per-RP override, none for RPs without', async () => {
    const global = regCert({ name: 'Global name' });
    const bank = regCert({ name: 'Bank name' });
    const cfg = testConfig({ VP_REGISTRATION_CERT: global, RP_BANK_REGISTRATION_CERT: bank });
    const svc = await createServices(cfg);
    const payload = async (rpId: string, pres: string) => {
      const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === rpId)!, pres, '/');
      return JSON.parse(Buffer.from((await svc.verifier.signedRequestObject(tx)).split('.')[1]!, 'base64url').toString());
    };
    expect((await payload('bank', 'pid')).verifier_info).toEqual([{ format: 'registration_cert', data: bank }]);
    expect((await payload('university', 'pid')).verifier_info).toEqual([{ format: 'registration_cert', data: global }]); // falls back to the global one
    const none = await createServices(testConfig({ VP_REGISTRATION_CERT: 'none' })); // "none" switches the shipped default off
    const tx = await none.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    expect(JSON.parse(Buffer.from((await none.verifier.signedRequestObject(tx)).split('.')[1]!, 'base64url').toString())).not.toHaveProperty('verifier_info');
    // an unreadable value is ignored rather than breaking the request
    const bad = await createServices(testConfig({ VP_REGISTRATION_CERT: 'garbage' }));
    const tx2 = await bad.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    expect(JSON.parse(Buffer.from((await bad.verifier.signedRequestObject(tx2)).split('.')[1]!, 'base64url').toString())).not.toHaveProperty('verifier_info');
  });

  it('is NOT put in an unsigned by-value link (redirect_uri scheme): too large for a QR code, no access certificate to bind to', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri', VP_REGISTRATION_CERT: regCert() });
    const svc = await createServices(cfg);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    expect(svc.verifier.walletLink(tx)).not.toContain('verifier_info');
    expect(Object.keys(svc.verifier.requestParams(tx))).not.toContain('verifier_info');
  });

  it('/vp/verifier reports what each RP sends and why not, without exposing the certificate', async () => {
    const jwt = regCert();
    const signed = testConfig({ DIAGNOSTICS_ENDPOINT: 'true', VP_REGISTRATION_CERT: jwt, RP_ESHOP_REGISTRATION_CERT: 'garbage' });
    const rep = (await request(createApp(signed, await createServices(signed))).get('/vp/verifier')).body.registration_certificates;
    expect(rep.bank).toMatchObject({ configured: true, readable: true, sent: true, name: 'Demo Bank (IN Groupe)', subject: 'LEIXG-TESTBANK0000000001', purpose: ['Know-your-customer check'] });
    expect(rep.eshop).toMatchObject({ configured: true, readable: false, sent: false });
    expect(JSON.stringify(rep)).not.toContain(jwt);
    const byValue = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri', VP_REGISTRATION_CERT: jwt, VP_REGISTRATION_LINKS: 'off' });
    const rep2 = (await request(createApp(byValue, await createServices(byValue))).get('/vp/verifier')).body.registration_certificates;
    expect(rep2.bank).toMatchObject({ sent: false, not_sent_because: expect.stringContaining('x509_hash') });
    const none = testConfig({ VP_REGISTRATION_CERT: 'none' });
    expect((await request(createApp(none, await createServices(none))).get('/vp/verifier')).body.registration_certificates.bank).toEqual({ configured: false });
  });

  it('ships with the test registration certificate (config/registration-cert.jwt) as default for every RP', async () => {
    const { readFileSync } = await import('node:fs');
    const file = readFileSync(new URL('../config/registration-cert.jwt', import.meta.url), 'utf8').trim();
    const cfg = testConfig();
    expect(cfg.verifier.registrationCert).toBe(file);
    const parsed = parseRegistrationCert(file, Date.parse('2026-11-19'))!;
    expect(parsed).toMatchObject({ ok: true, info: { name: 'Web Verifier (PROD)', purposes: ['For Testing Purposes'], subject: 'LEIXG-529900T8BM49AURSDO55', type: 'rc-wrp+jwt' } });
    expect(testConfig({ VP_REGISTRATION_CERT: 'none' }).verifier.registrationCert).toBeUndefined();
  });

  it('is attached only where it covers the request: what the certificate registers (PID, mDL, ...) yes; our payment attestation and birth certificate no', async () => {
    const { readFileSync } = await import('node:fs');
    const file = readFileSync(new URL('../config/registration-cert.jwt', import.meta.url), 'utf8').trim();
    const reg = parseRegistrationCert(file)!;
    if (!reg.ok) throw new Error('unreadable');
    expect(reg.info.credentials!.map((c) => c.doctype ?? c.vcts.join(','))).toEqual(expect.arrayContaining(['eu.europa.ec.eudi.pid.1', 'urn:eudi:pid:1', 'org.iso.18013.5.1.mDL']));
    const mdocPid = (claims: string[]) => [{ format: 'mso_mdoc', meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' }, claims: claims.map((c) => ({ path: ['eu.europa.ec.eudi.pid.1', c] })) }];
    expect(registrationCovers(reg.info, mdocPid(['given_name', 'family_name', 'birth_date']))).toEqual({ covered: true });
    expect(registrationCovers(reg.info, mdocPid(['given_name', 'birth_place']))).toMatchObject({ covered: false, reason: expect.stringContaining('birth_place') }); // a claim it does not register
    expect(registrationCovers(reg.info, [{ format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['family_name'] }] }])).toEqual({ covered: true });
    expect(registrationCovers(reg.info, [{ format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1', 'https://credentials.benin.example/pid'] }, claims: [] }])).toMatchObject({ covered: false }); // every requested type must be registered
    expect(registrationCovers(reg.info, [{ format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:demo:payment-attestation:1'] }, claims: [{ path: ['iban'] }] }])).toMatchObject({ covered: false, reason: expect.stringContaining('payment-attestation') });
    expect(registrationCovers(reg.info, [...mdocPid(['given_name']), { format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:birth_certificate:1'] } }])).toMatchObject({ covered: false }); // one uncovered credential spoils the request
    // a certificate that lists no credentials restricts nothing we know of
    const open = parseRegistrationCert(regCert());
    if (!open?.ok) throw new Error('unreadable');
    expect(registrationCovers(open.info, [{ format: 'dc+sd-jwt', meta: { vct_values: ['anything'] } }])).toEqual({ covered: true });
  });

  it('live (by value): the Open-in-wallet link of the PID requests carries the certificate, the eShop payment and the birth certificate requests do not; the QR link never does', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    const svc = await createServices(cfg);
    const link = async (rp: string, pres: string, sameDevice: boolean) => new URL(svc.verifier.walletLink(await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === rp)!, pres, '/'), sameDevice));
    for (const [rp, pres] of [['bank', 'pid'], ['electricity', 'pid'], ['university', 'pid']] as const) {
      expect((await link(rp, pres, true)).searchParams.get('verifier_info'), `${rp}/${pres}`).not.toBeNull();
      expect((await link(rp, pres, false)).searchParams.get('verifier_info'), `${rp}/${pres} QR`).toBeNull();
    }
    for (const [rp, pres] of [['eshop', 'payment'], ['university', 'bc'], ['university', 'pid_bc']] as const) expect((await link(rp, pres, true)).searchParams.get('verifier_info'), `${rp}/${pres}`).toBeNull();
    const rep = svc.verifier.registrationReport() as Record<string, any>;
    expect(rep.bank.presentations.pid).toBe('attached');
    expect(rep.eshop.presentations.payment).toContain('not attached');
    expect(rep.eshop.presentations.payment).toContain('payment-attestation');
    expect(rep.university.presentations.bc).toContain('not attached');
  });

  it('signed requests follow the same rule: no verifier_info for a request the certificate does not cover', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'x509_hash' });
    const svc = await createServices(cfg);
    const payload = async (rp: string, pres: string) => JSON.parse(Buffer.from((await svc.verifier.signedRequestObject(await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === rp)!, pres, '/'))).split('.')[1]!, 'base64url').toString());
    expect(await payload('eshop', 'payment')).not.toHaveProperty('verifier_info');
    expect(await payload('university', 'bc')).not.toHaveProperty('verifier_info');
  });

  it('VP_REGISTRATION_LINKS=all puts it in every unsigned link (far too big for a QR code)', async () => {
    const { qrDataUrlOrUndefined } = await import('../src/issuer/offer.js');
    const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri', VP_REGISTRATION_LINKS: 'all' });
    const svc = await createServices(cfg);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const link = svc.verifier.walletLink(tx);
    expect(JSON.parse(new URL(link).searchParams.get('verifier_info')!)).toEqual([{ format: 'registration_cert', data: cfg.verifier.registrationCert }]);
    expect(await qrDataUrlOrUndefined(link)).toBeUndefined(); // the page then shows the button / phone-camera route instead of a QR code
    expect((svc.verifier.registrationReport().bank as any).sent).toBe(true);
  });

  it('default (button mode): only the same-device button link carries it, the QR link stays small', async () => {
    const { qrDataUrlOrUndefined } = await import('../src/issuer/offer.js');
    const cfg = testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri' });
    expect(cfg.verifier.registrationByValue).toBe('button');
    const svc = await createServices(cfg);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const button = svc.verifier.walletLink(tx, true);
    const qr = svc.verifier.walletLink(tx);
    expect(JSON.parse(new URL(button).searchParams.get('verifier_info')!)).toEqual([{ format: 'registration_cert', data: cfg.verifier.registrationCert }]);
    expect(new URL(button).searchParams.get('state')).toBe(`${tx.state}.sd`);
    expect(qr).not.toContain('verifier_info');
    expect(qr.length).toBeLessThan(1700);
    expect(await qrDataUrlOrUndefined(qr)).toBeDefined();
    expect(svc.verifier.registrationReport().bank).toMatchObject({ sent: true, sent_in: 'the Open-in-wallet button only (QR code stays small)' });
    expect(testConfig({ VP_REGISTRATION_LINKS: 'off' }).verifier.registrationByValue).toBe('off');
    const off = await createServices(testConfig({ MOCK_MODE: 'false', VP_CLIENT_ID_SCHEME: 'redirect_uri', VP_REGISTRATION_LINKS: 'off' }));
    const t2 = await off.verifier.createTransaction(testConfig().rps.find((r) => r.id === 'bank')!, 'pid', '/');
    expect(off.verifier.walletLink(t2, true)).not.toContain('verifier_info');
  });
});

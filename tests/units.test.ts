import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { buildRpConfigs, loadConfig, parseBool } from '../src/config.js';
import { allDictionaries, LOCALES } from '../src/i18n/index.js';
import { buildRequest, createExternalOffer, parseResponse } from '../src/issuer/external.js';
import { createIssuerProvider } from '../src/issuer/provider.js';
import { addDemoCredential, buildVpToken, respondToVerifier } from '../src/mock/wallet.js';
import { issueSdJwt, resolveDisclosures, sha256b64u, splitSdJwt } from '../src/sdjwt/index.js';
import { createServices } from '../src/services.js';
import { createIssuerKeyResolver, jwtVcIssuerMetadataUrls, validateX5cChain } from '../src/verifier/trust.js';
import { extractPresentations } from '../src/verifier/service.js';
import { testConfig } from './helpers.js';

describe('config loader', () => {
  it('has sane defaults and builds redirect-free public URLs', () => {
    const c = loadConfig({ NODE_ENV: 'test', MOCK_MODE: 'true' });
    expect(c.port).toBe(3000);
    expect(c.publicBaseUrl).toBe('http://localhost:3000');
    expect(c.issuer.mode).toBe('local');
    expect(c.verifier.clientIdScheme).toBe('x509_hash');
    expect(c.verifier.responseMode).toBe('direct_post.jwt');
    expect(loadConfig({ MOCK_MODE: 'true', VP_CLIENT_ID_SCHEME: 'x509_san_dns', VP_RESPONSE_MODE: 'direct_post' }).verifier).toMatchObject({ clientIdScheme: 'x509_san_dns', responseMode: 'direct_post' });
    expect(c.rps.map((r) => r.id)).toEqual(['bank', 'eshop', 'university', 'electricity']);
    expect(Object.keys(c.attestations).sort()).toEqual(['account', 'birth_certificate', 'payment', 'pid']);
  });
  it('uses PUBLIC_BASE_URL, then RENDER_EXTERNAL_URL, trimming slashes; reads PORT', () => {
    expect(loadConfig({ MOCK_MODE: 'true', PUBLIC_BASE_URL: 'https://a.example/', RENDER_EXTERNAL_URL: 'https://b.example' }).publicBaseUrl).toBe('https://a.example');
    expect(loadConfig({ MOCK_MODE: 'true', RENDER_EXTERNAL_URL: 'https://b.example' }).publicBaseUrl).toBe('https://b.example');
    expect(loadConfig({ MOCK_MODE: 'true', PORT: '10000' }).port).toBe(10000);
    expect(loadConfig({ MOCK_MODE: 'true', PUBLIC_BASE_URL: 'https://a.example' }).issuer.localIssuerUrl).toBe('https://a.example/issuer');
  });
  it('rejects invalid or unsafe production settings', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', MOCK_MODE: 'true' })).toThrow(/SESSION_SECRET/);
    expect(() => loadConfig({ NODE_ENV: 'production', SESSION_SECRET: 'x', TRUSTED_ISSUERS: '*' })).toThrow(/not allowed in production/);
    expect(() => loadConfig({ PORT: 'abc' })).toThrow(/PORT/);
    expect(() => loadConfig({ PUBLIC_BASE_URL: 'not a url' })).toThrow(/PUBLIC_BASE_URL/);
    expect(() => loadConfig({ ISSUER_MODE: 'external' })).toThrow(/ISSUER_API_BASE_URL/);
  });
  it('applies env overrides for credential configuration ids, vct and theme', () => {
    const c = loadConfig({ MOCK_MODE: 'true', ATTESTATION_PAYMENT_CONFIG_ID: 'ext_payment', ATTESTATION_PID_ACCEPTED_VCT: 'urn:a, urn:b', RP_BANK_THEME_COLOR: '#112233', MULTI_CREDENTIAL: 'yes' });
    expect(c.attestations.payment!.credentialConfigurationId).toBe('ext_payment');
    expect(c.attestations.pid!.acceptedVct).toEqual(['urn:a', 'urn:b']);
    expect(c.rps[0]!.themeColor).toBe('#112233');
    expect(c.multiCredential).toBe(true);
  });
  it('validates rps.json content', () => {
    const atts = loadConfig({ MOCK_MODE: 'true' }).attestations;
    expect(() => buildRpConfigs({ rps: [] }, atts, {})).toThrow();
    expect(() => buildRpConfigs({ rps: [{ id: 'Bad Id', displayName: 'x', themeColor: '#000000', presentations: {}, attestations: [] }] }, atts, {})).toThrow(/slug/);
    expect(() => buildRpConfigs({ rps: [{ id: 'a', displayName: 'x', themeColor: 'red', presentations: {}, attestations: [] }] }, atts, {})).toThrow(/themeColor/);
    expect(() => buildRpConfigs({ rps: [{ id: 'a', displayName: 'x', themeColor: '#000000', presentations: {}, attestations: ['nope'] }] }, atts, {})).toThrow(/unknown attestation/);
    const ok = { id: 'a', displayName: 'x', themeColor: '#000000', presentations: {}, attestations: [] };
    expect(() => buildRpConfigs({ rps: [ok, ok] }, atts, {})).toThrow(/duplicate/);
    expect(parseBool('Yes')).toBe(true); expect(parseBool('0')).toBe(false); expect(parseBool(undefined, true)).toBe(true);
  });
});

describe('i18n', () => {
  it('supports en, fr, es, nl, de, da, mt, sv with identical keys and placeholders', () => {
    expect(LOCALES.map((l) => l.code)).toEqual(['en', 'fr', 'es', 'nl', 'de', 'da', 'mt', 'sv']);
    const d = allDictionaries();
    const en = d.en;
    const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join();
    for (const l of LOCALES) {
      expect(Object.keys(d[l.code]).sort(), l.code).toEqual(Object.keys(en).sort());
      for (const k of Object.keys(en)) {
        expect(d[l.code][k]!.trim(), `${l.code}:${k}`).not.toBe('');
        expect(ph(d[l.code][k]!), `${l.code}:${k}`).toBe(ph(en[k]!));
      }
    }
  });
});

describe('SD-JWT disclosure handling', () => {
  it('rebuilds nested claims and refuses unreferenced, duplicate or clashing disclosures', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const jwt = await issueSdJwt({ privateKey, iss: 'https://i.example', vct: 'urn:x', claims: { a: 1, b: { c: 2 } } });
    const { jwt: j, disclosures } = splitSdJwt(jwt);
    const payload = JSON.parse(Buffer.from(j.split('.')[1]!, 'base64url').toString());
    expect(resolveDisclosures(payload, disclosures)).toMatchObject({ a: 1, b: { c: 2 } });
    expect(resolveDisclosures(payload, [])).not.toHaveProperty('a');
    const stray = Buffer.from(JSON.stringify(['s', 'z', 9])).toString('base64url');
    expect(() => resolveDisclosures(payload, [...disclosures, stray])).toThrow(/not referenced/);
    expect(() => resolveDisclosures(payload, [disclosures[0]!, disclosures[0]!])).toThrow(/Duplicate/);
    const clash = Buffer.from(JSON.stringify(['s', 'a', 'x'])).toString('base64url');
    expect(() => resolveDisclosures({ a: 1, _sd: [sha256b64u(clash)] }, [clash])).toThrow(/clashes/);
    expect(() => splitSdJwt('nodelimiter')).toThrow();
    expect(() => resolveDisclosures({ _sd_alg: 'sha-512' }, [])).toThrow(/_sd_alg/);
  });
  it('extracts presentations from string, array and DCQL object shapes', () => {
    expect(extractPresentations('a~b~')).toEqual(['a~b~']);
    expect(extractPresentations(['a~', 'b~'])).toEqual(['a~', 'b~']);
    expect(extractPresentations({ pid: ['a~'], bc: ['b~'] })).toEqual(['a~', 'b~']);
    expect(extractPresentations(JSON.stringify({ pid: ['a~'] }))).toEqual(['a~']);
    expect(() => extractPresentations('plain')).toThrow();
    expect(() => extractPresentations(undefined)).toThrow();
    expect(() => extractPresentations('{bad')).toThrow(/JSON/);
  });
});

describe('issuer trust', () => {
  it('validates an x5c chain against a trusted root (and refuses unknown roots / broken chains)', async () => {
    const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
    const mk = async (name: string, issuer?: { cert: x509.X509Certificate; key: CryptoKey }, ca = false) => {
      const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
      const common = { serialNumber: String(Math.floor(Math.random() * 1e6) + 1), notBefore: new Date(Date.now() - 3600_000), notAfter: new Date(Date.now() + 3600_000), signingAlgorithm: alg };
      const cert = issuer
        ? await x509.X509CertificateGenerator.create({ ...common, subject: `CN=${name}`, issuer: issuer.cert.subject, publicKey: keys.publicKey, signingKey: issuer.key, extensions: [new x509.BasicConstraintsExtension(ca, undefined, true)] })
        : await x509.X509CertificateGenerator.createSelfSigned({ ...common, name: `CN=${name}`, keys, extensions: [new x509.BasicConstraintsExtension(true, undefined, true)] });
      return { cert, key: keys.privateKey as CryptoKey };
    };
    const root = await mk('Root'); const inter = await mk('Inter', root, true); const leaf = await mk('Leaf', inter);
    const b64 = (c: x509.X509Certificate) => Buffer.from(c.rawData).toString('base64');
    expect(validateX5cChain([b64(leaf.cert), b64(inter.cert)], [root.cert.toString('pem')]).subject).toContain('Leaf');
    const other = await mk('Other');
    expect(() => validateX5cChain([b64(leaf.cert), b64(inter.cert)], [other.cert.toString('pem')])).toThrow(/trusted root/);
    expect(() => validateX5cChain([b64(leaf.cert)], [root.cert.toString('pem')])).toThrow(/trusted root/); // missing intermediate
    expect(() => validateX5cChain([b64(leaf.cert), b64(inter.cert)], [])).toThrow(/trust anchors/);
    expect(() => validateX5cChain([b64(leaf.cert), b64(inter.cert)], [root.cert.toString('pem')], new Date(Date.now() + 7200_000))).toThrow(/validity/);
  });

  it('verifies a PID from an external issuer via its jwt-vc-issuer metadata, only if that issuer is trusted', async () => {
    const issuerUrl = 'https://issuer.in-groupe.example';
    const ext = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const pub = { ...(await exportJWK(ext.publicKey)), kid: 'k1', alg: 'ES256' };
    const calls: string[] = [];
    const fakeFetch = (async (url: string) => {
      calls.push(url);
      return url === `${issuerUrl}/.well-known/jwt-vc-issuer` ? new Response(JSON.stringify({ issuer: issuerUrl, jwks: { keys: [pub] } })) : new Response('nope', { status: 404 });
    }) as unknown as typeof fetch;

    for (const [trusted, shouldPass] of [[[issuerUrl], true], [[], false], [['https://other.example'], false], [['*'], true]] as const) {
      const cfg = testConfig({ TRUSTED_ISSUERS: trusted.join(',') });
      const svc = await createServices(cfg, fakeFetch);
      const cred = await issueSdJwt({ privateKey: ext.privateKey, kid: 'k1', iss: issuerUrl, vct: 'urn:eudi:pid:1', claims: { given_name: 'Ext', family_name: 'Person', birth_date: '1990-01-01', birth_place: 'Paris', nationality: 'FR', resident_address: 'x', issuing_country: 'FR' }, holderJwk: await exportJWK(holder.publicKey) });
      const session: Record<string, any> = { wallet: [{ id: '1', typeKey: 'pid', vct: 'urn:eudi:pid:1', credential: cred, holderPrivateJwk: await exportJWK(holder.privateKey), issuedAt: '' }] };
      const tx = await svc.verifier.createTransaction(cfg.rps[0]!, 'pid', '/bank/');
      const vp = await buildVpToken(session, tx, svc.verifier);
      const attempt = respondToVerifier(svc.verifier, tx, { vp_token: vp });
      if (shouldPass) { await attempt; expect(tx.result!.issuers).toEqual([issuerUrl]); }
      else { await expect(attempt).rejects.toThrow(); expect(tx.errorCode).toBe('untrusted_issuer'); }
    }
    expect(jwtVcIssuerMetadataUrls('https://x.example/tenant/a')[0]).toBe('https://x.example/.well-known/jwt-vc-issuer/tenant/a');
    void createIssuerKeyResolver; void addDemoCredential;
  });
});

describe('Benin PID rulebook v2.0 shapes', () => {
  it('requests and verifies a Benin SD-JWT PID (vct https://credentials.benin.example/pid, rulebook claim names)', async () => {
    const issuerUrl = 'https://issuer.example.bj';
    const ext = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const pub = { ...(await exportJWK(ext.publicKey)), kid: 'k1', alg: 'ES256' };
    const fakeFetch = (async (url: string) => (url === `${issuerUrl}/.well-known/jwt-vc-issuer` ? new Response(JSON.stringify({ issuer: issuerUrl, jwks: { keys: [pub] } })) : new Response('nope', { status: 404 }))) as unknown as typeof fetch;
    const cfg = testConfig({ TRUSTED_ISSUERS: issuerUrl });
    const svc = await createServices(cfg, fakeFetch);
    // payload from the rulebook's Examples sheet
    const cred = await issueSdJwt({ privateKey: ext.privateKey, kid: 'k1', iss: issuerUrl, vct: 'https://credentials.benin.example/pid', holderJwk: await exportJWK(holder.publicKey),
      claims: { given_name: 'Jean', family_name: 'KOSSI', birth_date: '1990-04-15', age_over_18: true, birth_place: 'Cotonou', birth_state: 'Littoral', birth_city: 'Cotonou', birth_country: 'BJ', nationality: 'BJ', gender: 1, document_number: 'CNIB123456789', issuance_date: '2026-01-10', expiry_date: '2031-01-10', issuing_authority: 'ANIP', issuing_country: 'BJ', personal_administrative_number: '1234567890123' } });
    const session: Record<string, any> = { wallet: [{ id: '1', typeKey: 'pid', vct: 'https://credentials.benin.example/pid', credential: cred, holderPrivateJwk: await exportJWK(holder.privateKey), issuedAt: '' }] };
    for (const [rpId, pres] of [['bank', 'pid'], ['electricity', 'pid'], ['bank', 'pid_any_sd']] as const) {
      const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === rpId)!, pres, '/');
      const q = (svc.verifier.requestParams(tx) as any).dcql_query;
      expect(q.credentials.find((c: any) => c.format === 'dc+sd-jwt').meta.vct_values).toContain('https://credentials.benin.example/pid');
      await respondToVerifier(svc.verifier, tx, { vp_token: await buildVpToken(session, tx, svc.verifier) });
      const pid = tx.result!.byType.pid!;
      expect(pid).toMatchObject({ given_name: 'Jean', family_name: 'KOSSI', ...(pres === 'pid_any_sd' ? {} : { birth_date: '1990-04-15' }) });
      expect(pid.personal_administrative_number).toBeUndefined(); // sensitive and never requested
      expect(pid.gender).toBeUndefined();
    }
  });
});

describe('external issuer adapter (SIGMA offer API)', () => {
  const cfg = (env: Record<string, string>) => testConfig({ ISSUER_MODE: 'external', ISSUER_API_BASE_URL: 'https://issuer.api.example/', ...env });
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const OFFER = 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.api.example%22%7D';

  it('builds the offer request exactly like the WalletTester portal', () => {
    const c = cfg({});
    expect(buildRequest(c.attestations.birth_certificate!, {}, 'biz-1')).toEqual({
      identifier: 'user-bc-sd-jwt-001', businessId: 'biz-1',
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt', credential_identifiers: ['birth_certificate_full_data'] }],
    });
    expect(buildRequest(c.attestations.pid!, { identifier: 'user-002', walletIdentifier: 'w-002' }, 'biz-2')).toEqual({
      identifier: 'user-002', businessId: 'biz-2', walletIdentifier: 'w-002',
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'eu.europa.ec.eudi.pid_mdoc', credential_identifiers: ['credential_id_1'] }],
    });
    // PID via IdP login: fixed placeholder identifier + wallet id + the eMRTD configuration, no credential identifier
    expect(buildRequest(c.attestations.pid!, { identifier: 'xyz-198772', walletIdentifier: 'w-001', configurationId: 'eu.europa.ec.eudi.pid_mdoc_emrtd' }, 'biz-3')).toEqual({
      identifier: 'xyz-198772', businessId: 'biz-3', walletIdentifier: 'w-001',
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'eu.europa.ec.eudi.pid_mdoc_emrtd' }],
    });
    expect(buildRequest(c.attestations.pid!).businessId).toMatch(/^[0-9a-f-]{36}$/);
    expect(() => buildRequest(c.attestations.account!)).toThrow(/No identifier/); // no sample users configured for a type the issuer does not know
    expect(buildRequest(c.attestations.account!, { identifier: 'x' }).authorization_details[0]!.credential_configuration_id).toBe('demo_bank_account');
  });

  it('parses the issuer reply (uri, tx_code) and the fallbacks', () => {
    const o = parseResponse({ qr_code: 'AAAA', uri: OFFER, tx_code: '593296', authorization_code: 'abc' });
    expect(o.deeplink).toBe(OFFER);
    expect(o.txCode).toBe('593296');
    expect(o.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(parseResponse({ credential_offer_uri: 'https://i.example/o/1' }).deeplink).toBe('openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2Fo%2F1');
    expect(parseResponse({ credential_offer: { credential_issuer: 'https://i.example' } }).deeplink).toContain('credential_offer=');
    expect(parseResponse({ uri: OFFER, tx_code: 123456 }).txCode).toBe('123456');
    expect(() => parseResponse({})).toThrow(/no credential offer/);
  });

  it('POSTs to /offer on the base URL and returns deeplink, tx code and QR; the legacy path setting maps to /offer', async () => {
    expect(cfg({ ISSUER_EXTERNAL_OFFER_PATH: '/credential-offers' }).issuer.external.offerPath).toBe('/offer');
    expect(cfg({}).issuer.external.offerPath).toBe('/offer');
    const c = cfg({});
    let seen: { url: string; init: RequestInit } | undefined;
    const f = (async (url: string, init: RequestInit) => { seen = { url, init }; return reply({ uri: OFFER, tx_code: '111222', qr_code: 'x', authorization_code: 'y' }); }) as unknown as typeof fetch;
    const provider = createIssuerProvider(c, undefined, f);
    const offer = await provider.createOffer('birth_certificate', {}, { identifier: 'user-bc-sd-jwt-002' });
    expect(provider.mode).toBe('external');
    expect(seen!.url).toBe('https://issuer.api.example/offer');
    expect((seen!.init.headers as Record<string, string>).authorization).toBeUndefined(); // the preprod offer API is unauthenticated
    expect(JSON.parse(String(seen!.init.body)).identifier).toBe('user-bc-sd-jwt-002');
    expect(offer).toMatchObject({ provider: 'external', txCode: '111222', deeplink: OFFER });
    expect(offer.id).toBeUndefined();
    expect(offer.qr.startsWith('data:image/png;base64,')).toBe(true);
  });

  it('supports bearer / client_credentials when the API is later protected, and surfaces API errors', async () => {
    const c = cfg({ ISSUER_EXTERNAL_AUTH: 'client_credentials', ISSUER_EXTERNAL_TOKEN_URL: 'https://auth.example/token', ISSUER_CLIENT_ID: 'id', ISSUER_CLIENT_SECRET: 'secret' });
    const urls: string[] = [];
    const f = (async (url: string, init: RequestInit) => {
      urls.push(url);
      if (url === 'https://auth.example/token') { expect((init.headers as Record<string, string>).authorization).toBe(`Basic ${Buffer.from('id:secret').toString('base64')}`); return reply({ access_token: 'at', expires_in: 60 }); }
      expect((init.headers as Record<string, string>).authorization).toBe('Bearer at');
      return reply({ error: 'boom' }, 500);
    }) as unknown as typeof fetch;
    await expect(createExternalOffer(c, c.attestations.pid!, {}, f)).rejects.toThrow(/answered 500/);
    expect(urls[0]).toBe('https://auth.example/token');
    await expect(createExternalOffer(cfg({ ISSUER_EXTERNAL_AUTH: 'bearer' }), c.attestations.pid!, {}, f)).rejects.toThrow(/ISSUER_API_TOKEN/);
  });
});

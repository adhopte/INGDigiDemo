import { calculateJwkThumbprint, SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createSign, createPrivateKey } from 'node:crypto';
import { Decoder, Encoder, Tag } from 'cbor-x';
import { describe, expect, it } from 'vitest';
import { openId4VpSessionTranscripts } from '../src/mdoc/index.js';
import { respondToVerifier } from '../src/mock/wallet.js';
import { PRE_AUTH_GRANT } from '../src/issuer/local/service.js';
import { createServices } from '../src/services.js';
import { testConfig } from './helpers.js';

const enc = new Encoder({ useRecords: false, mapsAsObjects: false });
const dec = new Decoder({ useRecords: false, mapsAsObjects: false });
const decode = (b: Uint8Array) => dec.decode(b);
const NS = 'org.iso.18013.5.1';
const DOC = 'org.iso.18013.5.1.mDL';

/** The wallet side: redeem a local mdoc offer, then wrap the IssuerSigned in a DeviceResponse signed with the holder key. */
async function issueMdl(svc: Awaited<ReturnType<typeof createServices>>, claims: Record<string, unknown>) {
  const o = svc.local.createOffer('mdl', claims, 'mdoc');
  const offer = svc.local.offerObject(o.id) as any;
  expect(offer.credential_configuration_ids).toEqual(['demo_mdl_mdoc']);
  const code = offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'];
  const token = await svc.local.exchangePreAuthorizedCode({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, ...(o.txCode ? { tx_code: o.txCode } : {}) });
  const kp = await generateKeyPair('ES256', { extractable: true });
  const proof = await new SignJWT({ nonce: token.c_nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(kp.publicKey) }).setAudience(svc.local.issuerUrl).setIssuedAt().sign(kp.privateKey);
  const res = await svc.local.issueCredential(token.access_token, { credential_configuration_id: 'demo_mdl_mdoc', proofs: { jwt: [proof] } });
  const holder = createPrivateKey({ key: await exportJWK(kp.privateKey), format: 'jwk' });
  return { issuerSigned: res.credentials[0]!.credential, holder };
}

function deviceResponse(issuerSignedB64: string, holder: ReturnType<typeof createPrivateKey>, sessionTranscript: unknown, only?: string[]) {
  const is = decode(Buffer.from(issuerSignedB64, 'base64url')) as Map<string, any>;
  const items = (is.get('nameSpaces') as Map<string, Tag[]>).get(NS)!.filter((t) => !only || only.includes((decode(t.value) as Map<string, unknown>).get('elementIdentifier') as string));
  const devNs = new Tag(Buffer.from(enc.encode(new Map())), 24);
  const protectedHdr = Buffer.from(enc.encode(new Map([[1, -7]])));
  const payload = Buffer.from(enc.encode(new Tag(Buffer.from(enc.encode(['DeviceAuthentication', sessionTranscript, DOC, devNs])), 24)));
  const sig = createSign('sha256').update(Buffer.from(enc.encode(['Signature1', protectedHdr, Buffer.alloc(0), payload]))).sign({ key: holder, dsaEncoding: 'ieee-p1363' });
  const doc = new Map<string, unknown>([
    ['docType', DOC],
    ['issuerSigned', new Map<string, unknown>([['nameSpaces', new Map([[NS, items]])], ['issuerAuth', is.get('issuerAuth')]])],
    ['deviceSigned', new Map<string, unknown>([['nameSpaces', devNs], ['deviceAuth', new Map([['deviceSignature', [protectedHdr, new Map(), null, sig]]])]])],
  ]);
  return Buffer.from(enc.encode(new Map<string, unknown>([['version', '1.0'], ['documents', [doc]], ['status', 0]]))).toString('base64url');
}

const CLAIMS = { given_name: 'Camille', family_name: 'Demo', birth_date: '1992-04-17', issue_date: '2022-03-01', expiry_date: '2032-03-01', issuing_country: 'FR', document_number: 'DL12345678', un_distinguishing_sign: 'F', age_over_18: true, age_over_21: true, driving_privileges: [{ vehicle_category_code: 'B', issue_date: '2022-03-01', expiry_date: '2032-03-01' }] };

describe('local issuer: the driving licence as an ISO mdoc (proximity-capable)', () => {
  it('declares the mdoc configuration next to the SD-JWT one (cose_key binding, ES256 = -7, namespace paths)', async () => {
    const svc = await createServices(testConfig({ MOCK_MODE: 'false' }));
    const c = (svc.local.metadata() as any).credential_configurations_supported;
    expect(c.demo_mdl.format).toBe('dc+sd-jwt');
    expect(c.demo_mdl_mdoc).toMatchObject({ format: 'mso_mdoc', doctype: DOC, cryptographic_binding_methods_supported: ['cose_key'], credential_signing_alg_values_supported: [-7] });
    expect(c.demo_mdl_mdoc.claims[0].path).toEqual([NS, 'family_name']);
    expect(c.demo_pid_mdoc).toBeUndefined(); // only the driving licence has a local mdoc
    expect(() => svc.local.createOffer('pid', {}, 'mdoc')).toThrow(/as mdoc/);
  });

  it('issues a well-formed mdoc: dates as full-date, MSO digests, device key, issuer signature with the certificate chain', async () => {
    const svc = await createServices(testConfig({ MOCK_MODE: 'false' }));
    const { issuerSigned } = await issueMdl(svc, CLAIMS);
    const is = decode(Buffer.from(issuerSigned, 'base64url')) as Map<string, any>;
    const auth = is.get('issuerAuth') as any[];
    expect(auth).toHaveLength(4);
    expect((auth[1] as Map<number, unknown>).get(33)).toBeTruthy(); // x5chain
    const mso = decode(decode(auth[2]).value) as Map<string, any>;
    expect(mso.get('docType')).toBe(DOC);
    expect(mso.get('digestAlgorithm')).toBe('SHA-256');
    expect(mso.get('valueDigests').get(NS).size).toBe(Object.keys(CLAIMS).length);
    const items = (is.get('nameSpaces') as Map<string, Tag[]>).get(NS)!.map((t) => decode(t.value) as Map<string, any>);
    const birth = items.find((i) => i.get('elementIdentifier') === 'birth_date')!.get('elementValue');
    expect(birth).toBeInstanceOf(Tag);
    expect((birth as Tag).tag).toBe(1004);
    expect(items.find((i) => i.get('elementIdentifier') === 'age_over_18')!.get('elementValue')).toBe(true);
    expect(items.find((i) => i.get('elementIdentifier') === 'driving_privileges')!.get('elementValue')[0]).toBeInstanceOf(Map);
  });

  it('is accepted by the verifier as a presentation to Demo Drive (issuer signature, digests, device signature, claims)', async () => {
    const cfg = testConfig({ MOCK_MODE: 'false', VP_RESPONSE_MODE: 'direct_post.jwt', TRUST_ANY_ISSUER: 'true' });
    const svc = await createServices(cfg);
    const { issuerSigned, holder } = await issueMdl(svc, CLAIMS);
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'rental')!, 'mdl', '/rental/booking');
    const thumb = Buffer.from(await calculateJwkThumbprint(tx.enc!.publicJwk, 'sha256'), 'base64url');
    const st = openId4VpSessionTranscripts({ clientId: svc.verifier.clientIdFor(tx), nonce: tx.nonce, responseUri: svc.verifier.responseUri(tx), jwkThumbprint: thumb })[0];
    const dr = deviceResponse(issuerSigned, holder, st, ['given_name', 'family_name', 'birth_date', 'document_number', 'issue_date', 'expiry_date']);
    await respondToVerifier(svc.verifier, tx, { vp_token: { mdl_mdoc: [dr] } });
    expect(tx.status).toBe('complete');
    expect(tx.result!.byType.mdl).toMatchObject({ given_name: 'Camille', family_name: 'Demo', document_number: 'DL12345678', expiry_date: '2032-03-01', issue_date: '2022-03-01' });
  });
});

describe('local issuer: an offer of both formats (EHIC, Health ID)', () => {
  it('lists the SD-JWT and the mdoc configuration, issues each in its own request with the same token, and uses the claims of each format', async () => {
    const { ehicFromHiid } = await import('../src/rps/health-data.js');
    const svc = await createServices(testConfig({ MOCK_MODE: 'false' }));
    const { sd, mdoc } = ehicFromHiid({ health_insurance_id: 'HI123456789012', matching_registered_family_name: 'Demo', matching_registered_given_name: 'Camille', matching_birth_date: '1992-04-17', affiliation_country: 'FR' });
    const o = svc.local.createOffer('ehic', sd, 'both', mdoc);
    expect((svc.local.offerObject(o.id) as any).credential_configuration_ids).toEqual(['demo_ehic', 'demo_ehic_mdoc']);
    const code = (svc.local.offerObject(o.id) as any).grants[PRE_AUTH_GRANT]['pre-authorized_code'];
    const token = await svc.local.exchangePreAuthorizedCode({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, ...(o.txCode ? { tx_code: o.txCode } : {}) });
    const request = async (configId: string) => {
      const kp = await generateKeyPair('ES256', { extractable: true });
      const nonce = svc.local.newNonce();
      const proof = await new SignJWT({ nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(kp.publicKey) }).setAudience(svc.local.issuerUrl).setIssuedAt().sign(kp.privateKey);
      return svc.local.issueCredential(token.access_token, { credential_configuration_id: configId, proofs: { jwt: [proof] } });
    };
    const sdJwt = (await request('demo_ehic')).credentials[0]!.credential;
    const sdClaims = JSON.parse(Buffer.from(sdJwt.split('~')[1]!, 'base64url').toString()); // first disclosure: [salt, name, value]
    expect(sdJwt.split('.').length).toBeGreaterThan(2);
    expect(sdClaims[1]).toBeTruthy();
    const disclosed = Object.fromEntries(sdJwt.split('~').slice(1, -1).map((d) => { const a = JSON.parse(Buffer.from(d, 'base64url').toString()); return [a[1], a[2]]; }));
    expect(disclosed).toMatchObject({ personal_administrative_number: 'HI123456789012', issuing_authority: { id: 'DE-DEMO-HF-01', name: 'Demo Health Fund' }, subject: { family_name: 'Demo', given_name: 'Camille' } });
    expect(disclosed.social_security_pin).toBeUndefined(); // the mdoc names stay out of the SD-JWT
    const mdocB64 = (await request('demo_ehic_mdoc')).credentials[0]!.credential;
    const is = decode(Buffer.from(mdocB64, 'base64url')) as Map<string, any>;
    const items = Object.fromEntries((is.get('nameSpaces') as Map<string, Tag[]>).get('eu.europa.ec.eudi.ehic.1')!.map((t) => { const m = decode(t.value) as Map<string, any>; return [m.get('elementIdentifier'), m.get('elementValue')]; }));
    expect(Object.keys(items)).toEqual(expect.arrayContaining(['social_security_pin', 'competent_institution', 'document_id', 'credential_holder', 'subject', 'starting_date', 'ending_date']));
    expect(items.social_security_pin).toBe('HI123456789012');
    expect(items.starting_date).toBeInstanceOf(Tag);
    expect(items.subject).toBeInstanceOf(Map);
    expect((items.subject as Map<string, unknown>).get('birth_date')).toBeInstanceOf(Tag);
    await expect(request('demo_ehic')).rejects.toThrow(); // both were issued: the token is used up
    expect(() => svc.local.createOffer('pid', {}, 'both')).toThrow();
  });
});

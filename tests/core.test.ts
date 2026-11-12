import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { addDemoCredential, buildVpToken, respondToVerifier } from '../src/mock/wallet.js';
import { createServices } from '../src/services.js';
import { issueSdJwt, presentSdJwt } from '../src/sdjwt/index.js';
import { VpError } from '../src/verifier/service.js';
import { testConfig } from './helpers.js';

async function setup(env: Record<string, string> = {}) {
  const cfg = testConfig(env);
  const svc = await createServices(cfg);
  const session: Record<string, any> = {};
  return { cfg, svc, session };
}

describe.each([['direct_post'], ['direct_post.jwt']])('OpenID4VP verification end to end (%s)', (mode) => {
  it('verifies a PID issued by the local OpenID4VCI issuer and minimises disclosure', async () => {
    const { cfg, svc, session } = await setup({ VP_RESPONSE_MODE: mode });
    await addDemoCredential(svc.local, cfg, session, 'pid', 'fr');
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    const tx = await svc.verifier.createTransaction(rp, 'pid', '/bank/kyc');
    const vp = await buildVpToken(session, tx, svc.verifier);
    const res = await respondToVerifier(svc.verifier, tx, { vp_token: vp });
    expect(res.redirect_uri).toContain(`/bank/verify/finish/${tx.id}`);
    expect(tx.status).toBe('complete');
    const pid = tx.result!.byType.pid!;
    expect(pid.given_name).toBe('Camille');
    expect(pid.nationalities).toEqual(['FR']);
    expect(pid.age_over_18).toBeUndefined(); // not requested -> not disclosed
    expect(tx.result!.issuers).toEqual([cfg.issuer.localIssuerUrl]);
  });

  it('rejects a replayed response', async () => {
    const { cfg, svc, session } = await setup({ VP_RESPONSE_MODE: mode });
    await addDemoCredential(svc.local, cfg, session, 'pid', 'de');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'electricity')!, 'pid', '/');
    const vp = await buildVpToken(session, tx, svc.verifier);
    await respondToVerifier(svc.verifier, tx, { vp_token: vp });
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: vp })).rejects.toBeInstanceOf(VpError);
  });
});

describe('verifier rejects bad presentations', () => {
  it('wrong nonce (presentation built for another transaction)', async () => {
    const { cfg, svc, session } = await setup();
    await addDemoCredential(svc.local, cfg, session, 'pid', 'es');
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    const a = await svc.verifier.createTransaction(rp, 'pid', '/');
    const b = await svc.verifier.createTransaction(rp, 'pid', '/');
    const vpForA = await buildVpToken(session, a, svc.verifier);
    await expect(respondToVerifier(svc.verifier, b, { vp_token: vpForA })).rejects.toThrow(/nonce/i);
    expect(b.errorCode).toBe('invalid_presentation');
  });

  it('credential from an untrusted issuer', async () => {
    const { cfg, svc } = await setup();
    const rogue = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const cred = await issueSdJwt({ privateKey: rogue.privateKey, iss: 'https://evil.example', vct: 'urn:eudi:pid:1', claims: { given_name: 'Eve' }, holderJwk: await exportJWK(holder.publicKey) });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await presentSdJwt({ credential: cred, reveal: ['given_name'], holderPrivateKey: holder.privateKey, aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [vp] } })).rejects.toBeInstanceOf(VpError);
    expect(tx.errorCode).toBe('untrusted_issuer');
  });

  it('credential claiming to be our local issuer but signed with another key', async () => {
    const { cfg, svc } = await setup();
    const rogue = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const cred = await issueSdJwt({ privateKey: rogue.privateKey, iss: cfg.issuer.localIssuerUrl, vct: 'urn:eudi:pid:1', claims: { given_name: 'Eve' }, holderJwk: await exportJWK(holder.publicKey) });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await presentSdJwt({ credential: cred, reveal: ['given_name'], holderPrivateKey: holder.privateKey, aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [vp] } })).rejects.toThrow(/signature/i);
    expect(tx.errorCode).toBe('invalid_presentation');
  });

  it('presentation without key binding', async () => {
    const { cfg, svc, session } = await setup();
    await addDemoCredential(svc.local, cfg, session, 'pid', 'nl');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await buildVpToken(session, tx, svc.verifier);
    const noKb = vp.pid![0]!.slice(0, vp.pid![0]!.lastIndexOf('~') + 1);
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [noKb] } })).rejects.toThrow(/key-binding/i);
  });

  it('key-binding JWT signed by a different holder key', async () => {
    const { cfg, svc, session } = await setup();
    const held = await addDemoCredential(svc.local, cfg, session, 'pid', 'dk');
    const other = await generateKeyPair('ES256', { extractable: true });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await presentSdJwt({ credential: held.credential, reveal: ['given_name'], holderPrivateKey: other.privateKey, aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [vp] } })).rejects.toThrow(/key-binding/i);
  });

  it('wrong audience', async () => {
    const { cfg, svc, session } = await setup();
    const held = await addDemoCredential(svc.local, cfg, session, 'pid', 'mt');
    const { importJWK } = await import('jose');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await presentSdJwt({ credential: held.credential, reveal: ['given_name'], holderPrivateKey: await importJWK(held.holderPrivateJwk, 'ES256'), aud: 'x509_hash:other', nonce: tx.nonce });
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [vp] } })).rejects.toThrow(/key-binding/i);
  });

  it('forged disclosure is refused', async () => {
    const { cfg, svc, session } = await setup();
    const held = await addDemoCredential(svc.local, cfg, session, 'pid', 'se');
    const { importJWK } = await import('jose');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const vp = await presentSdJwt({ credential: held.credential, reveal: ['given_name'], holderPrivateKey: await importJWK(held.holderPrivateJwk, 'ES256'), aud: svc.verifier.identity.clientId, nonce: tx.nonce });
    const forged = Buffer.from(JSON.stringify(['salt', 'family_name', 'Hacked'])).toString('base64url');
    const parts = vp.split('~');
    parts.splice(1, 0, forged);
    await expect(respondToVerifier(svc.verifier, tx, { vp_token: { pid: [parts.join('~')] } })).rejects.toThrow();
  });

  it('missing required credential (university needs PID and birth certificate)', async () => {
    const { cfg, svc, session } = await setup();
    await addDemoCredential(svc.local, cfg, session, 'pid', 'fr');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'university')!, 'pid_bc', '/');
    await expect(buildVpToken(session, tx, svc.verifier)).rejects.toThrow(/birth_certificate/);
  });

  it('PID + birth certificate in one request', async () => {
    const { cfg, svc, session } = await setup();
    await addDemoCredential(svc.local, cfg, session, 'pid', 'fr');
    await addDemoCredential(svc.local, cfg, session, 'birth_certificate', 'fr');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'university')!, 'pid_bc', '/');
    await respondToVerifier(svc.verifier, tx, { vp_token: await buildVpToken(session, tx, svc.verifier) });
    expect(Object.keys(tx.result!.byType).sort()).toEqual(['birth_certificate', 'pid']);
    expect(tx.result!.byType.birth_certificate!.certificate_number).toMatch(/^BC-FR-/);
  });
});

describe('request object', () => {
  it('is a signed JWT with x5c, DCQL query and client_id scheme', async () => {
    const { cfg, svc } = await setup();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'university')!, 'pid_bc', '/');
    const jwt = await svc.verifier.signedRequestObject(tx, 'wn');
    const [h, p] = jwt.split('.').slice(0, 2).map((x) => JSON.parse(Buffer.from(x!, 'base64url').toString()));
    expect(h.typ).toBe('oauth-authz-req+jwt');
    expect(h.x5c).toHaveLength(1);
    expect(p.client_id).toMatch(/^x509_hash:[A-Za-z0-9_-]{43}$/);
    expect(p.client_metadata.encrypted_response_enc_values_supported).toEqual(['A128GCM', 'A256GCM']);
    const san = await createServices(testConfig({ VP_CLIENT_ID_SCHEME: 'x509_san_dns' }));
    expect(san.verifier.identity.clientId).toBe('x509_san_dns:rp.example.test');
    expect(p.response_uri).toBe(`https://rp.example.test/vp/response/${tx.id}`);
    expect(p.dcql_query.credentials.map((c: any) => c.id)).toEqual(['pid', 'birth_certificate']);
    expect(p.client_metadata.jwks.keys[0].use).toBe('enc');
    expect(p.wallet_nonce).toBe('wn');
    const link = svc.verifier.walletLink(tx);
    expect(link.startsWith('openid4vp://authorize?')).toBe(true);
    expect(link).toContain(encodeURIComponent(`https://rp.example.test/vp/request/${tx.id}`));
    void SignJWT;
  });

  it('supports Presentation Exchange', async () => {
    const { cfg, svc } = await setup({ VP_QUERY_LANGUAGE: 'pex' });
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'eshop')!, 'payment', '/');
    const p = svc.verifier.requestParams(tx) as any;
    expect(p.dcql_query).toBeUndefined();
    expect(p.presentation_definition.input_descriptors[0].constraints.limit_disclosure).toBe('required');
  });
});

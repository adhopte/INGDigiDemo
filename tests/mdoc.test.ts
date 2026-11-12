import { calculateJwkThumbprint } from 'jose';
import { describe, expect, it } from 'vitest';
import { openId4VpSessionTranscripts, verifyDeviceResponse } from '../src/mdoc/index.js';
import { respondToVerifier } from '../src/mock/wallet.js';
import { createServices } from '../src/services.js';
import { createMdocChainValidator, validateX5cChain } from '../src/verifier/trust.js';
import { buildDeviceResponse, makeCa, makeDsc } from './mdoc-helper.js';
import { testConfig } from './helpers.js';

const PID = { family_name: 'Muster', given_name: 'Erika', birth_date: '1985-03-04', nationality: 'DE', resident_address: 'Heidestrasse 17, 51147 Köln', issuing_country: 'DE', issuing_authority: 'IN Groupe Issuer (test)', age_over_18: true };

async function setup(env: Record<string, string> = {}, mode = 'direct_post.jwt') {
  const ca = await makeCa();
  const dsc = await makeDsc(ca);
  const cfg = testConfig({ VP_RESPONSE_MODE: mode, TRUSTED_CA_PEM: ca.cert.toString('pem'), ...env });
  const svc = await createServices(cfg);
  return { ca, dsc, cfg, svc };
}

async function transcriptFor(svc: Awaited<ReturnType<typeof setup>>['svc'], tx: any, variant = 0) {
  const thumb = tx.enc ? Buffer.from(await calculateJwkThumbprint(tx.enc.publicJwk, 'sha256'), 'base64url') : undefined;
  return openId4VpSessionTranscripts({ clientId: svc.verifier.identity.clientId, nonce: tx.nonce, responseUri: svc.verifier.responseUri(tx), ...(thumb ? { jwkThumbprint: thumb } : {}) })[variant];
}

describe('mdoc (mso_mdoc) PID presentation', () => {
  it('verifies chain, digests, validity and device signature, and maps elements to claims', async () => {
    const { dsc, cfg, svc } = await setup();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/bank/kyc');
    const dr = buildDeviceResponse({ elements: PID, dsc, sessionTranscript: await transcriptFor(svc, tx) });
    await respondToVerifier(svc.verifier, tx, { vp_token: { pid_mdoc: [dr] } });
    expect(tx.status).toBe('complete');
    const pid = tx.result!.byType.pid!;
    expect(pid).toMatchObject({ given_name: 'Erika', family_name: 'Muster', birthdate: '1985-03-04', nationalities: ['DE'], issuing_country: 'DE' });
    expect(pid.address).toEqual({ formatted: 'Heidestrasse 17, 51147 Köln' });
    expect(tx.result!.issuers[0]).toContain('Test DS');
  });

  it('also works with plain direct_post and with the client_id-without-prefix transcript variant', async () => {
    const { dsc, cfg, svc } = await setup({}, 'direct_post');
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'electricity')!, 'pid', '/');
    const dr = buildDeviceResponse({ elements: PID, dsc, sessionTranscript: await transcriptFor(svc, tx, 1) });
    await respondToVerifier(svc.verifier, tx, { vp_token: { pid_mdoc: [dr] } });
    expect(tx.result!.byType.pid!.given_name).toBe('Erika');
  });

  it('accepts a PID that has only the minimum claims (claim_sets fallback)', async () => {
    const { dsc, cfg, svc } = await setup();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const dr = buildDeviceResponse({ elements: { family_name: 'Muster', given_name: 'Erika', birth_date: '1985-03-04' }, dsc, sessionTranscript: await transcriptFor(svc, tx) });
    await respondToVerifier(svc.verifier, tx, { vp_token: { pid_mdoc: [dr] } });
    expect(Object.keys(tx.result!.byType.pid!).sort()).toEqual(['birthdate', 'family_name', 'given_name']);
    // …but not a PID lacking the minimum
    const tx2 = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
    const bad = buildDeviceResponse({ elements: { family_name: 'Muster' }, dsc, sessionTranscript: await transcriptFor(svc, tx2) });
    await expect(respondToVerifier(svc.verifier, tx2, { vp_token: { pid_mdoc: [bad] } })).rejects.toThrow(/lacks required claims/);
    expect(tx2.errorCode).toBe('missing_credential');
  });

  it('rejects: other transaction (nonce), forged element, untrusted CA, expired MSO, wrong docType', async () => {
    const { dsc, cfg, svc, ca } = await setup();
    const rp = cfg.rps.find((r) => r.id === 'bank')!;
    const a = await svc.verifier.createTransaction(rp, 'pid', '/');
    const b = await svc.verifier.createTransaction(rp, 'pid', '/');
    const forA = buildDeviceResponse({ elements: PID, dsc, sessionTranscript: await transcriptFor(svc, a) });
    await expect(respondToVerifier(svc.verifier, b, { vp_token: { pid_mdoc: [forA] } })).rejects.toThrow(/device signature/);
    const t2 = await svc.verifier.createTransaction(rp, 'pid', '/');
    await expect(respondToVerifier(svc.verifier, t2, { vp_token: { pid_mdoc: [buildDeviceResponse({ elements: PID, dsc, sessionTranscript: await transcriptFor(svc, t2), tamper: true })] } })).rejects.toThrow(/digest mismatch/);
    const t3 = await svc.verifier.createTransaction(rp, 'pid', '/');
    const rogueDsc = await makeDsc(await makeCa('Rogue CA'));
    await expect(respondToVerifier(svc.verifier, t3, { vp_token: { pid_mdoc: [buildDeviceResponse({ elements: PID, dsc: rogueDsc, sessionTranscript: await transcriptFor(svc, t3) })] } })).rejects.toThrow();
    expect(t3.errorCode).toBe('untrusted_issuer');
    const t4 = await svc.verifier.createTransaction(rp, 'pid', '/');
    await expect(respondToVerifier(svc.verifier, t4, { vp_token: { pid_mdoc: [buildDeviceResponse({ elements: PID, dsc, sessionTranscript: await transcriptFor(svc, t4), validUntil: new Date(Date.now() - 1000) })] } })).rejects.toThrow(/validity/);
    const t5 = await svc.verifier.createTransaction(rp, 'pid', '/');
    await expect(respondToVerifier(svc.verifier, t5, { vp_token: { pid_mdoc: [buildDeviceResponse({ docType: 'org.iso.18013.5.1.mDL', elements: PID, dsc, sessionTranscript: await transcriptFor(svc, t5) })] } })).rejects.toThrow(/no document of type/);
    void ca;
  });

  it('TRUST_ANY_ISSUER (demo) accepts an unknown CA, the default refuses it', async () => {
    const rogue = await makeDsc(await makeCa('Unknown CA'));
    for (const [any, ok] of [['true', true], ['false', false]] as const) {
      const { cfg, svc } = await setup({ TRUST_ANY_ISSUER: any });
      const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/');
      const dr = buildDeviceResponse({ elements: PID, dsc: rogue, sessionTranscript: await transcriptFor(svc, tx) });
      const attempt = respondToVerifier(svc.verifier, tx, { vp_token: { pid_mdoc: [dr] } });
      if (ok) await attempt; else await expect(attempt).rejects.toThrow();
    }
  });

  it('the DCQL request offers SD-JWT and mdoc alternatives with claim_sets, and omits vct when wildcarded', async () => {
    const { cfg, svc } = await setup();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'university')!, 'pid_bc', '/');
    const q = (svc.verifier.requestParams(tx) as any).dcql_query;
    expect(q.credentials.map((c: any) => c.id)).toEqual(['pid', 'pid_mdoc', 'birth_certificate']);
    expect(q.credentials[0].meta.vct_values).toEqual(['urn:eudi:pid:1', 'urn:eu.europa.ec.eudi:pid:1']);
    expect(q.credentials[1]).toMatchObject({ format: 'mso_mdoc', meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' } });
    expect(q.credentials[1].claims[0].path).toEqual(['eu.europa.ec.eudi.pid.1', 'given_name']);
    expect(q.credentials[1].claim_sets).toHaveLength(2);
    expect(q.credential_sets).toEqual([{ options: [['pid'], ['pid_mdoc']] }, { options: [['birth_certificate']] }]);
    const wild = await createServices(testConfig({ ATTESTATION_PID_ACCEPTED_VCT: '*' }));
    const tx2 = await wild.verifier.createTransaction(cfg.rps[0]!, 'pid', '/');
    expect((wild.verifier.requestParams(tx2) as any).dcql_query.credentials[0].meta).toEqual({});
  });

  it('declares mso_mdoc in client_metadata only when an mdoc answer is acceptable', async () => {
    const { cfg, svc } = await setup();
    const bank = (svc.verifier.requestParams(await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid', '/')) as any).client_metadata;
    expect(bank.vp_formats_supported.mso_mdoc).toEqual({ issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] });
    expect(Object.keys(bank.vp_formats_supported).sort()).toEqual(['dc+sd-jwt', 'mso_mdoc']);
    expect(bank.vp_formats).toEqual(bank.vp_formats_supported);
    expect(bank.vp_formats_supported['dc+sd-jwt']).toBeTruthy();
    const shop = (svc.verifier.requestParams(await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'eshop')!, 'payment', '/')) as any).client_metadata;
    expect(shop.vp_formats_supported.mso_mdoc).toBeUndefined();
  });

  it('probe presentation pid_any: wildcard vct, two claims, no claim_sets', async () => {
    const { cfg, svc } = await setup();
    const tx = await svc.verifier.createTransaction(cfg.rps.find((r) => r.id === 'bank')!, 'pid_any', '/');
    const q = (svc.verifier.requestParams(tx) as any).dcql_query;
    expect(q.credentials[0]).toEqual({ id: 'pid', format: 'dc+sd-jwt', meta: {}, claims: [{ path: ['given_name'] }, { path: ['family_name'] }] });
    expect(q.credentials[1].claims.map((c: any) => c.path[1])).toEqual(['given_name', 'family_name']);
    expect(q.credentials[1].claim_sets).toBeUndefined();
  });

  it('unit: chain validator and primitives', async () => {
    const ca = await makeCa(); const dsc = await makeDsc(ca);
    const leaf = Buffer.from(dsc.cert.rawData);
    const cfg = testConfig({ TRUSTED_CA_PEM: ca.cert.toString('pem') });
    expect(createMdocChainValidator(cfg)([leaf]).subject).toContain('Test DS');
    expect(() => createMdocChainValidator(testConfig())([leaf])).toThrow(/trust anchors/);
    const otherCa = await makeCa('x');
    expect(() => validateX5cChain([leaf.toString('base64')], [otherCa.cert.toString('pem')])).toThrow(/trusted root/);
    expect(() => verifyDeviceResponse('AAAA', { docType: 'x', validateChain: () => { throw new Error('n/a'); }, sessionTranscripts: [] })).toThrow();
  });
});

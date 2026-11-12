import type { AttestationConfig, PresentationConfig } from '../config.js';

export interface RequestedCredential {
  type: string;
  attestation: AttestationConfig;
  /** Claims requested for this credential (presentation claims that this credential type can carry). */
  claims: string[];
  /** Subset that must be present; the wallet may satisfy the request with just these (DCQL claim_sets). */
  minClaims: string[];
  /** Probe: no vct restriction. */
  anyVct: boolean;
  /** Formats actually requested (presentation override, else the attestation's). */
  formats: string[];
}

export function requestedCredentials(presentation: PresentationConfig, attestations: Record<string, AttestationConfig>): RequestedCredential[] {
  return presentation.types.map((type) => {
    const attestation = attestations[type];
    if (!attestation) throw new Error(`Presentation references unknown credential type "${type}"`);
    const subset = presentation.claims.filter((c) => attestation.claims.includes(c));
    const claims = subset.length ? subset : attestation.claims;
    const min = presentation.minClaims.filter((c) => claims.includes(c));
    return { type, attestation, claims, minClaims: min.length && min.length < claims.length ? min : claims, anyVct: presentation.anyVct, formats: presentation.formats.length ? presentation.formats : attestation.formats };
  });
}

/** Wallets (e.g. kotlinx-based DCQL parsers) REQUIRE vct_values for dc+sd-jwt, so a wildcard is expressed as a list of well-known PID types. */
export const PROBE_VCTS = ['urn:eudi:pid:1', 'urn:eu.europa.ec.eudi:pid:1', 'eu.europa.ec.eudi.pid.1', 'urn:eudi:pid:de:1', 'urn:eudi:pid:fr:1'];

export const mdocQueryId = (type: string) => `${type}_mdoc`;
const claimId = (s: string) => s.replace(/[^A-Za-z0-9_-]/g, '_');

/** One DCQL credential query per requested format; claim_sets express "all of these, or at least the minimum". */
function claimsPart(names: string[], r: RequestedCredential, path: (n: string) => string[]) {
  const withSets = r.minClaims.length < r.claims.length;
  return {
    claims: names.map((n) => ({ ...(withSets ? { id: claimId(n) } : {}), path: path(n) })),
    ...(withSets ? { claim_sets: [names.map(claimId), r.minClaims.filter((m) => names.includes(m)).map(claimId)] } : {}),
  };
}

/** DCQL (OpenID4VP 1.0). Types offered in several formats become alternatives in `credential_sets`. */
export function buildDcql(reqs: RequestedCredential[]) {
  const credentials: unknown[] = [];
  const sets: { options: string[][] }[] = [];
  for (const r of reqs) {
    const ids: string[] = [];
    if (r.formats.includes('dc+sd-jwt')) {
      const anyVct = r.anyVct || r.attestation.acceptedVct.includes('*');
      credentials.push({ id: r.type, format: 'dc+sd-jwt', meta: { vct_values: anyVct ? [...new Set([...r.attestation.acceptedVct.filter((v) => v !== '*'), ...PROBE_VCTS])] : r.attestation.acceptedVct }, ...claimsPart(r.claims, r, (n) => [n]) });
      ids.push(r.type);
    }
    const m = r.attestation.mdoc;
    if (m && r.formats.includes('mso_mdoc')) {
      const mapped = r.claims.filter((c) => m.elements[c]);
      const mapR = { ...r, claims: mapped, minClaims: r.minClaims.filter((c) => m.elements[c]) };
      credentials.push({
        id: mdocQueryId(r.type), format: 'mso_mdoc', meta: { doctype_value: m.docType },
        ...claimsPart(mapped.map((c) => m.elements[c]!), { ...mapR, minClaims: mapR.minClaims.map((c) => m.elements[c]!) }, (n) => [m.namespace, n]),
      });
      ids.push(mdocQueryId(r.type));
    }
    sets.push({ options: ids.map((i) => [i]) });
  }
  const needSets = sets.some((s) => s.options.length > 1);
  return { credentials, ...(needSets ? { credential_sets: sets.map((s) => ({ options: s.options })) } : {}) };
}

/** DIF Presentation Exchange 2.0 (SD-JWT only; for wallets that have not moved to DCQL). */
export function buildPresentationDefinition(reqs: RequestedCredential[], id: string) {
  const alg = { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] };
  return {
    id,
    input_descriptors: reqs.map((r) => ({
      id: r.type,
      format: { 'dc+sd-jwt': alg, 'vc+sd-jwt': alg },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          ...(r.anyVct || r.attestation.acceptedVct.includes('*') ? [] : [{ path: ['$.vct'], filter: { type: 'string', enum: r.attestation.acceptedVct } }]),
          ...r.minClaims.map((c) => ({ path: [`$.${c}`] })),
        ],
      },
    })),
  };
}

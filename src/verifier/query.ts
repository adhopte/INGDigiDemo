import type { AttestationConfig, PresentationConfig } from '../config.js';

export interface RequestedCredential {
  type: string;
  attestation: AttestationConfig;
  /** Claims requested for this credential (presentation claims that this credential type can carry). */
  claims: string[];
}

export function requestedCredentials(presentation: PresentationConfig, attestations: Record<string, AttestationConfig>): RequestedCredential[] {
  return presentation.types.map((type) => {
    const attestation = attestations[type];
    if (!attestation) throw new Error(`Presentation references unknown credential type "${type}"`);
    const subset = presentation.claims.filter((c) => attestation.claims.includes(c));
    return { type, attestation, claims: subset.length ? subset : attestation.claims };
  });
}

/** DCQL (OpenID4VP 1.0). All listed credentials are required (no credential_sets). */
export function buildDcql(reqs: RequestedCredential[]) {
  return {
    credentials: reqs.map((r) => ({
      id: r.type,
      format: 'dc+sd-jwt',
      meta: { vct_values: r.attestation.acceptedVct },
      claims: r.claims.map((c) => ({ path: [c] })),
    })),
  };
}

/** DIF Presentation Exchange 2.0 (OpenID4VP drafts ≤ 21 and wallets that have not moved to DCQL yet). */
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
          { path: ['$.vct'], filter: { type: 'string', enum: r.attestation.acceptedVct } },
          ...r.claims.map((c) => ({ path: [`$.${c}`] })),
        ],
      },
    })),
  };
}

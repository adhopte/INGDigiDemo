import type { PresentationConfig, RpConfig } from '../config.js';
import type { Claims } from '../oidc/types.js';

/** Clearly fake values for mock mode. Never real data. */
const FAKE: Record<string, unknown> = {
  given_name: 'Alex (MOCK)',
  family_name: 'Example (MOCK)',
  birthdate: '1990-01-01',
  nationality: 'XX',
  place_of_birth: { locality: 'Mockville', country: 'XX' },
  address: { street_address: '1 Mock Street', locality: 'Mockville', postal_code: '00000', country: 'XX' },
  parent_names: ['Pat Example (MOCK)', 'Sam Example (MOCK)'],
  account_holder_name: 'Alex Example (MOCK)',
  iban: 'XX00MOCK00000000000001',
  bank_name: 'Demo Bank (MOCK)',
};

export function mockClaimsFor(rp: Pick<RpConfig, 'id'>, presentationKey: string, presentation: Pick<PresentationConfig, 'claims'>): Claims {
  const out: Claims = { sub: `mock-subject-${rp.id}-${presentationKey}`, mock: true };
  for (const name of presentation.claims) out[name] = FAKE[name] ?? `MOCK ${name}`;
  return out;
}

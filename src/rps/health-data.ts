import { randomInt } from 'node:crypto';
import type { Claims } from '../sdjwt/index.js';
import { str } from './context.js';

const day = (d: Date) => d.toISOString().slice(0, 10);
const plusYears = (d: Date, n: number) => new Date(Date.UTC(d.getUTCFullYear() + n, d.getUTCMonth(), d.getUTCDate()));
const digits = (n: number) => String(randomInt(0, 10 ** Math.min(n, 9))).padStart(Math.min(n, 9), '0');

export const HEALTH_FUND = { id: 'DE-DEMO-HF-01', name: 'Demo Health Fund' } as const;

/** Health ID (hiid) derived from a verified PID: the PID's identity is kept as the "matching" attributes the health fund checks against. */
export function hiidFromPid(p: Claims, now = new Date()): Claims {
  const country = (str(p.nationality) || 'DE').toUpperCase().slice(0, 2);
  const address = typeof p.resident_address === 'string' ? p.resident_address : '';
  return {
    health_insurance_id: `HI${digits(9)}${digits(3)}`,
    affiliation_country: country,
    issuance_date: day(now), expiry_date: day(plusYears(now, 1)),
    matching_registered_family_name: str(p.family_name), matching_registered_given_name: str(p.given_name), matching_birth_date: str(p.birth_date),
    ...(address ? { matching_resident_address: address } : {}),
    issuing_authority: HEALTH_FUND.name, issuing_country: country, document_number: `HD${digits(8)}`,
  };
}

/**
 * European Health Insurance Card derived from a verified Health ID, in the two formats of the EUDI reference issuer: the SD-JWT VC
 * (`urn:eudi:ehic:1`: personal_administrative_number, nested issuing_authority / authentic_source) and the mdoc (`eu.europa.ec.eudi.ehic.1`:
 * social_security_pin, competent_institution, …). The holder's name travels as a `subject` object in both, so the insurer can greet the member.
 */
export function ehicFromHiid(h: Claims, now = new Date()): { sd: Claims; mdoc: Claims } {
  const holder = { family_name: str(h.matching_registered_family_name), given_name: str(h.matching_registered_given_name), birth_date: str(h.matching_birth_date) };
  const from = day(now), until = day(plusYears(now, 2));
  const country = str(h.affiliation_country) || 'DE';
  const pan = str(h.health_insurance_id);
  return {
    sd: {
      personal_administrative_number: pan,
      issuing_authority: { id: HEALTH_FUND.id, name: HEALTH_FUND.name }, issuing_country: country,
      date_of_issuance: from, date_of_expiry: until,
      authentic_source: { id: 'DEMO-SIS', name: 'Demo Health Fund member registry' },
      starting_date: from, ending_date: until, subject: holder,
    },
    mdoc: {
      credential_holder: holder, subject: holder, social_security_pin: pan,
      starting_date: from, ending_date: until, document_id: `EH${digits(9)}`, competent_institution: HEALTH_FUND.id,
      issuance_date: from, expiry_date: until, issuing_authority: HEALTH_FUND.name, issuing_country: country,
    },
  };
}

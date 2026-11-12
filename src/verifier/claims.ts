import type { Claims } from '../sdjwt/index.js';

/**
 * Canonical claim names follow the Benin PID rulebook (standard EUDI element names: birth_date, birth_place, nationality,
 * resident_address). SD-JWT PIDs that use the older EU names are mapped so they display and compare the same way.
 */
export function canonicalizeClaims(c: Claims): Claims {
  const o: Claims = { ...c };
  const move = (from: string, to: string, f: (v: unknown) => unknown = (v) => v) => {
    if (o[from] !== undefined && o[to] === undefined) o[to] = f(o[from]);
    delete o[from];
  };
  move('birthdate', 'birth_date');
  move('nationalities', 'nationality');
  move('address', 'resident_address');
  if (o.place_of_birth && typeof o.place_of_birth === 'object') {
    const p = o.place_of_birth as Record<string, unknown>;
    if (o.birth_place === undefined && typeof p.locality === 'string') o.birth_place = p.locality;
    if (o.birth_country === undefined && typeof p.country === 'string') o.birth_country = p.country;
  }
  delete o.place_of_birth;
  return o;
}

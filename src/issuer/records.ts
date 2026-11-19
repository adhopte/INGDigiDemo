import { randomBytes } from 'node:crypto';

export type FieldKind = 'text' | 'date' | 'gender' | 'boolean';
export interface FieldDef { name: string; kind: FieldKind; required?: boolean; max?: number }

/** Attributes the admin can enter per use case (the SIGMA issuer's own record layout; the portrait is not editable). */
export const RECORD_FIELDS: Record<string, FieldDef[]> = {
  pid: [
    { name: 'given_name', kind: 'text', required: true }, { name: 'family_name', kind: 'text', required: true }, { name: 'family_name_birth', kind: 'text' },
    { name: 'birth_date', kind: 'date', required: true }, { name: 'gender', kind: 'gender' }, { name: 'nationality', kind: 'text', max: 2 }, { name: 'age_over_18', kind: 'boolean' },
    { name: 'birth_country', kind: 'text', max: 2 }, { name: 'birth_state', kind: 'text' }, { name: 'birth_city', kind: 'text' }, { name: 'birth_place', kind: 'text' },
    { name: 'resident_address', kind: 'text', max: 200 }, { name: 'document_number', kind: 'text' },
    { name: 'issuance_date', kind: 'date' }, { name: 'expiry_date', kind: 'date' }, { name: 'issuing_authority', kind: 'text' }, { name: 'issuing_country', kind: 'text', max: 2 },
    { name: 'personal_administrative_number', kind: 'text' },
  ],
  'birth-certificate': [
    { name: 'given_name', kind: 'text', required: true }, { name: 'family_name', kind: 'text', required: true }, { name: 'given_name_birth', kind: 'text' }, { name: 'family_name_birth', kind: 'text' },
    { name: 'birth_date', kind: 'date', required: true }, { name: 'birth_place', kind: 'text' }, { name: 'birth_country', kind: 'text', max: 2 }, { name: 'birth_state', kind: 'text' }, { name: 'birth_city', kind: 'text' }, { name: 'gender', kind: 'gender' },
    { name: 'mother_family_name', kind: 'text' }, { name: 'mother_given_name', kind: 'text' }, { name: 'father_family_name', kind: 'text' }, { name: 'father_given_name', kind: 'text' },
    { name: 'birth_record_reference', kind: 'text' }, { name: 'issuance_date', kind: 'date' }, { name: 'issuing_authority', kind: 'text' },
    { name: 'registration_date', kind: 'date' }, { name: 'registration_place', kind: 'text' }, { name: 'declarant_name', kind: 'text' }, { name: 'declarant_relationship', kind: 'text' },
    { name: 'marginal_mentions1', kind: 'text' }, { name: 'marginal_mentions2', kind: 'text' }, { name: 'document_number', kind: 'text' },
  ],
};

export interface CustomRecord {
  /** Identifier handed to the issuer's offer API (and served by the record service). */
  identifier: string;
  credentialId: string;
  useCase: string;
  attributes: Record<string, string>;
  createdAt: string;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

const ageOver18 = (birthDate: string, now = new Date()): boolean => {
  const b = new Date(`${birthDate}T00:00:00Z`);
  const cutoff = new Date(Date.UTC(now.getUTCFullYear() - 18, now.getUTCMonth(), now.getUTCDate()));
  return b.getTime() <= cutoff.getTime();
};

export type Validated = { ok: true; attributes: Record<string, string> } | { ok: false; errors: Record<string, string> };

/** Validate admin input against the field definitions; unknown fields are dropped, age_over_18 is derived when left empty. */
export function validateRecord(useCase: string, input: Record<string, unknown>): Validated {
  const defs = RECORD_FIELDS[useCase];
  if (!defs) return { ok: false, errors: { useCase: 'admin.err.required' } };
  const attributes: Record<string, string> = {};
  const errors: Record<string, string> = {};
  for (const d of defs) {
    const raw = typeof input[d.name] === 'string' ? (input[d.name] as string).trim() : '';
    if (!raw) { if (d.required) errors[d.name] = 'admin.err.required'; continue; }
    if (raw.length > (d.max ?? 120)) { errors[d.name] = 'admin.err.too_long'; continue; }
    if (/[\u0000-\u001f<>]/.test(raw)) { errors[d.name] = 'admin.err.chars'; continue; }
    if (d.kind === 'date' && (!DATE.test(raw) || Number.isNaN(Date.parse(`${raw}T00:00:00Z`)))) { errors[d.name] = 'admin.err.date'; continue; }
    if (d.kind === 'gender' && !['0', '1', '2', '9'].includes(raw)) { errors[d.name] = 'admin.err.choice'; continue; }
    if (d.kind === 'boolean' && !['True', 'False'].includes(raw)) { errors[d.name] = 'admin.err.choice'; continue; }
    attributes[d.name] = raw;
  }
  if (defs.some((d) => d.name === 'age_over_18') && !attributes.age_over_18 && attributes.birth_date) attributes.age_over_18 = ageOver18(attributes.birth_date) ? 'True' : 'False';
  return Object.keys(errors).length ? { ok: false, errors } : { ok: true, attributes };
}

/** In-memory records entered by the admin. Lost on restart. */
export class RecordStore {
  private records = new Map<string, CustomRecord>();
  static readonly MAX = 100;

  add(useCase: string, attributes: Record<string, string>): CustomRecord {
    if (this.records.size >= RecordStore.MAX) this.records.delete(this.records.keys().next().value as string); // drop the oldest
    const suffix = randomBytes(4).toString('hex'); // unguessable: the record service answers to anyone who knows the identifier
    const identifier = `custom-${useCase === 'pid' ? 'pid' : 'bc'}-${suffix}`;
    const rec: CustomRecord = { identifier, credentialId: useCase === 'pid' ? 'custom_pid_mdoc' : 'custom_birth_certificate', useCase, attributes, createdAt: new Date().toISOString() };
    this.records.set(identifier, rec);
    return rec;
  }
  get(identifier: string): CustomRecord | undefined { return this.records.get(identifier); }
  delete(identifier: string): boolean { return this.records.delete(identifier); }
  list(): CustomRecord[] { return [...this.records.values()].reverse(); }
}

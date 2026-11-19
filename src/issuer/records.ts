import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';

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
  /** Base64 JPEG portrait (PID only). */
  portrait?: string;
  createdAt: string;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

const ageOver18 = (birthDate: string, now = new Date()): boolean => {
  const b = new Date(`${birthDate}T00:00:00Z`);
  const cutoff = new Date(Date.UTC(now.getUTCFullYear() - 18, now.getUTCMonth(), now.getUTCDate()));
  return b.getTime() <= cutoff.getTime();
};

/** Max length of the base64 portrait (the browser shrinks the photo before sending it; keeps the form post small). */
export const PORTRAIT_MAX_CHARS = 90_000;

/** A portrait must be base64 and really a JPEG (starts with FFD8FF). Empty means none. */
export function validatePortrait(raw: unknown): { ok: true; portrait: string | undefined } | { ok: false } {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!v) return { ok: true, portrait: undefined };
  if (v.length > PORTRAIT_MAX_CHARS || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return { ok: false };
  const head = Buffer.from(v.slice(0, 8), 'base64');
  return head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff ? { ok: true, portrait: v } : { ok: false };
}

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

export const USE_CASE_CONFIG: Record<string, string> = {
  pid: 'eu.europa.ec.eudi.pid_mdoc',
  'birth-certificate': 'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt',
};
const CREDENTIAL_ID: Record<string, string> = { pid: 'custom_pid_mdoc', 'birth-certificate': 'custom_birth_certificate' };
export const SAFE_ID = /^[A-Za-z0-9._:@-]{1,64}$/;

/** A new record with an unguessable identifier (the record service answers to anyone who knows it). */
export function buildRecord(useCase: string, attributes: Record<string, string>, portrait?: string, identifier?: string): CustomRecord {
  const id = identifier ?? `custom-${useCase === 'pid' ? 'pid' : 'bc'}-${randomBytes(4).toString('hex')}`;
  return { identifier: id, credentialId: CREDENTIAL_ID[useCase] ?? 'custom_credential', useCase, attributes, ...(portrait ? { portrait } : {}), createdAt: new Date().toISOString() };
}

type MaybePromise<T> = T | Promise<T>;
/** Where the admin console keeps its records: in memory, or in a standalone record service. */
export interface RecordBackend {
  add(useCase: string, attributes: Record<string, string>, portrait?: string): MaybePromise<CustomRecord>;
  get(identifier: string): MaybePromise<CustomRecord | undefined>;
  delete(identifier: string): MaybePromise<boolean>;
  list(): MaybePromise<CustomRecord[]>;
}

/** In-memory records entered by the admin. Lost on restart. */
export class RecordStore implements RecordBackend {
  protected records = new Map<string, CustomRecord>();
  static readonly MAX = 100;

  /** Hook for subclasses that persist. */
  protected changed(): void {}

  put(rec: CustomRecord): CustomRecord {
    if (!this.records.has(rec.identifier) && this.records.size >= RecordStore.MAX) this.records.delete(this.records.keys().next().value as string); // drop the oldest
    this.records.set(rec.identifier, rec);
    this.changed();
    return rec;
  }
  add(useCase: string, attributes: Record<string, string>, portrait?: string): CustomRecord { return this.put(buildRecord(useCase, attributes, portrait)); }
  get(identifier: string): CustomRecord | undefined { return this.records.get(identifier); }
  delete(identifier: string): boolean { const ok = this.records.delete(identifier); if (ok) this.changed(); return ok; }
  list(): CustomRecord[] { return [...this.records.values()].reverse(); }
}

/** Records kept in a JSON file (survives restarts of the service as far as the file system does). */
export class FileRecordStore extends RecordStore {
  constructor(private readonly file: string) {
    super();
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8')) as CustomRecord[];
      for (const r of Array.isArray(raw) ? raw : []) if (r && SAFE_ID.test(r.identifier) && RECORD_FIELDS[r.useCase]) this.records.set(r.identifier, r);
    } catch { /* no file yet */ }
  }
  protected override changed(): void {
    mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify([...this.records.values()]), { mode: 0o600 });
    renameSync(tmp, this.file);
  }
}

/** Client of the standalone record service (src/sor): the admin console writes there, the SIGMA issuer reads from there. */
export class RemoteRecordStore implements RecordBackend {
  constructor(private readonly baseUrl: string, private readonly token: string | undefined, private readonly fetchImpl: typeof fetch = fetch) {}
  private async call(method: string, p: string, body?: unknown): Promise<Response> {
    const res = await this.fetchImpl(`${this.baseUrl}${p}`, {
      method,
      headers: { ...(this.token ? { authorization: `Bearer ${this.token}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}), accept: 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok && res.status !== 404) throw new Error(`Record service answered ${res.status}`);
    return res;
  }
  async add(useCase: string, attributes: Record<string, string>, portrait?: string): Promise<CustomRecord> {
    const rec = buildRecord(useCase, attributes, portrait);
    await this.call('PUT', `/records/${encodeURIComponent(rec.identifier)}`, { useCase, attributes, ...(portrait ? { portrait } : {}) });
    return rec;
  }
  async get(identifier: string): Promise<CustomRecord | undefined> {
    const res = await this.call('GET', `/records/${encodeURIComponent(identifier)}`);
    return res.status === 404 ? undefined : ((await res.json()) as CustomRecord);
  }
  async delete(identifier: string): Promise<boolean> { return (await this.call('DELETE', `/records/${encodeURIComponent(identifier)}`)).status !== 404; }
  async list(): Promise<CustomRecord[]> { return (await (await this.call('GET', '/records')).json()) as CustomRecord[]; }
}

/** The record-service contract (same as the WalletTester's SoR server): one record by identifier [and credential identifier], without internal fields. */
export function sorLookup(
  custom: CustomRecord | undefined,
  samples: Array<{ identifier: string; credentialId: string; configurationId: string; attributes: Record<string, string>; portrait?: string | undefined }>,
  configId: string,
  identifier: string,
  credentialId?: string,
): { identifier: string; attributes: Array<{ name: string; value: string }> } | undefined {
  const sample = samples.find((u) => u.identifier === identifier && u.configurationId === configId);
  const found = custom && USE_CASE_CONFIG[custom.useCase] === configId ? { credentialId: custom.credentialId, attributes: custom.attributes, portrait: custom.portrait } : sample;
  if (!found || (credentialId !== undefined && credentialId !== found.credentialId)) return undefined;
  return { identifier, attributes: [...Object.entries(found.attributes).map(([name, value]) => ({ name, value })), ...(found.portrait ? [{ name: 'portrait', value: found.portrait }] : [])] };
}

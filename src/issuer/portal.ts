import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT_DIR } from '../config.js';

/** One record of the issuer's system of record, as listed by the issuer's own in-person portal. */
export interface PortalUser {
  identifier: string;
  credentialId: string;
  configurationId: string;
  walletId?: string;
  attributes: Record<string, string>;
  /** Base64 JPEG, when the record has a portrait. */
  portrait?: string;
}

export interface PortalUseCase {
  /** Stable URL segment. */
  id: string;
  /** Attestation key in config/rps.json. */
  attestation: string;
  /** Attributes shown in the table (all attributes are available per row). */
  columns: string[];
  users: PortalUser[];
}

const DEFINITIONS: Array<{ id: string; attestation: string; file: string; columns: string[] }> = [
  { id: 'pid', attestation: 'pid', file: 'user_pid_claims.json', columns: ['given_name', 'family_name', 'birth_date', 'nationality', 'issuance_date', 'expiry_date'] },
  { id: 'mdl', attestation: 'mdl', file: 'mdl_claims.json', columns: ['given_name', 'family_name', 'birth_date', 'issue_date', 'expiry_date', 'document_number'] },
  { id: 'birth-certificate', attestation: 'birth_certificate', file: 'birth_certificate_claims_sd_jwt.json', columns: ['given_name', 'family_name', 'birth_date', 'birth_place', 'issuance_date', 'document_number'] },
];

interface RawUser { identifier?: unknown; credentialId?: unknown; credentialConfigurationId?: unknown; walletId?: unknown; attributes?: unknown }

export function parseUsers(raw: unknown): PortalUser[] {
  if (!Array.isArray(raw)) return [];
  const users: PortalUser[] = [];
  for (const u of raw as RawUser[]) {
    if (typeof u?.identifier !== 'string' || typeof u.credentialId !== 'string' || typeof u.credentialConfigurationId !== 'string' || !Array.isArray(u.attributes)) continue;
    const attributes: Record<string, string> = {};
    let portrait: string | undefined;
    for (const a of u.attributes as Array<{ name?: unknown; value?: unknown }>) {
      if (typeof a?.name !== 'string') continue;
      const value = typeof a.value === 'string' ? a.value : typeof a.value === 'boolean' ? (a.value ? 'True' : 'False') : typeof a.value === 'object' && a.value !== null ? JSON.stringify(a.value) : String(a.value ?? '');
      if (a.name === 'portrait') portrait = /^[A-Za-z0-9+/=]+$/.test(value) ? value : undefined;
      else attributes[a.name] = value;
    }
    users.push({ identifier: u.identifier, credentialId: u.credentialId, configurationId: u.credentialConfigurationId, ...(typeof u.walletId === 'string' ? { walletId: u.walletId } : {}), attributes, ...(portrait ? { portrait } : {}) });
  }
  return users;
}

/** Sample records for the portal, from config/portal/*.json (snapshots of the issuer portal's own data files). */
export function loadPortalUseCases(dir = path.join(ROOT_DIR, 'config', 'portal')): PortalUseCase[] {
  return DEFINITIONS.map((d) => {
    let users: PortalUser[] = [];
    try { users = parseUsers(JSON.parse(readFileSync(path.join(dir, d.file), 'utf8'))); } catch { /* missing file: empty use case */ }
    return { id: d.id, attestation: d.attestation, columns: d.columns, users };
  });
}

/** Use-case ids of the issuer portal's record store (GET <issuer>/api/in-person-portal-sor/<id>/sor/ lists its records). */
export const SOR_USE_CASE_ID: Record<string, string> = { pid: 'oid_pid_inp_uc1', 'birth-certificate': 'oid_birth_certificate_sd_jwt_uc1', mdl: 'oid_mdl_uc1' };
export const SOR_LIST_PATH = '/api/in-person-portal-sor';

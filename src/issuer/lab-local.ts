import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT_DIR, type AppConfig } from '../config.js';
import type { Claims } from '../sdjwt/index.js';
import type { LocalIssuer } from './local/service.js';
import { deeplinkForOfferObject, qrDataUrl } from './offer.js';

/** The credentials of the issuance workspace and how the LOCAL issuer issues them: the same formats as at the external issuer (PID and driving licence as mdoc, birth certificate as SD-JWT VC). */
export const LAB_CREDENTIALS: Record<string, { attestation: string; format: 'sd-jwt' | 'mdoc' }> = {
  'eu.europa.ec.eudi.pid_mdoc': { attestation: 'pid', format: 'mdoc' },
  'org.iso.18013.5.1.mDL': { attestation: 'mdl', format: 'mdoc' },
  'eu.europa.ec.eudi.birth_certificate_vc_sd_jwt': { attestation: 'birth_certificate', format: 'sd-jwt' },
};

interface LabField { name: string; label: string; displays?: Array<{ locale: string; name: string }>; mandatory: boolean; type: string; valueType?: string }
interface LabConfiguration { id: string; format: string; name: string; displays?: Array<{ locale: string; name: string }>; fields: LabField[] }
interface CaseCredential { credentialConfigurationId: string; credentialIdentifier: string; attributes: Record<string, unknown> }
interface CaseRecord {
  identifier: string;
  identity: Record<string, string>;
  credentials: CaseCredential[];
  status: 'offer_created';
  createdAt: number;
  expiresAt: number;
  retrievals: number;
  offer: { qr_code: string; uri: string; tx_code: string | undefined };
  offerError: null;
}

const MAX_CASES = 300;
const today = () => new Date();
const ageOver = (born: string, years: number, now = today()) => {
  const b = new Date(`${born}T00:00:00Z`);
  if (Number.isNaN(b.getTime())) return undefined;
  return b.getTime() <= Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate());
};

/**
 * The issuance workspace backed by the local issuer: presets, credential configurations and "cases" (one identity + its credentials = one
 * pre-authorised offer with a 6-digit transaction code), shaped like the external issuer's data API so the same page drives both.
 */
export class LocalLab {
  private readonly presetsFile: { presets: unknown[] };
  private readonly configs: LabConfiguration[];
  private readonly cases = new Map<string, CaseRecord>();

  constructor(private readonly cfg: AppConfig, private readonly local: LocalIssuer, dir = path.join(ROOT_DIR, 'config', 'portal')) {
    this.presetsFile = JSON.parse(readFileSync(path.join(dir, 'lab-presets.json'), 'utf8'));
    this.configs = (JSON.parse(readFileSync(path.join(dir, 'lab-configurations.json'), 'utf8')) as { configurations: LabConfiguration[] }).configurations.filter((c) => c.id in LAB_CREDENTIALS);
  }

  presets() {
    return { presets: this.presetsFile.presets };
  }

  /** The credential configurations with the labels of the language (English where there is none). */
  configurations(locale: string) {
    const pick = (list: Array<{ locale: string; name: string }> | undefined, fallback: string) => list?.find((d) => d.locale.toLowerCase().startsWith(locale))?.name ?? fallback;
    return {
      configurations: this.configs.map((c) => ({ ...c, name: pick(c.displays, c.name), fields: c.fields.map((f) => ({ ...f, label: pick(f.displays, f.label) })) })),
    };
  }

  /** The attributes of one credential: what the identity provides (where the credential has such a field) plus the entered ones, plus derived age flags. */
  private attributesOf(conf: LabConfiguration, identity: Record<string, string>, entered: Record<string, unknown>, portraitFromIdentity: boolean): Record<string, unknown> {
    const names = new Set(conf.fields.map((f) => f.name));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(identity)) if (k !== 'portrait' && names.has(k) && v) out[k] = v;
    if (portraitFromIdentity && names.has('portrait') && identity.portrait) out.portrait = identity.portrait;
    Object.assign(out, entered);
    const born = typeof out.birth_date === 'string' ? out.birth_date : '';
    if (born) {
      if (names.has('age_over_18') && out.age_over_18 === undefined) out.age_over_18 = ageOver(born, 18);
      if (names.has('age_over_21') && out.age_over_21 === undefined) out.age_over_21 = ageOver(born, 21);
    }
    return out;
  }

  /** Attribute values → what the local issuer puts into the credential (driving privileges as the structured list, nationality as the list the PID uses). */
  private claimsFor(attestation: string, attrs: Record<string, unknown>): Claims {
    const c: Record<string, unknown> = { ...attrs };
    if (attestation === 'mdl' && typeof c.driving_privileges === 'string') {
      c.driving_privileges = [{ vehicle_category_code: c.driving_privileges, ...(c.issue_date ? { issue_date: c.issue_date } : {}), ...(c.expiry_date ? { expiry_date: c.expiry_date } : {}) }];
    }
    if (attestation === 'pid' && typeof c.nationality === 'string') c.nationality = [c.nationality];
    return c as Claims;
  }

  private async makeOffer(identifier: string, identity: Record<string, string>, creds: CaseCredential[]): Promise<CaseRecord['offer'] & { expiresAt: number }> {
    const entries = creds.map((c) => {
      const m = LAB_CREDENTIALS[c.credentialConfigurationId]!;
      return { attestationKey: m.attestation, format: m.format, claims: this.claimsFor(m.attestation, c.attributes) };
    });
    void identity; void identifier;
    const o = this.local.createMultiOffer(entries, { txLength: 6 }); // a 6-digit transaction code, as at the external issuer
    const uri = deeplinkForOfferObject(this.local.offerObject(o.id)!);
    const png = await qrDataUrl(uri);
    return { uri, tx_code: o.txCode, qr_code: png.replace(/^data:image\/png;base64,/, ''), expiresAt: o.expiresAt.getTime() };
  }

  /** `credentials`: validated by the caller (known configuration ids are checked here). */
  async createCase(identity: Record<string, string>, credentials: Array<{ credentialConfigurationId: string; attributes: Record<string, unknown>; portraitFromIdentity?: boolean }>): Promise<{ status: number; body: unknown }> {
    const bad = credentials.find((c) => !(c.credentialConfigurationId in LAB_CREDENTIALS));
    if (bad) return { status: 422, body: { error: { message: `The credential ${bad.credentialConfigurationId} is not offered.` } } };
    const identifier = `local-${randomBytes(12).toString('hex')}`;
    const creds: CaseCredential[] = credentials.map((c) => ({
      credentialConfigurationId: c.credentialConfigurationId,
      credentialIdentifier: `cred-${randomBytes(9).toString('hex')}`,
      attributes: this.attributesOf(this.configs.find((x) => x.id === c.credentialConfigurationId)!, identity, c.attributes, c.portraitFromIdentity === true),
    }));
    const offer = await this.makeOffer(identifier, identity, creds);
    const rec: CaseRecord = { identifier, identity, credentials: creds, status: 'offer_created', createdAt: Date.now(), expiresAt: offer.expiresAt, retrievals: 0, offer: { qr_code: offer.qr_code, uri: offer.uri, tx_code: offer.tx_code }, offerError: null };
    this.cases.set(identifier, rec);
    while (this.cases.size > MAX_CASES) this.cases.delete(this.cases.keys().next().value as string);
    return { status: 201, body: { case: rec } };
  }

  get(id: string) {
    const rec = this.cases.get(id);
    return rec ? { status: 200, body: { case: rec } } : { status: 404, body: { error: { message: 'Unknown case.' } } };
  }

  async regenerate(id: string) {
    const rec = this.cases.get(id);
    if (!rec) return { status: 404, body: { error: { message: 'Unknown case.' } } };
    const offer = await this.makeOffer(rec.identifier, rec.identity, rec.credentials);
    rec.offer = { qr_code: offer.qr_code, uri: offer.uri, tx_code: offer.tx_code };
    rec.expiresAt = offer.expiresAt;
    return { status: 200, body: { case: rec } };
  }
}

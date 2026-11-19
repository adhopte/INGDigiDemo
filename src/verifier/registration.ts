/**
 * Registration certificate of the relying party (ETSI TS 119 475 "WRP registration certificate", a JWT of type rc-wrp+jwt).
 * It is sent in the `verifier_info` request parameter ([{ format: "registration_cert", data: "<JWT>" }], OpenID4VP 1.0) and wallets
 * built on the EUDI wallet kit show its `name` and `purpose` to the user. It is issued by a registrar for ONE verifier (identified by its
 * LEI in `sub`), so it can only be supplied by configuration, never generated here. The signature is NOT checked here (the wallet does that
 * against its trust list); we only read it to report what will be shown and to catch obvious mistakes.
 */
export interface RegistrationInfo {
  name: string | undefined;
  purposes: string[];
  /** Registered identifier of the verifier (LEI), `sub`. */
  subject: string | undefined;
  country: string | undefined;
  registryUri: string | undefined;
  type: string | undefined;
  issuedAt: string | undefined;
  expiresAt: string | undefined;
  expired: boolean;
  sizeBytes: number;
}

export type ParsedRegistration = { ok: true; jwt: string; info: RegistrationInfo; warnings: string[] } | { ok: false; error: string };

const decode = (part: string): Record<string, unknown> | undefined => {
  try {
    const v = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
};
const s = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);
const iso = (v: unknown): string | undefined => (typeof v === 'number' && Number.isFinite(v) ? new Date(v * 1000).toISOString() : undefined);

export function parseRegistrationCert(raw: string | undefined, now = Date.now()): ParsedRegistration | undefined {
  if (!raw || !raw.trim()) return undefined;
  const jwt = raw.replace(/\s+/g, '').replace(/^"|"$/g, '');
  const parts = jwt.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]*$/.test(p)) || !parts[0] || !parts[1] || !parts[2]) return { ok: false, error: 'not a compact JWT (header.payload.signature)' };
  const header = decode(parts[0]!);
  const payload = decode(parts[1]!);
  if (!header || !payload) return { ok: false, error: 'header or payload is not valid JSON' };
  const warnings: string[] = [];
  if (header.typ !== 'rc-wrp+jwt') warnings.push(`header typ is "${String(header.typ)}", expected "rc-wrp+jwt"`);
  const purposes = Array.isArray(payload.purpose) ? (payload.purpose as unknown[]).map((p) => s((p as { value?: unknown })?.value)).filter((x): x is string => !!x) : typeof payload.purpose === 'string' ? [payload.purpose] : [];
  const exp = typeof payload.exp === 'number' ? payload.exp * 1000 : undefined;
  const expired = exp !== undefined && exp < now;
  if (expired) warnings.push('the certificate has expired');
  if (!s(payload.name)) warnings.push('no "name": the wallet has nothing to display');
  if (!s(payload.sub)) warnings.push('no "sub" (registered identifier of the verifier)');
  return {
    ok: true, jwt, warnings,
    info: { name: s(payload.name), purposes, subject: s(payload.sub), country: s(payload.country), registryUri: s(payload.registry_uri), type: s(header.typ), issuedAt: iso(payload.iat), expiresAt: iso(payload.exp), expired, sizeBytes: jwt.length },
  };
}

/** The `verifier_info` request parameter for a registration certificate. */
export const verifierInfo = (jwt: string) => [{ format: 'registration_cert', data: jwt }];

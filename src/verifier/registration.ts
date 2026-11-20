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
  /** What the certificate registers this verifier to request; undefined = the certificate lists none (no restriction known). */
  credentials: RegisteredCredential[] | undefined;
}

export interface RegisteredCredential { format: string; vcts: string[]; doctype: string | undefined; claimPaths: string[][] }

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

function registeredCredentials(raw: unknown): RegisteredCredential[] | undefined {
  if (!Array.isArray(raw) || !raw.length) return undefined;
  return raw.flatMap((c: any) => {
    if (!c || typeof c.format !== 'string') return [];
    const claims = Array.isArray(c.claims) ? c.claims : Array.isArray(c.claim) ? c.claim : []; // the spec says `claims`, the EUDI registrar writes `claim`
    return [{
      format: c.format,
      vcts: Array.isArray(c.meta?.vct_values) ? c.meta.vct_values.filter((v: unknown) => typeof v === 'string') : [],
      doctype: typeof c.meta?.doctype_value === 'string' ? c.meta.doctype_value : undefined,
      claimPaths: claims.flatMap((x: any) => (Array.isArray(x?.path) ? [x.path.map((e: unknown) => String(e))] : [])),
    }];
  });
}

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
    info: { name: s(payload.name), purposes, subject: s(payload.sub), country: s(payload.country), registryUri: s(payload.registry_uri), type: s(header.typ), issuedAt: iso(payload.iat), expiresAt: iso(payload.exp), expired, sizeBytes: jwt.length, credentials: registeredCredentials(payload.credentials) },
  };
}

/** The `verifier_info` request parameter for a registration certificate. */
export const verifierInfo = (jwt: string) => [{ format: 'registration_cert', data: jwt }];

interface DcqlCredentialQuery { format?: string; meta?: { vct_values?: string[]; doctype_value?: string }; claims?: Array<{ path?: unknown[] }> }

/**
 * Does the registration certificate cover EVERY credential a request asks for (format, credential type, and each claim)? A wallet that checks the
 * certificate against the request rejects what is outside it, so an uncovered request must go without the certificate.
 * A certificate that lists no credentials restricts nothing we know of, so it covers everything.
 */
export function registrationCovers(info: RegistrationInfo, credentials: unknown): { covered: true } | { covered: false; reason: string } {
  if (!info.credentials) return { covered: true };
  for (const q of (Array.isArray(credentials) ? credentials : []) as DcqlCredentialQuery[]) {
    const what = q.meta?.doctype_value ?? q.meta?.vct_values?.join('|') ?? q.format ?? 'credential';
    const entry = info.credentials.find((e) => e.format === q.format && (q.meta?.doctype_value !== undefined ? e.doctype === q.meta.doctype_value : (q.meta?.vct_values ?? []).every((v) => e.vcts.includes(v))));
    if (!entry) return { covered: false, reason: `${what} (${q.format}) is not among the credentials the certificate registers` };
    for (const c of q.claims ?? []) {
      const path = (c.path ?? []).map(String);
      if (!entry.claimPaths.some((p) => p.length === path.length && p.every((x, i) => x === path[i]))) return { covered: false, reason: `claim ${path.join('/')} of ${what} is not registered` };
    }
  }
  return { covered: true };
}

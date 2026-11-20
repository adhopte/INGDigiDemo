import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export interface PresentationConfig {
  /** Logical credential types requested, e.g. ["pid"], ["payment"], ["pid","birth_certificate"]. */
  types: string[];
  /** Probe mode: accept / request any SD-JWT vct (wildcard) for this presentation. */
  anyVct: boolean;
  /** Probe: exact vct_values to request (overrides the attestation's list). */
  vctValues: string[];
  /** Probe: any verified answer counts as success (no claim checks). */
  probe: boolean;
  /** Probe: raw mdoc element identifiers to request (overrides the claim mapping). */
  mdocElements: string[];
  /** Claims requested when the request is passed by value (QR-sized): preferred set, with `minClaims` as the fallback. */
  compactClaims: string[];
  /** Restrict the credential formats requested by this presentation (overrides the attestation's). */
  formats: string[];
  /** Fallback claim set accepted when the wallet's credential lacks some of `claims` (DCQL claim_sets). */
  minClaims: string[];
  /** Claims requested from the wallet (and shown to the user). */
  claims: string[];
}

export interface AttestationConfig {
  key: string;
  /** Credential configuration id of the LOCAL demo issuer. */
  credentialConfigurationId: string;
  /** Credential configuration id at the EXTERNAL issuer (SIGMA), when it differs. */
  externalConfigurationId: string | undefined;
  /** Identifiers (and their credential identifier) known to the external issuer's system of record. */
  externalUsers: { identifier: string; credentialIdentifier: string | undefined; walletIdentifier: string | undefined; configurationId: string | undefined; label: string }[];
  vct: string;
  /** Extra vct values the verifier accepts for this credential type. */
  acceptedVct: string[];
  /** Credential formats requested for this type: dc+sd-jwt and/or mso_mdoc. */
  formats: string[];
  /** ISO mdoc description (docType, namespace, internal claim → mdoc element). */
  mdoc: { docType: string; namespace: string; elements: Record<string, string> } | undefined;
  claims: string[];
}

export interface RpConfig {
  id: string;
  displayName: string;
  themeColor: string;
  /** Registration certificate (JWT) of this RP (RP_<ID>_REGISTRATION_CERT or "registrationCertificate" in rps.json). */
  registrationCert?: string | undefined;
  presentations: Record<string, PresentationConfig>;
  /** Keys into AppConfig.attestations that this RP can issue. */
  attestations: string[];
}

export interface BrandConfig {
  name: string;
  product: string;
  primary: string;
  accent: string;
}

export type IssuerMode = 'local' | 'external';

export interface ExternalIssuerConfig {
  apiBaseUrl: string | undefined;
  offerPath: string;
  authMode: 'none' | 'bearer' | 'client_credentials';
  tokenUrl: string | undefined;
  clientId: string | undefined;
  /** Secrets: read from env only, never logged. */
  clientSecret: string | undefined;
  apiToken: string | undefined;
}

export interface VerifierConfig {
  /** x509_hash (HAIP default) / x509_san_dns: signed request object with an X.509 chain. redirect_uri: unsigned, by value. */
  clientIdScheme: 'x509_hash' | 'x509_san_dns' | 'redirect_uri';
  responseMode: 'direct_post' | 'direct_post.jwt';
  queryLanguage: 'dcql' | 'pex';
  /** By-value (redirect_uri) requests must fit a QR code: request only these formats (when the presentation allows them). */
  byValueFormats: string[];
  /** Wallet invocation URL prefix, e.g. openid4vp://authorize or haip://authorize. */
  deeplinkBase: string;
  /** `iss` URL prefixes whose JWKS may be fetched to verify credentials ('*' = any, demo only). */
  trustedIssuers: string[];
  /** PEM trust anchors for x5c credential chains. */
  trustedCaPem: string[];
  /** DEMO ONLY: accept credentials from any issuer (signature still checked against the credential's own key/certificate). */
  trustAnyIssuer: boolean;
  /** Registration certificate (JWT) sent as `verifier_info` for RPs without their own (VP_REGISTRATION_CERT). Needs signed requests (x509 client id schemes). */
  registrationCert: string | undefined;
  registrationByValue: 'off' | 'button' | 'all';
  /** Verifier identity (secrets, env only). When absent a self-signed demo identity is generated at startup. */
  signingKeyJwk: string | undefined;
  certChainPem: string | undefined;
}

export interface IssuerConfig {
  mode: IssuerMode;
  /** OID4VCI issuer metadata URL of the external issuer (credential catalogue); defaults to <ISSUER_API_BASE_URL>/.well-known/openid-credential-issuer. */
  metadataUrl: string | undefined;
  /** External mode: issue attestations the external issuer does not offer with the local demo issuer instead of failing. */
  fallbackLocal: boolean;
  /** Issuer identifier of the local issuer: <PUBLIC_BASE_URL>/issuer */
  localIssuerUrl: string;
  txCode: boolean;
  /** Local issuer: declare the SIGMA credential_reuse_policy in the metadata ("sigma", default) or not ("off": wallets then treat each copy as single-use). Switchable at runtime by the admin. */
  reusePolicy: 'sigma' | 'off';
  signingKeyJwk: string | undefined;
  external: ExternalIssuerConfig;
}

export interface AppConfig {
  nodeEnv: string;
  isProduction: boolean;
  port: number;
  publicBaseUrl: string;
  mockMode: boolean;
  /** Expose GET /vp/diagnostics (recent verifier events, no personal data). */
  diagnostics: boolean;
  /** Password of the issuer portal's admin user ("authentic source" console). Default is the demo password; override with ADMIN_PASSWORD. */
  adminPassword: string;
  multiCredential: boolean;
  /** University: require the PID and the birth certificate to describe the same person (name + date of birth). Off by default. */
  universityRequireMatch: boolean;
  sessionSecret: string;
  verifier: VerifierConfig;
  brand: BrandConfig;
  attestations: Record<string, AttestationConfig>;
  issuer: IssuerConfig;
  rps: RpConfig[];
}

type Env = Record<string, string | undefined>;

const TRUE = new Set(['1', 'true', 'yes', 'on']);
export function parseBool(value: string | undefined, fallback = false): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return TRUE.has(value.trim().toLowerCase());
}

const upper = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]/g, '_');

function str(v: unknown, where: string): string {
  if (typeof v !== 'string' || v.trim() === '') throw new Error(`Invalid config: ${where} must be a non-empty string`);
  return v;
}

const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

export function buildAttestations(raw: unknown, env: Env): Record<string, AttestationConfig> {
  const out: Record<string, AttestationConfig> = {};
  for (const [key, a] of Object.entries((raw ?? {}) as Record<string, any>)) {
    const vct = env[`ATTESTATION_${upper(key)}_VCT`] ?? str(a.vct, `attestations.${key}.vct`);
    out[key] = {
      key,
      credentialConfigurationId: env[`ATTESTATION_${upper(key)}_CONFIG_ID`] ?? str(a.credentialConfigurationId, `attestations.${key}.credentialConfigurationId`),
      externalUsers: Array.isArray(a.externalUsers) ? a.externalUsers.map((u: any) => ({ identifier: str(u.identifier, `attestations.${key}.externalUsers[].identifier`), credentialIdentifier: typeof u.credentialIdentifier === 'string' ? u.credentialIdentifier : undefined, walletIdentifier: typeof u.walletIdentifier === 'string' ? u.walletIdentifier : undefined, configurationId: typeof u.configurationId === 'string' ? u.configurationId : undefined, label: typeof u.label === 'string' ? u.label : u.identifier })) : [],
      externalConfigurationId: env[`ATTESTATION_${upper(key)}_EXTERNAL_CONFIG_ID`] ?? (typeof a.externalConfigurationId === 'string' ? a.externalConfigurationId : undefined),
      vct,
      acceptedVct: env[`ATTESTATION_${upper(key)}_ACCEPTED_VCT`] ? env[`ATTESTATION_${upper(key)}_ACCEPTED_VCT`]!.split(',').map((x) => x.trim()).filter(Boolean) : [...new Set([vct, ...strList(a.acceptedVct)])],
      formats: env[`ATTESTATION_${upper(key)}_FORMATS`] ? env[`ATTESTATION_${upper(key)}_FORMATS`]!.split(',').map((x) => x.trim()).filter(Boolean) : strList(a.formats).length ? strList(a.formats) : ['dc+sd-jwt'],
      mdoc: a.mdoc && typeof a.mdoc === 'object' ? { docType: str(a.mdoc.docType, `attestations.${key}.mdoc.docType`), namespace: str(a.mdoc.namespace, `attestations.${key}.mdoc.namespace`), elements: { ...(a.mdoc.elements as Record<string, string>) } } : undefined,
      claims: strList(a.claims),
    };
  }
  return out;
}

/** The registration certificate shipped in config/registration-cert.jwt, if present. */
function defaultRegistrationCert(): string | undefined {
  try {
    return readFileSync(path.join(ROOT_DIR, 'config', 'registration-cert.jwt'), 'utf8').trim() || undefined;
  } catch {
    return undefined;
  }
}

/** Validate rps.json and apply env-var overrides. */
export function buildRpConfigs(raw: unknown, attestations: Record<string, AttestationConfig>, env: Env): RpConfig[] {
  const list = (raw as { rps?: unknown })?.rps;
  if (!Array.isArray(list) || list.length === 0) throw new Error('Invalid config: "rps" must be a non-empty array');

  const seen = new Set<string>();
  return list.map((entry, i): RpConfig => {
    const where = `rps[${i}]`;
    const e = entry as Record<string, any>;
    const id = str(e.id, `${where}.id`);
    if (!/^[a-z][a-z0-9-]*$/.test(id)) throw new Error(`Invalid config: ${where}.id "${id}" must be a lowercase slug`);
    if (seen.has(id)) throw new Error(`Invalid config: duplicate RP id "${id}"`);
    seen.add(id);
    const P = `RP_${upper(id)}`;

    const themeColor = env[`${P}_THEME_COLOR`] ?? str(e.themeColor, `${where}.themeColor`);
    if (!/^#[0-9a-fA-F]{6}$/.test(themeColor)) throw new Error(`Invalid config: ${where}.themeColor must be #rrggbb`);

    const presentations: Record<string, PresentationConfig> = {};
    for (const [pk, p] of Object.entries((e.presentations ?? {}) as Record<string, any>)) {
        presentations[pk] = {
        types: strList(p.types),
        anyVct: p.anyVct === true,
        vctValues: strList(p.vctValues),
        probe: p.probe === true,
        mdocElements: strList(p.mdocElements),
        compactClaims: strList(p.compactClaims),
        formats: strList(p.formats),
        minClaims: env[`${P}_${upper(pk)}_MIN_CLAIMS`] ? env[`${P}_${upper(pk)}_MIN_CLAIMS`]!.split(',').map((x) => x.trim()).filter(Boolean) : strList(p.minClaims),
        claims: env[`${P}_${upper(pk)}_CLAIMS`] ? env[`${P}_${upper(pk)}_CLAIMS`]!.split(',').map((x) => x.trim()).filter(Boolean) : strList(p.claims),
      };
    }

    const atts = strList(e.attestations);
    for (const a of atts) if (!attestations[a]) throw new Error(`Invalid config: ${where} references unknown attestation "${a}"`);

    return {
      id,
      displayName: str(e.displayName, `${where}.displayName`),
      themeColor,
      registrationCert: env[`${P}_REGISTRATION_CERT`] || (typeof e.registrationCertificate === 'string' ? e.registrationCertificate : undefined),
      presentations,
      attestations: atts,
    };
  });
}

export function loadConfig(
  env: Env = process.env,
  files = { rps: path.join(ROOT_DIR, 'config', 'rps.json'), brand: path.join(ROOT_DIR, 'config', 'brand.json') },
): AppConfig {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const isProduction = nodeEnv === 'production';
  const mockMode = parseBool(env.MOCK_MODE, false);

  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`Invalid PORT "${env.PORT}"`);

  // Render exposes RENDER_EXTERNAL_URL automatically; PUBLIC_BASE_URL wins when set.
  const publicBaseUrl = (env.PUBLIC_BASE_URL || env.RENDER_EXTERNAL_URL || `http://localhost:${port}`).replace(/\/+$/, '');
  try {
    new URL(publicBaseUrl);
  } catch {
    throw new Error(`Invalid PUBLIC_BASE_URL "${publicBaseUrl}"`);
  }

  let sessionSecret = env.SESSION_SECRET ?? '';
  if (!sessionSecret) {
    if (isProduction) throw new Error('SESSION_SECRET is required in production');
    sessionSecret = 'dev-only-insecure-session-secret';
  }

  const rawRps = JSON.parse(readFileSync(files.rps, 'utf8'));
  const rawBrand = JSON.parse(readFileSync(files.brand, 'utf8'));
  const attestations = buildAttestations(rawRps.attestations, env);
  const rps = buildRpConfigs(rawRps, attestations, env);

  const pems = (v: string | undefined) => (v ? v.replace(/\\n/g, '\n').split(/(?<=-----END CERTIFICATE-----)\s*/).map((x) => x.trim()).filter(Boolean) : []);
  const verifier: VerifierConfig = {
    clientIdScheme: (['x509_san_dns', 'redirect_uri'] as const).find((s) => s === env.VP_CLIENT_ID_SCHEME) ?? 'x509_hash',
    // HAIP wallets require an encrypted response, so direct_post.jwt is the default.
    responseMode: env.VP_RESPONSE_MODE === 'direct_post' ? 'direct_post' : 'direct_post.jwt',
    queryLanguage: env.VP_QUERY_LANGUAGE === 'pex' ? 'pex' : 'dcql',
    // by-value requests must fit a QR code: real wallets hold the SIGMA PID as mdoc; with the simulated wallet (SD-JWT only) offer both
    byValueFormats: (env.VP_BY_VALUE_FORMATS ?? (mockMode ? 'mso_mdoc,dc+sd-jwt' : 'mso_mdoc')).split(',').map((x) => x.trim()).filter(Boolean),
    deeplinkBase: env.VP_DEEPLINK_BASE || 'openid4vp://authorize',
    trustedIssuers: (env.TRUSTED_ISSUERS ?? '').split(',').map((x) => x.trim().replace(/\/+$/, '')).filter(Boolean),
    trustedCaPem: pems(env.TRUSTED_CA_PEM),
    trustAnyIssuer: parseBool(env.TRUST_ANY_ISSUER, false),
    // default: config/registration-cert.jwt (the test registration certificate); VP_REGISTRATION_CERT overrides it, "none" turns it off
    registrationCert: env.VP_REGISTRATION_CERT === 'none' ? undefined : env.VP_REGISTRATION_CERT || defaultRegistrationCert(),
    // Unsigned by-value links (redirect_uri scheme): off | button (only the "Open in wallet" button of the page, the QR code stays small) | all (every link: ~15 KB, no QR code).
    registrationByValue: ((v) => (v === 'all' || v === 'true' ? 'all' : v === 'off' || v === 'false' ? 'off' : 'button'))((env.VP_REGISTRATION_LINKS ?? '').toLowerCase()),
    signingKeyJwk: env.VERIFIER_SIGNING_KEY_JWK || undefined,
    certChainPem: env.VERIFIER_CERT_CHAIN_PEM ? env.VERIFIER_CERT_CHAIN_PEM.replace(/\\n/g, '\n') : undefined,
  };
  if (isProduction && verifier.trustedIssuers.includes('*')) throw new Error('TRUSTED_ISSUERS=* is not allowed in production');

  const issuerMode: IssuerMode = (env.ISSUER_MODE ?? 'local') === 'external' ? 'external' : 'local';
  const authMode = (['none', 'bearer', 'client_credentials'] as const).find((m) => m === env.ISSUER_EXTERNAL_AUTH) ?? 'none';
  const external: ExternalIssuerConfig = {
    apiBaseUrl: env.ISSUER_API_BASE_URL?.replace(/\/+$/, '') || undefined,
    // the SIGMA offer API is POST /offer ('/credential-offers' was an earlier guess and may linger in stored settings)
    offerPath: !env.ISSUER_EXTERNAL_OFFER_PATH || env.ISSUER_EXTERNAL_OFFER_PATH === '/credential-offers' ? '/offer' : env.ISSUER_EXTERNAL_OFFER_PATH,
    authMode,
    tokenUrl: env.ISSUER_EXTERNAL_TOKEN_URL || undefined,
    clientId: env.ISSUER_CLIENT_ID || undefined,
    clientSecret: env.ISSUER_CLIENT_SECRET || undefined,
    apiToken: env.ISSUER_API_TOKEN || undefined,
  };
  if (issuerMode === 'external' && !external.apiBaseUrl) throw new Error('ISSUER_API_BASE_URL is required when ISSUER_MODE=external');

  return {
    nodeEnv,
    isProduction,
    port,
    publicBaseUrl,
    mockMode,
    diagnostics: parseBool(env.DIAGNOSTICS_ENDPOINT, true),
    adminPassword: env.ADMIN_PASSWORD || 'Admin123',
    multiCredential: parseBool(env.MULTI_CREDENTIAL, false),
    universityRequireMatch: parseBool(env.UNIVERSITY_REQUIRE_MATCH, false),
    sessionSecret,
    verifier,
    brand: {
      name: str(rawBrand.name, 'brand.name'),
      product: str(rawBrand.product, 'brand.product'),
      primary: env.BRAND_PRIMARY ?? str(rawBrand.primary, 'brand.primary'),
      accent: env.BRAND_ACCENT ?? str(rawBrand.accent, 'brand.accent'),
    },
    attestations,
    issuer: {
      mode: issuerMode,
      metadataUrl: env.ISSUER_METADATA_URL || (external.apiBaseUrl ? `${external.apiBaseUrl}/.well-known/openid-credential-issuer` : undefined),
      fallbackLocal: parseBool(env.ISSUER_FALLBACK_LOCAL, true),
      localIssuerUrl: `${publicBaseUrl}/issuer`,
      txCode: parseBool(env.ISSUER_TX_CODE, false),
      reusePolicy: (env.ISSUER_REUSE_POLICY ?? '').toLowerCase() === 'off' ? 'off' : 'sigma',
      signingKeyJwk: env.ISSUER_SIGNING_KEY_JWK || undefined,
      external,
    },
    rps,
  };
}


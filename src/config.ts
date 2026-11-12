import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export interface PresentationConfig {
  /** Logical credential types requested, e.g. ["pid"], ["payment"], ["pid","birth_certificate"]. */
  types: string[];
  /** Probe mode: accept / request any SD-JWT vct (wildcard) for this presentation. */
  anyVct: boolean;
  /** Fallback claim set accepted when the wallet's credential lacks some of `claims` (DCQL claim_sets). */
  minClaims: string[];
  /** Claims requested from the wallet (and shown to the user). */
  claims: string[];
}

export interface AttestationConfig {
  key: string;
  credentialConfigurationId: string;
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
  responseUriField: string;
}

export interface VerifierConfig {
  /** x509_hash (HAIP default) / x509_san_dns: signed request object with an X.509 chain. redirect_uri: unsigned, by value. */
  clientIdScheme: 'x509_hash' | 'x509_san_dns' | 'redirect_uri';
  responseMode: 'direct_post' | 'direct_post.jwt';
  queryLanguage: 'dcql' | 'pex';
  /** Wallet invocation URL prefix, e.g. openid4vp://authorize or haip://authorize. */
  deeplinkBase: string;
  /** `iss` URL prefixes whose JWKS may be fetched to verify credentials ('*' = any, demo only). */
  trustedIssuers: string[];
  /** PEM trust anchors for x5c credential chains. */
  trustedCaPem: string[];
  /** DEMO ONLY: accept credentials from any issuer (signature still checked against the credential's own key/certificate). */
  trustAnyIssuer: boolean;
  /** Verifier identity (secrets, env only). When absent a self-signed demo identity is generated at startup. */
  signingKeyJwk: string | undefined;
  certChainPem: string | undefined;
}

export interface IssuerConfig {
  mode: IssuerMode;
  /** Issuer identifier of the local issuer: <PUBLIC_BASE_URL>/issuer */
  localIssuerUrl: string;
  txCode: boolean;
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
  multiCredential: boolean;
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
      vct,
      acceptedVct: env[`ATTESTATION_${upper(key)}_ACCEPTED_VCT`] ? env[`ATTESTATION_${upper(key)}_ACCEPTED_VCT`]!.split(',').map((x) => x.trim()).filter(Boolean) : [...new Set([vct, ...strList(a.acceptedVct)])],
      formats: env[`ATTESTATION_${upper(key)}_FORMATS`] ? env[`ATTESTATION_${upper(key)}_FORMATS`]!.split(',').map((x) => x.trim()).filter(Boolean) : strList(a.formats).length ? strList(a.formats) : ['dc+sd-jwt'],
      mdoc: a.mdoc && typeof a.mdoc === 'object' ? { docType: str(a.mdoc.docType, `attestations.${key}.mdoc.docType`), namespace: str(a.mdoc.namespace, `attestations.${key}.mdoc.namespace`), elements: { ...(a.mdoc.elements as Record<string, string>) } } : undefined,
      claims: strList(a.claims),
    };
  }
  return out;
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
    deeplinkBase: env.VP_DEEPLINK_BASE || 'openid4vp://authorize',
    trustedIssuers: (env.TRUSTED_ISSUERS ?? '').split(',').map((x) => x.trim().replace(/\/+$/, '')).filter(Boolean),
    trustedCaPem: pems(env.TRUSTED_CA_PEM),
    trustAnyIssuer: parseBool(env.TRUST_ANY_ISSUER, false),
    signingKeyJwk: env.VERIFIER_SIGNING_KEY_JWK || undefined,
    certChainPem: env.VERIFIER_CERT_CHAIN_PEM ? env.VERIFIER_CERT_CHAIN_PEM.replace(/\\n/g, '\n') : undefined,
  };
  if (isProduction && verifier.trustedIssuers.includes('*')) throw new Error('TRUSTED_ISSUERS=* is not allowed in production');

  const issuerMode: IssuerMode = (env.ISSUER_MODE ?? 'local') === 'external' ? 'external' : 'local';
  const authMode = (['none', 'bearer', 'client_credentials'] as const).find((m) => m === env.ISSUER_EXTERNAL_AUTH) ?? 'none';
  const external: ExternalIssuerConfig = {
    apiBaseUrl: env.ISSUER_API_BASE_URL?.replace(/\/+$/, '') || undefined,
    offerPath: env.ISSUER_EXTERNAL_OFFER_PATH || '/credential-offers',
    authMode,
    tokenUrl: env.ISSUER_EXTERNAL_TOKEN_URL || undefined,
    clientId: env.ISSUER_CLIENT_ID || undefined,
    clientSecret: env.ISSUER_CLIENT_SECRET || undefined,
    apiToken: env.ISSUER_API_TOKEN || undefined,
    responseUriField: env.ISSUER_EXTERNAL_RESPONSE_URI_FIELD || 'credential_offer_uri',
  };
  if (issuerMode === 'external' && !external.apiBaseUrl) throw new Error('ISSUER_API_BASE_URL is required when ISSUER_MODE=external');

  return {
    nodeEnv,
    isProduction,
    port,
    publicBaseUrl,
    mockMode,
    diagnostics: parseBool(env.DIAGNOSTICS_ENDPOINT, true),
    multiCredential: parseBool(env.MULTI_CREDENTIAL, false),
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
      localIssuerUrl: `${publicBaseUrl}/issuer`,
      txCode: parseBool(env.ISSUER_TX_CODE, false),
      signingKeyJwk: env.ISSUER_SIGNING_KEY_JWK || undefined,
      external,
    },
    rps,
  };
}


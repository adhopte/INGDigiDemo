import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export interface PresentationConfig {
  label: string;
  scope: string;
  acrValues: string;
  claims: string[];
}

export interface AttestationConfig {
  label: string;
  credentialConfigurationId: string;
}

export interface RpConfig {
  id: string;
  displayName: string;
  tagline: string;
  themeColor: string;
  clientId: string;
  clientSecretEnv: string;
  presentations: Record<string, PresentationConfig>;
  attestations: Record<string, AttestationConfig>;
}

export interface AppConfig {
  nodeEnv: string;
  isProduction: boolean;
  port: number;
  publicBaseUrl: string;
  mockMode: boolean;
  multiCredential: boolean;
  sessionSecret: string;
  intermediaryIssuerUrl: string | undefined;
  /** Token endpoint client authentication for the RP clients on the Intermediary. */
  oidcClientAuth: 'basic' | 'post';
  issuer: {
    apiBaseUrl: string | undefined;
    clientId: string | undefined;
    clientSecretEnv: string;
  };
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

/** Validate the raw rps.json content and apply env-var overrides. */
export function buildRpConfigs(raw: unknown, env: Env): RpConfig[] {
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
    for (const [pid, p] of Object.entries((e.presentations ?? {}) as Record<string, any>)) {
      const PP = `${P}_${upper(pid)}`;
      presentations[pid] = {
        label: str(p.label, `${where}.presentations.${pid}.label`),
        scope: env[`${PP}_SCOPE`] ?? str(p.scope, `${where}.presentations.${pid}.scope`),
        acrValues: env[`${PP}_ACR_VALUES`] ?? str(p.acrValues, `${where}.presentations.${pid}.acrValues`),
        claims: Array.isArray(p.claims) ? p.claims.map(String) : [],
      };
    }

    const attestations: Record<string, AttestationConfig> = {};
    for (const [aid, a] of Object.entries((e.attestations ?? {}) as Record<string, any>)) {
      attestations[aid] = {
        label: str(a.label, `${where}.attestations.${aid}.label`),
        credentialConfigurationId:
          env[`${P}_CRED_${upper(aid)}`] ?? str(a.credentialConfigurationId, `${where}.attestations.${aid}.credentialConfigurationId`),
      };
    }

    return {
      id,
      displayName: str(e.displayName, `${where}.displayName`),
      tagline: typeof e.tagline === 'string' ? e.tagline : '',
      themeColor,
      clientId: env[`${P}_CLIENT_ID`] ?? str(e.clientId, `${where}.clientId`),
      clientSecretEnv: str(e.clientSecretEnv, `${where}.clientSecretEnv`),
      presentations,
      attestations,
    };
  });
}

export function loadConfig(env: Env = process.env, rpsFile = path.join(ROOT_DIR, 'config', 'rps.json')): AppConfig {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const isProduction = nodeEnv === 'production';
  const mockMode = parseBool(env.MOCK_MODE, false);

  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`Invalid PORT "${env.PORT}"`);

  const publicBaseUrl = (env.PUBLIC_BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, '');
  try {
    new URL(publicBaseUrl);
  } catch {
    throw new Error(`Invalid PUBLIC_BASE_URL "${env.PUBLIC_BASE_URL}"`);
  }

  let sessionSecret = env.SESSION_SECRET ?? '';
  if (!sessionSecret) {
    if (isProduction) throw new Error('SESSION_SECRET is required in production');
    sessionSecret = 'dev-only-insecure-session-secret';
  }

  const raw = JSON.parse(readFileSync(rpsFile, 'utf8'));
  const rps = buildRpConfigs(raw, env);

  const intermediaryIssuerUrl = env.INTERMEDIARY_ISSUER_URL?.replace(/\/+$/, '') || undefined;
  if (!mockMode && !intermediaryIssuerUrl) throw new Error('INTERMEDIARY_ISSUER_URL is required when MOCK_MODE is not true');

  return {
    nodeEnv,
    isProduction,
    port,
    publicBaseUrl,
    mockMode,
    multiCredential: parseBool(env.MULTI_CREDENTIAL, false),
    sessionSecret,
    intermediaryIssuerUrl,
    oidcClientAuth: env.OIDC_CLIENT_AUTH === 'post' ? 'post' : 'basic',
    issuer: {
      apiBaseUrl: env.ISSUER_API_BASE_URL?.replace(/\/+$/, '') || undefined,
      clientId: env.ISSUER_CLIENT_ID || undefined,
      clientSecretEnv: 'ISSUER_CLIENT_SECRET',
    },
    rps,
  };
}

export const redirectUriFor = (cfg: Pick<AppConfig, 'publicBaseUrl'>, rpId: string) => `${cfg.publicBaseUrl}/${rpId}/callback`;

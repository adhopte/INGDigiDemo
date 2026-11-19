import type { AppConfig, AttestationConfig } from '../config.js';
import { log } from '../logger.js';

export interface RemoteConfig {
  id: string;
  format: string;
  vct?: string;
  doctype?: string;
  scope?: string;
  claims: string[];
  display: string;
}

export interface RemoteSummary {
  reachable: boolean;
  issuer?: string;
  authorizationServers: string[];
  configs: RemoteConfig[];
  error?: string;
  fetchedAt?: string;
}

const TTL_MS = 10 * 60 * 1000;
const FAIL_TTL_MS = 60 * 1000;

/** Parse an OpenID4VCI credential issuer metadata document into the few facts the app needs. */
export function parseIssuerMetadata(m: any): Omit<RemoteSummary, 'reachable' | 'fetchedAt'> {
  const configs: RemoteConfig[] = Object.entries((m?.credential_configurations_supported ?? {}) as Record<string, any>).map(([id, c]) => {
    const meta = c.credential_metadata ?? {};
    const rawClaims: any[] = Array.isArray(meta.claims) ? meta.claims : Array.isArray(c.claims) ? c.claims : [];
    return {
      id,
      format: String(c.format ?? ''),
      vct: typeof c.vct === 'string' ? c.vct : undefined,
      doctype: typeof c.doctype === 'string' ? c.doctype : undefined,
      scope: typeof c.scope === 'string' ? c.scope : undefined,
      claims: rawClaims.map((x) => (Array.isArray(x?.path) ? String(x.path[x.path.length - 1]) : '')).filter(Boolean),
      display: String((meta.display ?? c.display ?? [])[0]?.name ?? id),
    };
  });
  return { issuer: m?.credential_issuer, authorizationServers: [...new Set<string>(m?.authorization_servers ?? [])], configs };
}

/** Which remote configuration issues this attestation type (by vct / mdoc docType; preferring the configured id)? */
export function matchConfig(att: AttestationConfig, configs: RemoteConfig[]): RemoteConfig | undefined {
  const matches = configs.filter(
    (c) => (c.format === 'dc+sd-jwt' && !!c.vct && [att.vct, ...att.acceptedVct].includes(c.vct)) || (c.format === 'mso_mdoc' && !!att.mdoc && c.doctype === att.mdoc.docType),
  );
  return matches.find((c) => c.id === att.externalConfigurationId) ?? matches[0];
}

/** Claims the verifier requests for this type that the remote configuration does not list (should be empty). */
export function missingClaims(att: AttestationConfig, rc: RemoteConfig, requested: string[]): string[] {
  const mapped = rc.format === 'mso_mdoc' ? requested.map((c) => att.mdoc?.elements[c] ?? c) : requested;
  return mapped.filter((c) => !rc.claims.includes(c));
}

/** Live view of the external issuer's credential catalogue (cached). */
export class RemoteIssuerMetadata {
  private cache: { at: number; summary: RemoteSummary } | undefined;

  constructor(
    private readonly cfg: AppConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  get url(): string | undefined {
    return this.cfg.issuer.metadataUrl;
  }

  async summary(force = false): Promise<RemoteSummary | undefined> {
    const url = this.url;
    if (!url) return undefined;
    const now = Date.now();
    if (!force && this.cache && now - this.cache.at < (this.cache.summary.reachable ? TTL_MS : FAIL_TTL_MS)) return this.cache.summary;
    let summary: RemoteSummary;
    try {
      const res = await this.fetchImpl(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      summary = { reachable: true, ...parseIssuerMetadata(await res.json()), fetchedAt: new Date().toISOString() };
      log.info('external issuer metadata loaded', { issuer: summary.issuer, configs: summary.configs.map((c) => c.id) });
    } catch (e) {
      summary = { reachable: false, authorizationServers: [], configs: [], error: (e as Error).message };
      log.warn('external issuer metadata unavailable', { error: summary.error });
    }
    this.cache = { at: now, summary };
    return summary;
  }

  async configFor(att: AttestationConfig): Promise<RemoteConfig | undefined> {
    const s = await this.summary();
    return s?.reachable ? matchConfig(att, s.configs) : undefined;
  }
}

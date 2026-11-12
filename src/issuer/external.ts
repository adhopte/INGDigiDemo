/**
 * EXTERNAL ISSUER ADAPTER – the only place that knows the external Issuer's backend API.
 *
 * ASSUMPTION (NOT CONFIRMED – the real SIGMA Issuer schema was not provided):
 *   POST {ISSUER_API_BASE_URL}{ISSUER_EXTERNAL_OFFER_PATH}            (default path: /credential-offers)
 *   Authorization: Bearer <token>            (ISSUER_EXTERNAL_AUTH=bearer | client_credentials | none)
 *   Body : { "credential_configuration_id": "...", "claims": { ... } }
 *   Reply: JSON containing ONE of
 *            "credential_offer_uri": "https://…"           (field name configurable: ISSUER_EXTERNAL_RESPONSE_URI_FIELD)
 *            "credential_offer":     { …OID4VCI offer object… }
 *            "deeplink":             "openid-credential-offer://…"
 *          and optionally "tx_code": "1234", "expires_in": 600.
 * If the real API differs, change ONLY this file (buildRequest / parseResponse).
 */
import type { AppConfig, AttestationConfig } from '../config.js';
import { log } from '../logger.js';
import type { Claims } from '../sdjwt/index.js';
import { deeplinkForOfferObject, deeplinkForOfferUri } from './offer.js';

export interface ExternalOffer {
  deeplink: string;
  txCode: string | undefined;
  expiresAt: Date;
}

let cachedToken: { value: string; exp: number } | undefined;

async function accessToken(cfg: AppConfig['issuer']['external'], fetchImpl: typeof fetch): Promise<string | undefined> {
  if (cfg.authMode === 'none') return undefined;
  if (cfg.authMode === 'bearer') {
    if (!cfg.apiToken) throw new Error('ISSUER_API_TOKEN is required for ISSUER_EXTERNAL_AUTH=bearer');
    return cfg.apiToken;
  }
  if (cachedToken && cachedToken.exp > Date.now() + 10_000) return cachedToken.value;
  if (!cfg.tokenUrl || !cfg.clientId || !cfg.clientSecret) throw new Error('ISSUER_EXTERNAL_TOKEN_URL, ISSUER_CLIENT_ID and ISSUER_CLIENT_SECRET are required for client_credentials');
  const res = await fetchImpl(cfg.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64')}` },
    body: 'grant_type=client_credentials',
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Issuer token endpoint answered ${res.status}`);
  const json = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!json.access_token) throw new Error('Issuer token endpoint returned no access_token');
  cachedToken = { value: json.access_token, exp: Date.now() + (json.expires_in ?? 300) * 1000 };
  return cachedToken.value;
}

export function buildRequest(attestation: AttestationConfig, claims: Claims): unknown {
  return { credential_configuration_id: attestation.credentialConfigurationId, claims };
}

export function parseResponse(json: Record<string, unknown>, uriField: string): ExternalOffer {
  let deeplink: string | undefined;
  const uri = json[uriField];
  if (typeof json.deeplink === 'string') deeplink = json.deeplink;
  else if (typeof uri === 'string') deeplink = uri.startsWith('http') ? deeplinkForOfferUri(uri) : uri;
  else if (json.credential_offer && typeof json.credential_offer === 'object') deeplink = deeplinkForOfferObject(json.credential_offer);
  if (!deeplink) throw new Error('Issuer reply contains no credential offer');
  const ttl = typeof json.expires_in === 'number' ? json.expires_in : 600;
  return { deeplink, txCode: typeof json.tx_code === 'string' ? json.tx_code : undefined, expiresAt: new Date(Date.now() + ttl * 1000) };
}

export async function createExternalOffer(cfg: AppConfig, attestation: AttestationConfig, claims: Claims, fetchImpl: typeof fetch = fetch): Promise<ExternalOffer> {
  const ext = cfg.issuer.external;
  if (!ext.apiBaseUrl) throw new Error('ISSUER_API_BASE_URL is not configured');
  const token = await accessToken(ext, fetchImpl);
  const res = await fetchImpl(`${ext.apiBaseUrl}${ext.offerPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(buildRequest(attestation, claims)),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    log.error('external issuer error', { status: res.status, attestation: attestation.key });
    throw new Error(`Issuer API answered ${res.status}`);
  }
  return parseResponse((await res.json()) as Record<string, unknown>, ext.responseUriField);
}

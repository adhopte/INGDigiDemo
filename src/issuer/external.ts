/**
 * EXTERNAL ISSUER ADAPTER for the SIGMA OID4VCI issuer ("oid-vci-adapter" offer API, as used by the WalletTester portal).
 *
 *   POST {ISSUER_API_BASE_URL}/offer            (no authentication on the preprod issuer; bearer / client_credentials supported if added)
 *   Body : { "identifier": "<user id in the issuer's system of record>",
 *            "businessId": "<uuid>",
 *            "walletIdentifier": "<optional wallet id>",
 *            "authorization_details": [{ "type": "openid_credential",
 *                                         "credential_configuration_id": "<id from the issuer metadata>",
 *                                         "credential_identifiers": ["<optional credential id>"] }] }
 *   Reply: { "uri": "openid-credential-offer://?credential_offer=…",      (pre-authorised code offer, by value)
 *            "qr_code": "<base64 JPEG>", "tx_code": "123456", "authorization_code": "<pre-authorised code>" }
 *
 * The claim VALUES are not part of the request: the issuer resolves them from its own system of record for `identifier`.
 * Offer creation does not validate the identifier; an unknown one fails later, when the wallet fetches the credential.
 */
import { randomUUID } from 'node:crypto';
import type { AppConfig, AttestationConfig } from '../config.js';
import { log } from '../logger.js';
import { deeplinkForOfferObject, deeplinkForOfferUri } from './offer.js';

export interface ExternalOffer {
  deeplink: string;
  txCode: string | undefined;
  /** The pre-authorised code (also inside the deeplink), shown on the issuer portal like the WalletTester does. */
  authorizationCode?: string;
  expiresAt: Date;
}

/** Which record of the external issuer's system of record to issue. */
export interface ExternalOfferOptions {
  identifier?: string;
  credentialIdentifier?: string;
  walletIdentifier?: string;
  /** Use this credential configuration of the external issuer instead of the attestation's default (e.g. the IdP-login PID). */
  configurationId?: string;
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

export function buildRequest(attestation: AttestationConfig, opts: ExternalOfferOptions = {}, businessId: string = randomUUID()) {
  const user = attestation.externalUsers.find((u) => u.identifier === opts.identifier) ?? (opts.identifier ? undefined : attestation.externalUsers[0]);
  const identifier = opts.identifier ?? user?.identifier;
  if (!identifier) throw new Error(`No identifier for the external issuer: configure attestations.${attestation.key}.externalUsers or pass one`);
  const credentialIdentifier = opts.credentialIdentifier ?? user?.credentialIdentifier;
  const walletIdentifier = opts.walletIdentifier ?? user?.walletIdentifier;
  return {
    identifier,
    businessId,
    ...(walletIdentifier ? { walletIdentifier } : {}),
    authorization_details: [
      {
        type: 'openid_credential',
        credential_configuration_id: opts.configurationId ?? user?.configurationId ?? attestation.externalConfigurationId ?? attestation.credentialConfigurationId,
        ...(credentialIdentifier ? { credential_identifiers: [credentialIdentifier] } : {}),
      },
    ],
  };
}

export function parseResponse(json: Record<string, unknown>): ExternalOffer {
  let deeplink: string | undefined;
  const uri = json.uri ?? json.credential_offer_uri;
  if (typeof uri === 'string') deeplink = /^https?:/.test(uri) ? deeplinkForOfferUri(uri) : uri;
  else if (json.credential_offer && typeof json.credential_offer === 'object') deeplink = deeplinkForOfferObject(json.credential_offer);
  if (!deeplink) throw new Error('Issuer reply contains no credential offer');
  const ttl = typeof json.expires_in === 'number' ? json.expires_in : 600; // not reported by the issuer: assume 10 minutes
  const tx = json.tx_code;
  const ac = json.authorization_code;
  return { deeplink, txCode: typeof tx === 'string' || typeof tx === 'number' ? String(tx) : undefined, ...(typeof ac === 'string' ? { authorizationCode: ac } : {}), expiresAt: new Date(Date.now() + ttl * 1000) };
}

export async function createExternalOffer(cfg: AppConfig, attestation: AttestationConfig, opts: ExternalOfferOptions = {}, fetchImpl: typeof fetch = fetch): Promise<ExternalOffer> {
  const ext = cfg.issuer.external;
  if (!ext.apiBaseUrl) throw new Error('ISSUER_API_BASE_URL is not configured');
  const token = await accessToken(ext, fetchImpl);
  const body = buildRequest(attestation, opts);
  const res = await fetchImpl(`${ext.apiBaseUrl}${ext.offerPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    log.error('external issuer error', { status: res.status, attestation: attestation.key });
    throw new Error(`Issuer API answered ${res.status}`);
  }
  return parseResponse((await res.json()) as Record<string, unknown>);
}

import type { AppConfig } from '../config.js';
import { log } from '../logger.js';
import type { Claims } from '../sdjwt/index.js';
import { createExternalOffer, type ExternalOfferOptions } from './external.js';
import type { RemoteIssuerMetadata } from './remote.js';
import type { LocalIssuer } from './local/service.js';
import { deeplinkForOfferObject, deeplinkForOfferUri, qrDataUrl, qrDataUrlOrUndefined } from './offer.js';

/** Vector QR (sharp at any size, smallest grid for the link) with the PNG as a fallback. */
const offerQr = async (text: string) => (await qrDataUrlOrUndefined(text)) ?? qrDataUrl(text);

export interface IssuedOffer {
  /** Local offer id (lets the simulated wallet redeem it); undefined for external issuers. */
  id: string | undefined;
  deeplink: string;
  qr: string;
  txCode: string | undefined;
  authorizationCode?: string;
  expiresAt: Date;
  provider: 'local' | 'external';
  /** External mode only: the external issuer does not offer this attestation, so the local demo issuer issued it. */
  fallback?: boolean;
}

export interface IssuerProvider {
  readonly mode: 'local' | 'external';
  /** `claims` are used by the local issuer; the external issuer resolves its data itself from `options.identifier`. */
  createOffer(attestationKey: string, claims: Claims, options?: ExternalOfferOptions): Promise<IssuedOffer>;
}

/** Selects the local demo issuer or the external Issuer purely from configuration (ISSUER_MODE). */
export function createIssuerProvider(cfg: AppConfig, local: LocalIssuer | undefined, fetchImpl: typeof fetch = fetch, remote?: RemoteIssuerMetadata): IssuerProvider {
  const localOffer = async (key: string, claims: Claims, fallback: boolean, format: 'sd-jwt' | 'mdoc' | 'both' = 'sd-jwt', mdocClaims?: Claims): Promise<IssuedOffer> => {
    if (!local) throw new Error('Local issuer not initialised');
    const o = local.createOffer(key, claims, format, mdocClaims);
    // By value (like the SIGMA issuer's offers): wallets that do not resolve credential_offer_uri still accept it.
    const obj = local.offerObject(o.id);
    const deeplink = obj ? deeplinkForOfferObject(obj) : deeplinkForOfferUri(o.offerUri);
    log.info('offer created', { provider: 'local', attestation: key, fallback });
    return { id: o.id, deeplink, qr: await offerQr(deeplink), txCode: o.txCode, expiresAt: o.expiresAt, provider: 'local', ...(fallback ? { fallback: true } : {}) };
  };

  if (cfg.issuer.mode === 'external') {
    return {
      mode: 'external',
      async createOffer(key, claims, options) {
        const att = cfg.attestations[key];
        if (!att) throw new Error(`Unknown attestation "${key}"`);
        // Use the external issuer's own configuration id (from its live metadata when reachable).
        const rc = remote ? await remote.configFor(att) : undefined;
        const configId = rc?.id ?? att.externalConfigurationId;
        const offeredRemotely = remote?.url ? !!rc || (!(await remote.summary())?.reachable && !!att.externalConfigurationId) : !!att.externalConfigurationId;
        if (!offeredRemotely && cfg.issuer.fallbackLocal && local) return localOffer(key, claims, true, options?.format, options?.mdocClaims);
        const o = await createExternalOffer(cfg, { ...att, externalConfigurationId: configId ?? att.externalConfigurationId }, options, fetchImpl);
        log.info('offer created', { provider: 'external', attestation: key, configuration: configId });
        return { id: undefined, deeplink: o.deeplink, qr: await offerQr(o.deeplink), txCode: o.txCode, ...(o.authorizationCode ? { authorizationCode: o.authorizationCode } : {}), expiresAt: o.expiresAt, provider: 'external' };
      },
    };
  }
  return { mode: 'local', createOffer: (key, claims, options) => localOffer(key, claims, false, options?.format, options?.mdocClaims) };
}

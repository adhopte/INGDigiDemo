import type { AppConfig } from '../config.js';
import { log } from '../logger.js';
import type { Claims } from '../sdjwt/index.js';
import { createExternalOffer } from './external.js';
import type { RemoteIssuerMetadata } from './remote.js';
import type { LocalIssuer } from './local/service.js';
import { deeplinkForOfferUri, qrDataUrl } from './offer.js';

export interface IssuedOffer {
  /** Local offer id (lets the simulated wallet redeem it); undefined for external issuers. */
  id: string | undefined;
  deeplink: string;
  qr: string;
  txCode: string | undefined;
  expiresAt: Date;
  provider: 'local' | 'external';
  /** External mode only: the external issuer does not offer this attestation, so the local demo issuer issued it. */
  fallback?: boolean;
}

export interface IssuerProvider {
  readonly mode: 'local' | 'external';
  createOffer(attestationKey: string, claims: Claims): Promise<IssuedOffer>;
}

/** Selects the local demo issuer or the external Issuer purely from configuration (ISSUER_MODE). */
export function createIssuerProvider(cfg: AppConfig, local: LocalIssuer | undefined, fetchImpl: typeof fetch = fetch, remote?: RemoteIssuerMetadata): IssuerProvider {
  const localOffer = async (key: string, claims: Claims, fallback: boolean): Promise<IssuedOffer> => {
    if (!local) throw new Error('Local issuer not initialised');
    const o = local.createOffer(key, claims);
    const deeplink = deeplinkForOfferUri(o.offerUri);
    log.info('offer created', { provider: 'local', attestation: key, fallback });
    return { id: o.id, deeplink, qr: await qrDataUrl(deeplink), txCode: o.txCode, expiresAt: o.expiresAt, provider: 'local', ...(fallback ? { fallback: true } : {}) };
  };

  if (cfg.issuer.mode === 'external') {
    return {
      mode: 'external',
      async createOffer(key, claims) {
        const att = cfg.attestations[key];
        if (!att) throw new Error(`Unknown attestation "${key}"`);
        // Use the external issuer's own configuration id (from its live metadata when reachable).
        const rc = remote ? await remote.configFor(att) : undefined;
        const configId = rc?.id ?? att.externalConfigurationId;
        const offeredRemotely = remote?.url ? !!rc || (!(await remote.summary())?.reachable && !!att.externalConfigurationId) : !!att.externalConfigurationId;
        if (!offeredRemotely && cfg.issuer.fallbackLocal && local) return localOffer(key, claims, true);
        const o = await createExternalOffer(cfg, { ...att, credentialConfigurationId: configId ?? att.credentialConfigurationId }, claims, fetchImpl);
        log.info('offer created', { provider: 'external', attestation: key, configuration: configId });
        return { id: undefined, deeplink: o.deeplink, qr: await qrDataUrl(o.deeplink), txCode: o.txCode, expiresAt: o.expiresAt, provider: 'external' };
      },
    };
  }
  return { mode: 'local', createOffer: (key, claims) => localOffer(key, claims, false) };
}

import type { AppConfig } from '../config.js';
import { log } from '../logger.js';
import type { Claims } from '../sdjwt/index.js';
import { createExternalOffer } from './external.js';
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
}

export interface IssuerProvider {
  readonly mode: 'local' | 'external';
  createOffer(attestationKey: string, claims: Claims): Promise<IssuedOffer>;
}

/** Selects the local demo issuer or the external Issuer purely from configuration (ISSUER_MODE). */
export function createIssuerProvider(cfg: AppConfig, local: LocalIssuer | undefined, fetchImpl: typeof fetch = fetch): IssuerProvider {
  if (cfg.issuer.mode === 'external') {
    return {
      mode: 'external',
      async createOffer(key, claims) {
        const att = cfg.attestations[key];
        if (!att) throw new Error(`Unknown attestation "${key}"`);
        const o = await createExternalOffer(cfg, att, claims, fetchImpl);
        log.info('offer created', { provider: 'external', attestation: key });
        return { id: undefined, deeplink: o.deeplink, qr: await qrDataUrl(o.deeplink), txCode: o.txCode, expiresAt: o.expiresAt, provider: 'external' };
      },
    };
  }
  if (!local) throw new Error('Local issuer not initialised');
  return {
    mode: 'local',
    async createOffer(key, claims) {
      const o = local.createOffer(key, claims);
      const deeplink = deeplinkForOfferUri(o.offerUri);
      log.info('offer created', { provider: 'local', attestation: key });
      return { id: o.id, deeplink, qr: await qrDataUrl(deeplink), txCode: o.txCode, expiresAt: o.expiresAt, provider: 'local' };
    },
  };
}

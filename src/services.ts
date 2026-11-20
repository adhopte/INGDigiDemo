import type { AppConfig } from './config.js';
import { createIssuerProvider, type IssuerProvider } from './issuer/provider.js';
import { RemoteIssuerMetadata } from './issuer/remote.js';
import { loadOrGenerateKey } from './issuer/local/keys.js';
import { LocalIssuer } from './issuer/local/service.js';
import { log } from './logger.js';
import { createVerifierIdentity } from './verifier/identity.js';
import { Verifier } from './verifier/service.js';
import { createIssuerKeyResolver } from './verifier/trust.js';

export interface Services {
  /** The local OpenID4VCI issuer. Always built: even with ISSUER_MODE=external it stays the trusted source for demo PIDs. */
  local: LocalIssuer;
  issuer: IssuerProvider;
  verifier: Verifier;
  /** Live metadata of the external issuer (undefined when no metadata URL is configured). */
  remote: RemoteIssuerMetadata | undefined;
  /** HTTP client used for all outbound calls (injectable in tests). */
  fetchImpl: typeof fetch;
}

export async function createServices(cfg: AppConfig, fetchImpl: typeof fetch = fetch): Promise<Services> {
  const keys = await loadOrGenerateKey(cfg.issuer.signingKeyJwk);
  if (keys.ephemeral) log.warn('Local issuer uses an ephemeral signing key (regenerated on restart); set ISSUER_SIGNING_KEY_JWK to keep issued credentials valid across restarts');
  const local = await new LocalIssuer(cfg, keys).init();
  const remote = cfg.issuer.metadataUrl ? new RemoteIssuerMetadata(cfg, fetchImpl) : undefined;
  const issuer = createIssuerProvider(cfg, local, fetchImpl, remote);
  const identity = await createVerifierIdentity(cfg);
  const verifier = new Verifier(cfg, identity, createIssuerKeyResolver(cfg, local, fetchImpl));
  return { local, issuer, verifier, remote, fetchImpl };
}

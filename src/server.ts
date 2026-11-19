import 'dotenv/config';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { log } from './logger.js';
import { createServices } from './services.js';

const config = loadConfig();
const services = await createServices(config);
const app = createApp(config, services);

app.listen(config.port, () => {
  log.info('server started', {
    port: config.port,
    env: config.nodeEnv,
    mockMode: config.mockMode,
    issuerMode: config.issuer.mode,
    multiCredential: config.multiCredential,
    publicBaseUrl: config.publicBaseUrl,
    verifierClientId: services.verifier.identity.clientId,
    responseMode: config.verifier.responseMode,
    queryLanguage: config.verifier.queryLanguage,
    rps: config.rps.map((r) => r.id),
  });
  for (const [rp, r] of Object.entries(services.verifier.registrationReport()) as [string, any][]) {
    if (!r.configured) continue;
    if (!r.readable) log.warn('registration certificate is not usable', { rp, error: r.error });
    else log.info('registration certificate', { rp, name: r.name, subject: r.subject, sent: r.sent, expired: r.expired, warnings: r.warnings });
  }
  if (config.mockMode) log.warn('MOCK_MODE is ON: simulated wallet enabled; no real wallet is needed');
});

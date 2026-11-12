import 'dotenv/config';
import { loadConfig } from './config.js';
import { createApp } from './app.js';
import { log } from './logger.js';

const config = loadConfig();
const app = createApp(config);

app.listen(config.port, () => {
  log.info('server started', {
    port: config.port,
    env: config.nodeEnv,
    mockMode: config.mockMode,
    multiCredential: config.multiCredential,
    publicBaseUrl: config.publicBaseUrl,
    rps: config.rps.map((r) => r.id),
  });
  if (config.mockMode) log.warn('MOCK_MODE is ON: no real wallet or Issuer calls are made');
});

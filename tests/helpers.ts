import { loadConfig, type AppConfig } from '../src/config.js';

export function testConfig(env: Record<string, string> = {}): AppConfig {
  return loadConfig({ NODE_ENV: 'test', MOCK_MODE: 'true', PUBLIC_BASE_URL: 'https://rp.example.test', ...env });
}

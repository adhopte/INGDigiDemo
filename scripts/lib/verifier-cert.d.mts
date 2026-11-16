export function x509HashClientId(cert: { rawData: ArrayBuffer }): string;
export function generateDemoPki(host: string, o?: { org?: string; days?: number }): Promise<{
  caPem: string; leafPem: string; chainPem: string;
  leaf: { rawData: ArrayBuffer }; ca: { rawData: ArrayBuffer };
  keyJwk: Record<string, unknown>;
  env: { VERIFIER_SIGNING_KEY_JWK: string; VERIFIER_CERT_CHAIN_PEM: string };
  clientIds: { x509_hash: string; x509_san_dns: string };
}>;
export function generateCsr(host: string, o?: { org?: string }): Promise<{ csrPem: string; keyJwk: Record<string, unknown>; keyEnv: string }>;

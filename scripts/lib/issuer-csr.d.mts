export function generateIssuerCsr(issuerUrl: string, o?: { org?: string }): Promise<{
  host: string; issuerUrl: string; org: string; kid: string; csrPem: string; keyEnv: string; publicKeySha256: string;
}>;
export function requestText(r: { host: string; issuerUrl: string; org: string; publicKeySha256: string }): string;

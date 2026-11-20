export function generateIssuerCsr(issuerUrl: string, o?: { org?: string; subject?: string; ca?: string }): Promise<{
  host: string; issuerUrl: string; org: string; ca: string; subject: string; kid: string; csrPem: string; keyEnv: string; publicKeySha256: string;
}>;
export function requestText(r: { host: string; issuerUrl: string; org: string; ca: string; subject: string; publicKeySha256: string }): string;

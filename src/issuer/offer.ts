import QRCode from 'qrcode';

export const deeplinkForOfferUri = (offerUri: string) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
export const deeplinkForOfferObject = (offer: unknown) => `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;

/** Like qrDataUrl, but lowers the error-correction level for long links and returns undefined when even that does not fit (link-only). */
export async function qrDataUrlOrUndefined(text: string): Promise<string | undefined> {
  // long payloads: start at the lowest error-correction level, which yields the smallest (most scannable) grid
  for (const level of (text.length > 900 ? ['L'] : ['M', 'L']) as ('M' | 'L')[]) {
    try {
      return await QRCode.toDataURL(text, { errorCorrectionLevel: level, margin: 4, width: 1000 });
    } catch { /* too long for this level */ }
  }
  return undefined;
}

/** PNG data URL (rendered inline, so no extra request and no CSP exception beyond img-src data:). */
export function qrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 4, width: 720, color: { dark: '#000000', light: '#ffffff' } });
}

import QRCode from 'qrcode';

export const deeplinkForOfferUri = (offerUri: string) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
export const deeplinkForOfferObject = (offer: unknown) => `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;

/** PNG data URL (rendered inline, so no extra request and no CSP exception beyond img-src data:). */
export function qrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 360, color: { dark: '#000000', light: '#ffffff' } });
}

import { createHash, X509Certificate } from 'node:crypto';
import express, { Router, type Request, type Response } from 'express';
import { log } from '../logger.js';
import { VpError, type Verifier } from './service.js';

/** OpenID4VP endpoints the WALLET calls: request object (request_uri) and response_uri. */
export function vpRouter(verifier: Verifier, diagnosticsEnabled = false): Router {
  const r = Router();
  r.use(express.urlencoded({ extended: false, limit: '512kb' }));
  r.use(express.json({ limit: '512kb' }));
  r.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  const requestObject = async (req: Request, res: Response) => {
    const tx = verifier.get(String(req.params.id));
    if (!tx || tx.status !== 'pending') return void res.status(404).json({ error: 'invalid_request_uri', error_description: 'Unknown or expired request' });
    if (verifier.byValue) return void res.status(404).json({ error: 'invalid_request_uri', error_description: 'Request is passed by value' });
    const walletNonce = typeof req.body?.wallet_nonce === 'string' ? req.body.wallet_nonce : undefined; // request_uri_method=post
    // What the wallet says it supports (helps diagnose NoMatchingDocuments-style failures). No personal data in there.
    let wm: Record<string, unknown> | undefined;
    try {
      wm = typeof req.body?.wallet_metadata === 'string' ? JSON.parse(req.body.wallet_metadata) : req.body?.wallet_metadata;
    } catch { /* ignore */ }
    verifier.record({ event: 'wallet_fetched_request', rp: tx.rpId, presentation: tx.presentationKey, method: req.method, userAgent: String(req.headers['user-agent'] ?? '').slice(0, 160), walletMetadata: wm ? JSON.stringify(wm).slice(0, 1500) : undefined });
    log.info('wallet fetched request', { rp: tx.rpId, method: req.method, userAgent: String(req.headers['user-agent'] ?? '').slice(0, 120), walletFormats: wm?.vp_formats_supported ? JSON.stringify(wm.vp_formats_supported).slice(0, 400) : undefined, walletResponseModes: wm?.response_modes_supported, walletClientIdPrefixes: wm?.client_id_prefixes_supported ?? wm?.client_id_schemes_supported });
    res.type('application/oauth-authz-req+jwt').send(await verifier.signedRequestObject(tx, walletNonce));
  };
  /** Public: the certificate requests are signed with, so a wallet / trust-list operator knows what to trust. */
  r.get('/verifier', (_req, res) => {
    const id = verifier.identity;
    const leafDer = id.x5c[0] ? Buffer.from(id.x5c[0], 'base64') : undefined;
    const cert = leafDer ? new X509Certificate(leafDer) : undefined;
    const pemOf = (b64: string) => `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----\n`;
    res.json({
      client_id_scheme: verifier.byValue ? 'redirect_uri' : id.clientId.split(':')[0],
      client_id: verifier.byValue ? 'redirect_uri:<response_uri of each request>' : id.clientId,
      x509_hash_client_id: leafDer ? `x509_hash:${createHash('sha256').update(leafDer).digest('base64url')}` : undefined,
      x509_san_dns_client_id: `x509_san_dns:${id.hostname}`,
      self_signed_ephemeral: id.ephemeral,
      subject: cert?.subject.replace(/\n/g, ', '),
      issuer: cert?.issuer.replace(/\n/g, ', '),
      valid_from: cert?.validFrom,
      valid_to: cert?.validTo,
      chain_pem: id.x5c.map(pemOf),
      note: id.ephemeral ? 'Self-signed demo certificate regenerated at every start: no wallet will trust it. Configure VERIFIER_SIGNING_KEY_JWK and VERIFIER_CERT_CHAIN_PEM (npm run gen:verifier-cert).' : undefined,
    });
  });
  if (diagnosticsEnabled) r.get('/diagnostics', (_req, res) => void res.json({ note: 'Recent verifier events. No claim values or tokens.', events: verifier.diagnostics() }));
  r.get('/request/:id', requestObject);
  r.post('/request/:id', requestObject);

  r.post('/response/:id', async (req, res) => {
    try {
      res.json(await verifier.handleResponse(String(req.params.id), (req.body ?? {}) as Record<string, unknown>));
    } catch (e) {
      if (e instanceof VpError) return void res.status(e.status).json({ error: e.error, error_description: e.message });
      log.error('vp response failed', { error: e instanceof Error ? e.message : String(e) });
      res.status(500).json({ error: 'server_error' });
    }
  });
  return r;
}

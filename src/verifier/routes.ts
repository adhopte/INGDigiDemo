import express, { Router, type Request, type Response } from 'express';
import { log } from '../logger.js';
import { VpError, type Verifier } from './service.js';

/** OpenID4VP endpoints the WALLET calls: request object (request_uri) and response_uri. */
export function vpRouter(verifier: Verifier): Router {
  const r = Router();
  r.use(express.urlencoded({ extended: false, limit: '512kb' }));
  r.use(express.json({ limit: '512kb' }));
  r.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  const requestObject = async (req: Request, res: Response) => {
    const tx = verifier.get(String(req.params.id));
    if (!tx || tx.status !== 'pending') return void res.status(404).json({ error: 'invalid_request_uri', error_description: 'Unknown or expired request' });
    if (verifier.identity.clientId.startsWith('redirect_uri:')) return void res.status(404).json({ error: 'invalid_request_uri', error_description: 'Request is passed by value' });
    const walletNonce = typeof req.body?.wallet_nonce === 'string' ? req.body.wallet_nonce : undefined; // request_uri_method=post
    // What the wallet says it supports (helps diagnose NoMatchingDocuments-style failures). No personal data in there.
    let wm: Record<string, unknown> | undefined;
    try {
      wm = typeof req.body?.wallet_metadata === 'string' ? JSON.parse(req.body.wallet_metadata) : req.body?.wallet_metadata;
    } catch { /* ignore */ }
    log.info('wallet fetched request', { rp: tx.rpId, method: req.method, userAgent: String(req.headers['user-agent'] ?? '').slice(0, 120), walletFormats: wm?.vp_formats_supported ? JSON.stringify(wm.vp_formats_supported).slice(0, 400) : undefined, walletResponseModes: wm?.response_modes_supported, walletClientIdPrefixes: wm?.client_id_prefixes_supported ?? wm?.client_id_schemes_supported });
    res.type('application/oauth-authz-req+jwt').send(await verifier.signedRequestObject(tx, walletNonce));
  };
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

import { randomBytes } from 'node:crypto';
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { encryptCredentialResponse, readEncryptionParams } from './encryption.js';
import { IssuerError, type LocalIssuer } from './service.js';

const noStore = (res: Response) => res.set('Cache-Control', 'no-store');

/** OpenID4VCI endpoints. `main` is mounted at /issuer, `wellKnown` at the site root. */
export function issuerRouters(issuer: LocalIssuer, log?: (e: Record<string, unknown>) => void): { main: Router; wellKnown: Router } {
  const main = Router();
  const wellKnown = Router();

  main.use((req: Request, res: Response, next: NextFunction) => {
    res.set('Access-Control-Allow-Origin', '*').set('Access-Control-Allow-Headers', 'authorization, content-type, dpop');
    if (req.method === 'OPTIONS') return void res.sendStatus(204);
    next();
  });
  // Diagnostics: which OpenID4VCI calls the wallet really makes, and how each ended (no tokens, no claim values).
  const track = (req: Request, res: Response, next: NextFunction) => {
    const h = req.headers;
    res.on('finish', () => log?.({
      event: 'issuer_request', method: req.method, path: req.originalUrl.split('?')[0], status: res.statusCode,
      userAgent: String(h['user-agent'] ?? '').slice(0, 120),
      headers: ['authorization', 'dpop', 'oauth-client-attestation', 'oauth-client-attestation-pop', 'content-type'].filter((k) => h[k]),
      errorCode: res.locals.issuerError,
      ...(res.locals.issuerNote ? { note: res.locals.issuerNote } : {}),
    }));
    next();
  };
  if (log) {
    main.use(track);
    wellKnown.use('/.well-known', track);
  }
  main.use(express.json({ limit: '64kb' }));
  main.use(express.text({ type: 'application/jwt', limit: '64kb' })); // encrypted Credential Requests are compact JWEs
  main.use(express.urlencoded({ extended: false, limit: '64kb' })); // the token endpoint is application/x-www-form-urlencoded (RFC 6749)

  const asyncRoute = (fn: (req: Request, res: Response) => Promise<void> | void) => async (req: Request, res: Response, next: NextFunction) => {
    try {
      await fn(req, res);
    } catch (e) {
      if (e instanceof IssuerError) {
        res.locals.issuerError = `${e.error}: ${e.message}`.slice(0, 200);
        noStore(res).status(e.status).json({ error: e.error, error_description: e.message, ...e.extra });
        return;
      }
      next(e);
    }
  };

  const metadata = (_req: Request, res: Response) => void res.json(issuer.metadata());
  const asMetadata = (_req: Request, res: Response) => void res.json(issuer.authorizationServerMetadata());
  const vcIssuer = (_req: Request, res: Response) => void res.json(issuer.jwtVcIssuerMetadata());

  // Issuer identifier has a path (/issuer): RFC 8615 style well-known (inserted after the host) ...
  wellKnown.get('/.well-known/openid-credential-issuer/issuer', metadata);
  wellKnown.get('/.well-known/oauth-authorization-server/issuer', asMetadata);
  wellKnown.get('/.well-known/jwt-vc-issuer/issuer', vcIssuer);
  // ... and the appended form some wallets use.
  main.get('/.well-known/openid-credential-issuer', metadata);
  main.get('/.well-known/oauth-authorization-server', asMetadata);
  main.get('/.well-known/jwt-vc-issuer', vcIssuer);

  main.get('/offers/:id', (req, res) => {
    const offer = issuer.offerObject(String(req.params.id));
    if (!offer) return void noStore(res).status(404).json({ error: 'not_found' });
    noStore(res).json(offer);
  });

  main.post('/token', asyncRoute(async (req, res) => {
    noStore(res).json(await issuer.exchangePreAuthorizedCode(req.body ?? {}, typeof req.headers.dpop === 'string' ? req.headers.dpop : undefined));
  }));

  // like the SIGMA issuer, also offer a DPoP nonce in a header (wallets include it in later DPoP proofs; the issuer does not require it)
  main.post('/nonce', (_req, res) => void noStore(res).set('DPoP-Nonce', randomBytes(24).toString('base64url')).json({ c_nonce: issuer.newNonce(), c_nonce_expires_in: 300 }));

  main.post('/credential', asyncRoute(async (req, res) => {
    const m = /^(Bearer|DPoP)\s+(\S+)$/i.exec(req.headers.authorization ?? '');
    const refuse = (error: string, description: string) => {
      res.locals.issuerError = `${error}: ${description}`;
      return void noStore(res).status(400).json({ error, error_description: description });
    };
    // an encrypted Credential Request arrives as a compact JWE (application/jwt)
    let body: Record<string, unknown> = typeof req.body === 'object' && req.body ? req.body : {};
    if (typeof req.body === 'string') {
      if (!issuer.requestEncryption) return refuse('invalid_credential_request', 'This issuer does not accept encrypted requests');
      try {
        body = await issuer.requestEncryption.decrypt(req.body);
      } catch (e) {
        return refuse('invalid_credential_request', (e as Error).message);
      }
    }
    // validate the response-encryption request BEFORE issuing: a refused request must not consume the offer
    let enc;
    try {
      enc = await readEncryptionParams(body.credential_response_encryption);
    } catch (e) {
      return refuse('invalid_encryption_parameters', (e as Error).message);
    }
    const response = await issuer.issueCredential(m?.[2], body as Parameters<LocalIssuer['issueCredential']>[1], { ...(m?.[1] ? { scheme: m[1] } : {}), ...(typeof req.headers.dpop === 'string' ? { dpop: req.headers.dpop } : {}) });
    res.locals.issuerNote = `${response.credentials.length} credential(s) issued${enc ? ', response encrypted' : ''}`; // visible in /vp/diagnostics
    if (!enc) return void noStore(res).json(response);
    try {
      noStore(res).type('application/jwt').send(await encryptCredentialResponse(enc, response));
    } catch (e) {
      refuse('invalid_encryption_parameters', (e as Error).message);
    }
  }));

  return { main, wellKnown };
}

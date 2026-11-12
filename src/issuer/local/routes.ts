import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { IssuerError, type LocalIssuer } from './service.js';

const noStore = (res: Response) => res.set('Cache-Control', 'no-store');

/** OpenID4VCI endpoints. `main` is mounted at /issuer, `wellKnown` at the site root. */
export function issuerRouters(issuer: LocalIssuer): { main: Router; wellKnown: Router } {
  const main = Router();
  const wellKnown = Router();

  main.use((req: Request, res: Response, next: NextFunction) => {
    res.set('Access-Control-Allow-Origin', '*').set('Access-Control-Allow-Headers', 'authorization, content-type, dpop');
    if (req.method === 'OPTIONS') return void res.sendStatus(204);
    next();
  });
  main.use(express.json({ limit: '64kb' }));
  main.use(express.urlencoded({ extended: false, limit: '64kb' })); // the token endpoint is application/x-www-form-urlencoded (RFC 6749)

  const asyncRoute = (fn: (req: Request, res: Response) => Promise<void> | void) => async (req: Request, res: Response, next: NextFunction) => {
    try {
      await fn(req, res);
    } catch (e) {
      if (e instanceof IssuerError) {
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

  main.post('/token', asyncRoute((req, res) => {
    noStore(res).json(issuer.exchangePreAuthorizedCode(req.body ?? {}));
  }));

  main.post('/nonce', (_req, res) => void noStore(res).json({ c_nonce: issuer.newNonce(), c_nonce_expires_in: 300 }));

  main.post('/credential', asyncRoute(async (req, res) => {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '');
    noStore(res).json(await issuer.issueCredential(m?.[1], req.body ?? {}));
  }));

  return { main, wellKnown };
}

import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import helmet from 'helmet';
import MemoryStore from 'memorystore';
import path from 'node:path';
import { ROOT_DIR, type AppConfig } from './config.js';
import { i18nMiddleware } from './i18n/index.js';
import { issuerRouters } from './issuer/local/routes.js';
import { log } from './logger.js';
import { extrasRouter } from './routes/extras.js';
import { rpRouterFor } from './rps/index.js';
import type { Services } from './services.js';
import { vpRouter } from './verifier/routes.js';
import { VpError } from './verifier/service.js';
import './session.js';

export function createApp(cfg: AppConfig, svc: Services) {
  const app = express();
  const ctx = { cfg, svc };

  app.set('trust proxy', 1); // Render terminates TLS in front of the app
  app.set('view engine', 'ejs');
  app.set('views', path.join(ROOT_DIR, 'views'));
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"], // only /js/verify-poll.js (progressive enhancement); no inline scripts
          styleSrc: ["'self'"], // no inline styles anywhere
          imgSrc: ["'self'", 'data:'], // data: = inline QR codes
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: cfg.isProduction ? [] : null,
        },
      },
    }),
  );

  app.use(express.static(path.join(ROOT_DIR, 'public'), { maxAge: cfg.isProduction ? '1h' : 0 }));

  // Wallet-facing protocol endpoints: no browser session, no i18n.
  app.use('/vp', vpRouter(svc.verifier));
  const issuer = issuerRouters(svc.local);
  app.use(issuer.wellKnown);
  app.use('/issuer', issuer.main);

  app.get('/healthz', (_req, res) => void res.status(200).json({ status: 'ok' }));

  // ---- Browser-facing app ----
  const Store = MemoryStore(session);
  app.use(express.urlencoded({ extended: false }));
  app.use(
    session({
      name: 'rp_playground_sid',
      secret: cfg.sessionSecret,
      resave: false,
      saveUninitialized: false,
      store: new Store({ checkPeriod: 15 * 60 * 1000 }),
      cookie: { httpOnly: true, sameSite: 'lax', secure: cfg.isProduction, maxAge: 60 * 60 * 1000 },
    }),
  );
  app.use(i18nMiddleware(cfg.isProduction));
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.locals.brand = cfg.brand;
    res.locals.mockMode = cfg.mockMode;
    res.locals.issuerMode = cfg.issuer.mode;
    res.locals.multiCredential = cfg.multiCredential;
    res.locals.trustAny = cfg.verifier.trustAnyIssuer;
    res.locals.rps = cfg.rps;
    res.locals.rp = undefined;
    res.locals.skin = 'dashboard';
    res.locals.basePath = '';
    res.locals.flash = req.session.flash;
    if (req.session.flash) delete req.session.flash;
    next();
  });

  app.get('/', (_req, res) => res.render('dashboard', { title: res.locals.t('dash.title'), issuerUrl: cfg.issuer.localIssuerUrl }));
  app.use(extrasRouter(ctx));
  for (const rp of cfg.rps) app.use(`/${rp.id}`, rpRouterFor(ctx, rp));

  app.use((_req, res) => res.status(404).render('error', { title: res.locals.t('error.title'), message: res.locals.t('error.not_found'), retryHref: '/' }));

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    log.error('unhandled error', { path: req.path, error: err instanceof Error ? err.message : String(err) });
    if (res.headersSent) return;
    if (err instanceof VpError) {
      res.status(err.status === 503 ? 503 : 400).render('error', { title: res.locals.t('error.title'), message: res.locals.t('error.generic'), retryHref: '/' });
      return;
    }
    res.status(500).render('error', { title: res.locals.t?.('error.title') ?? 'Error', message: res.locals.t?.('error.generic') ?? 'Something went wrong.', retryHref: '/' });
  });

  return app;
}

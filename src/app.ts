import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import helmet from 'helmet';
import path from 'node:path';
import { ROOT_DIR, type AppConfig, type RpConfig } from './config.js';
import { log } from './logger.js';
import { rpRouter } from './rps/router.js';

declare module 'express-session' {
  interface SessionData {
    // Filled in by later steps (OIDC state, disclosed claims, etc.)
    [key: string]: unknown;
  }
}

export function createApp(config: AppConfig) {
  const app = express();

  app.set('trust proxy', 1); // Render terminates TLS in front of the app
  app.set('view engine', 'ejs');
  app.set('views', path.join(ROOT_DIR, 'views'));
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'], // data: for inline QR codes
          styleSrc: ["'self'", "'unsafe-inline'"], // per-RP theme colour is set via inline style
          formAction: ["'self'"], // OIDC starts via GET links/redirects, never a cross-origin form POST
          upgradeInsecureRequests: config.isProduction ? [] : null, // would break plain-http localhost
        },
      },
    }),
  );
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(ROOT_DIR, 'public')));

  app.use(
    session({
      name: 'sigma_demo_sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, sameSite: 'lax', secure: config.isProduction, maxAge: 30 * 60 * 1000 },
    }),
  );

  app.use((req: Request, res: Response, next: NextFunction) => {
    res.locals.mockMode = config.mockMode;
    res.locals.rps = config.rps;
    res.locals.rp = undefined;
    res.locals.themeColor = '#1d2433';
    res.locals.basePath = '';
    next();
  });

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/', (_req, res) => res.render('landing', { title: 'SIGMA EUDI Wallet – Demo Relying Parties' }));

  for (const rp of config.rps) app.use(`/${rp.id}`, rpRouter(config, rp));

  app.use((_req, res) => res.status(404).render('error', { title: 'Not found', message: 'Page not found.' }));

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    log.error('unhandled error', { path: req.path, error: err instanceof Error ? err.message : String(err) });
    res.status(500).render('error', { title: 'Error', message: 'Something went wrong.' });
  });

  return app;
}

export type { RpConfig };

# SIGMA EUDI Wallet – Demo Relying Parties

One Express app hosting four demo Relying Parties for the IN Groupe **SIGMA** EUDI Wallet platform:

| Path | RP | Use case |
|---|---|---|
| `/bank` | Demo Bank | PID onboarding (KYC) → account attestation; payment attestation download |
| `/eshop` | Demo eShop | Pay with a payment attestation |
| `/university` | Demo University | PID + Birth Certificate registration → diploma attestation |
| `/electricity` | Demo Power Co | PID → pre-filled contract subscription |

The RP never speaks OpenID4VP. It redirects to the SIGMA **Wallet Intermediary** (a standard OIDC provider, authorization code + PKCE), which shows the OID4VP QR/deeplink, verifies the presentation and returns an ID token with the disclosed claims. Credentials are issued via OpenID4VCI credential offers created through the SIGMA **Issuer** backend API.

> Status: implementation in progress (step 1 – scaffold). Sections below are completed as the steps land.

## Quick start (mock mode)

```bash
npm ci
cp .env.example .env      # MOCK_MODE=true by default
npm run dev               # http://localhost:3000
```

In mock mode a yellow banner is shown on every page, the OIDC redirect is replaced by a local "Simulated wallet" page and the Issuer is replaced by a fake `openid-credential-offer://` URI.

## Configuration

* `config/rps.json` – per-RP definition: id, display name, theme colour, OIDC `client_id`, name of the env var holding the client secret, presentations (`scope`, `acr_values`, expected claims) and issuable attestations (`credential_configuration_id`).
* Environment variables override the file (see `.env.example`). **Secrets are only ever read from env vars.**

## Scripts

| Script | Purpose |
|---|---|
| `npm run dev` | run with reload (tsx) |
| `npm run build` | compile TypeScript to `dist/` |
| `npm start` | `node dist/server.js` |
| `npm test` | vitest |

## Endpoints

* `GET /` landing page · `GET /healthz` health check (200)
* `GET /<rp>/auth/start?p=<presentation>&returnTo=/<rp>/…` starts a wallet presentation (PKCE S256 + state + nonce)
* `GET /<rp>/callback` OIDC redirect URI (`<PUBLIC_BASE_URL>/<rp>/callback`); validates and stores the disclosed claims in the session
* `GET /<rp>/mock-wallet` simulated wallet (MOCK_MODE only)

## OIDC integration (`src/oidc/`)

* `client.ts` – per-RP openid-client `Configuration` via discovery on `INTERMEDIARY_ISSUER_URL` (client secret read from the env var named in `rps.json`; `OIDC_CLIENT_AUTH=basic|post`).
* `flow.ts` – `beginAuth` / `completeAuth`. State is single-use and kept in the session; the callback URL is rebuilt from `PUBLIC_BASE_URL` so it matches the registered redirect URI behind Render's proxy. `exchangeAndValidate` delegates signature/`iss`/`aud`/`exp`/`nonce`/PKCE/`state` checks to openid-client. `returnTo` is restricted to the RP's own paths. Only claim *names* are logged.

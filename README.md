# IN Groupe – EU Wallet Relying Party Playground

A demo dashboard with four relying parties (RPs) for the **IN Groupe SIGMA** EU Digital Identity Wallet implementation, plus a built-in **OpenID4VCI issuer**. Everything speaks the real wallet protocols directly:

| Role | Protocol | Where |
|---|---|---|
| Verifier (all four RPs) | **OpenID4VP** – signed request object (JAR), DCQL or Presentation Exchange, `direct_post` / `direct_post.jwt`, SD-JWT VC with key binding | `src/verifier/` |
| Issuer (local demo issuer) | **OpenID4VCI** – credential offer, pre-authorised code (optional `tx_code`), nonce-bound JWT proof, SD-JWT VC (`dc+sd-jwt`, ES256) | `src/issuer/local/` |
| Issuer (external) | adapter to your Issuer backend, chosen by configuration | `src/issuer/external.ts` |

| Path | Site | What it does |
|---|---|---|
| `/` | **EU Wallet Demo Dashboard** (IN Groupe branding) | entry point, mode indicators, links |
| `/bank` | **Demo Bank** (typical European bank look) | KYC with any PID → account opened and signed in → download **account attestation** and **payment attestation** (QR or deeplink) |
| `/eshop` | **Demo eShop** (generic e-commerce, standalone) | cart → "Pay with EU Wallet" → verifies the **payment attestation** issued by the bank → order confirmation. Age proof shown as "Coming soon". |
| `/university` | **Demo University** | requires **PID + birth certificate** (one combined request with `MULTI_CREDENTIAL=true`, else two in a row), cross-checks both describe the same person, pre-filled enrolment form → student number |
| `/electricity` | **Demo Power Co** | PID → access to the customer account |
| `/demo-issuer` | Demo issuer console | create credential offers for a **demo PID** / **birth certificate** for a real wallet |

Languages: **English, Français, Español, Nederlands, Deutsch, Dansk, Malti, Svenska** (switcher on every page, `?lang=xx`, cookie, `Accept-Language`).
Responsive (phone → desktop), WCAG 2.2 A/AA oriented, no inline scripts/styles (strict CSP).

> **Demo only.** Fictitious data. The local issuer's credentials are not real PIDs and must never be accepted by production services.

## How it fits together

```
 Browser ── / /bank /eshop /university /electricity ──► RP pages (Express + EJS)
    │                                                    │ create transaction
    │  QR / openid4vp:// deeplink                        ▼
    ▼                                         ┌────────────────────────┐
 EU Wallet ── GET|POST /vp/request/:id ─────► │ Verifier (OpenID4VP)    │  signed request object (x5c),
    │      ◄── JWT (DCQL, nonce, response_uri) │                         │  DCQL / PEX, client_metadata
    └──── POST /vp/response/:id (vp_token) ──► │ verify SD-JWT VC + KB   │  issuer trust, nonce, aud, sd_hash
                                               └────────────────────────┘
 EU Wallet ── GET /issuer/offers/:id, POST /issuer/token, /nonce, /credential ──► Local OpenID4VCI issuer
            (credential_offer_uri from the QR / openid-credential-offer:// deeplink)
```

*Mock mode* adds a **simulated wallet** (clearly flagged, yellow banner on every page). It is not a mock of the protocol: it redeems offers through the real issuer code, stores real SD-JWT credentials with a holder key, and builds real selective-disclosure presentations with key-binding JWTs that go through the same verifier code as a real wallet's response.

## Quick start

```bash
npm ci
cp .env.example .env      # MOCK_MODE=true: works without any wallet
npm run dev               # http://localhost:3000
```

Walk-through in mock mode (all in one browser, so the simulated wallet carries credentials from one site to the next):

1. **Bank** → "Open an account / Sign in" → "Open the simulated wallet" → *Add demo PID* → *Approve and share* → KYC result → account.
2. On the account page: **Get account attestation**, then **Get payment attestation** → *Receive in simulated wallet*.
3. **eShop** → add products → *Pay with EU Wallet* → simulated wallet → *Approve*: the payment attestation the bank just issued is verified.
4. **University** → *Start enrolment* → present PID, then birth certificate (add a demo one) → enrolment form.
5. **Power Co** → *Sign in with EU Wallet* → account access.

### Using a real wallet

1. Make the app reachable over **public HTTPS** (deploy to Render, or run a tunnel locally) and set `PUBLIC_BASE_URL`.
2. `MOCK_MODE=false`.
3. **Verifier identity** – wallets validate the request object's certificate. Set `VERIFIER_SIGNING_KEY_JWK` (`npm run keygen`) and `VERIFIER_CERT_CHAIN_PEM` (certificate whose SAN dNSName is your host, chained to a root the wallet trusts). Without them a self-signed demo certificate is generated at startup – fine only for wallets configured to trust it.
4. **Trust the PID issuer** – `TRUSTED_ISSUERS=<IN Groupe Issuer URL>` (its keys are read from `<iss>/.well-known/jwt-vc-issuer`) and/or `TRUSTED_CA_PEM` for credentials that carry an `x5c` chain. The local demo issuer is always trusted.
5. Get test credentials: PID from the IN Groupe Issuer (or a demo PID from `/demo-issuer`), birth certificate from `/demo-issuer`, bank attestations from the bank page.

**Benin PID rulebook.** Claim names, `vct` and docTypes follow the *Benin PID / Birth Certificate Rulebook v2.0* (standard EUDI namespace): PID SD-JWT `vct` `https://credentials.benin.example/pid`, mdoc docType/namespace `eu.europa.ec.eudi.pid.1`; birth certificate `vct` `https://credentials.benin.example/birth-certificate`, mdoc `eu.europa.ec.eudi.birth_certificate.1`; claims `family_name`, `given_name`, `birth_date`, `birth_place`, `birth_country`, `nationality`, `resident_address`, … (see `config/rps.json`). The sensitive `personal_administrative_number` and the portrait are never requested. SD-JWT PIDs that use the older EU names (`birthdate`, `nationalities`, `address`, `place_of_birth`) are mapped to these names.

**HAIP wallets.** The defaults follow the OpenID4VC High Assurance Interoperability Profile: DCQL, signed request object with `x509_hash` client identifier, and an **encrypted** response (`direct_post.jwt`, ECDH-ES, A128GCM or A256GCM). A wallet that reports *"HAIP profile requires an encrypted response mode"* was talking to an older build with `direct_post`. The DC API (`dc_api`) transport is not implemented (redirect/QR/deeplink only). If the wallet shows *"Unknown relying party"*, the verifier certificate is not known to it: register it (see the verifier identity above) – a self-signed demo certificate is never recognised by a production wallet.

> Interoperability with real wallets could not be tested in the build environment. The protocol layers are covered by automated tests that act as a wallet over HTTP, but expect some per-wallet tuning of `VP_RESPONSE_MODE`, `VP_QUERY_LANGUAGE`, `VP_CLIENT_ID_SCHEME` and `VP_DEEPLINK_BASE`.

## Configuration

Everything is configured with environment variables (see `.env.example`); credential-related defaults live in `config/rps.json`. Secrets are only ever read from the environment.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | injected by Render |
| `PUBLIC_BASE_URL` | `RENDER_EXTERNAL_URL`, else `http://localhost:PORT` | base for all wallet-facing URLs |
| `SESSION_SECRET` | – | required in production |
| `MOCK_MODE` | `false` | simulated wallet on/off |
| `MULTI_CREDENTIAL` | `false` | university: one combined request vs two |
| `VP_CLIENT_ID_SCHEME` | `x509_hash` | or `x509_san_dns`, `redirect_uri` (unsigned, by value) |
| `VP_RESPONSE_MODE` | `direct_post.jwt` | encrypted response (HAIP); or `direct_post` |
| `VP_QUERY_LANGUAGE` | `dcql` | or `pex` |
| `VP_DEEPLINK_BASE` | `openid4vp://authorize` | wallet invocation scheme |
| `TRUSTED_ISSUERS`, `TRUSTED_CA_PEM` | empty | who may issue credentials accepted by the verifier |
| `VERIFIER_SIGNING_KEY_JWK`, `VERIFIER_CERT_CHAIN_PEM` | generated | verifier identity (secrets) |
| `ISSUER_MODE` | `local` | `local` or `external` |
| `ISSUER_SIGNING_KEY_JWK` | ephemeral | local issuer key (secret) |
| `ISSUER_TX_CODE` | `false` | local issuer: require a 4-digit transaction code |
| `ISSUER_API_BASE_URL`, `ISSUER_EXTERNAL_*`, `ISSUER_API_TOKEN`, `ISSUER_CLIENT_ID`, `ISSUER_CLIENT_SECRET` | – | external issuer |
| `ATTESTATION_<KEY>_CONFIG_ID` / `_VCT` / `_ACCEPTED_VCT` | from `rps.json` | `KEY` = `PID`, `ACCOUNT`, `PAYMENT`, `BIRTH_CERTIFICATE` |
| `RP_<ID>_THEME_COLOR`, `BRAND_PRIMARY`, `BRAND_ACCENT` | from config | styling |

`config/rps.json` defines, per RP, which credential types and claims it requests (`presentations`) and what it can issue (`attestations`), plus the attestation catalogue (`credentialConfigurationId`, `vct`, claims).

### Local issuer (OpenID4VCI)

Issuer identifier `<PUBLIC_BASE_URL>/issuer`.

| Endpoint | |
|---|---|
| `/.well-known/openid-credential-issuer/issuer` (also `/issuer/.well-known/…`) | credential issuer metadata (display names in all 8 languages) |
| `/.well-known/oauth-authorization-server/issuer` | authorization server metadata (pre-authorised grant, anonymous) |
| `/.well-known/jwt-vc-issuer/issuer` | signing keys (JWKS) for verifiers |
| `GET /issuer/offers/:id` | credential offer (`credential_offer_uri` target) |
| `POST /issuer/token` | `urn:ietf:params:oauth:grant-type:pre-authorized_code` (+ `tx_code`) |
| `POST /issuer/nonce` | fresh `c_nonce` |
| `POST /issuer/credential` | accepts `proofs.jwt[]` (1.0) or `proof.jwt` (drafts); returns `credentials[0].credential` and `credential` |

Credential configurations: `demo_pid`, `demo_bank_account`, `demo_bank_payment`, `demo_birth_certificate`. Offers expire after 10 minutes, are single-use, and `tx_code` is limited to 5 attempts. Signing key: set `ISSUER_SIGNING_KEY_JWK`, otherwise credentials stop verifying after a restart.

### External issuer

`ISSUER_MODE=external` sends offer creation to your Issuer through **one module, `src/issuer/external.ts`**.

> ⚠️ **The request/response schema there is an assumption** (`POST {ISSUER_API_BASE_URL}{ISSUER_EXTERNAL_OFFER_PATH}` with `{credential_configuration_id, claims}`; reply containing `credential_offer_uri`, `credential_offer` or `deeplink`). It must be aligned with the real SIGMA Issuer API. Only `buildRequest` and `parseResponse` need to change. Auth: `none`, `bearer` or `client_credentials`.

The bank page then uses the external issuer for the account and payment attestations; the `/demo-issuer` console always uses the local one.

### Verifier behaviour

* Request object signed with an X.509 chain (`x509_san_dns:<host>`), `request_uri` (GET and POST with `wallet_nonce`), or unsigned by value (`redirect_uri:` scheme).
* `direct_post.jwt`: a per-request ECDH-ES P-256 key is published in `client_metadata.jwks`; responses are decrypted (A128GCM). Plain responses are refused in this mode.
* Per presentation the verifier checks: issuer signature (local key, `x5c` chain to `TRUSTED_CA_PEM`, or JWKS of a `TRUSTED_ISSUERS` entry), validity window, accepted `vct`, disclosure digests (no forged, duplicate or unreferenced disclosures), mandatory key binding (`cnf.jwk`, `kb+jwt`, `aud`, `nonce`, freshness, `sd_hash`), `state`, single use. Only requested claims are kept (data minimisation).
* **PID formats:** the PID is requested as `dc+sd-jwt` **or** `mso_mdoc` (alternatives in DCQL `credential_sets`; `ATTESTATION_PID_FORMATS` to restrict). mdoc verification covers the issuer signature and `x5chain`, element digests against the MSO, validity, and the device signature over the OpenID4VP `SessionTranscript` (1.0 handover; with and without the `client_id` prefix and the encryption-key thumbprint). The request asks for the full claim set but accepts the minimum (`given_name`, `family_name`, `birthdate`) via DCQL `claim_sets`, so a PID lacking e.g. an address still matches. Accepted SD-JWT `vct` values default to `urn:eudi:pid:1` and `urn:eu.europa.ec.eudi:pid:1` (`ATTESTATION_PID_ACCEPTED_VCT`, `*` = any).
* **Trust:** `TRUST_ANY_ISSUER=true` (demo) accepts any issuer after checking the signature against the credential's own key/certificate; the dashboard shows a warning chip. For anything stricter use `TRUSTED_CA_PEM` / `TRUSTED_ISSUERS`.
* **Diagnostics:** `GET /vp/diagnostics` (on by default, `DIAGNOSTICS_ENDPOINT=false` to disable; shows no claim values or tokens) lists recent events, including what the wallet reports about itself. The server also logs what the wallet reports about itself when it fetches the request object (supported formats, response modes, client-id prefixes), and the failure page shows technical details of why a presentation was rejected. A wallet-side error such as `NoMatchingDocumentsException` means the wallet found no credential matching the query: compare its PID format / `vct` / claims with the DCQL in `GET /vp/request/:id`.
* Limits: ES256 only, no `deviceMac` (device signature only), no revocation/status-list checking, no transaction data (the eShop shows a banner that transaction-bound SCA comes later).

## Internationalisation

`src/i18n/locales/*.json` (flat keys, `{placeholders}`), English is the fallback. `npm run check:i18n` and the test suite enforce identical keys and placeholders in all locales. The translations were drafted by an AI model and **should be reviewed by native speakers** before external use (Maltese in particular). To add a language: add `xx.json`, add it to `LOCALES` in `src/i18n/index.ts`.

## Accessibility

Landmarks and skip link, one `h1` per page, visible focus ring, 44 px targets, no colour-only information, labelled form controls with an error summary, `aria-live` wallet status, QR codes with text alternative and an always-available text link, `<details>`-based language switcher (works without JavaScript), reduced-motion and forced-colours support, reflow down to 320 px. The only script (`public/js/verify-poll.js`) is progressive enhancement; a no-JS button continues the flow.

`npm run a11y` (with the app running in mock mode) walks every flow on a desktop and a phone viewport and runs **axe-core** (WCAG 2.0–2.2 A/AA rules) on each page. Automated checks find only part of the issues: do a manual pass (screen reader, keyboard-only, 200 % zoom) before claiming conformance.

## Deploy to Render

1. Push this repository to GitHub.
2. In Render: **New → Blueprint**, select the repo. Render reads `render.yaml` (one web service, Node 20, plan *starter*, EU region, health check `/healthz`, **one instance** – state is in memory).
3. Fill in the variables marked `sync: false` when prompted (all optional for a first mock-mode deploy). `SESSION_SECRET` is generated for you. Recommended for a real deployment:
   * `ISSUER_SIGNING_KEY_JWK` and `VERIFIER_SIGNING_KEY_JWK` (`npm run keygen`), `VERIFIER_CERT_CHAIN_PEM`
   * `TRUSTED_ISSUERS` (IN Groupe Issuer URL) and/or `TRUSTED_CA_PEM`
   * `PUBLIC_BASE_URL` if you use a custom domain (otherwise `RENDER_EXTERNAL_URL` is used automatically)
   * `MOCK_MODE=false` once a real wallet is connected
4. Deploy and open `https://<service>.onrender.com/`. Check `/healthz` and `/.well-known/openid-credential-issuer/issuer`.
5. **No redirect URIs have to be registered** anywhere: OpenID4VP uses `response_uri` values generated per request (`<PUBLIC_BASE_URL>/vp/response/<id>`). Instead, register the **verifier identity** with the wallet/trust list operator (certificate / `client_id` `x509_san_dns:<host>`) as your trust framework requires.

## Tests

```bash
npm test              # vitest: SD-JWT, issuer + verifier over HTTP (acting as a wallet), trust, config, i18n, adapters
npm run build         # tsc → dist/
npm run a11y          # browser walk-through + axe-core (app must be running with MOCK_MODE=true)
```

## Security notes and limitations

* State (sessions, offers, verifier transactions) is **in memory**: single instance, lost on restart, bounded (5 000 open offers/transactions).
* No rate limiting, WAF or revocation handling: put the app behind proper infrastructure for anything beyond demos.
* `TRUSTED_ISSUERS=*` is accepted outside production only.
* Helmet with a strict CSP (`script-src 'self'`, no inline styles), `Secure`/`HttpOnly`/`SameSite=Lax` session cookie in production, `trust proxy` enabled. Logs contain no tokens, credentials or personal claims (sensitive keys are also redacted in production).
* A generated verifier certificate and an ephemeral issuer key are fine for demos; supply real keys for anything else.

## Project layout

```
config/            rps.json (RPs, presentations, attestation catalogue), brand.json (placeholder IN Groupe branding)
src/sdjwt/         SD-JWT VC issue / present / verify
src/issuer/        local OpenID4VCI issuer, external adapter, provider switch, QR + deeplinks
src/verifier/      OpenID4VP verifier: identity, DCQL/PEX, trust, transactions, HTTP endpoints
src/mock/          simulated wallet + demo personas
src/rps/           bank, eshop, university, electricity routers (+ shared verification flow)
src/i18n/          8 locales
views/ public/     EJS templates, per-site CSS skins, placeholder logo
tests/ scripts/    vitest suites; a11y walk-through, key generator, i18n check
```

**Branding.** The dashboard uses the IN Groupe logo (`public/img/in-groupe-logo.svg`, taken from ingroupe.com), navy `#002F87` and red `#E4032E` (`config/brand.json`). IN Groupe's typeface is Avenir, a licensed font that is **not bundled**: it is used when installed locally or when `avenir-roman.woff2` / `avenir-heavy.woff2` are placed in `public/fonts/avenir/`; otherwise the bundled, free Nunito Sans is used. The four demo RPs are fictitious brands with their own identity (bank: emerald/Inter, eShop: indigo+coral/Inter, university: burgundy+gold/Source Serif 4, energy: green-black+yellow/Inter). Fonts are self-hosted (SIL OFL, Latin + Latin Extended for Maltese).

## What to configure on the SIGMA / IN Groupe side

* **Verifier**: register the verifier identity (certificate chain / `client_id` `x509_san_dns:<host>`) with the wallet provider or trust list; confirm which `client_id` scheme, `response_mode` (`direct_post` vs `direct_post.jwt`), query language (DCQL vs PEX) and invocation scheme (`openid4vp://`, `haip://`, …) the SIGMA wallet supports.
* **PID trust**: issuer URL(s) (`TRUSTED_ISSUERS`) or CA roots (`TRUSTED_CA_PEM`) of the IN Groupe PID Issuer; the PID `vct` and format (`dc+sd-jwt` vs `mso_mdoc`, claim names such as `nationalities`, `place_of_birth`, `address`) – override with `ATTESTATION_PID_ACCEPTED_VCT` / `config/rps.json`.
* **External Issuer** (if used): offer-creation API (URL, auth, request and response schema → `src/issuer/external.ts`), `credential_configuration_id`s for account, payment and birth-certificate attestations (`ATTESTATION_*_CONFIG_ID`), claim names.
* **Wallet side**: the wallet must trust the local issuer's metadata (`<PUBLIC_BASE_URL>/issuer`) for demo credentials, and must be able to reach the Render service over HTTPS.

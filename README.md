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
3. **Verifier identity** – wallets validate the request object's certificate. Set `VERIFIER_SIGNING_KEY_JWK` and `VERIFIER_CERT_CHAIN_PEM` (certificate whose SAN dNSName is your host, chained to a root the wallet trusts) – see *Verifier certificate (wallet trust)* below (`npm run gen:csr` / `npm run gen:verifier-cert`). Without them a self-signed demo certificate is generated at startup, which wallets do not trust.
4. **Trust the PID issuer** – `TRUSTED_ISSUERS=<IN Groupe Issuer URL>` (its keys are read from `<iss>/.well-known/jwt-vc-issuer`) and/or `TRUSTED_CA_PEM` for credentials that carry an `x5c` chain. The local demo issuer is always trusted.
5. Get test credentials: PID from the IN Groupe Issuer (or a demo PID from `/demo-issuer`), birth certificate from `/demo-issuer`, bank attestations from the bank page.

### SIGMA issuer connection

The catalogue of the SIGMA preprod issuer (`https://issuer.sigma.prep.smartid.nuagein.io/.well-known/openid-credential-issuer`) drives the configuration. It offers exactly three credentials:

| SIGMA configuration | Format | Type | Used by |
|---|---|---|---|
| `eu.europa.ec.eudi.pid_mdoc` (and `…pid_mdoc_emrtd`) | `mso_mdoc` | docType / namespace `eu.europa.ec.eudi.pid.1` | bank, university, electricity (the PID is **mdoc only**) |
| `eu.europa.ec.eudi.birth_certificate_vc_sd_jwt` | `dc+sd-jwt` | `vct` `urn:eudi:birth_certificate:1` | university |

With `ISSUER_MODE=external` (+ `ISSUER_API_BASE_URL`, optional `ISSUER_METADATA_URL`) the app reads this metadata live (cached 10 min), shows on the dashboard which attestation is issued by SIGMA and which is not, and uses SIGMA's own configuration ids. **The bank account and payment attestations are not offered by this issuer**, so they are issued by the local demo issuer (`ISSUER_FALLBACK_LOCAL=true`, the default) and the offer page says so. `tests/fixtures/sigma-issuer-metadata.json` is a snapshot; the test-suite checks that every claim each RP requests exists in that catalogue.

**Offer API (confirmed).** The SIGMA issuer exposes `POST <issuer>/offer` (the "oid-vci-adapter" API used by the *WalletTester* portal, https://github.com/adhopte/WalletTester); on the preprod issuer it needs no authentication. Request: `{ identifier, businessId (uuid), walletIdentifier?, authorization_details: [{ type: "openid_credential", credential_configuration_id, credential_identifiers? }] }`. Reply: `{ uri (openid-credential-offer://?credential_offer=… , pre-authorised code), qr_code (base64 JPEG), tx_code (6 digits), authorization_code }`. The `/demo-issuer` console creates such offers for **sample users** (`externalUsers` in `config/rps.json`: PID `user-001…003`, birth certificate `user-bc-sd-jwt-001/002`) and shows the 6-digit code the wallet asks for.

Two things to know about this API:
* **Admin console (mock authentic-source check).** `/demo-issuer/admin` (user `admin`, password `Admin123`, override with `ADMIN_PASSWORD`). The SIGMA issuer issues only what its own record store holds, and that store cannot be written or repointed from here. So the admin types a person's attributes and the app **matches** them (case/accent-insensitive; empty fields ignored) against the issuer's records (`GET <issuer>/api/in-person-portal-sor/<use case>/sor/`, publicly readable; the saved copy in `config/portal/` is used when it cannot be reached). One match → the SIGMA offer for that record is created; several → pick one; none → "no record in the authentic source" with the list of available records. In mock mode the typed values are issued by the local demo issuer instead.
* **HAIP wallets and the local issuer (bank account / payment attestations).** The metadata declares `key_attestations_required` (basic key storage / user authentication, as the SIGMA issuer does) on every `jwt` proof type, which HAIP wallets insist on (`jwt proof must contain 'key_attestations_required'` otherwise). Proofs may carry a `key_attestation` header: it must be a well-formed, unexpired `keyattestation+jwt` whose `attested_keys` contain the proof key (the proof key defaults to the first attested key when no `jwk` header is present) and whose signature verifies against its own `x5c` certificate. The wallet provider's trust chain is **not** evaluated (demo issuer), and plain `jwk` proofs are still accepted for the simulated wallet. **Credential response encryption:** the metadata declares `credential_response_encryption` (`ECDH-ES` / `RSA-OAEP-256`, `A128GCM` / `A256GCM`, not mandatory). A Credential Request carrying `credential_response_encryption: {jwk, alg, enc}` gets a compact JWE (`application/jwt`) addressed to that key; invalid parameters are refused with `invalid_encryption_parameters` *before* anything is issued (the offer is not consumed). Without the parameter the response stays plain JSON.
* **Registration certificate (the relying party's name in the wallet).** Wallets built on the EUDI wallet kit show the relying party's `name` and `purpose` from its *registration certificate* (a JWT of type `rc-wrp+jwt`, ETSI TS 119 475) carried in the request's `verifier_info` parameter: `[{ "format": "registration_cert", "data": "<JWT>" }]` (not in `client_metadata`). Set `VP_REGISTRATION_CERT` (all RPs) and/or `RP_<ID>_REGISTRATION_CERT` (e.g. `RP_BANK_REGISTRATION_CERT`, `RP_UNIVERSITY_REGISTRATION_CERT`, …; or `registrationCertificate` in `config/rps.json`). The certificate is issued by a registrar for **one** verifier (its LEI is the `sub`), so it cannot be generated here: obtain one per RP and paste it in. It is sent only in **signed** requests (`VP_CLIENT_ID_SCHEME=x509_hash` or `x509_san_dns` with the verifier certificate, fetched through `request_uri`); it is about 15 KB, far too large for the unsigned by-value link / QR code of the `redirect_uri` scheme, and a wallet only trusts it next to an X.509 access certificate whose `organizationIdentifier` equals the certificate's `sub`. `GET /vp/verifier` reports per RP what is sent (name, purpose, subject, expiry, `matches_access_certificate`) and why a configured certificate is *not* sent. **Default:** `config/registration-cert.jwt` ships the EUDI reference registrar's *test* certificate ("Web Verifier (PROD)", purpose "For Testing Purposes", LEI `LEIXG-529900T8BM49AURSDO55`) and is used for **all** RPs until `VP_REGISTRATION_CERT` / `RP_<ID>_REGISTRATION_CERT` override it (`VP_REGISTRATION_CERT=none` turns it off). It identifies the EUDI test verifier, not IN Groupe: replace it with a certificate issued for your own verifier. **Unsigned links:** `VP_REGISTRATION_LINKS` = `button` (default: only the *Open in wallet* button of the verification page carries it, the QR code stays small), `all` (every link, about 15 KB: no QR code) or `off`.
* **Issuer portal (`/demo-issuer`).** Modelled on the SIGMA issuer's own in-person portal / the WalletTester pre-authorised-code workflow, in IN Groupe branding: 1. pick a use case (only those in the issuer's live catalogue), 2. pick a sample record (table with portrait and all attributes), 3. *Create offer* → QR code, wallet button, transaction code, pre-authorised code and a copyable deeplink. The records are snapshots of the issuer portal's public data files in `config/portal/` (`user_pid_claims.json`, `birth_certificate_claims_sd_jwt.json`); a test keeps them in sync with the sample users in `config/rps.json`. *Use other identifiers* creates an offer for an identifier / credential identifier you type. The WalletTester's identity-proofing flows (Colombia, Finland, Netherlands, DTC) need an identity-verification backend and are not included.
* **PID route.** `eu.europa.ec.eudi.pid_mdoc` is issued from a stored record (pre-authorised offer + 6-digit code) and works only for an `identifier` / credential identifier pair that exists in the issuer's system of record. The working pairs are the ones the issuer's own in-person portal lists (`/in-person-portal/assets/jsons/user_pid_claims.json`): `user-pid-mdoc-001` / `credential_id_1_mdoc` and `user-pid-mdoc-002` / `credential_id_2_mdoc`. Anything else yields an empty PID or `CredentialIssuanceError` in the wallet. The eMRTD/IdP-login configuration (`pid_mdoc_emrtd`) needs a real passport and is not offered in the console.
* **The credential identifier matters.** The issuer looks the record up by `identifier` **and** `credential_identifiers`. The WalletTester sends `credential_id_1` for PID users and `birth_certificate_full_data` for birth-certificate users; **omitting it produces an empty credential** (a PID card whose fields all read "UNKNOW", plus a download error in the wallet). Delete such a credential in the wallet before re-issuing.
* **The claim values are not part of the request.** The issuer fills the credential from its own system of record for the given `identifier`; a relying party cannot supply data. Offer creation does not validate the identifier (an unknown one fails later, when the wallet fetches the credential). Which identifiers carry which data has to come from the SIGMA team.
* **Account / payment attestations** are not offered by this issuer (no credential configuration, no record), so they stay with the local demo issuer. They switch automatically once SIGMA offers a configuration with the same `vct`, **and** its system of record holds the data: the bank cannot push the customer's account data into a SIGMA credential through this API.

### Verifier certificate (wallet trust)

Wallets evaluate the certificate that signs the request object. A wallet that answers *"Trust evaluation failed: the certificate '<host>' is not trustworthy"* does not know the verifier's certificate: the **self-signed demo certificate** the app generates at startup is never trusted. `GET /vp/verifier` shows exactly what the service currently signs with (subject, issuer, validity, PEM chain, `x509_hash` / `x509_san_dns` client identifiers).

Pick one:

1. **Certificate from the wallet's trusted PKI (recommended).** `npm run gen:csr -- <your-host>` writes `verifier-cert-out/csr.pem` (subject `CN=<host>`, SAN `dNSName=<host>`) and `key-env.txt`. Have the CA that the wallet trusts (e.g. the IN Groupe / SIGMA PKI) sign the CSR, then set `VERIFIER_SIGNING_KEY_JWK` (from `key-env.txt`) and `VERIFIER_CERT_CHAIN_PEM` (returned chain, leaf first, newlines as `\n`).
2. **Your own demo CA, added to the wallet's trust anchors.** `npm run gen:verifier-cert -- <your-host>` creates a root CA and a leaf certificate for the host. Give `verifier-cert-out/ca.pem` to whoever manages the wallet's trust anchors; set `VERIFIER_SIGNING_KEY_JWK` and `VERIFIER_CERT_CHAIN_PEM` from `verifier-cert-out/env.txt`. The script also prints the `x509_hash` client id, in case the wallet pins that instead.
3. **No certificate (quick test only).** `VP_CLIENT_ID_SCHEME=redirect_uri` sends the request unsigned and by value (minimum claims, so the link fits a QR code). The verifier is then not authenticated at all, and wallets that enforce HAIP may refuse it.

`verifier-cert-out/` is git-ignored: the files contain a private key, never commit or share them. Certificates from the scripts are valid for one year.

**Benin PID rulebook.** Claim names follow the *Benin PID / Birth Certificate Rulebook v2.0* (standard EUDI element names); identifiers follow the live SIGMA issuer metadata (see *SIGMA issuer connection*): PID mdoc docType/namespace `eu.europa.ec.eudi.pid.1` (the rulebook's example SD-JWT `vct` `https://credentials.benin.example/pid` is still accepted), birth certificate `vct` `urn:eudi:birth_certificate:1`; claims `family_name`, `given_name`, `birth_date`, `birth_place`, `birth_country`, `nationality`, `resident_address`, … (see `config/rps.json`). The sensitive `personal_administrative_number` and the portrait are never requested. SD-JWT PIDs that use the older EU names (`birthdate`, `nationalities`, `address`, `place_of_birth`) are mapped to these names.

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

`ISSUER_MODE=external` sends offer creation to the SIGMA issuer through **one module, `src/issuer/external.ts`** (request/response schema in the previous section; default path `/offer`, `ISSUER_EXTERNAL_OFFER_PATH`; authentication `none` by default, `bearer` / `client_credentials` supported should the API be protected later). The offer's `tx_code` is shown on the offer page. Attestations the external issuer does not offer fall back to the local demo issuer (`ISSUER_FALLBACK_LOCAL`).

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

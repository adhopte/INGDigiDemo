// Creates a persistent signing key for the local OpenID4VCI issuer and a certificate signing request for it (+ the covering message for the CA).
//   npm run gen:issuer-csr -- https://eu-wallet-rp-playground.onrender.com/issuer [outDir] [--subject "CN=...,O=...,C=..."] [--ca "EUDI test CA"]
// --subject: the exact distinguished name, when the CA insists on particular fields (country, organization identifier, ...).
// Send csr.pem and request-for-sigma.txt to the CA. Set ISSUER_SIGNING_KEY_JWK from key-env.txt NOW (the certificate belongs to this key), and
// ISSUER_CERT_CHAIN_PEM to the returned chain (leaf first) when it arrives. Credentials issued before the key is set stay bound to the old key.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateIssuerCsr, requestText } from './lib/issuer-csr.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const subject = opt('--subject');
const ca = opt('--ca');
const issuerUrl = args[0];
if (!issuerUrl || !/^https:\/\//.test(issuerUrl)) { console.error('usage: node scripts/gen-issuer-csr.mjs <https issuer URL, e.g. https://host/issuer> [outDir] [--subject "CN=...,O=...,C=..."] [--ca "name of the CA"]'); process.exit(1); }
const out = args[1] ?? 'issuer-cert-out';
mkdirSync(out, { recursive: true });
const r = await generateIssuerCsr(issuerUrl, { ...(subject ? { subject } : {}), ...(ca ? { ca } : {}) });
writeFileSync(join(out, 'csr.pem'), r.csrPem);
writeFileSync(join(out, 'key-env.txt'), `ISSUER_SIGNING_KEY_JWK=${r.keyEnv}\n`, { mode: 0o600 });
writeFileSync(join(out, 'request-for-ca.txt'), requestText(r));
console.log(`Written to ${out}/  (git-ignored; key-env.txt holds a PRIVATE key: never commit or share it)\n`);
console.log(`  csr.pem               send to the CA (${r.subject}; SAN dNSName ${r.host} + URI ${r.issuerUrl})`);
console.log('  request-for-ca.txt    the covering message');
console.log('  key-env.txt           ISSUER_SIGNING_KEY_JWK=<private JWK>: set it as a SECRET environment variable on the service');
console.log('\nWhen the signed certificate (+ intermediates) returns, set ISSUER_CERT_CHAIN_PEM to the PEM chain, leaf first (newlines as \\n).');

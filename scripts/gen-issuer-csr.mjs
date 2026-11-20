// Creates a persistent signing key for the local OpenID4VCI issuer and a certificate signing request for it (+ the covering message for the CA).
//   npm run gen:issuer-csr -- https://eu-wallet-rp-playground.onrender.com/issuer [outDir]
// Send csr.pem and request-for-sigma.txt to the CA. Set ISSUER_SIGNING_KEY_JWK from key-env.txt NOW (the certificate belongs to this key), and
// ISSUER_CERT_CHAIN_PEM to the returned chain (leaf first) when it arrives. Credentials issued before the key is set stay bound to the old key.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateIssuerCsr, requestText } from './lib/issuer-csr.mjs';

const issuerUrl = process.argv[2];
if (!issuerUrl || !/^https:\/\//.test(issuerUrl)) { console.error('usage: node scripts/gen-issuer-csr.mjs <https issuer URL, e.g. https://host/issuer> [outDir]'); process.exit(1); }
const out = process.argv[3] ?? 'issuer-cert-out';
mkdirSync(out, { recursive: true });
const r = await generateIssuerCsr(issuerUrl);
writeFileSync(join(out, 'csr.pem'), r.csrPem);
writeFileSync(join(out, 'key-env.txt'), `ISSUER_SIGNING_KEY_JWK=${r.keyEnv}\n`, { mode: 0o600 });
writeFileSync(join(out, 'request-for-sigma.txt'), requestText(r));
console.log(`Written to ${out}/  (git-ignored; key-env.txt holds a PRIVATE key: never commit or share it)\n`);
console.log(`  csr.pem               send to the CA (CN=${r.host}, SAN dNSName ${r.host} + URI ${r.issuerUrl})`);
console.log('  request-for-sigma.txt the covering message');
console.log('  key-env.txt           ISSUER_SIGNING_KEY_JWK=<private JWK>: set it as a SECRET environment variable on the service');
console.log('\nWhen the signed certificate (+ intermediates) returns, set ISSUER_CERT_CHAIN_PEM to the PEM chain, leaf first (newlines as \\n).');

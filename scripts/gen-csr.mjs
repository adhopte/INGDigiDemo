// Creates a verifier key and a certificate signing request for a CA the wallet trusts (e.g. IN Groupe / SIGMA PKI).
//   node scripts/gen-csr.mjs eu-wallet-rp-playground.onrender.com [outDir]
// Send csr.pem to the CA; set VERIFIER_SIGNING_KEY_JWK from key-env.txt and VERIFIER_CERT_CHAIN_PEM to the returned chain (leaf first).
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateCsr } from './lib/verifier-cert.mjs';

const host = process.argv[2];
if (!host || host.includes('/')) { console.error('usage: node scripts/gen-csr.mjs <host> [outDir]'); process.exit(1); }
const out = process.argv[3] ?? 'verifier-cert-out';
mkdirSync(out, { recursive: true });
const r = await generateCsr(host);
writeFileSync(join(out, 'csr.pem'), r.csrPem);
writeFileSync(join(out, 'key-env.txt'), `VERIFIER_SIGNING_KEY_JWK=${r.keyEnv}\n`, { mode: 0o600 });
console.log(`Written to ${out}/ (git-ignored; key-env.txt holds a PRIVATE key – never commit or share it)\n`);
console.log(`Send ${join(out, 'csr.pem')} to the CA (subject CN=${host}, SAN dNSName=${host}).`);
console.log('When the signed certificate (+ intermediates) comes back, set VERIFIER_CERT_CHAIN_PEM to the PEM chain, leaf first (newlines as \\n).');

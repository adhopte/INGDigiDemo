// Creates a verifier certificate chain for your deployment host (demo PKI) and prints the environment values to set.
//   node scripts/gen-verifier-cert.mjs eu-wallet-rp-playground.onrender.com [outDir]
// Give ca.pem to whoever manages the wallet's trust anchors; set the two VERIFIER_* values on the service.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateDemoPki } from './lib/verifier-cert.mjs';

const host = process.argv[2];
if (!host || host.includes('/')) { console.error('usage: node scripts/gen-verifier-cert.mjs <host> [outDir]   e.g. my-app.onrender.com'); process.exit(1); }
const out = process.argv[3] ?? 'verifier-cert-out';
mkdirSync(out, { recursive: true });
const p = await generateDemoPki(host);
writeFileSync(join(out, 'ca.pem'), p.caPem);
writeFileSync(join(out, 'verifier-chain.pem'), p.chainPem);
writeFileSync(join(out, 'verifier-key.jwk.json'), JSON.stringify(p.keyJwk), { mode: 0o600 });
writeFileSync(join(out, 'env.txt'), Object.entries(p.env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
console.log(`Written to ${out}/ (git-ignored; contains a PRIVATE key – never commit or share env.txt / verifier-key.jwk.json)\n`);
console.log('1. Give this root CA to the wallet / trust-list operator to add as a trust anchor:  ' + join(out, 'ca.pem'));
console.log('2. Set on the service (Render → Environment): VERIFIER_SIGNING_KEY_JWK and VERIFIER_CERT_CHAIN_PEM from ' + join(out, 'env.txt'));
console.log('3. Client identifiers this certificate yields (VP_CLIENT_ID_SCHEME):');
for (const [k, v] of Object.entries(p.clientIds)) console.log(`     ${k.padEnd(13)} ${v}`);

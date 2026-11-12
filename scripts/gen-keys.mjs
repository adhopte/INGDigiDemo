// Prints a fresh ES256 private JWK (one line) for ISSUER_SIGNING_KEY_JWK or VERIFIER_SIGNING_KEY_JWK.
// Usage: node scripts/gen-keys.mjs [kid]      Never commit the output: set it as a secret environment variable.
import { exportJWK, generateKeyPair } from 'jose';
const { privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = await exportJWK(privateKey);
if (process.argv[2]) jwk.kid = process.argv[2];
console.log(JSON.stringify(jwk));

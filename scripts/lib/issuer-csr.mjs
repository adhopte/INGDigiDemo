// Persistent ES256 signing key for the local OpenID4VCI issuer + a PKCS#10 certificate signing request for it, to be signed by a CA the wallet
// trusts (e.g. the IN Groupe / SIGMA PKI). The certificate then goes into the x5c header of every credential the issuer signs.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash } from 'node:crypto';

const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

/**
 * SD-JWT VC (§3.5): with x5c, the certificate must carry the `iss` host as a dNSName or the `iss` URL as a URI SAN. We ask for both.
 * @param {string} issuerUrl the credential issuer identifier, e.g. https://eu-wallet-rp-playground.onrender.com/issuer
 */
export async function generateIssuerCsr(issuerUrl, { org = 'IN Groupe' } = {}) {
  const url = new URL(issuerUrl);
  if (url.protocol !== 'https:') throw new Error('The issuer URL must be https');
  const host = url.hostname;
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${host}, O=${org}`, keys, signingAlgorithm: alg,
    extensions: [
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }, { type: 'url', value: issuerUrl.replace(/\/+$/, '') }], false),
    ],
  });
  const priv = { ...(await crypto.subtle.exportKey('jwk', keys.privateKey)), alg: 'ES256', use: 'sig' };
  const pub = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const kid = createHash('sha256').update(JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y })).digest('base64url').slice(0, 16);
  priv.kid = kid;
  return {
    host, issuerUrl: issuerUrl.replace(/\/+$/, ''), org, kid,
    csrPem: csr.toString('pem'),
    keyEnv: JSON.stringify(priv),
    publicKeySha256: createHash('sha256').update(Buffer.from(csr.publicKey.rawData)).digest('hex'),
  };
}

/** The covering message for the CA / SIGMA team. */
export function requestText(r) {
  return `Subject: Certificate request – OpenID4VCI issuer signing key (${r.host})

Hello,

we operate an OpenID4VCI demo issuer, "${r.issuerUrl}", that issues the bank account and payment attestations (SD-JWT VC, dc+sd-jwt)
to the IN Groupe SIGMA wallet. Your wallet matches SD-JWT credentials through the issuer certificate in the x5c header: the credentials of the SIGMA
issuer have one, ours carry a self-signed demo certificate, which is not in any trust list. Please sign the attached request.

  Request file          csr.pem  (PKCS#10, ECDSA P-256 / SHA-256, proof of possession included)
  Subject               CN=${r.host}, O=${r.org}   (adjust to your naming policy)
  Subject alt. names    dNSName ${r.host}
                        uniformResourceIdentifier ${r.issuerUrl}      (this is the \`iss\` of the credentials, SD-JWT VC §3.5)
  Key usage             digitalSignature
  Public key SHA-256    ${r.publicKeySha256}
  Validity              as your policy allows (the key is persistent; the certificate is installed by configuration, no code change)

Please return the certificate followed by its intermediates (PEM, leaf first). We will configure it as ISSUER_CERT_CHAIN_PEM.

Two questions for the wallet team:
  1. Is the CA that signs this certificate in the trust list of the wallet (so that the issuer is shown by name instead of "Unknown issuing party")?
  2. Does the wallet require a particular extension (certificate policy, extended key usage) on an SD-JWT VC issuer certificate?

Thank you.
`;
}

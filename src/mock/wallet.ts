import { randomUUID } from 'node:crypto';
import { CompactEncrypt, SignJWT, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import type { SessionData } from 'express-session';
import type { AppConfig } from '../config.js';
import type { LocalIssuer } from '../issuer/local/service.js';
import { PRE_AUTH_GRANT } from '../issuer/local/service.js';
import { peekClaims, presentSdJwt, type Claims } from '../sdjwt/index.js';
import type { WalletCredential } from '../session.js';
import type { Transaction, Verifier } from '../verifier/service.js';

type SessionLike = Partial<SessionData>;

/** Fake people, one per supported language/country. Names are obviously synthetic ("Demo"). */
export const PERSONAS = [
  { id: 'ie', given: 'Aoife', family: 'Demo', born: '1991-03-12', city: 'Cork', street: '1 Example Street' },
  { id: 'fr', given: 'Camille', family: 'Demo', born: '1992-04-17', city: 'Lyon', street: '12 rue de l’Exemple' },
  { id: 'es', given: 'Lucía', family: 'Demo', born: '1995-02-21', city: 'Sevilla', street: 'Calle Ejemplo 3' },
  { id: 'nl', given: 'Daan', family: 'Demo', born: '1990-07-09', city: 'Utrecht', street: 'Voorbeeldstraat 5' },
  { id: 'de', given: 'Lukas', family: 'Demo', born: '1988-11-03', city: 'Köln', street: 'Beispielweg 7' },
  { id: 'dk', given: 'Freja', family: 'Demo', born: '1993-12-30', city: 'Aarhus', street: 'Eksempelvej 9' },
  { id: 'mt', given: 'Maria', family: 'Demo', born: '1985-05-14', city: 'Valletta', street: '4 Triq l-Eżempju' },
  { id: 'se', given: 'Astrid', family: 'Demo', born: '1997-09-26', city: 'Göteborg', street: 'Exempelgatan 11' },
] as const;

export type Persona = (typeof PERSONAS)[number];
export const personaFor = (id: unknown): Persona => PERSONAS.find((p) => p.id === id) ?? PERSONAS[0];
const ISO = (id: string) => id.toUpperCase();

export function demoClaims(typeKey: string, p: Persona): Claims {
  const cc = ISO(p.id);
  switch (typeKey) {
    case 'pid':
      return {
        family_name: p.family, given_name: p.given, birth_date: p.born, birth_place: p.city, birth_country: cc,
        nationality: cc, resident_address: `${p.street}, 00000 ${p.city}`,
        document_number: `ID${Math.floor(100000000 + Math.random() * 899999999)}`, issuance_date: '2026-01-10', expiry_date: '2031-01-10',
        issuing_authority: 'IN Groupe Issuer (demo PID)', issuing_country: cc, age_over_18: true,
      };
    case 'birth_certificate':
      return {
        family_name: p.family, given_name: p.given, birth_date: p.born, birth_place: p.city, birth_country: cc,
        mother_family_name: p.family, mother_given_name: 'Pat',
        father_family_name: p.family, father_given_name: 'Sam',
        birth_record_reference: `ACTE-${Math.floor(100000 + Math.random() * 899999)}`,
        issuing_authority: `Civil registry of ${p.city} (demo)`,
      };
    default:
      throw new Error(`No demo data for ${typeKey}`);
  }
}

async function holderKeyPair() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  return { publicJwk: await exportJWK(publicKey), privateJwk: await exportJWK(privateKey) };
}

/**
 * Simulated wallet redeeming a local credential offer. Runs the genuine OpenID4VCI steps against the local issuer
 * (offer → pre-authorised code → token → nonce-bound proof → credential), just without HTTP.
 */
export async function redeemOffer(local: LocalIssuer, session: SessionLike, offerId: string, txCode?: string): Promise<WalletCredential> {
  if (!session.offerIds?.includes(offerId)) throw new Error('Offer does not belong to this session');
  const offer = local.offerObject(offerId) as { grants?: Record<string, { 'pre-authorized_code'?: string }>; credential_configuration_ids?: string[] } | undefined;
  const code = offer?.grants?.[PRE_AUTH_GRANT]?.['pre-authorized_code'];
  if (!offer || !code) throw new Error('Offer is no longer available');

  const token = local.exchangePreAuthorizedCode({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': code, ...(txCode ? { tx_code: txCode } : {}) });
  const { publicJwk, privateJwk } = await holderKeyPair();
  const proof = await new SignJWT({ nonce: token.c_nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
    .setAudience(local.issuerUrl)
    .setIssuedAt()
    .sign(await importJWK(privateJwk, 'ES256'));
  const configId = offer.credential_configuration_ids![0]!;
  const res = await local.issueCredential(token.access_token, { credential_configuration_id: configId, proofs: { jwt: [proof] } });
  const credential = res.credentials[0]!.credential;
  return storeCredential(session, local, configId, credential, privateJwk);
}

function storeCredential(session: SessionLike, local: LocalIssuer, configId: string, credential: string, holderPrivateJwk: JWK): WalletCredential {
  const payload = JSON.parse(Buffer.from(credential.split('.')[1]!, 'base64url').toString()) as { vct: string };
  const typeKey = local.typeKeyForConfig(configId) ?? payload.vct;
  const entry: WalletCredential = { id: randomUUID(), typeKey, vct: payload.vct, credential, holderPrivateJwk, issuedAt: new Date().toISOString() };
  session.wallet = [...(session.wallet ?? []).filter((c) => c.typeKey !== typeKey), entry]; // newest per type
  return entry;
}

/** Issue a demo credential (PID, birth certificate) straight into the simulated wallet via the local issuer. */
export async function addDemoCredential(local: LocalIssuer, cfg: AppConfig, session: SessionLike, typeKey: string, personaId: string): Promise<WalletCredential> {
  const created = local.createOffer(typeKey, demoClaims(typeKey, personaFor(personaId)));
  session.offerIds = [...(session.offerIds ?? []), created.id];
  void cfg;
  return redeemOffer(local, session, created.id);
}

export const heldCredential = (session: SessionLike, typeKey: string) => session.wallet?.find((c) => c.typeKey === typeKey);
export const heldClaims = (c: WalletCredential): Claims => peekClaims(c.credential);

/** Build the vp_token (selective disclosure + key binding) for a transaction. Throws if a required credential is missing. */
export async function buildVpToken(session: SessionLike, tx: Transaction, verifier: Verifier): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  for (const req of tx.reqs) {
    const held = heldCredential(session, req.type);
    if (!held) throw new Error(`Wallet holds no ${req.type}`);
    out[req.type] = [
      await presentSdJwt({
        credential: held.credential,
        reveal: req.claims,
        holderPrivateKey: await importJWK(held.holderPrivateJwk, 'ES256'),
        aud: verifier.identity.clientId,
        nonce: tx.nonce,
      }),
    ];
  }
  return out;
}

/** Deliver the response exactly as a wallet would (direct_post or direct_post.jwt). Returns the response_uri result. */
export async function respondToVerifier(verifier: Verifier, tx: Transaction, payload: { vp_token?: unknown; error?: string }) {
  const body = { ...payload, state: tx.state };
  if (tx.enc) {
    const key = await importJWK(tx.enc.publicJwk, 'ECDH-ES');
    const response = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(body)))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: tx.enc.publicJwk.kid })
      .encrypt(key);
    return verifier.handleResponse(tx.id, { response });
  }
  return verifier.handleResponse(tx.id, { ...body, vp_token: JSON.stringify(body.vp_token) });
}

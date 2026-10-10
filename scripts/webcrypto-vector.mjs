import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const subtle = webcrypto.subtle;
const message = 'clavicularius-interop';
const bytes = new TextEncoder().encode(message);

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function publicFields(jwk) {
  const out = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    d: jwk.d,
    kid: 'throwaway',
    alg: jwk.alg,
  };
  if (jwk.y) out.y = jwk.y;
  return out;
}

const es = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const esJwk = await subtle.exportKey('jwk', es.privateKey);
esJwk.alg = 'ES256';
esJwk.kid = 'throwaway';
const esSig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, es.privateKey, bytes);
writeFileSync(
  new URL('../testdata/webcrypto-es256.json', import.meta.url),
  `${JSON.stringify({ message, private_jwk: publicFields(esJwk), signature: b64url(esSig) }, null, 2)}\n`,
);

const ed = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const edJwk = await subtle.exportKey('jwk', ed.privateKey);
edJwk.alg = 'EdDSA';
edJwk.kid = 'throwaway';
const edSig = await subtle.sign({ name: 'Ed25519' }, ed.privateKey, bytes);
writeFileSync(
  new URL('../testdata/webcrypto-ed25519.json', import.meta.url),
  `${JSON.stringify({ message, private_jwk: publicFields(edJwk), signature: b64url(edSig) }, null, 2)}\n`,
);

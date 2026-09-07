import { describe, expect, it } from 'vitest';
import {
  base64urlEncode,
  createNewEd25519Keypair,
  JwtVerificationError,
  signPayloadEd25519,
  verifyJwt,
} from '../src/crypto';

/*

  JWT expiry

  `crypto/jwt.ts` ships on the public `./crypto` subpath, so an integrator can
  reach it directly. Its `JwtClaims` type says `exp: number`, but the payload is
  a `JSON.parse` cast — the runtime value can be anything, and every non-number
  loses the `payload.exp <= currentTime` comparison rather than failing it. An
  `exp` this verifier cannot read is not an expiry it can honor, so it is a
  rejection.

*/

const keypair = createNewEd25519Keypair();

const signJwt = async (claims: Record<string, unknown>): Promise<string> => {
  const header = base64urlEncode(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }));
  const payload = base64urlEncode(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sig = await signPayloadEd25519(new TextEncoder().encode(signingInput), keypair.privateKey);
  return `${signingInput}.${base64urlEncode(sig)}`;
};

const baseClaims = {
  iss: 'did:dfos:issuer',
  sub: 'did:dfos:subject',
  iat: Math.floor(Date.now() / 1000),
};

describe('verifyJwt exp', () => {
  it('accepts a token with a future integer exp', async () => {
    const token = await signJwt({ ...baseClaims, exp: Math.floor(Date.now() / 1000) + 3600 });
    const { payload } = verifyJwt({ token, publicKey: keypair.publicKey });
    expect(payload.iss).toBe('did:dfos:issuer');
  });

  it('rejects a token with no exp at all', async () => {
    const token = await signJwt({ ...baseClaims });
    expect(() => verifyJwt({ token, publicKey: keypair.publicKey })).toThrow(JwtVerificationError);
  });

  it('rejects a string exp, however far in the future it reads', async () => {
    const token = await signJwt({ ...baseClaims, exp: '99999999999' });
    expect(() => verifyJwt({ token, publicKey: keypair.publicKey })).toThrow(/expired/i);
  });

  it('rejects a null exp and a boolean exp', async () => {
    for (const exp of [null, true]) {
      const token = await signJwt({ ...baseClaims, exp });
      expect(() => verifyJwt({ token, publicKey: keypair.publicKey })).toThrow(/expired/i);
    }
  });

  it('rejects a non-integer and an out-of-range exp', async () => {
    for (const exp of [1.5, 1e30]) {
      const token = await signJwt({ ...baseClaims, exp });
      expect(() => verifyJwt({ token, publicKey: keypair.publicKey })).toThrow(/expired/i);
    }
  });

  it('still rejects a genuinely expired token', async () => {
    const token = await signJwt({ ...baseClaims, exp: Math.floor(Date.now() / 1000) - 10 });
    expect(() => verifyJwt({ token, publicKey: keypair.publicKey })).toThrow(/expired/i);
  });
});

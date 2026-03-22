import { describe, expect, it } from 'vitest';
import {
  AuthTokenVerificationError,
  createAuthToken,
  createCredential,
  CredentialVerificationError,
  decodeCredentialUnsafe,
  VC_TYPE_CONTENT_READ,
  VC_TYPE_CONTENT_WRITE,
  verifyAuthToken,
  verifyCredential,
} from '../src/credentials';
import { createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';

// =============================================================================
// helpers
// =============================================================================

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, did, kid, signer };
};

const futureUnix = (minutes: number) => Math.floor(Date.now() / 1000) + minutes * 60;
const pastUnix = (minutes: number) => Math.floor(Date.now() / 1000) - minutes * 60;

// =============================================================================
// auth tokens
// =============================================================================

describe('auth token', () => {
  it('should create and verify round-trip', async () => {
    const id = makeIdentity();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: futureUnix(5),
      kid: id.kid,
      sign: id.signer,
    });

    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const result = verifyAuthToken({
      token,
      publicKey: id.keypair.publicKey,
      audience: 'relay.example.com',
    });

    expect(result.iss).toBe(id.did);
    expect(result.aud).toBe('relay.example.com');
    expect(result.kid).toBe(id.kid);
  });

  it('should reject expired token', async () => {
    const id = makeIdentity();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: pastUnix(5),
      kid: id.kid,
      sign: id.signer,
    });

    expect(() =>
      verifyAuthToken({
        token,
        publicKey: id.keypair.publicKey,
        audience: 'relay.example.com',
      }),
    ).toThrow(/expired/i);
  });

  it('should reject wrong audience', async () => {
    const id = makeIdentity();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: futureUnix(5),
      kid: id.kid,
      sign: id.signer,
    });

    expect(() =>
      verifyAuthToken({
        token,
        publicKey: id.keypair.publicKey,
        audience: 'other-relay.example.com',
      }),
    ).toThrow(/audience/i);
  });

  it('should reject wrong signing key', async () => {
    const id = makeIdentity();
    const wrong = createNewEd25519Keypair();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: futureUnix(5),
      kid: id.kid,
      sign: id.signer,
    });

    expect(() =>
      verifyAuthToken({
        token,
        publicKey: wrong.publicKey,
        audience: 'relay.example.com',
      }),
    ).toThrow(/signature/i);
  });

  it('should reject kid without DID URL format', async () => {
    const id = makeIdentity();
    await expect(
      createAuthToken({
        iss: id.did,
        aud: 'relay.example.com',
        exp: futureUnix(5),
        kid: 'bare_key_id',
        sign: id.signer,
      }),
    ).rejects.toThrow(/DID URL/i);
  });

  it('should reject kid DID mismatch with iss', async () => {
    const id = makeIdentity();
    const other = makeIdentity();
    await expect(
      createAuthToken({
        iss: id.did,
        aud: 'relay.example.com',
        exp: futureUnix(5),
        kid: other.kid,
        sign: id.signer,
      }),
    ).rejects.toThrow(/does not match/i);
  });

  it('should respect currentTime override', async () => {
    const id = makeIdentity();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: 1000,
      kid: id.kid,
      iat: 100,
      sign: id.signer,
    });

    // passes with time between iat and exp
    const result = verifyAuthToken({
      token,
      publicKey: id.keypair.publicKey,
      audience: 'relay.example.com',
      currentTime: 500,
    });
    expect(result.iss).toBe(id.did);

    // fails with time after expiry
    expect(() =>
      verifyAuthToken({
        token,
        publicKey: id.keypair.publicKey,
        audience: 'relay.example.com',
        currentTime: 2000,
      }),
    ).toThrow(/expired/i);
  });

  it('should reject auth token issued in the future (iat > currentTime)', async () => {
    const id = makeIdentity();
    const token = await createAuthToken({
      iss: id.did,
      aud: 'relay.example.com',
      exp: 10000,
      kid: id.kid,
      iat: 5000,
      sign: id.signer,
    });

    // currentTime before iat — should reject
    expect(() =>
      verifyAuthToken({
        token,
        publicKey: id.keypair.publicKey,
        audience: 'relay.example.com',
        currentTime: 3000,
      }),
    ).toThrow(/not yet valid/i);

    // currentTime at iat — should pass
    const result = verifyAuthToken({
      token,
      publicKey: id.keypair.publicKey,
      audience: 'relay.example.com',
      currentTime: 5000,
    });
    expect(result.iss).toBe(id.did);
  });

  it('should throw AuthTokenVerificationError on invalid claims', async () => {
    const id = makeIdentity();
    // manually create a JWT with bad payload (missing sub)
    const { createJwt } = await import('../src/crypto');
    const token = await createJwt({
      header: { alg: 'EdDSA', typ: 'JWT', kid: id.kid },
      payload: {
        iss: id.did,
        sub: id.did,
        aud: 'relay.example.com',
        exp: futureUnix(5),
        iat: Math.floor(Date.now() / 1000),
        extraField: 'not allowed',
      },
      sign: id.signer,
    });

    expect(() =>
      verifyAuthToken({
        token,
        publicKey: id.keypair.publicKey,
        audience: 'relay.example.com',
      }),
    ).toThrow(AuthTokenVerificationError);
  });
});

// =============================================================================
// credentials (VC-JWT)
// =============================================================================

describe('credential', () => {
  // --- create / verify round-trips ---

  it('should create and verify a DFOSContentWrite credential', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    const result = verifyCredential({
      token,
      publicKey: issuer.keypair.publicKey,
    });

    expect(result.iss).toBe(issuer.did);
    expect(result.sub).toBe(subject.did);
    expect(result.type).toBe(VC_TYPE_CONTENT_WRITE);
    expect(result.contentId).toBeUndefined();
  });

  it('should create and verify a DFOSContentRead credential', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_READ,
      sign: issuer.signer,
    });

    const result = verifyCredential({
      token,
      publicKey: issuer.keypair.publicKey,
    });

    expect(result.type).toBe(VC_TYPE_CONTENT_READ);
  });

  it('should create and verify a credential with contentId narrowing', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      contentId: 'k2abc123',
      sign: issuer.signer,
    });

    const result = verifyCredential({
      token,
      publicKey: issuer.keypair.publicKey,
    });

    expect(result.contentId).toBe('k2abc123');
    expect(result.type).toBe(VC_TYPE_CONTENT_WRITE);
  });

  // --- verification failures ---

  it('should reject expired credential', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: pastUnix(5),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    expect(() =>
      verifyCredential({
        token,
        publicKey: issuer.keypair.publicKey,
      }),
    ).toThrow(/expired/i);
  });

  it('should reject credential issued in the future (iat > currentTime)', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: 10000,
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      iat: 5000,
      sign: issuer.signer,
    });

    // currentTime before iat — should reject
    expect(() =>
      verifyCredential({
        token,
        publicKey: issuer.keypair.publicKey,
        currentTime: 3000,
      }),
    ).toThrow(/not yet valid/i);

    // currentTime at iat — should pass
    const result = verifyCredential({
      token,
      publicKey: issuer.keypair.publicKey,
      currentTime: 5000,
    });
    expect(result.iss).toBe(issuer.did);
  });

  it('should reject wrong subject', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const other = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    expect(() =>
      verifyCredential({
        token,
        publicKey: issuer.keypair.publicKey,
        subject: other.did,
      }),
    ).toThrow(/subject mismatch/i);
  });

  it('should reject wrong credential type', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_READ,
      sign: issuer.signer,
    });

    expect(() =>
      verifyCredential({
        token,
        publicKey: issuer.keypair.publicKey,
        expectedType: VC_TYPE_CONTENT_WRITE,
      }),
    ).toThrow(/type mismatch/i);
  });

  it('should reject invalid signature', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const wrong = createNewEd25519Keypair();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    expect(() =>
      verifyCredential({
        token,
        publicKey: wrong.publicKey,
      }),
    ).toThrow(/invalid signature/i);
  });

  it('should reject kid without DID URL', async () => {
    const issuer = makeIdentity();
    await expect(
      createCredential({
        iss: issuer.did,
        sub: 'did:dfos:someone',
        exp: futureUnix(60),
        kid: 'bare_key',
        type: VC_TYPE_CONTENT_WRITE,
        sign: issuer.signer,
      }),
    ).rejects.toThrow(/DID URL/i);
  });

  it('should reject kid DID mismatch with iss', async () => {
    const issuer = makeIdentity();
    const other = makeIdentity();
    await expect(
      createCredential({
        iss: issuer.did,
        sub: 'did:dfos:someone',
        exp: futureUnix(60),
        kid: other.kid,
        type: VC_TYPE_CONTENT_WRITE,
        sign: issuer.signer,
      }),
    ).rejects.toThrow(/does not match/i);
  });

  it('should respect currentTime for expiry checking', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: 5000,
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      iat: 500,
      sign: issuer.signer,
    });

    // passes at time between iat and exp
    const result = verifyCredential({
      token,
      publicKey: issuer.keypair.publicKey,
      currentTime: 1000,
    });
    expect(result.iss).toBe(issuer.did);

    // fails at time after expiry
    expect(() =>
      verifyCredential({
        token,
        publicKey: issuer.keypair.publicKey,
        currentTime: 6000,
      }),
    ).toThrow(/expired/i);
  });

  it('should throw CredentialVerificationError', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const wrong = createNewEd25519Keypair();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    expect(() =>
      verifyCredential({
        token,
        publicKey: wrong.publicKey,
      }),
    ).toThrow(CredentialVerificationError);
  });

  // --- decode unsafe ---

  it('should decode credential without verification', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      contentId: 'k2narrow',
      sign: issuer.signer,
    });

    const decoded = decodeCredentialUnsafe(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.typ).toBe('vc+jwt');
    expect(decoded!.header.kid).toBe(issuer.kid);
    expect(decoded!.claims.iss).toBe(issuer.did);
    expect(decoded!.claims.sub).toBe(subject.did);
    expect(decoded!.claims.vc.type[1]).toBe(VC_TYPE_CONTENT_WRITE);
    expect(decoded!.claims.vc.credentialSubject.contentId).toBe('k2narrow');
  });

  it('should return null for malformed tokens', () => {
    expect(decodeCredentialUnsafe('not-a-token')).toBeNull();
    expect(decodeCredentialUnsafe('a.b')).toBeNull();
    expect(decodeCredentialUnsafe('')).toBeNull();
  });

  // --- VC-JWT structure ---

  it('should produce valid VC-JWT structure', async () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();

    const token = await createCredential({
      iss: issuer.did,
      sub: subject.did,
      exp: futureUnix(60),
      kid: issuer.kid,
      type: VC_TYPE_CONTENT_WRITE,
      sign: issuer.signer,
    });

    const decoded = decodeCredentialUnsafe(token)!;
    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.header.typ).toBe('vc+jwt');
    expect(decoded.claims.vc['@context']).toEqual(['https://www.w3.org/ns/credentials/v2']);
    expect(decoded.claims.vc.type).toEqual(['VerifiableCredential', 'DFOSContentWrite']);
  });
});

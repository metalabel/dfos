import { describe, expect, it } from 'vitest';
import { encodeEd25519Multikey } from '../src/chain';
import type { VerifiedIdentity } from '../src/chain';
import {
  AuthTokenVerificationError,
  createAuthToken,
  createDFOSCredential,
  CredentialVerificationError,
  decodeDFOSCredentialUnsafe,
  isAttenuated,
  matchesResource,
  verifyAuthToken,
  verifyDelegationChain,
  verifyDFOSCredential,
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
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    authKeys: [
      { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
    ],
    assertKeys: [],
    controllerKeys: [],
  };
  return { keypair, keyId, did, kid, signer, identity };
};

const futureUnix = (minutes: number) => Math.floor(Date.now() / 1000) + minutes * 60;
const pastUnix = (minutes: number) => Math.floor(Date.now() / 1000) - minutes * 60;

// shared identity registry for resolveIdentity
const identityMap = new Map<string, VerifiedIdentity>();
const resolveIdentity = async (did: string) => identityMap.get(did);

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
// DFOS credentials
// =============================================================================

describe('dfos credential', () => {
  // --- create / verify round-trip ---

  it('should create and verify round-trip', async () => {
    const issuer = makeIdentity();
    const target = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: target.did,
      att: [{ resource: 'chain:content123', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const verified = await verifyDFOSCredential(token, { resolveIdentity });

    expect(verified.iss).toBe(issuer.did);
    expect(verified.aud).toBe(target.did);
    expect(verified.att).toEqual([{ resource: 'chain:content123', action: 'write' }]);
    expect(verified.prf).toEqual([]);
    expect(verified.credentialCID).toBeTruthy();
    expect(verified.signerKeyId).toBe(issuer.kid);
  });

  // --- verification failures ---

  it('should reject verification with wrong key', async () => {
    const issuer = makeIdentity();
    const wrong = makeIdentity();
    // register identity with issuer's DID and key ID but wrong public key bytes
    identityMap.set(issuer.did, {
      did: issuer.did,
      isDeleted: false,
      authKeys: [
        {
          id: issuer.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(wrong.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
    });

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(/signature/i);

    // clean up
    identityMap.delete(issuer.did);
  });

  it('should reject expired credential', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: pastUnix(5),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(/expired/i);
  });

  it('should reject credential not yet valid (iat in future)', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: 20000,
      iat: 15000,
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity, now: 10000 })).rejects.toThrow(
      /not yet valid/i,
    );
  });

  // --- delegation chains ---

  it('should verify a 2-hop delegation chain (space -> member)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    // root credential: space -> member
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    // leaf credential: member -> anyone, with parent proof
    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    const chain = await verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did });

    expect(chain.rootDID).toBe(space.did);
    expect(chain.chain).toHaveLength(2);
    expect(chain.credential.iss).toBe(member.did);
  });

  it('should verify a 3-hop delegation chain (space -> member -> device)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const device = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);
    identityMap.set(device.did, device.identity);

    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(120),
      signer: space.signer,
      keyId: space.keyId,
    });

    const midToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: device.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(60),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leafToken = await createDFOSCredential({
      issuerDID: device.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [midToken],
      exp: futureUnix(30),
      signer: device.signer,
      keyId: device.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    const chain = await verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did });

    expect(chain.rootDID).toBe(space.did);
    expect(chain.chain).toHaveLength(3);
  });

  // --- attenuation enforcement ---

  it('should accept child that narrows scope', () => {
    const parent = [
      { resource: 'chain:content1', action: 'write' },
      { resource: 'chain:content2', action: 'write' },
    ];
    const child = [{ resource: 'chain:content1', action: 'write' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should reject child that widens scope', () => {
    const parent = [{ resource: 'chain:content1', action: 'write' }];
    const child = [
      { resource: 'chain:content1', action: 'write' },
      { resource: 'chain:content2', action: 'write' },
    ];
    expect(isAttenuated(parent, child)).toBe(false);
  });

  it('should reject child that extends expiry in delegation chain', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(30),
      signer: space.signer,
      keyId: space.keyId,
    });

    // child has exp beyond parent
    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(120),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did }),
    ).rejects.toThrow(/expiry/i);
  });

  // --- resource matching ---

  it('should match chain:X against chain:X', async () => {
    const att = [{ resource: 'chain:content1', action: 'write' }];
    expect(await matchesResource(att, 'chain:content1', 'write')).toBe(true);
  });

  it('should not match chain:X against chain:Y', async () => {
    const att = [{ resource: 'chain:content1', action: 'write' }];
    expect(await matchesResource(att, 'chain:content2', 'write')).toBe(false);
  });

  it('should match manifest:M with lookup', async () => {
    const att = [{ resource: 'manifest:manifest1', action: 'write' }];
    const result = await matchesResource(att, 'chain:content1', 'write', {
      manifestLookup: async () => ['content1', 'content2'],
    });
    expect(result).toBe(true);
  });

  it('should not match manifest:M without lookup', async () => {
    const att = [{ resource: 'manifest:manifest1', action: 'write' }];
    const result = await matchesResource(att, 'chain:content1', 'write');
    expect(result).toBe(false);
  });

  // --- attenuation: manifest / chain interactions ---

  it('should accept manifest:M -> chain:X as valid narrowing', () => {
    const parent = [{ resource: 'manifest:manifest1', action: 'write' }];
    const child = [{ resource: 'chain:content1', action: 'write' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should reject chain:X -> manifest:M as invalid widening', () => {
    const parent = [{ resource: 'chain:content1', action: 'write' }];
    const child = [{ resource: 'manifest:manifest1', action: 'write' }];
    expect(isAttenuated(parent, child)).toBe(false);
  });

  // --- public credentials ---

  it('should create and verify public credential with aud "*"', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:pub1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const verified = await verifyDFOSCredential(token, { resolveIdentity });
    expect(verified.aud).toBe('*');
    expect(verified.iss).toBe(issuer.did);
  });

  // --- decode unsafe ---

  it('should decode credential without verification via decodeDFOSCredentialUnsafe', async () => {
    const issuer = makeIdentity();

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const decoded = decodeDFOSCredentialUnsafe(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.typ).toBe('did:dfos:credential');
    expect(decoded!.header.kid).toBe(issuer.kid);
    expect(decoded!.payload.iss).toBe(issuer.did);
    expect(decoded!.payload.aud).toBe('*');
    expect(decoded!.payload.att).toEqual([{ resource: 'chain:abc', action: 'write' }]);
    expect(decoded!.header.cid).toBeTruthy();
  });

  it('should return null for malformed tokens via decodeDFOSCredentialUnsafe', () => {
    expect(decodeDFOSCredentialUnsafe('not-a-token')).toBeNull();
    expect(decodeDFOSCredentialUnsafe('a.b')).toBeNull();
    expect(decodeDFOSCredentialUnsafe('')).toBeNull();
  });

  // --- delegation failures ---

  it('should reject delegation gap (child iss does not match any parent aud)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const outsider = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);
    identityMap.set(outsider.did, outsider.identity);

    // root credential: space -> member
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    // outsider tries to use root credential they are not audience of
    const leafToken = await createDFOSCredential({
      issuerDID: outsider.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: outsider.signer,
      keyId: outsider.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did }),
    ).rejects.toThrow(/delegation gap/i);
  });

  it('should reject delegation root mismatch', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const wrongRoot = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    // root credential issued by space
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    // verify against wrong root DID
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: wrongRoot.did }),
    ).rejects.toThrow(/root/i);
  });

  it('should throw CredentialVerificationError on failures', async () => {
    const issuer = makeIdentity();
    const wrong = makeIdentity();
    identityMap.set(issuer.did, {
      did: issuer.did,
      isDeleted: false,
      authKeys: [
        {
          id: issuer.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(wrong.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
    });

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(
      CredentialVerificationError,
    );

    identityMap.delete(issuer.did);
  });
});

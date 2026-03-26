import { describe, expect, it } from 'vitest';
import {
  ArtifactPayload,
  encodeEd25519Multikey,
  MAX_ARTIFACT_PAYLOAD_SIZE,
  signArtifact,
  verifyArtifact,
} from '../src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// artifact
// =============================================================================

describe('artifact', () => {
  const makeIdentity = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const kid = `${did}#${keyId}`;
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    const resolveKey = async (_kid: string) => keypair.publicKey;
    return { keypair, keyId, did, kid, signer, resolveKey };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  // --- round-trip ---

  it('should sign and verify an artifact round-trip', async () => {
    const id = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: {
        $schema: 'dfos:relay-profile',
        name: 'Test Relay',
        operator: 'Test Operator',
      },
      createdAt: ts(),
    };

    const { jwsToken, artifactCID } = await signArtifact({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyArtifact({
      jwsToken,
      resolveKey: id.resolveKey,
    });

    expect(result.payload.did).toBe(id.did);
    expect(result.payload.content.$schema).toBe('dfos:relay-profile');
    expect(result.payload.content['name']).toBe('Test Relay');
    expect(result.artifactCID).toBe(artifactCID);
  });

  // --- CID determinism ---

  it('should produce deterministic CID for same payload', async () => {
    const id = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: { $schema: 'dfos:test', value: 42 },
      createdAt: '2026-01-01T00:00:00.000Z',
    };

    const r1 = await signArtifact({ payload, signer: id.signer, kid: id.kid });
    const r2 = await signArtifact({ payload, signer: id.signer, kid: id.kid });

    expect(r1.artifactCID).toBe(r2.artifactCID);
  });

  // --- JWS header format ---

  it('should use did:dfos:artifact as JWS typ with correct kid and cid', async () => {
    const id = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: { $schema: 'dfos:test' },
      createdAt: ts(),
    };

    const { jwsToken, artifactCID } = await signArtifact({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const decoded = decodeJwsUnsafe(jwsToken)!;
    expect(decoded.header.typ).toBe('did:dfos:artifact');
    expect(decoded.header.kid).toBe(id.kid);
    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.header.cid).toBe(artifactCID);
  });

  // --- kid DID mismatch ---

  it('should reject artifact with kid DID not matching payload did', async () => {
    const author = makeIdentity();
    const other = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: author.did,
      content: { $schema: 'dfos:test' },
      createdAt: ts(),
    };

    const { jwsToken } = await signArtifact({
      payload,
      signer: other.signer,
      kid: other.kid,
    });

    await expect(verifyArtifact({ jwsToken, resolveKey: other.resolveKey })).rejects.toThrow(
      /kid DID does not match/i,
    );
  });

  // --- invalid signature ---

  it('should reject artifact with invalid signature (wrong key)', async () => {
    const id = makeIdentity();
    const wrongKey = createNewEd25519Keypair();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: { $schema: 'dfos:test' },
      createdAt: ts(),
    };

    const { jwsToken } = await signArtifact({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    await expect(
      verifyArtifact({
        jwsToken,
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid artifact signature/i);
  });

  // --- content preserves arbitrary keys ---

  it('should preserve arbitrary content keys through sign/verify', async () => {
    const id = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: {
        $schema: 'dfos:relay-profile',
        name: 'Edge Relay',
        description: 'Proof-plane relay on edge',
        image: { id: 'content123', uri: 'https://cdn.example/logo.png' },
        operator: 'Metalabel',
        motd: 'gm from the edge',
        nested: { deep: { value: true } },
      },
      createdAt: ts(),
    };

    const { jwsToken } = await signArtifact({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyArtifact({
      jwsToken,
      resolveKey: id.resolveKey,
    });

    expect(result.payload.content['name']).toBe('Edge Relay');
    expect(result.payload.content['motd']).toBe('gm from the edge');
    expect((result.payload.content['image'] as Record<string, unknown>)['uri']).toBe(
      'https://cdn.example/logo.png',
    );
  });

  // --- size limit ---

  it('should reject artifact exceeding MAX_ARTIFACT_PAYLOAD_SIZE on sign', async () => {
    const id = makeIdentity();

    // create a payload with a very large content field
    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: {
        $schema: 'dfos:test',
        data: 'x'.repeat(MAX_ARTIFACT_PAYLOAD_SIZE),
      },
      createdAt: ts(),
    };

    await expect(signArtifact({ payload, signer: id.signer, kid: id.kid })).rejects.toThrow(
      /exceeds max size/i,
    );
  });

  // --- missing $schema ---

  it('should reject artifact without $schema in content', async () => {
    const id = makeIdentity();

    const payload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: { name: 'no schema' },
      createdAt: ts(),
    };

    // sign manually since the type won't match ArtifactPayload
    const encoded = await dagCborCanonicalEncode(payload);
    const artifactCID = encoded.cid.toString();
    const { createJws } = await import('../src/crypto/jws');
    const jwsToken = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:artifact', kid: id.kid, cid: artifactCID },
      payload: payload as unknown as Record<string, unknown>,
      sign: id.signer,
    });

    await expect(verifyArtifact({ jwsToken, resolveKey: id.resolveKey })).rejects.toThrow();
  });

  // --- bare kid (no DID URL) ---

  it('should reject artifact with bare kid (not a DID URL)', async () => {
    const id = makeIdentity();

    const payload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: id.did,
      content: { $schema: 'dfos:test' },
      createdAt: ts(),
    };

    const encoded = await dagCborCanonicalEncode(payload);
    const artifactCID = encoded.cid.toString();
    const { createJws } = await import('../src/crypto/jws');
    const jwsToken = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:artifact', kid: id.keyId, cid: artifactCID },
      payload: payload as unknown as Record<string, unknown>,
      sign: id.signer,
    });

    await expect(verifyArtifact({ jwsToken, resolveKey: id.resolveKey })).rejects.toThrow(
      /kid must be a DID URL/i,
    );
  });
});

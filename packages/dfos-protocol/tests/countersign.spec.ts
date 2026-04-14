import { describe, expect, it } from 'vitest';
import {
  signArtifact,
  signBeacon,
  signContentOperation,
  signCountersignature,
  verifyCountersignature,
} from '../src/chain';
import type {
  ArtifactPayload,
  BeaconPayload,
  ContentOperation,
  CountersignPayload,
} from '../src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// helpers
// =============================================================================

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

const makeDocCID = async (content: object) => {
  const encoded = await dagCborCanonicalEncode(content);
  return encoded.cid.toString();
};

// =============================================================================
// countersignature — standalone witness attestation
// =============================================================================

describe('countersignature', () => {
  const createTarget = async () => {
    const author = makeIdentity();
    const docCID = await makeDocCID({ type: 'post', title: 'Hello', body: 'World' });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: author.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { operationCID } = await signContentOperation({
      operation: op,
      signer: author.signer,
      kid: author.kid,
    });
    return { author, operationCID };
  };

  // --- round-trip ---

  it('should sign and verify a countersignature round-trip', async () => {
    const { author, operationCID } = await createTarget();
    const witness = makeIdentity();

    const payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: operationCID,
      createdAt: ts(1),
    };

    const { jwsToken, countersignCID } = await signCountersignature({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    const result = await verifyCountersignature({
      jwsToken,
      resolveKey: witness.resolveKey,
    });

    expect(result.witnessDID).toBe(witness.did);
    expect(result.targetCID).toBe(operationCID);
    expect(result.countersignCID).toBe(countersignCID);
    // countersign CID is distinct from target CID
    expect(result.countersignCID).not.toBe(operationCID);
  });

  // --- CID determinism ---

  it('should produce deterministic CID for same payload', async () => {
    const witness = makeIdentity();
    const payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y',
      createdAt: '2026-01-01T00:00:00.000Z',
    };

    const r1 = await signCountersignature({ payload, signer: witness.signer, kid: witness.kid });
    const r2 = await signCountersignature({ payload, signer: witness.signer, kid: witness.kid });
    expect(r1.countersignCID).toBe(r2.countersignCID);
  });

  // --- JWS header format ---

  it('should use did:dfos:countersign as JWS typ', async () => {
    const witness = makeIdentity();
    const payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y',
      createdAt: ts(),
    };

    const { jwsToken, countersignCID } = await signCountersignature({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    const decoded = decodeJwsUnsafe(jwsToken)!;
    expect(decoded.header.typ).toBe('did:dfos:countersign');
    expect(decoded.header.kid).toBe(witness.kid);
    expect(decoded.header.cid).toBe(countersignCID);
  });

  // --- kid DID mismatch ---

  it('should reject countersignature with kid DID not matching payload did', async () => {
    const witness = makeIdentity();
    const other = makeIdentity();

    const payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y',
      createdAt: ts(),
    };

    // sign with other's kid (DID mismatch)
    const { jwsToken } = await signCountersignature({
      payload,
      signer: other.signer,
      kid: other.kid,
    });

    await expect(
      verifyCountersignature({ jwsToken, resolveKey: other.resolveKey }),
    ).rejects.toThrow(/kid DID does not match/i);
  });

  // --- invalid signature ---

  it('should reject countersignature with invalid signature', async () => {
    const witness = makeIdentity();
    const wrongKey = createNewEd25519Keypair();

    const payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y',
      createdAt: ts(),
    };

    const { jwsToken } = await signCountersignature({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    await expect(
      verifyCountersignature({
        jwsToken,
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid countersignature/i);
  });

  // --- multiple witnesses ---

  it('should allow multiple witnesses to countersign the same target', async () => {
    const { operationCID } = await createTarget();
    const witnesses = [makeIdentity(), makeIdentity(), makeIdentity()];

    const results = await Promise.all(
      witnesses.map(async (w) => {
        const payload: CountersignPayload = {
          version: 1,
          type: 'countersign',
          did: w.did,
          targetCID: operationCID,
          createdAt: ts(),
        };
        const { jwsToken, countersignCID } = await signCountersignature({
          payload,
          signer: w.signer,
          kid: w.kid,
        });
        return { jwsToken, countersignCID, witness: w };
      }),
    );

    // each countersign has a distinct CID (different witness DID in payload)
    const cids = new Set(results.map((r) => r.countersignCID));
    expect(cids.size).toBe(3);

    // all verify independently
    for (const r of results) {
      const verified = await verifyCountersignature({
        jwsToken: r.jwsToken,
        resolveKey: r.witness.resolveKey,
      });
      expect(verified.targetCID).toBe(operationCID);
      expect(verified.witnessDID).toBe(r.witness.did);
    }
  });

  // --- countersign a beacon ---

  it('should countersign a beacon', async () => {
    const controller = makeIdentity();
    const witness = makeIdentity();

    const beaconPayload: BeaconPayload = {
      version: 1,
      type: 'beacon',
      did: controller.did,
      manifestContentId: 'test_manifest_content_id',
      createdAt: ts(),
    };
    const { beaconCID } = await signBeacon({
      payload: beaconPayload,
      signer: controller.signer,
      kid: controller.kid,
    });

    const csPayload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: beaconCID,
      createdAt: ts(1),
    };
    const { jwsToken } = await signCountersignature({
      payload: csPayload,
      signer: witness.signer,
      kid: witness.kid,
    });

    const result = await verifyCountersignature({
      jwsToken,
      resolveKey: witness.resolveKey,
    });
    expect(result.targetCID).toBe(beaconCID);
    expect(result.witnessDID).toBe(witness.did);
  });

  // --- countersign an artifact ---

  it('should countersign an artifact', async () => {
    const author = makeIdentity();
    const witness = makeIdentity();

    const artifactPayload: ArtifactPayload = {
      version: 1,
      type: 'artifact',
      did: author.did,
      content: { $schema: 'test/v1', title: 'Hello artifact' },
      createdAt: ts(),
    };
    const { artifactCID } = await signArtifact({
      payload: artifactPayload,
      signer: author.signer,
      kid: author.kid,
    });

    const csPayload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: artifactCID,
      createdAt: ts(1),
    };
    const { jwsToken } = await signCountersignature({
      payload: csPayload,
      signer: witness.signer,
      kid: witness.kid,
    });

    const result = await verifyCountersignature({
      jwsToken,
      resolveKey: witness.resolveKey,
    });
    expect(result.targetCID).toBe(artifactCID);
    expect(result.witnessDID).toBe(witness.did);
  });

  // --- countersign a countersign (meta-attestation) ---

  it('should countersign another countersign', async () => {
    const { operationCID } = await createTarget();
    const witness1 = makeIdentity();
    const witness2 = makeIdentity();

    // witness1 countersigns the original
    const cs1Payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness1.did,
      targetCID: operationCID,
      createdAt: ts(1),
    };
    const { countersignCID: cs1CID } = await signCountersignature({
      payload: cs1Payload,
      signer: witness1.signer,
      kid: witness1.kid,
    });

    // witness2 countersigns witness1's countersign
    const cs2Payload: CountersignPayload = {
      version: 1,
      type: 'countersign',
      did: witness2.did,
      targetCID: cs1CID,
      createdAt: ts(2),
    };
    const { jwsToken: cs2Token } = await signCountersignature({
      payload: cs2Payload,
      signer: witness2.signer,
      kid: witness2.kid,
    });

    const result = await verifyCountersignature({
      jwsToken: cs2Token,
      resolveKey: witness2.resolveKey,
    });
    expect(result.targetCID).toBe(cs1CID);
    expect(result.witnessDID).toBe(witness2.did);
  });
});

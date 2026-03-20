import { describe, expect, it } from 'vitest';
import {
  signBeacon,
  signContentOperation,
  signCountersignature,
  verifyBeaconCountersignature,
  verifyCountersignature,
} from '../src/chain';
import type { BeaconPayload, ContentOperation } from '../src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// countersignature
// =============================================================================

describe('countersignature', () => {
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

  /** Create a signed content operation from the author, return it along with both identities */
  const createSignedOperation = async () => {
    const author = makeIdentity();
    const witness = makeIdentity();
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

    const { jwsToken: authorJws, operationCID } = await signContentOperation({
      operation: op,
      signer: author.signer,
      kid: author.kid,
    });

    return { author, witness, op, authorJws, operationCID };
  };

  // --- round-trip ---

  it('should sign a countersignature and verify it', async () => {
    const { witness, op, operationCID } = await createSignedOperation();

    const { jwsToken: witnessJws, operationCID: witnessCID } = await signCountersignature({
      operationPayload: op,
      signer: witness.signer,
      kid: witness.kid,
    });

    const result = await verifyCountersignature({
      jwsToken: witnessJws,
      expectedCID: operationCID,
      resolveKey: witness.resolveKey,
    });

    expect(result.authorDID).toBe(op.did);
    expect(result.witnessDID).toBe(witness.did);
    expect(result.operationCID).toBe(operationCID);
    expect(witnessCID).toBe(operationCID);
  });

  // --- CID match ---

  it('should produce same CID as the original operation', async () => {
    const { witness, op, operationCID } = await createSignedOperation();

    const { operationCID: witnessCID } = await signCountersignature({
      operationPayload: op,
      signer: witness.signer,
      kid: witness.kid,
    });

    expect(witnessCID).toBe(operationCID);
  });

  // --- author cannot countersign own operation ---

  it('should reject countersignature where kid DID equals payload did', async () => {
    const { author, op, operationCID } = await createSignedOperation();

    // author tries to countersign their own operation
    const { jwsToken } = await signCountersignature({
      operationPayload: op,
      signer: author.signer,
      kid: author.kid,
    });

    await expect(
      verifyCountersignature({
        jwsToken,
        expectedCID: operationCID,
        resolveKey: author.resolveKey,
      }),
    ).rejects.toThrow(/must differ from operation did/i);
  });

  // --- wrong expectedCID ---

  it('should reject countersignature with wrong expectedCID', async () => {
    const { witness, op } = await createSignedOperation();

    const { jwsToken } = await signCountersignature({
      operationPayload: op,
      signer: witness.signer,
      kid: witness.kid,
    });

    await expect(
      verifyCountersignature({
        jwsToken,
        expectedCID: 'bafyreifakecid',
        resolveKey: witness.resolveKey,
      }),
    ).rejects.toThrow(/does not match expected CID/i);
  });

  // --- invalid signature ---

  it('should reject countersignature with invalid signature (wrong key)', async () => {
    const { witness, op, operationCID } = await createSignedOperation();
    const wrongKey = createNewEd25519Keypair();

    const { jwsToken } = await signCountersignature({
      operationPayload: op,
      signer: witness.signer,
      kid: witness.kid,
    });

    // resolve to wrong key
    await expect(
      verifyCountersignature({
        jwsToken,
        expectedCID: operationCID,
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid countersignature/i);
  });

  // --- multiple witnesses ---

  it('should allow multiple witnesses to countersign the same operation', async () => {
    const { op, operationCID } = await createSignedOperation();

    const witness1 = makeIdentity();
    const witness2 = makeIdentity();
    const witness3 = makeIdentity();

    const results = await Promise.all(
      [witness1, witness2, witness3].map(async (w) => {
        const { jwsToken, operationCID: cid } = await signCountersignature({
          operationPayload: op,
          signer: w.signer,
          kid: w.kid,
        });
        return { jwsToken, cid, witness: w };
      }),
    );

    // all produce the same CID
    for (const r of results) {
      expect(r.cid).toBe(operationCID);
    }

    // all verify independently
    for (const r of results) {
      const verified = await verifyCountersignature({
        jwsToken: r.jwsToken,
        expectedCID: operationCID,
        resolveKey: r.witness.resolveKey,
      });
      expect(verified.operationCID).toBe(operationCID);
      expect(verified.witnessDID).toBe(r.witness.did);
      expect(verified.authorDID).toBe(op.did);
    }
  });
});

// =============================================================================
// beacon countersignature
// =============================================================================

describe('beacon countersignature', () => {
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

  const merkleRoot = 'a'.repeat(64);

  const createSignedBeacon = async () => {
    const controller = makeIdentity();
    const witness = makeIdentity();

    const payload: BeaconPayload = {
      version: 1,
      type: 'beacon',
      did: controller.did,
      merkleRoot,
      createdAt: ts(),
    };

    const encoded = await dagCborCanonicalEncode(payload);
    const beaconCID = encoded.cid.toString();

    return { controller, witness, payload, beaconCID };
  };

  // --- round-trip ---

  it('should sign a beacon countersignature and verify it', async () => {
    const { witness, payload, beaconCID } = await createSignedBeacon();

    const { jwsToken, beaconCID: witnessCID } = await signBeacon({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    const result = await verifyBeaconCountersignature({
      jwsToken,
      expectedCID: beaconCID,
      resolveKey: witness.resolveKey,
    });

    expect(result.controllerDID).toBe(payload.did);
    expect(result.witnessDID).toBe(witness.did);
    expect(result.beaconCID).toBe(beaconCID);
    expect(witnessCID).toBe(beaconCID);
  });

  // --- CID match ---

  it('should produce same CID as the original beacon', async () => {
    const { witness, payload, beaconCID } = await createSignedBeacon();

    const { beaconCID: witnessCID } = await signBeacon({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    expect(witnessCID).toBe(beaconCID);
  });

  // --- controller cannot countersign own beacon ---

  it('should reject beacon countersignature where kid DID equals payload did', async () => {
    const { controller, payload, beaconCID } = await createSignedBeacon();

    const { jwsToken } = await signBeacon({
      payload,
      signer: controller.signer,
      kid: controller.kid,
    });

    await expect(
      verifyBeaconCountersignature({
        jwsToken,
        expectedCID: beaconCID,
        resolveKey: controller.resolveKey,
      }),
    ).rejects.toThrow(/must differ from beacon did/i);
  });

  // --- wrong expectedCID ---

  it('should reject beacon countersignature with wrong expectedCID', async () => {
    const { witness, payload } = await createSignedBeacon();

    const { jwsToken } = await signBeacon({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    await expect(
      verifyBeaconCountersignature({
        jwsToken,
        expectedCID: 'bafyreifakecid',
        resolveKey: witness.resolveKey,
      }),
    ).rejects.toThrow(/does not match expected CID/i);
  });

  // --- invalid signature ---

  it('should reject beacon countersignature with invalid signature (wrong key)', async () => {
    const { witness, payload, beaconCID } = await createSignedBeacon();
    const wrongKey = createNewEd25519Keypair();

    const { jwsToken } = await signBeacon({
      payload,
      signer: witness.signer,
      kid: witness.kid,
    });

    await expect(
      verifyBeaconCountersignature({
        jwsToken,
        expectedCID: beaconCID,
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid beacon countersignature/i);
  });

  // --- multiple witnesses ---

  it('should allow multiple witnesses to countersign the same beacon', async () => {
    const { payload, beaconCID } = await createSignedBeacon();

    const witness1 = makeIdentity();
    const witness2 = makeIdentity();
    const witness3 = makeIdentity();

    const results = await Promise.all(
      [witness1, witness2, witness3].map(async (w) => {
        const { jwsToken, beaconCID: cid } = await signBeacon({
          payload,
          signer: w.signer,
          kid: w.kid,
        });
        return { jwsToken, cid, witness: w };
      }),
    );

    // all produce the same CID
    for (const r of results) {
      expect(r.cid).toBe(beaconCID);
    }

    // all verify independently
    for (const r of results) {
      const verified = await verifyBeaconCountersignature({
        jwsToken: r.jwsToken,
        expectedCID: beaconCID,
        resolveKey: r.witness.resolveKey,
      });
      expect(verified.beaconCID).toBe(beaconCID);
      expect(verified.witnessDID).toBe(r.witness.did);
      expect(verified.controllerDID).toBe(payload.did);
    }
  });
});

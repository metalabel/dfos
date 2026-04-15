import {
  encodeEd25519Multikey,
  MAX_ARTIFACT_PAYLOAD_SIZE,
  signArtifact,
  signBeacon,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  signRevocation,
  type ArtifactPayload,
  type BeaconPayload,
  type ContentOperation,
  type CountersignPayload,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createAuthToken,
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { bootstrapRelayIdentity, createRelay, ingestOperations, MemoryRelayStore } from '../src';
import type { PeerClient, PeerLogEntry, RelayIdentity } from '../src';

// =============================================================================
// helpers
// =============================================================================

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) =>
  new Date(Date.now() + offset * 60_000).toISOString().replace(/\d{4}Z$/, (m) => m);

/** Set during beforeEach — the relay's JIT-generated DID */
let RELAY_DID: string;
let RELAY_IDENTITY: RelayIdentity;

/** Create a complete identity chain (genesis) and return the DID and signing info */
const createIdentity = async () => {
  const controller = makeKey();
  const authKey = makeKey();

  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [authKey.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    createdAt: ts(),
  };

  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });

  // derive DID from the genesis operation CID
  const encoded = await dagCborCanonicalEncode(createOp);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');

  return { did, controller, authKey, jwsToken, operationCID };
};

/** Create a content chain genesis operation signed by a given identity */
const createContentOp = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  opts?: { createdAt?: string },
) => {
  // create a document and derive its CID
  const document = { type: 'post', title: 'hello world', body: 'test content' };
  const docEncoded = await dagCborCanonicalEncode(document as unknown as Record<string, unknown>);
  const documentCID = docEncoded.cid.toString();

  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID,
    baseDocumentCID: null,
    createdAt: opts?.createdAt ?? ts(1),
    note: null,
  };

  const kid = `${identity.did}#${identity.authKey.keyId}`;
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer: identity.authKey.signer,
    kid,
  });

  return { jwsToken, operationCID, documentCID, document };
};

/** Create an auth token for a given identity targeting the test relay */
const createTestAuthToken = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  keyOverride?: { keyId: string; signer: (msg: Uint8Array) => Promise<Uint8Array> },
) => {
  const now = Math.floor(Date.now() / 1000);
  const key = keyOverride ?? identity.authKey;
  return createAuthToken({
    iss: identity.did,
    aud: RELAY_DID,
    exp: now + 300,
    kid: `${identity.did}#${key.keyId}`,
    iat: now,
    sign: key.signer,
  });
};

// =============================================================================
// relay-backed mock peer client
// =============================================================================

/**
 * Mock PeerClient backed by a real MemoryRelayStore. Reads chain data and global
 * log directly from the backing store using the same pagination logic as the
 * real HTTP endpoints. Records submitOperations calls for gossip assertion.
 */
class RelayBackedPeerClient implements PeerClient {
  readonly submitCalls: { peerUrl: string; operations: string[] }[] = [];

  constructor(
    private backingStore: MemoryRelayStore,
    private pageSize?: number,
  ) {}

  async getIdentityLog(
    _peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null> {
    const chain = await this.backingStore.getIdentityChain(did);
    if (!chain) return null;
    return this.paginateChainLog(chain.log, params);
  }

  async getContentLog(
    _peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null> {
    const chain = await this.backingStore.getContentChain(contentId);
    if (!chain) return null;
    return this.paginateChainLog(chain.log, params);
  }

  async getOperationLog(
    _peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null> {
    const limit = this.pageSize ?? params?.limit ?? 1000;
    const result = await this.backingStore.readLog({
      ...(params?.after ? { after: params.after } : {}),
      limit,
    });
    return {
      entries: result.entries.map((e) => ({ cid: e.cid, jwsToken: e.jwsToken })),
      cursor: result.cursor,
    };
  }

  async submitOperations(peerUrl: string, operations: string[]): Promise<void> {
    this.submitCalls.push({ peerUrl, operations });
  }

  private paginateChainLog(
    log: string[],
    params?: { after?: string; limit?: number },
  ): { entries: PeerLogEntry[]; cursor: string | null } {
    const limit = this.pageSize ?? params?.limit ?? 1000;
    const entries: PeerLogEntry[] = log.map((jws) => {
      const decoded = decodeJwsUnsafe(jws);
      return { cid: decoded?.header.cid || '', jwsToken: jws };
    });

    let startIdx = 0;
    if (params?.after) {
      const idx = entries.findIndex((e) => e.cid === params.after);
      startIdx = idx >= 0 ? idx + 1 : entries.length;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const cursor = page.length === limit ? page[page.length - 1]!.cid : null;
    return { entries: page, cursor };
  }
}

// =============================================================================
// tests
// =============================================================================

describe('web relay', () => {
  let store: MemoryRelayStore;
  let app: Awaited<ReturnType<typeof createRelay>>;

  beforeEach(async () => {
    store = new MemoryRelayStore();
    RELAY_IDENTITY = await bootstrapRelayIdentity(store);
    RELAY_DID = RELAY_IDENTITY.did;
    app = await createRelay({ store, identity: RELAY_IDENTITY });
  });

  const req = (path: string, init?: RequestInit) =>
    app.app.request(`http://localhost${path}`, init);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = async (res: Response): Promise<any> => res.json();

  const postOps = (operations: string[]) =>
    req('/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations }),
    });

  const putBlob = (contentId: string, operationCID: string, authToken: string, body: Uint8Array) =>
    req(`/content/${contentId}/blob/${operationCID}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${authToken}`,
        'content-type': 'application/octet-stream',
      },
      body,
    });

  // ---------------------------------------------------------------------------
  // well-known
  // ---------------------------------------------------------------------------

  describe('well-known', () => {
    it('should return relay metadata', async () => {
      const res = await req('/.well-known/dfos-relay');
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.did).toBe(RELAY_DID);
      expect(body.protocol).toBe('dfos-web-relay');
    });

    it('should include capabilities with proof and content by default', async () => {
      const res = await req('/.well-known/dfos-relay');
      const body = await json(res);
      expect(body.capabilities.proof).toBe(true);
      expect(body.capabilities.content).toBe(true);
      expect(body.capabilities.documents).toBe(true);
      expect(body.capabilities.log).toBe(true);
    });

    it('should include content: false in capabilities when relay created with content: false', async () => {
      const noContentRelay = await createRelay({ store, identity: RELAY_IDENTITY, content: false });
      const res = await noContentRelay.app.request('http://localhost/.well-known/dfos-relay');
      const body = (await res.json()) as Record<string, unknown>;
      const caps = body.capabilities as Record<string, unknown>;
      expect(caps.content).toBe(false);
      expect(caps.documents).toBe(false);
    });

    it('should always include profile in well-known response', async () => {
      const res = await req('/.well-known/dfos-relay');
      const body = await json(res);
      expect(typeof body.profile).toBe('string');
      expect(body.profile).toBe(RELAY_IDENTITY.profileArtifactJws);
    });
  });

  // ---------------------------------------------------------------------------
  // identity chain lifecycle
  // ---------------------------------------------------------------------------

  describe('identity chain ingestion', () => {
    it('should accept a genesis identity operation', async () => {
      const identity = await createIdentity();
      const res = await postOps([identity.jwsToken]);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.results).toHaveLength(1);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('identity-op');
      expect(body.results[0].chainId).toBe(identity.did);
    });

    it('should serve identity chain via GET', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/identities/${identity.did}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.did).toBe(identity.did);
      expect(body.headCID).toBeDefined();
      expect(body.state.isDeleted).toBe(false);
    });

    it('should return 404 for unknown identity', async () => {
      const res = await req('/identities/did:dfos:unknown000000000000');
      expect(res.status).toBe(404);
    });

    it('should accept identity chain extension', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // create an update operation
      const newKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, newKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');

      // verify chain now has 2 ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.headCID).toBeDefined();
    });

    it('should accept identity create + update in a single batch', async () => {
      const identity = await createIdentity();

      // create an update operation that chains off the genesis
      const newKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, newKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // submit in REVERSE order — update first, then genesis
      // the intra-kind topological sort should fix the processing order
      // but results must come back in SUBMISSION order
      const res = await postOps([updateToken, identity.jwsToken]);
      const body = await json(res);
      const newResults = body.results.filter((r: { status: string }) => r.status === 'new');
      expect(newResults).toHaveLength(2);

      // results[0] should be the update (submitted first), results[1] should be the genesis
      expect(body.results[0].cid).toBeTruthy();
      expect(body.results[1].cid).toBeTruthy();
      expect(body.results[0].cid).not.toBe(body.results[1].cid);

      // verify chain has both ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.headCID).toBeDefined();
    });

    it('should accept a 3-step identity chain in a single batch (any order)', async () => {
      const identity = await createIdentity();

      // update1 chains off genesis
      const key2 = makeKey();
      const update1Op: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, key2.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };
      const { jwsToken: update1Token, operationCID: update1CID } = await signIdentityOperation({
        operation: update1Op,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // update2 chains off update1
      const key3 = makeKey();
      const update2Op: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: update1CID,
        authKeys: [key3.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(3),
      };
      const { jwsToken: update2Token } = await signIdentityOperation({
        operation: update2Op,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // submit in REVERSE order: update2, update1, genesis
      const res = await postOps([update2Token, update1Token, identity.jwsToken]);
      const body = await json(res);
      const newResults = body.results.filter((r: { status: string }) => r.status === 'new');
      expect(newResults).toHaveLength(3);

      // verify the chain has all 3 ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.headCID).toBeDefined();
    });

    it('should be idempotent for duplicate operations', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);
      const res = await postOps([identity.jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('duplicate');
    });
  });

  // ---------------------------------------------------------------------------
  // content chain lifecycle
  // ---------------------------------------------------------------------------

  describe('content chain ingestion', () => {
    it('should accept a content chain genesis after identity exists', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);

      // submit both in one batch — content FIRST, identity SECOND
      // dependency sort processes identity first, but results must match submission order
      const res = await postOps([content.jwsToken, identity.jwsToken]);
      const body = await json(res);

      // both should be new (dependency sort ensures identity is processed first)
      const newResults = body.results.filter((r: { status: string }) => r.status === 'new');
      expect(newResults).toHaveLength(2);

      // results must be in submission order: content-op first, identity-op second
      expect(body.results[0].kind).toBe('content-op');
      expect(body.results[1].kind).toBe('identity-op');
    });

    it('should serve content chain via GET', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // find the contentId from the ingestion result
      const ingestRes = await postOps([content.jwsToken]); // idempotent re-submit
      const ingestBody = await json(ingestRes);
      const contentId = ingestBody.results[0].chainId;

      const res = await req(`/content/${contentId}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.contentId).toBe(contentId);
      expect(body.headCID).toBeDefined();
      expect(body.state.currentDocumentCID).toBe(content.documentCID);
    });

    it('should reject content operation when identity is unknown', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);

      // submit content op without identity — should fail
      const res = await postOps([content.jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });
  });

  // ---------------------------------------------------------------------------
  // operation lookup
  // ---------------------------------------------------------------------------

  describe('operation lookup', () => {
    it('should serve individual operations by CID', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/operations/${identity.operationCID}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.cid).toBe(identity.operationCID);
      expect(body.jwsToken).toBe(identity.jwsToken);
      expect(body.chainType).toBe('identity');
    });

    it('should return 404 for unknown operation', async () => {
      const res = await req(
        '/operations/bafyreibogus000000000000000000000000000000000000000000000',
      );
      expect(res.status).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // beacon lifecycle
  // ---------------------------------------------------------------------------

  describe('beacon ingestion', () => {
    it('should accept a beacon from a known identity', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const beaconPayload: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        manifestContentId: 'test_manifest_content_id',
        createdAt: ts(2),
      };

      const kid = `${identity.did}#${identity.controller.keyId}`;
      const { jwsToken: beaconToken } = await signBeacon({
        payload: beaconPayload,
        signer: identity.controller.signer,
        kid,
      });

      const res = await postOps([beaconToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('beacon');

      // query the beacon
      const beaconRes = await req(`/beacons/${identity.did}`);
      expect(beaconRes.status).toBe(200);
      const beaconBody = await json(beaconRes);
      expect(beaconBody.manifestContentId).toBe('test_manifest_content_id');
    });

    it('should replace beacon with newer one', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const kid = `${identity.did}#${identity.controller.keyId}`;

      const beacon1: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        manifestContentId: 'test_manifest_content_id_a',
        createdAt: ts(2),
      };
      const { jwsToken: token1 } = await signBeacon({
        payload: beacon1,
        signer: identity.controller.signer,
        kid,
      });

      const beacon2: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        manifestContentId: 'test_manifest_content_id_b',
        createdAt: ts(3),
      };
      const { jwsToken: token2 } = await signBeacon({
        payload: beacon2,
        signer: identity.controller.signer,
        kid,
      });

      await postOps([token1]);
      await postOps([token2]);

      const beaconRes = await req(`/beacons/${identity.did}`);
      const beaconBody = await json(beaconRes);
      expect(beaconBody.manifestContentId).toBe('test_manifest_content_id_b');
    });
  });

  // ---------------------------------------------------------------------------
  // countersignature lifecycle
  // ---------------------------------------------------------------------------

  describe('countersignature ingestion', () => {
    it('should accept a countersignature on a known content operation', async () => {
      const author = await createIdentity();
      const witness = await createIdentity();
      const content = await createContentOp(author);

      // ingest identities + content op
      await postOps([author.jwsToken, witness.jwsToken, content.jwsToken]);

      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const csPayload: CountersignPayload = {
        version: 1,
        type: 'countersign',
        did: witness.did,
        targetCID: content.operationCID,
        createdAt: ts(2),
      };
      const { jwsToken: csToken } = await signCountersignature({
        payload: csPayload,
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      const res = await postOps([csToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('countersign');
      expect(body.results[0].chainId).toBe(content.operationCID);

      // query countersignatures
      const csRes = await req(`/operations/${content.operationCID}/countersignatures`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });

    it('should be idempotent for duplicate countersignatures', async () => {
      const author = await createIdentity();
      const witness = await createIdentity();
      const content = await createContentOp(author);

      await postOps([author.jwsToken, witness.jwsToken, content.jwsToken]);

      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const csPayload: CountersignPayload = {
        version: 1,
        type: 'countersign',
        did: witness.did,
        targetCID: content.operationCID,
        createdAt: ts(2),
      };
      const { jwsToken: csToken } = await signCountersignature({
        payload: csPayload,
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      // submit the same countersignature twice
      await postOps([csToken]);
      await postOps([csToken]);

      // should still only have one
      const csRes = await req(`/operations/${content.operationCID}/countersignatures`);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });

    it('should count distinct witnesses independently', async () => {
      const author = await createIdentity();
      const witness1 = await createIdentity();
      const witness2 = await createIdentity();
      const content = await createContentOp(author);

      await postOps([author.jwsToken, witness1.jwsToken, witness2.jwsToken, content.jwsToken]);

      // witness1 countersigns
      const { jwsToken: cs1 } = await signCountersignature({
        payload: {
          version: 1,
          type: 'countersign',
          did: witness1.did,
          targetCID: content.operationCID,
          createdAt: ts(2),
        },
        signer: witness1.authKey.signer,
        kid: `${witness1.did}#${witness1.authKey.keyId}`,
      });

      // witness2 countersigns
      const { jwsToken: cs2 } = await signCountersignature({
        payload: {
          version: 1,
          type: 'countersign',
          did: witness2.did,
          targetCID: content.operationCID,
          createdAt: ts(3),
        },
        signer: witness2.authKey.signer,
        kid: `${witness2.did}#${witness2.authKey.keyId}`,
      });

      await postOps([cs1, cs2]);

      // should have exactly 2 distinct countersignatures
      const csRes = await req(`/countersignatures/${content.operationCID}`);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(2);

      // resubmit both — count must not change
      await postOps([cs1, cs2]);
      const csRes2 = await req(`/countersignatures/${content.operationCID}`);
      const csBody2 = await json(csRes2);
      expect(csBody2.countersignatures).toHaveLength(2);
    });

    it('should accept a beacon countersignature from a witness', async () => {
      const controller = await createIdentity();
      const witness = await createIdentity();
      await postOps([controller.jwsToken, witness.jwsToken]);

      // create and ingest a beacon
      const beaconPayload: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: controller.did,
        manifestContentId: 'test_manifest_content_id',
        createdAt: ts(2),
      };

      const controllerKid = `${controller.did}#${controller.controller.keyId}`;
      const { jwsToken: beaconToken, beaconCID } = await signBeacon({
        payload: beaconPayload,
        signer: controller.controller.signer,
        kid: controllerKid,
      });
      await postOps([beaconToken]);

      // witness creates a countersign targeting the beacon CID
      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: beaconCsToken } = await signCountersignature({
        payload: {
          version: 1,
          type: 'countersign',
          did: witness.did,
          targetCID: beaconCID,
          createdAt: ts(3),
        },
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      const res = await postOps([beaconCsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('countersign');
      expect(body.results[0].chainId).toBe(beaconCID);

      // query beacon countersignatures via the general countersig route
      const csRes = await req(`/countersignatures/${beaconCID}`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // countersignature query endpoints
  // ---------------------------------------------------------------------------

  describe('countersignature query', () => {
    it('should return same results from both countersig query paths', async () => {
      const author = await createIdentity();
      const witness = await createIdentity();
      const content = await createContentOp(author);
      await postOps([author.jwsToken, witness.jwsToken, content.jwsToken]);

      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: csToken } = await signCountersignature({
        payload: {
          version: 1,
          type: 'countersign',
          did: witness.did,
          targetCID: content.operationCID,
          createdAt: ts(2),
        },
        signer: witness.authKey.signer,
        kid: witnessKid,
      });
      await postOps([csToken]);

      // query via general path
      const generalRes = await req(`/countersignatures/${content.operationCID}`);
      expect(generalRes.status).toBe(200);
      const generalBody = await json(generalRes);

      // query via legacy per-operation path
      const legacyRes = await req(`/operations/${content.operationCID}/countersignatures`);
      expect(legacyRes.status).toBe(200);
      const legacyBody = await json(legacyRes);

      // both should return the same countersignatures
      expect(generalBody.countersignatures).toHaveLength(1);
      expect(legacyBody.countersignatures).toHaveLength(1);
      expect(generalBody.countersignatures[0]).toBe(legacyBody.countersignatures[0]);
    });

    it('should return 404 for countersigs on unknown CID', async () => {
      const res = await req(
        '/countersignatures/bafyreibogus000000000000000000000000000000000000000000000',
      );
      expect(res.status).toBe(404);
    });

    it('should return 404 for operation countersigs on unknown operation', async () => {
      const res = await req(
        '/operations/bafyreibogus000000000000000000000000000000000000000000000/countersignatures',
      );
      expect(res.status).toBe(404);
    });

    it('should return empty array for operation with no countersigs', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // query countersigs on the identity genesis op — nobody has countersigned it
      const csRes = await req(`/countersignatures/${identity.operationCID}`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // content plane — blob upload/download
  // ---------------------------------------------------------------------------

  describe('content plane blobs', () => {
    it('should allow chain creator to upload and download a blob', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // find contentId
      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // create auth token
      const authToken = await createTestAuthToken(identity);

      // encode the document as the blob (must match documentCID)
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));

      // upload
      const uploadRes = await putBlob(contentId, content.operationCID, authToken, docBytes);
      expect(uploadRes.status).toBe(200);

      // download as creator (no credential needed)
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      expect(downloadRes.status).toBe(200);
      const downloaded = new Uint8Array(await downloadRes.arrayBuffer());
      expect(downloaded).toEqual(docBytes);
      expect(downloadRes.headers.get('x-document-cid')).toBe(content.documentCID);
    });

    it('should reject blob upload when bytes do not match documentCID', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      const authToken = await createTestAuthToken(identity);

      // upload wrong bytes — doesn't match documentCID
      const uploadRes = await putBlob(
        contentId,
        content.operationCID,
        authToken,
        new TextEncoder().encode('completely wrong data'),
      );
      expect(uploadRes.status).toBe(400);
      const body = await json(uploadRes);
      expect(body.error).toContain('documentCID');
    });

    it('should require auth for blob upload', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      const res = await req(`/content/${contentId}/blob/${content.operationCID}`, {
        method: 'PUT',
        body: new Uint8Array([1, 2, 3]),
      });
      expect(res.status).toBe(401);
    });

    it('should allow reader with read credential to download', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator (encode doc as blob to match CID)
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // create a read credential from creator to reader
      const now = Math.floor(Date.now() / 1000);
      const readCredential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: reader.did,
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 300,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // download as reader with credential
      const readerToken = await createTestAuthToken(reader);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': readCredential,
        },
      });
      expect(downloadRes.status).toBe(200);
      const downloaded = new Uint8Array(await downloadRes.arrayBuffer());
      expect(downloaded).toEqual(docBytes);
    });

    it('should reject reader without credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob (encode doc to match CID)
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // try to download as reader without credential
      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(res.status).toBe(403);
    });

    it('should reject read credential issued by non-creator', async () => {
      const creator = await createIdentity();
      const attacker = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, attacker.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // attacker issues a read credential to reader (not the creator!)
      const now = Math.floor(Date.now() / 1000);
      const fakeCredential = await createDFOSCredential({
        issuerDID: attacker.did,
        audienceDID: reader.did,
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 300,
        signer: attacker.authKey.signer,
        keyId: attacker.authKey.keyId,
        iat: now,
      });

      // reader tries to download with attacker-issued credential
      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': fakeCredential,
        },
      });
      expect(res.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // key rotation — auth must use current keys only
  // ---------------------------------------------------------------------------

  describe('key rotation security', () => {
    it('should reject auth tokens signed with rotated-out keys', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // rotate the auth key
      const newAuthKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [newAuthKey.key], // old auth key removed
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
      await postOps([updateToken]);

      // create an auth token with the OLD (rotated-out) key
      const oldAuthToken = await createTestAuthToken(identity); // uses identity.authKey (the old one)

      // create a content chain to have something to access
      const content = await createContentOp(identity);
      // but this content op was signed with the old auth key during createContentOp...
      // actually just test the auth endpoint directly
      const contentOpRes = await postOps([content.jwsToken]);
      const contentBody = await json(contentOpRes);
      // content op might fail since it was signed with old key — that's fine
      // the important test is the auth token rejection

      // try to access content plane with old auth token
      const chainLookup = await req(`/content/someid/blob`, {
        headers: { authorization: `Bearer ${oldAuthToken}` },
      });
      // should be 401 because the old key is no longer in current state
      expect(chainLookup.status).toBe(401);

      // create auth token with the NEW key — should work (404 because no blob, but not 401)
      const newAuthToken = await createTestAuthToken(identity, newAuthKey);
      const newAuthRes = await req(`/content/someid/blob`, {
        headers: { authorization: `Bearer ${newAuthToken}` },
      });
      expect(newAuthRes.status).toBe(404); // 404 = authenticated but no content, not 401
    });

    it('should accept per-request credential signed with rotated-out key', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // issue read credential with CURRENT auth key
      const now = Math.floor(Date.now() / 1000);
      const readCredential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: reader.did,
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // rotate the auth key AFTER issuing the credential
      const newAuthKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: creator.operationCID,
        authKeys: [newAuthKey.key],
        assertKeys: [],
        controllerKeys: [creator.controller.key],
        createdAt: ts(3),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: creator.controller.signer,
        keyId: creator.controller.keyId,
        identityDID: creator.did,
      });
      await postOps([updateToken]);

      // reader uses credential signed with the OLD key — should still work
      const readerToken = await createTestAuthToken(reader);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': readCredential,
        },
      });
      expect(downloadRes.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  // identity delete lifecycle
  // ---------------------------------------------------------------------------

  describe('identity delete', () => {
    it('should accept identity delete and set isDeleted', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const deleteOp: IdentityOperation = {
        version: 1,
        type: 'delete',
        previousOperationCID: identity.operationCID,
        createdAt: ts(2),
      };

      const { jwsToken: deleteToken } = await signIdentityOperation({
        operation: deleteOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      const res = await postOps([deleteToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');

      // verify state shows deleted
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.state.isDeleted).toBe(true);
      expect(chainBody.headCID).toBeDefined();
    });

    it('should reject operations on a deleted identity', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // delete the identity
      const deleteOp: IdentityOperation = {
        version: 1,
        type: 'delete',
        previousOperationCID: identity.operationCID,
        createdAt: ts(2),
      };
      const { jwsToken: deleteToken, operationCID: deleteCID } = await signIdentityOperation({
        operation: deleteOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
      await postOps([deleteToken]);

      // try to extend with an update
      const newKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: deleteCID,
        authKeys: [newKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(3),
      };
      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });
  });

  // ---------------------------------------------------------------------------
  // content delete lifecycle
  // ---------------------------------------------------------------------------

  describe('content delete', () => {
    it('should accept content delete and set isDeleted', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const deleteOp: ContentOperation = {
        version: 1,
        type: 'delete',
        did: identity.did,
        previousOperationCID: content.operationCID,
        createdAt: ts(2),
        note: 'removing content',
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: deleteToken } = await signContentOperation({
        operation: deleteOp,
        signer: identity.authKey.signer,
        kid,
      });

      const res = await postOps([deleteToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');

      // verify state shows deleted
      const chainRes = await req(`/content/${contentId}`);
      const chainBody = await json(chainRes);
      expect(chainBody.state.isDeleted).toBe(true);
      expect(chainBody.state.currentDocumentCID).toBeNull();
      expect(chainBody.headCID).toBeDefined();
    });

    it('should reject operations on deleted content', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // delete the content
      const deleteOp: ContentOperation = {
        version: 1,
        type: 'delete',
        did: identity.did,
        previousOperationCID: content.operationCID,
        createdAt: ts(2),
        note: null,
      };
      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: deleteToken, operationCID: deleteCID } = await signContentOperation({
        operation: deleteOp,
        signer: identity.authKey.signer,
        kid,
      });
      await postOps([deleteToken]);

      // try to extend with an update
      const document2 = { type: 'post', title: 'updated' };
      const doc2Encoded = await dagCborCanonicalEncode(
        document2 as unknown as Record<string, unknown>,
      );
      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: deleteCID,
        documentCID: doc2Encoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(3),
        note: null,
      };
      const { jwsToken: updateToken } = await signContentOperation({
        operation: updateOp,
        signer: identity.authKey.signer,
        kid,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });

    it('should return 404 when downloading blob at head of deleted content', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob while content is alive
      const authToken = await createTestAuthToken(identity);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, authToken, docBytes);

      // delete the content
      const deleteOp: ContentOperation = {
        version: 1,
        type: 'delete',
        did: identity.did,
        previousOperationCID: content.operationCID,
        createdAt: ts(2),
        note: null,
      };
      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: deleteToken } = await signContentOperation({
        operation: deleteOp,
        signer: identity.authKey.signer,
        kid,
      });
      await postOps([deleteToken]);

      // downloading at head should 404 — currentDocumentCID is null after delete
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      expect(downloadRes.status).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // fork acceptance
  // ---------------------------------------------------------------------------

  describe('fork acceptance', () => {
    it('should accept content fork with same previousOperationCID (fork acceptance)', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      const ingestRes = await postOps([identity.jwsToken, content.jwsToken]);
      const ingestBody = await json(ingestRes);
      const contentId = ingestBody.results.find(
        (r: { kind: string }) => r.kind === 'content-op',
      ).chainId;

      const kid = `${identity.did}#${identity.authKey.keyId}`;

      // create two competing updates off the same previousOperationCID
      const doc1 = { type: 'post', title: 'update-a' };
      const doc1Encoded = await dagCborCanonicalEncode(doc1 as unknown as Record<string, unknown>);
      const updateA: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: content.operationCID,
        documentCID: doc1Encoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
      };
      const { jwsToken: tokenA } = await signContentOperation({
        operation: updateA,
        signer: identity.authKey.signer,
        kid,
      });

      const doc2 = { type: 'post', title: 'update-b' };
      const doc2Encoded = await dagCborCanonicalEncode(doc2 as unknown as Record<string, unknown>);
      const updateB: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: content.operationCID,
        documentCID: doc2Encoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(3),
        note: null,
      };
      const { jwsToken: tokenB } = await signContentOperation({
        operation: updateB,
        signer: identity.authKey.signer,
        kid,
      });

      // submit A first — should succeed
      const resA = await postOps([tokenA]);
      expect((await json(resA)).results[0].status).toBe('new');

      // submit B — also accepted (fork from same parent)
      const resB = await postOps([tokenB]);
      expect((await json(resB)).results[0].status).toBe('new');

      // head should be B (higher createdAt)
      const chainRes = await req(`/content/${contentId}`);
      const chain = await json(chainRes);
      expect(chain.state.currentDocumentCID).toBe(doc2Encoded.cid.toString());

      // chain log should contain all 3 operations (genesis + both fork branches)
      const logRes = await req(`/content/${contentId}/log`);
      const logBody = await json(logRes);
      expect(logBody.entries).toHaveLength(3);
    });

    it('should select head by highest createdAt (deterministic head selection)', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      const ingestRes = await postOps([identity.jwsToken, content.jwsToken]);
      const ingestBody = await json(ingestRes);
      const contentId = ingestBody.results.find(
        (r: { kind: string }) => r.kind === 'content-op',
      ).chainId;

      const kid = `${identity.did}#${identity.authKey.keyId}`;

      // fork A: lower createdAt
      const docA = { type: 'post', title: 'branch-a' };
      const docAEncoded = await dagCborCanonicalEncode(docA as unknown as Record<string, unknown>);
      const updateA: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: content.operationCID,
        documentCID: docAEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(100),
        note: null,
      };
      const { jwsToken: tokenA } = await signContentOperation({
        operation: updateA,
        signer: identity.authKey.signer,
        kid,
      });

      // fork B: higher createdAt — should become head
      const docB = { type: 'post', title: 'branch-b' };
      const docBEncoded = await dagCborCanonicalEncode(docB as unknown as Record<string, unknown>);
      const updateB: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: content.operationCID,
        documentCID: docBEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(200),
        note: null,
      };
      const { jwsToken: tokenB } = await signContentOperation({
        operation: updateB,
        signer: identity.authKey.signer,
        kid,
      });

      // submit A first (higher createdAt arrives second)
      await postOps([tokenA]);
      await postOps([tokenB]);

      // head should be B (higher createdAt wins)
      const chainRes = await req(`/content/${contentId}`);
      const chain = await json(chainRes);
      expect(chain.state.currentDocumentCID).toBe(docBEncoded.cid.toString());

      // now submit in reverse order on a fresh relay to prove order-independence
      const store2 = new MemoryRelayStore();
      const relay2 = await createRelay({ store: store2 });
      const req2 = (path: string, init?: RequestInit) =>
        relay2.app.request(`http://localhost${path}`, init);
      const postOps2 = (ops: string[]) =>
        req2('/operations', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operations: ops }),
        });

      // submit identity + genesis + B first, then A
      await postOps2([identity.jwsToken, content.jwsToken]);
      await postOps2([tokenB]);
      await postOps2([tokenA]);

      // same head regardless of ingestion order
      const chainRes2 = await req2(`/content/${contentId}`);
      const chain2 = await json(chainRes2);
      expect(chain2.state.currentDocumentCID).toBe(docBEncoded.cid.toString());
    });

    it('should include all fork branches in per-chain log', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      const ingestRes = await postOps([identity.jwsToken, content.jwsToken]);
      const ingestBody = await json(ingestRes);
      const contentId = ingestBody.results.find(
        (r: { kind: string }) => r.kind === 'content-op',
      ).chainId;

      const kid = `${identity.did}#${identity.authKey.keyId}`;

      // three fork branches off genesis
      const forks: string[] = [];
      for (let i = 0; i < 3; i++) {
        const doc = { type: 'post', title: `fork-${i}` };
        const docEncoded = await dagCborCanonicalEncode(doc as unknown as Record<string, unknown>);
        const update: ContentOperation = {
          version: 1,
          type: 'update',
          did: identity.did,
          previousOperationCID: content.operationCID,
          documentCID: docEncoded.cid.toString(),
          baseDocumentCID: null,
          createdAt: ts(10 + i),
          note: null,
        };
        const { jwsToken } = await signContentOperation({
          operation: update,
          signer: identity.authKey.signer,
          kid,
        });
        forks.push(jwsToken);
      }

      for (const f of forks) await postOps([f]);

      // chain log has genesis + 3 fork branches = 4 entries
      const logRes = await req(`/content/${contentId}/log`);
      const logBody = await json(logRes);
      expect(logBody.entries).toHaveLength(4);
    });
  });

  // ---------------------------------------------------------------------------
  // future timestamp guard
  // ---------------------------------------------------------------------------

  describe('future timestamp guard', () => {
    it('should reject identity operation with createdAt more than 24h in the future', async () => {
      const controller = makeKey();
      const authKey = makeKey();

      const farFuture = new Date(Date.now() + 25 * 60 * 60 * 1000).toISOString();
      const createOp: IdentityOperation = {
        version: 1,
        type: 'create',
        authKeys: [authKey.key],
        assertKeys: [],
        controllerKeys: [controller.key],
        createdAt: farFuture,
      };

      const { jwsToken } = await signIdentityOperation({
        operation: createOp,
        signer: controller.signer,
        keyId: controller.keyId,
      });

      const res = await postOps([jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
      expect(body.results[0].error).toContain('too far in the future');
    });

    it('should accept identity operation with createdAt 23h in the future', async () => {
      const controller = makeKey();
      const authKey = makeKey();

      const nearFuture = new Date(Date.now() + 23 * 60 * 60 * 1000).toISOString();
      const createOp: IdentityOperation = {
        version: 1,
        type: 'create',
        authKeys: [authKey.key],
        assertKeys: [],
        controllerKeys: [controller.key],
        createdAt: nearFuture,
      };

      const { jwsToken } = await signIdentityOperation({
        operation: createOp,
        signer: controller.signer,
        keyId: controller.keyId,
      });

      const res = await postOps([jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
    });

    it('should reject content operation with createdAt more than 24h in the future', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const farFuture = new Date(Date.now() + 25 * 60 * 60 * 1000).toISOString();
      const content = await createContentOp(identity, { createdAt: farFuture });

      const res = await postOps([content.jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
      expect(body.results[0].error).toContain('too far in the future');
    });
  });

  // ---------------------------------------------------------------------------
  // delegated content write
  // ---------------------------------------------------------------------------

  describe('delegated content write', () => {
    it('should accept content update with write credential', async () => {
      const creator = await createIdentity();
      const delegate = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, delegate.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // creator issues write credential to delegate
      const now = Math.floor(Date.now() / 1000);
      const writeCredential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: delegate.did,
        att: [{ resource: `chain:${contentId}`, action: 'write' }],
        exp: now + 300,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // delegate signs an update with the authorization credential
      const newDoc = { type: 'post', title: 'delegated update' };
      const newDocEncoded = await dagCborCanonicalEncode(
        newDoc as unknown as Record<string, unknown>,
      );

      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: content.operationCID,
        documentCID: newDocEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
        authorization: writeCredential,
      };

      const delegateKid = `${delegate.did}#${delegate.authKey.keyId}`;
      const { jwsToken: updateToken } = await signContentOperation({
        operation: updateOp,
        signer: delegate.authKey.signer,
        kid: delegateKid,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');

      // chain should now have 2 ops
      const chainRes = await req(`/content/${contentId}`);
      const chainBody = await json(chainRes);
      expect(chainBody.headCID).toBeDefined();
    });

    it('should reject delegated update without authorization credential', async () => {
      const creator = await createIdentity();
      const delegate = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, delegate.jwsToken, content.jwsToken]);

      // delegate signs an update WITHOUT authorization
      const newDoc = { type: 'post', title: 'unauthorized update' };
      const newDocEncoded = await dagCborCanonicalEncode(
        newDoc as unknown as Record<string, unknown>,
      );

      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: content.operationCID,
        documentCID: newDocEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
      };

      const delegateKid = `${delegate.did}#${delegate.authKey.keyId}`;
      const { jwsToken: updateToken } = await signContentOperation({
        operation: updateOp,
        signer: delegate.authKey.signer,
        kid: delegateKid,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });

    it('should allow delegate to upload blob for their operation', async () => {
      const creator = await createIdentity();
      const delegate = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, delegate.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // creator issues write credential to delegate
      const now = Math.floor(Date.now() / 1000);
      const writeCredential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: delegate.did,
        att: [{ resource: `chain:${contentId}`, action: 'write' }],
        exp: now + 300,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // delegate signs an update
      const newDoc = { type: 'post', title: 'delegated with blob' };
      const newDocEncoded = await dagCborCanonicalEncode(
        newDoc as unknown as Record<string, unknown>,
      );

      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: content.operationCID,
        documentCID: newDocEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
        authorization: writeCredential,
      };

      const delegateKid = `${delegate.did}#${delegate.authKey.keyId}`;
      const { jwsToken: updateToken, operationCID: updateCID } = await signContentOperation({
        operation: updateOp,
        signer: delegate.authKey.signer,
        kid: delegateKid,
      });

      await postOps([updateToken]);

      // delegate uploads blob for their own operation
      const delegateAuthToken = await createTestAuthToken(delegate);
      const newDocBytes = new TextEncoder().encode(JSON.stringify(newDoc));
      const uploadRes = await putBlob(contentId, updateCID, delegateAuthToken, newDocBytes);
      expect(uploadRes.status).toBe(200);

      // verify download works at the delegate's operation ref
      const creatorAuthToken = await createTestAuthToken(creator);
      const downloadRes = await req(`/content/${contentId}/blob/${updateCID}`, {
        headers: { authorization: `Bearer ${creatorAuthToken}` },
      });
      expect(downloadRes.status).toBe(200);
      const downloaded = new Uint8Array(await downloadRes.arrayBuffer());
      expect(downloaded).toEqual(newDocBytes);
    });

    it('should reject blob upload by non-signer of the operation', async () => {
      const creator = await createIdentity();
      const bystander = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, bystander.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // bystander tries to upload blob for creator's operation
      const bystanderToken = await createTestAuthToken(bystander);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      const uploadRes = await putBlob(contentId, content.operationCID, bystanderToken, docBytes);
      expect(uploadRes.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // auth token edge cases
  // ---------------------------------------------------------------------------

  describe('auth token edge cases', () => {
    it('should reject auth token with wrong audience', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob first with valid token
      const authToken = await createTestAuthToken(identity);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, authToken, docBytes);

      // create auth token targeting WRONG relay DID
      const wrongAudToken = await createAuthToken({
        iss: identity.did,
        aud: 'did:dfos:wrongrelaydid000000000',
        exp: Math.floor(Date.now() / 1000) + 300,
        kid: `${identity.did}#${identity.authKey.keyId}`,
        iat: Math.floor(Date.now() / 1000),
        sign: identity.authKey.signer,
      });

      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${wrongAudToken}` },
      });
      expect(res.status).toBe(401);
    });

    it('should reject expired auth token', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // create auth token that's already expired
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = await createAuthToken({
        iss: identity.did,
        aud: RELAY_DID,
        exp: now - 60, // expired 1 minute ago
        kid: `${identity.did}#${identity.authKey.keyId}`,
        iat: now - 120,
        sign: identity.authKey.signer,
      });

      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${expiredToken}` },
      });
      expect(res.status).toBe(401);
    });
  });

  // ---------------------------------------------------------------------------
  // blob download at historical ref
  // ---------------------------------------------------------------------------

  describe('blob at historical ref', () => {
    it('should download blob at specific operation CID ref', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob for v1
      const authToken = await createTestAuthToken(identity);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, authToken, docBytes);

      // download at the genesis operation CID ref
      const refRes = await req(`/content/${contentId}/blob/${content.operationCID}`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      expect(refRes.status).toBe(200);
      const refBody = new Uint8Array(await refRes.arrayBuffer());
      expect(refBody).toEqual(docBytes);
    });

    it('should download blob at head ref', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const authToken = await createTestAuthToken(identity);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, authToken, docBytes);

      const res = await req(`/content/${contentId}/blob/head`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      expect(res.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  // error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('should reject invalid JSON body', async () => {
      const res = await req('/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: 'not json',
      });
      expect(res.status).toBe(400);
    });

    it('should reject empty operations array', async () => {
      const res = await req('/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operations: [] }),
      });
      expect(res.status).toBe(400);
    });

    it('should reject malformed JWS tokens', async () => {
      const res = await postOps(['not.a.valid.jws']);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });
  });

  // ---------------------------------------------------------------------------
  // artifact ingestion
  // ---------------------------------------------------------------------------

  describe('artifact ingestion', () => {
    it('should accept a valid artifact and return newResults', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const artifactPayload: ArtifactPayload = {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'hello artifact' },
        createdAt: ts(1),
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: artifactToken } = await signArtifact({
        payload: artifactPayload,
        signer: identity.authKey.signer,
        kid,
      });

      const res = await postOps([artifactToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('artifact');
    });

    it('should reject artifact from unknown identity', async () => {
      const identity = await createIdentity();
      // do NOT ingest identity

      const artifactPayload: ArtifactPayload = {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'unknown' },
        createdAt: ts(1),
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: artifactToken } = await signArtifact({
        payload: artifactPayload,
        signer: identity.authKey.signer,
        kid,
      });

      const res = await postOps([artifactToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });

    it('should reject artifact from deleted identity', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // delete the identity
      const deleteOp: IdentityOperation = {
        version: 1,
        type: 'delete',
        previousOperationCID: identity.operationCID,
        createdAt: ts(2),
      };
      const { jwsToken: deleteToken } = await signIdentityOperation({
        operation: deleteOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
      await postOps([deleteToken]);

      const artifactPayload: ArtifactPayload = {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'after delete' },
        createdAt: ts(3),
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: artifactToken } = await signArtifact({
        payload: artifactPayload,
        signer: identity.authKey.signer,
        kid,
      });

      const res = await postOps([artifactToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });

    it('should deduplicate artifact', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const artifactPayload: ArtifactPayload = {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'dedup me' },
        createdAt: ts(1),
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: artifactToken } = await signArtifact({
        payload: artifactPayload,
        signer: identity.authKey.signer,
        kid,
      });

      const res1 = await postOps([artifactToken]);
      const body1 = await json(res1);
      expect(body1.results[0].status).toBe('new');

      const res2 = await postOps([artifactToken]);
      const body2 = await json(res2);
      expect(body2.results[0].status).toBe('duplicate');
    });

    it('should reject oversized artifact', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // build a payload that will exceed MAX_ARTIFACT_PAYLOAD_SIZE when CBOR-encoded
      const largeData = 'x'.repeat(MAX_ARTIFACT_PAYLOAD_SIZE);
      const artifactPayload: ArtifactPayload = {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', data: largeData },
        createdAt: ts(1),
      };

      const kid = `${identity.did}#${identity.authKey.keyId}`;

      // signArtifact itself should throw for oversized payloads
      await expect(
        signArtifact({
          payload: artifactPayload,
          signer: identity.authKey.signer,
          kid,
        }),
      ).rejects.toThrow('exceeds max size');
    });
  });

  // ---------------------------------------------------------------------------
  // operation log
  // ---------------------------------------------------------------------------

  describe('operation log', () => {
    it('should contain bootstrap entries initially', async () => {
      const res = await req('/log');
      expect(res.status).toBe(200);
      const body = await json(res);
      // relay bootstrap ingests 2 operations: identity genesis + profile artifact
      expect(body.entries).toHaveLength(2);
      expect(body.entries[0].kind).toBe('identity-op');
      expect(body.entries[1].kind).toBe('artifact');
    });

    it('should return ingested operations in order', async () => {
      // snapshot the initial log cursor so we can paginate past bootstrap entries
      const initialRes = await req('/log');
      const initialBody = await json(initialRes);
      const bootstrapCursor = initialBody.entries[initialBody.entries.length - 1].cid;

      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // ingest a beacon
      const beaconPayload: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        manifestContentId: 'test_manifest_content_id',
        createdAt: ts(2),
      };
      const kid = `${identity.did}#${identity.controller.keyId}`;
      const { jwsToken: beaconToken } = await signBeacon({
        payload: beaconPayload,
        signer: identity.controller.signer,
        kid,
      });
      await postOps([beaconToken]);

      // read only entries after the bootstrap
      const res = await req(`/log?after=${bootstrapCursor}`);
      const body = await json(res);
      expect(body.entries.length).toBe(3);
      expect(body.entries[0].kind).toBe('identity-op');
      expect(body.entries[1].kind).toBe('content-op');
      expect(body.entries[2].kind).toBe('beacon');
    });

    it('should paginate with cursor', async () => {
      // snapshot the initial log cursor so we can paginate past bootstrap entries
      const initialRes = await req('/log');
      const initialBody = await json(initialRes);
      const bootstrapCursor = initialBody.entries[initialBody.entries.length - 1].cid;

      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // create 2 updates
      let previousCID = identity.operationCID;
      for (let i = 0; i < 2; i++) {
        const newKey = makeKey();
        const updateOp: IdentityOperation = {
          version: 1,
          type: 'update',
          previousOperationCID: previousCID,
          authKeys: [identity.authKey.key, newKey.key],
          assertKeys: [],
          controllerKeys: [identity.controller.key],
          createdAt: ts(i + 2),
        };
        const { jwsToken: updateToken, operationCID } = await signIdentityOperation({
          operation: updateOp,
          signer: identity.controller.signer,
          keyId: identity.controller.keyId,
          identityDID: identity.did,
        });
        await postOps([updateToken]);
        previousCID = operationCID;
      }

      // total non-bootstrap entries should be 3 (create + 2 updates)
      // read with limit=2, starting after bootstrap
      const res1 = await req(`/log?after=${bootstrapCursor}&limit=2`);
      const body1 = await json(res1);
      expect(body1.entries).toHaveLength(2);
      expect(body1.cursor).not.toBeNull();

      // read with cursor
      const res2 = await req(`/log?after=${body1.cursor}`);
      const body2 = await json(res2);
      expect(body2.entries).toHaveLength(1);
      expect(body2.cursor).toBeNull();
    });

    it('should handle unknown cursor gracefully', async () => {
      const res = await req('/log?after=nonexistent');
      const body = await json(res);
      expect(body.entries).toEqual([]);
      expect(body.cursor).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // per-chain log
  // ---------------------------------------------------------------------------

  describe('per-chain log', () => {
    // NOTE: /identities/:did{.+}/log route is unreachable in Hono due to the
    // greedy {.+} regex consuming the /log suffix. Identity log tests use the
    // content chain log route instead, which uses standard path params.

    it('should return content chain log via /content/:contentId/log', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const res = await req(`/content/${contentId}/log`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.entries).toHaveLength(1);
      expect(body.entries[0].cid).toBeTruthy();
    });

    it('should return multiple entries in content chain log', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // extend with an update
      const doc2 = { type: 'post', title: 'updated' };
      const doc2Encoded = await dagCborCanonicalEncode(doc2 as unknown as Record<string, unknown>);
      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: identity.did,
        previousOperationCID: content.operationCID,
        documentCID: doc2Encoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
      };
      const kid = `${identity.did}#${identity.authKey.keyId}`;
      const { jwsToken: updateToken } = await signContentOperation({
        operation: updateOp,
        signer: identity.authKey.signer,
        kid,
      });
      await postOps([updateToken]);

      const res = await req(`/content/${contentId}/log`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.entries).toHaveLength(2);
      expect(body.entries[0].cid).toBeTruthy();
      expect(body.entries[1].cid).toBeTruthy();
    });

    it('should paginate per-chain log with cursor', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // extend with 2 updates for 3 total content ops
      let previousCID = content.operationCID;
      for (let i = 0; i < 2; i++) {
        const doc = { type: 'post', title: `update-${i}` };
        const docEncoded = await dagCborCanonicalEncode(doc as unknown as Record<string, unknown>);
        const updateOp: ContentOperation = {
          version: 1,
          type: 'update',
          did: identity.did,
          previousOperationCID: previousCID,
          documentCID: docEncoded.cid.toString(),
          baseDocumentCID: null,
          createdAt: ts(i + 2),
          note: null,
        };
        const kid = `${identity.did}#${identity.authKey.keyId}`;
        const { jwsToken: updateToken, operationCID } = await signContentOperation({
          operation: updateOp,
          signer: identity.authKey.signer,
          kid,
        });
        await postOps([updateToken]);
        previousCID = operationCID;
      }

      // paginate with limit=2
      const res1 = await req(`/content/${contentId}/log?limit=2`);
      const body1 = await json(res1);
      expect(body1.entries).toHaveLength(2);
      expect(body1.cursor).not.toBeNull();

      // read remainder
      const res2 = await req(`/content/${contentId}/log?after=${body1.cursor}`);
      const body2 = await json(res2);
      expect(body2.entries).toHaveLength(1);
      expect(body2.cursor).toBeNull();
    });

    it('should return 404 for unknown content log', async () => {
      const res = await req('/content/unknown-content-id/log');
      expect(res.status).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // content plane disabled
  // ---------------------------------------------------------------------------

  describe('content plane disabled', () => {
    it('should return 501 for blob upload when content: false', async () => {
      const noContentRelay = await createRelay({ store, identity: RELAY_IDENTITY, content: false });

      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const res = await noContentRelay.app.request('http://localhost/content/someid/blob/somecid', {
        method: 'PUT',
        headers: {
          'content-type': 'application/octet-stream',
          authorization: 'Bearer fake',
        },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(res.status).toBe(501);
    });

    it('should return 501 for blob download when content: false', async () => {
      const noContentRelay = await createRelay({ store, identity: RELAY_IDENTITY, content: false });

      const res = await noContentRelay.app.request('http://localhost/content/someid/blob', {
        headers: { authorization: 'Bearer fake' },
      });
      expect(res.status).toBe(501);
    });
  });

  // ---------------------------------------------------------------------------
  // log separation
  // ---------------------------------------------------------------------------

  describe('log separation', () => {
    it('identity response should NOT include log field', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/identities/${identity.did}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect('log' in body).toBe(false);
    });

    it('identity response should include headCID', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/identities/${identity.did}`);
      const body = await json(res);
      expect(typeof body.headCID).toBe('string');
    });

    it('content response should NOT include log field', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const res = await req(`/content/${contentId}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect('log' in body).toBe(false);
    });

    it('content response should include headCID', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const res = await req(`/content/${contentId}`);
      const body = await json(res);
      expect(typeof body.headCID).toBe('string');
    });
  });

  // ---------------------------------------------------------------------------
  // peering
  // ---------------------------------------------------------------------------

  describe('peering', () => {
    /** Create a local relay with a mock peer client backed by a given store */
    const createPeeredRelay = async (opts: {
      peerStore: MemoryRelayStore;
      peers: { url: string; gossip?: boolean; readThrough?: boolean; sync?: boolean }[];
      pageSize?: number;
    }) => {
      const mockPeerClient = new RelayBackedPeerClient(opts.peerStore, opts.pageSize);
      const localStore = new MemoryRelayStore();
      const relay = await createRelay({
        store: localStore,
        peers: opts.peers,
        peerClient: mockPeerClient,
      });
      const localReq = (path: string, init?: RequestInit) =>
        relay.app.request(`http://localhost${path}`, init);
      const localPostOps = (ops: string[]) =>
        localReq('/operations', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operations: ops }),
        });
      return { relay, localStore, mockPeerClient, req: localReq, postOps: localPostOps };
    };

    // -----------------------------------------------------------------------
    // gossip
    // -----------------------------------------------------------------------

    describe('gossip', () => {
      it('should gossip new ops to gossip-enabled peers', async () => {
        const peerStore = new MemoryRelayStore();
        const { mockPeerClient, postOps: localPostOps } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        const identity = await createIdentity();
        await localPostOps([identity.jwsToken]);

        expect(mockPeerClient.submitCalls).toHaveLength(1);
        expect(mockPeerClient.submitCalls[0]!.peerUrl).toBe('http://peer-a');
        expect(mockPeerClient.submitCalls[0]!.operations).toContain(identity.jwsToken);
      });

      it('should not gossip duplicate ops', async () => {
        const peerStore = new MemoryRelayStore();
        const { mockPeerClient, postOps: localPostOps } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        const identity = await createIdentity();
        await localPostOps([identity.jwsToken]);
        mockPeerClient.submitCalls.length = 0; // reset

        // ingest same op again — should be duplicate, no gossip
        await localPostOps([identity.jwsToken]);
        expect(mockPeerClient.submitCalls).toHaveLength(0);
      });

      it('should skip peers with gossip: false', async () => {
        const peerStore = new MemoryRelayStore();
        const { mockPeerClient, postOps: localPostOps } = await createPeeredRelay({
          peerStore,
          peers: [
            { url: 'http://peer-a', gossip: true },
            { url: 'http://peer-b', gossip: false },
          ],
        });

        const identity = await createIdentity();
        await localPostOps([identity.jwsToken]);

        expect(mockPeerClient.submitCalls).toHaveLength(1);
        expect(mockPeerClient.submitCalls[0]!.peerUrl).toBe('http://peer-a');
      });

      it('should gossip to all enabled peers', async () => {
        const peerStore = new MemoryRelayStore();
        const { mockPeerClient, postOps: localPostOps } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }, { url: 'http://peer-b' }, { url: 'http://peer-c' }],
        });

        const identity = await createIdentity();
        await localPostOps([identity.jwsToken]);

        expect(mockPeerClient.submitCalls).toHaveLength(3);
        const urls = mockPeerClient.submitCalls.map((c) => c.peerUrl).sort();
        expect(urls).toEqual(['http://peer-a', 'http://peer-b', 'http://peer-c']);
      });
    });

    // -----------------------------------------------------------------------
    // read-through
    // -----------------------------------------------------------------------

    describe('read-through', () => {
      it('should fetch identity from peer on local miss', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore);

        const { req: localReq } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        const res = await localReq(`/identities/${identity.did}`);
        expect(res.status).toBe(200);
        const body = (await res.json()) as Record<string, unknown>;
        expect(body.did).toBe(identity.did);
      });

      it('should return 404 when peer also misses', async () => {
        const peerStore = new MemoryRelayStore();
        const { req: localReq } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        const res = await localReq('/identities/did:dfos:nonexistent');
        expect(res.status).toBe(404);
      });

      it('should paginate through full identity log from peer', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();

        // create an identity update so the chain has 2 ops
        const newAuthKey = makeKey();
        const updateOp: IdentityOperation = {
          version: 1,
          type: 'update',
          previousOperationCID: identity.operationCID,
          authKeys: [newAuthKey.key],
          assertKeys: [],
          controllerKeys: [identity.controller.key],
          createdAt: ts(1),
        };
        const { jwsToken: updateToken } = await signIdentityOperation({
          operation: updateOp,
          signer: identity.controller.signer,
          keyId: identity.controller.keyId,
          identityDID: identity.did,
        });

        await ingestOperations([identity.jwsToken, updateToken], peerStore);

        // pageSize=1 forces 2 pages for a 2-op chain
        const { req: localReq, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
          pageSize: 1,
        });

        const res = await localReq(`/identities/${identity.did}`);
        expect(res.status).toBe(200);

        // verify the full chain was ingested (both ops in local store)
        const chain = await localStore.getIdentityChain(identity.did);
        expect(chain).toBeDefined();
        expect(chain!.log).toHaveLength(2);
      });

      it('should fetch content chain from peer on local miss', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        const content = await createContentOp(identity);

        // seed peer with identity + content
        const peerResults = await ingestOperations(
          [identity.jwsToken, content.jwsToken],
          peerStore,
        );
        const contentId = peerResults.find((r) => r.kind === 'content-op')!.chainId!;

        // local relay needs the identity to verify content ops
        const { req: localReq, postOps: localPostOps } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });
        await localPostOps([identity.jwsToken]);

        const res = await localReq(`/content/${contentId}`);
        expect(res.status).toBe(200);
        const body = (await res.json()) as Record<string, unknown>;
        expect(body.contentId).toBe(contentId);
      });

      it('should paginate through full content log from peer', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        const content = await createContentOp(identity);

        // create a content update so the chain has 2 ops
        const newDoc = { type: 'post', title: 'updated' };
        const newDocEncoded = await dagCborCanonicalEncode(
          newDoc as unknown as Record<string, unknown>,
        );
        const updateOp: ContentOperation = {
          version: 1,
          type: 'update',
          did: identity.did,
          previousOperationCID: content.operationCID,
          documentCID: newDocEncoded.cid.toString(),
          baseDocumentCID: null,
          createdAt: ts(2),
          note: null,
        };
        const kid = `${identity.did}#${identity.authKey.keyId}`;
        const { jwsToken: updateToken } = await signContentOperation({
          operation: updateOp,
          signer: identity.authKey.signer,
          kid,
        });

        await ingestOperations([identity.jwsToken, content.jwsToken, updateToken], peerStore);

        // pageSize=1 forces 2 pages for a 2-op content chain
        const {
          req: localReq,
          localStore,
          postOps: localPostOps,
        } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
          pageSize: 1,
        });

        // local relay needs the identity to verify content ops
        await localPostOps([identity.jwsToken]);

        const peerChain = await peerStore.getContentChain(
          (await peerStore.getOperation(content.operationCID))!.chainId!,
        );
        const contentId = peerChain!.contentId;

        const res = await localReq(`/content/${contentId}`);
        expect(res.status).toBe(200);

        // verify the full chain was ingested (both ops in local store)
        const chain = await localStore.getContentChain(contentId);
        expect(chain).toBeDefined();
        expect(chain!.log).toHaveLength(2);
      });

      it('should not consult peers with readThrough: false', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore);

        const { req: localReq } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a', readThrough: false }],
        });

        const res = await localReq(`/identities/${identity.did}`);
        expect(res.status).toBe(404);
      });

      it('should fall back to second peer when first misses', async () => {
        const emptyPeerStore = new MemoryRelayStore();
        const populatedPeerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], populatedPeerStore);

        // mock peer client that routes to different stores by URL
        const mockPeerClient: PeerClient = {
          async getIdentityLog(peerUrl, did, params) {
            const store = peerUrl === 'http://peer-a' ? emptyPeerStore : populatedPeerStore;
            const mock = new RelayBackedPeerClient(store);
            return mock.getIdentityLog(peerUrl, did, params);
          },
          async getContentLog(peerUrl, contentId, params) {
            const store = peerUrl === 'http://peer-a' ? emptyPeerStore : populatedPeerStore;
            const mock = new RelayBackedPeerClient(store);
            return mock.getContentLog(peerUrl, contentId, params);
          },
          async getOperationLog() {
            return null;
          },
          async submitOperations() {},
        };

        const localStore = new MemoryRelayStore();
        const relay = await createRelay({
          store: localStore,
          peers: [{ url: 'http://peer-a' }, { url: 'http://peer-b' }],
          peerClient: mockPeerClient,
        });

        const res = await relay.app.request(`http://localhost/identities/${identity.did}`);
        expect(res.status).toBe(200);
        const body = (await res.json()) as Record<string, unknown>;
        expect(body.did).toBe(identity.did);
      });
    });

    // -----------------------------------------------------------------------
    // sync-in
    // -----------------------------------------------------------------------

    describe('sync-in', () => {
      it('should sync operations from peer', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore, { logEnabled: true });

        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        await relay.syncFromPeers();

        const chain = await localStore.getIdentityChain(identity.did);
        expect(chain).toBeDefined();
        expect(chain!.did).toBe(identity.did);
      });

      it('should persist cursor as last entry CID on final page', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        const results = await ingestOperations([identity.jwsToken], peerStore, {
          logEnabled: true,
        });
        const opCID = results[0]!.cid;

        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        await relay.syncFromPeers();

        // single op < page size → final page → cursor = last entry CID
        const cursor = await localStore.getPeerCursor('http://peer-a');
        expect(cursor).toBe(opCID);
      });

      it('should handle multi-page sync', async () => {
        const peerStore = new MemoryRelayStore();

        // create 3 independent identities to populate the global log
        const ids = [];
        for (let i = 0; i < 3; i++) {
          const id = await createIdentity();
          await ingestOperations([id.jwsToken], peerStore, { logEnabled: true });
          ids.push(id);
        }

        // pageSize=1 forces 3 pages
        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
          pageSize: 1,
        });

        await relay.syncFromPeers();

        // all 3 identities should be synced
        for (const id of ids) {
          const chain = await localStore.getIdentityChain(id.did);
          expect(chain).toBeDefined();
        }
      });

      it('should resume from stored cursor position', async () => {
        const peerStore = new MemoryRelayStore();

        const idA = await createIdentity();
        const idB = await createIdentity();
        const idC = await createIdentity();
        const resultsA = await ingestOperations([idA.jwsToken], peerStore, { logEnabled: true });
        const resultsB = await ingestOperations([idB.jwsToken], peerStore, { logEnabled: true });
        await ingestOperations([idC.jwsToken], peerStore, { logEnabled: true });

        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        // pre-set cursor to B → sync should only fetch C
        await localStore.setPeerCursor('http://peer-a', resultsB[0]!.cid);

        await relay.syncFromPeers();

        // A and B should NOT be in local store (skipped by cursor)
        expect(await localStore.getOperation(resultsA[0]!.cid)).toBeUndefined();
        expect(await localStore.getOperation(resultsB[0]!.cid)).toBeUndefined();

        // C should be synced
        const chainC = await localStore.getIdentityChain(idC.did);
        expect(chainC).toBeDefined();
      });

      it('should skip peers with sync: false', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore, { logEnabled: true });

        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a', sync: false }],
        });

        await relay.syncFromPeers();

        const chain = await localStore.getIdentityChain(identity.did);
        expect(chain).toBeUndefined();
      });

      it('should no-op when peer has no operations', async () => {
        const peerStore = new MemoryRelayStore();
        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        await relay.syncFromPeers();

        // no cursor should be set (nothing to sync)
        const cursor = await localStore.getPeerCursor('http://peer-a');
        expect(cursor).toBeUndefined();
      });
    });
  });

  // ---------------------------------------------------------------------------
  // revocation ingestion
  // ---------------------------------------------------------------------------

  describe('revocation ingestion', () => {
    it('should accept a valid revocation', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);

      // create a credential to revoke
      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // decode to get credentialCID
      const decoded = decodeDFOSCredentialUnsafe(credential);
      expect(decoded).not.toBeNull();
      const credentialCID = decoded!.header.cid;

      // sign and submit revocation
      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: creator.did,
        credentialCID,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
      });

      const res = await postOps([revocationJws]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('revocation');
    });

    it('should be idempotent for duplicate revocations', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);

      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      const decoded = decodeDFOSCredentialUnsafe(credential);
      const credentialCID = decoded!.header.cid;

      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: creator.did,
        credentialCID,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
      });

      await postOps([revocationJws]);
      const res = await postOps([revocationJws]);
      const body = await json(res);
      expect(body.results[0].status).toBe('duplicate');
    });
  });

  // ---------------------------------------------------------------------------
  // public credential ingestion
  // ---------------------------------------------------------------------------

  describe('public credential ingestion', () => {
    it('should accept a public credential (aud: *)', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);

      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      const res = await postOps([credential]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('credential');
    });

    it('should reject non-public credential ingestion', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      await postOps([creator.jwsToken, reader.jwsToken]);

      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: reader.did,
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      const res = await postOps([credential]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });

    it('should accept public credential signed with rotated-out key', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);

      // sign a public credential with the CURRENT auth key
      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // rotate the auth key BEFORE submitting the credential
      const newAuthKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: creator.operationCID,
        authKeys: [newAuthKey.key],
        assertKeys: [],
        controllerKeys: [creator.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: creator.controller.signer,
        keyId: creator.controller.keyId,
        identityDID: creator.did,
      });
      await postOps([updateToken]);

      // now submit the credential signed with the old (rotated-out) key
      // it should still be accepted — revocation, not key rotation, invalidates
      const res = await postOps([credential]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('credential');
    });

    it('should reject ingestion of already-revoked credential', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);

      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      const decoded = decodeDFOSCredentialUnsafe(credential);
      const credentialCID = decoded!.header.cid;

      // revoke first
      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: creator.did,
        credentialCID,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
      });
      await postOps([revocationJws]);

      // now try to ingest the credential — should be rejected
      const res = await postOps([credential]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
      expect(body.results[0].error).toContain('revoked');
    });
  });

  // ---------------------------------------------------------------------------
  // standing authorization (public credentials for read access)
  // ---------------------------------------------------------------------------

  describe('standing authorization', () => {
    it('should grant read access via stored public credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob as creator
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // ingest public credential from creator
      const now = Math.floor(Date.now() / 1000);
      const publicCred = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });
      await postOps([publicCred]);

      // reader can download WITHOUT per-request credential (standing auth)
      const readerToken = await createTestAuthToken(reader);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(downloadRes.status).toBe(200);
    });

    it('should deny read access after revoking public credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // ingest public credential
      const now = Math.floor(Date.now() / 1000);
      const publicCred = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });
      await postOps([publicCred]);

      // revoke the public credential
      const decoded = decodeDFOSCredentialUnsafe(publicCred);
      const credentialCID = decoded!.header.cid;
      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: creator.did,
        credentialCID,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
      });
      await postOps([revocationJws]);

      // reader should now be denied
      const readerToken = await createTestAuthToken(reader);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(downloadRes.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // documents endpoint
  // ---------------------------------------------------------------------------

  describe('documents endpoint', () => {
    it('should return documents for a content chain', async () => {
      const creator = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // fetch documents
      const res = await req(`/content/${contentId}/documents`, {
        headers: { authorization: `Bearer ${creatorToken}` },
      });
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.contentId).toBe(contentId);
      expect(body.documents).toBeDefined();
      expect(body.documents.length).toBe(1);
      expect(body.documents[0].operationCID).toBe(content.operationCID);
      expect(body.documents[0].document).toEqual(content.document);
    });

    it('should require authentication', async () => {
      const creator = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const res = await req(`/content/${contentId}/documents`);
      expect(res.status).toBe(401);
    });

    it('should return 404 for unknown content', async () => {
      const creator = await createIdentity();
      await postOps([creator.jwsToken]);
      const creatorToken = await createTestAuthToken(creator);

      const res = await req(`/content/nonexistent/documents`, {
        headers: { authorization: `Bearer ${creatorToken}` },
      });
      expect(res.status).toBe(404);
    });

    it('should require read credential for non-creator', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/documents`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(res.status).toBe(403);
    });

    it('should allow access with read credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // create read credential
      const now = Math.floor(Date.now() / 1000);
      const readCred = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: reader.did,
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 300,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/documents`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': readCred,
        },
      });
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.documents.length).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // cascading revocation
  // ---------------------------------------------------------------------------

  describe('cascading revocation', () => {
    it('should invalidate child credential when parent credential is revoked', async () => {
      const creator = await createIdentity();
      const member = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, member.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob as creator
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creatorToken, docBytes);

      // creator issues root credential to member granting read access
      const now = Math.floor(Date.now() / 1000);
      const rootCredential = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: member.did,
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });

      // member issues a child credential (re-delegation) to anyone, with root as proof
      const childCredential = await createDFOSCredential({
        issuerDID: member.did,
        audienceDID: '*',
        att: [{ resource: `chain:${contentId}`, action: 'read' }],
        prf: [rootCredential],
        exp: now + 1800,
        signer: member.authKey.signer,
        keyId: member.authKey.keyId,
        iat: now,
      });

      // verify child credential grants access — member can read blob
      const memberToken = await createTestAuthToken(member);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${memberToken}`,
          'x-credential': childCredential,
        },
      });
      expect(downloadRes.status).toBe(200);

      // creator revokes the root credential
      const decoded = decodeDFOSCredentialUnsafe(rootCredential);
      const credentialCID = decoded!.header.cid;
      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: creator.did,
        credentialCID,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
      });
      await postOps([revocationJws]);

      // child credential should no longer grant access
      const downloadRes2 = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${memberToken}`,
          'x-credential': childCredential,
        },
      });
      expect(downloadRes2.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // chain:* wildcard standing authorization
  // ---------------------------------------------------------------------------

  describe('chain:* wildcard standing authorization', () => {
    it('should grant read access to all creator content via chain:* public credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();

      // create first content chain and upload blob
      const content1 = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content1.jwsToken]);

      const ingest1 = await postOps([content1.jwsToken]);
      const contentId1 = (await json(ingest1)).results[0].chainId;

      const creatorToken = await createTestAuthToken(creator);
      const docBytes1 = new TextEncoder().encode(JSON.stringify(content1.document));
      await putBlob(contentId1, content1.operationCID, creatorToken, docBytes1);

      // ingest public credential with chain:* from creator
      const now = Math.floor(Date.now() / 1000);
      const wildcardCred = await createDFOSCredential({
        issuerDID: creator.did,
        audienceDID: '*',
        att: [{ resource: 'chain:*', action: 'read' }],
        exp: now + 3600,
        signer: creator.authKey.signer,
        keyId: creator.authKey.keyId,
        iat: now,
      });
      await postOps([wildcardCred]);

      // create second content chain and upload blob
      const content2 = await createContentOp(creator, { createdAt: ts(2) });
      await postOps([content2.jwsToken]);

      const ingest2 = await postOps([content2.jwsToken]);
      const contentId2 = (await json(ingest2)).results[0].chainId;

      const docBytes2 = new TextEncoder().encode(JSON.stringify(content2.document));
      await putBlob(contentId2, content2.operationCID, creatorToken, docBytes2);

      // reader can download blob from first content chain (standing auth)
      const readerToken = await createTestAuthToken(reader);
      const dl1 = await req(`/content/${contentId1}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(dl1.status).toBe(200);

      // reader can download blob from second content chain (standing auth)
      const dl2 = await req(`/content/${contentId2}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(dl2.status).toBe(200);
    });
  });
});

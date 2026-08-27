import {
  encodeEd25519Multikey,
  MAX_ARTIFACT_PAYLOAD_SIZE,
  signArtifact,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  signRevocation,
  type ArtifactPayload,
  type ContentOperation,
  type CountersignPayload,
  type IdentityOperation,
  type MultikeyPublicKey,
  type ServiceEntry,
} from '@metalabel/dfos-protocol/chain';
import {
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
  signApiIdentityRequest,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  bootstrapRelayIdentity,
  chunkOps,
  createRelay,
  ingestOperations,
  MemoryRelayStore,
} from '../src';
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

/**
 * THE RELAY'S OWN CONFIGURED AUTHORITY in these tests. Every request goes to
 * `http://localhost/...`, so the authority a proof must bind to is `localhost`.
 * It is configuration, never read from the request (see RelayOptions.authority).
 */
const RELAY_AUTHORITY = 'localhost';

let jtiCounter = 0;

/**
 * Sign an API-AUTH identity proof for ONE exact request against the test relay.
 *
 * Unlike the auth token it replaces, a proof is not reusable across requests: it
 * binds the method, the relay's authority, the origin-form path, and the body
 * hash. Write-shaped routes (blob upload, ingestion) additionally require a
 * `jti`, which the caller opts into with `jti: true`.
 */
const identityProof = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  request: {
    method: string;
    path: string;
    body?: Uint8Array;
    jti?: boolean | string;
    iat?: number;
    keyOverride?: { keyId: string; signer: (msg: Uint8Array) => Promise<Uint8Array> };
    host?: string;
  },
): Promise<string> => {
  const key = request.keyOverride ?? identity.authKey;
  const jti =
    typeof request.jti === 'string'
      ? request.jti
      : request.jti
        ? `jti-${(jtiCounter += 1)}`
        : undefined;
  const { proof } = await signApiIdentityRequest({
    method: request.method,
    host: request.host ?? RELAY_AUTHORITY,
    path: request.path,
    ...(request.body ? { body: request.body } : {}),
    kid: `${identity.did}#${key.keyId}`,
    sign: key.signer,
    ...(request.iat !== undefined ? { iat: request.iat } : {}),
    ...(jti !== undefined ? { extraMembers: { jti } } : {}),
  });
  return proof;
};

/** The `Authorization` header an identity-proven request carries. */
const proofHeader = (proof: string) => `DFOS ${proof}`;

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
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | null> {
    const chain = await this.backingStore.getIdentityChain(did);
    if (!chain) return null;
    return this.paginateChainLog(chain.log, params);
  }

  async getContentLog(
    _peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | null> {
    const chain = await this.backingStore.getContentChain(contentId);
    if (!chain) return null;
    return this.paginateChainLog(chain.log, params);
  }

  async getOperationLog(
    _peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null> {
    const limit = this.pageSize ?? params?.limit ?? 1000;
    const result = await this.backingStore.readLog({
      ...(params?.after ? { after: params.after } : {}),
      limit,
    });
    if (!result) return 'invalid-cursor';
    return {
      entries: result.entries.map((e) => ({ cid: e.cid, jwsToken: e.jwsToken })),
      next: result.next,
    };
  }

  async submitOperations(peerUrl: string, operations: string[]): Promise<void> {
    this.submitCalls.push({ peerUrl, operations });
  }

  private paginateChainLog(
    log: string[],
    params?: { after?: string; limit?: number },
  ): { entries: PeerLogEntry[]; next: string | null } {
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
    const next = page.length === limit ? page[page.length - 1]!.cid : null;
    return { entries: page, next };
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
    app = await createRelay({ store, identity: RELAY_IDENTITY, authority: RELAY_AUTHORITY });
  });

  const req = (path: string, init?: RequestInit) =>
    app.app.request(`http://localhost${path}`, init);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = async (res: Response): Promise<any> => res.json();

  const postOps = (operations: string[]) =>
    req('/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations }),
    });

  /**
   * `req`, with an API-AUTH identity proof minted for EXACTLY this request.
   *
   * The proof is per-request by construction — there is no reusable token to
   * hand around, which is the whole point of what replaced the auth-token JWT.
   */
  const reqAs = async (
    path: string,
    identity: Awaited<ReturnType<typeof createIdentity>>,
    init: RequestInit & {
      keyOverride?: { keyId: string; signer: (msg: Uint8Array) => Promise<Uint8Array> };
      jti?: boolean | string;
      iat?: number;
      host?: string;
    } = {},
  ) => {
    const { keyOverride, jti, iat, host, headers, ...rest } = init;
    const method = (rest.method ?? 'GET').toUpperCase();
    const body =
      rest.body instanceof Uint8Array
        ? rest.body
        : typeof rest.body === 'string'
          ? new TextEncoder().encode(rest.body)
          : undefined;
    const proof = await identityProof(identity, {
      method,
      path,
      ...(body ? { body } : {}),
      // Write-shaped routes REQUIRE jti; read-shaped ones must not be given one
      // gratuitously, so the default follows the method.
      jti: jti ?? (method === 'PUT' || method === 'POST'),
      ...(iat !== undefined ? { iat } : {}),
      ...(keyOverride ? { keyOverride } : {}),
      ...(host !== undefined ? { host } : {}),
    });
    return req(path, {
      ...rest,
      headers: { ...(headers as Record<string, string> | undefined), authorization: proofHeader(proof) },
    });
  };

  const putBlob = (
    contentId: string,
    operationCID: string,
    uploader: Awaited<ReturnType<typeof createIdentity>>,
    body: Uint8Array,
  ) =>
    reqAs(`/content/${contentId}/blob/${operationCID}`, uploader, {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
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
      expect(body.capabilities.write).toBe(true);
      expect(body.capabilities.content).toBe(true);
      expect(body.capabilities.log).toBe(true);
      expect(body.capabilities.index).toBe(true);
    });

    it('should advertise write: false when relay created with write: false', async () => {
      const liteRelay = await createRelay({ store, identity: RELAY_IDENTITY, write: false });
      const res = await liteRelay.app.request('http://localhost/.well-known/dfos-relay');
      const body = (await res.json()) as Record<string, unknown>;
      const caps = body.capabilities as Record<string, unknown>;
      expect(caps.write).toBe(false);
      // a lite node is still a full proof node for reads
      expect(caps.proof).toBe(true);
    });

    it('should include content: false in capabilities when relay created with content: false', async () => {
      const noContentRelay = await createRelay({ store, identity: RELAY_IDENTITY, content: false });
      const res = await noContentRelay.app.request('http://localhost/.well-known/dfos-relay');
      const body = (await res.json()) as Record<string, unknown>;
      const caps = body.capabilities as Record<string, unknown>;
      expect(caps.content).toBe(false);
    });

    it('should always include profile in well-known response', async () => {
      const res = await req('/.well-known/dfos-relay');
      const body = await json(res);
      expect(typeof body.profile).toBe('string');
      expect(body.profile).toBe(RELAY_IDENTITY.profileArtifactJws);
    });
  });

  describe('lite pull-only node (write: false)', () => {
    it('rejects POST /proof/v1/operations with 501', async () => {
      const liteRelay = await createRelay({ store, identity: RELAY_IDENTITY, write: false });
      const res = await liteRelay.app.request('http://localhost/proof/v1/operations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operations: ['anything'] }),
      });
      // the gate fires before body parsing — writes are disabled by role
      expect(res.status).toBe(501);
    });

    it('still serves proof reads (it is a full proof node for reads)', async () => {
      const liteRelay = await createRelay({ store, identity: RELAY_IDENTITY, write: false });
      const wk = await liteRelay.app.request('http://localhost/.well-known/dfos-relay');
      expect(wk.status).toBe(200);
      const missing = await liteRelay.app.request(
        'http://localhost/proof/v1/identities/did:dfos:unknown000000000000',
      );
      // a read route that exists but has no data returns 404 (not 501) — reads work
      expect(missing.status).toBe(404);
    });

    it('a write-enabled relay does NOT 501 on POST', async () => {
      const res = await req('/proof/v1/operations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operations: ['not-a-valid-jws'] }),
      });
      // reaches body/ingest handling — 400 (bad op), never 501
      expect(res.status).not.toBe(501);
    });

    it('rejects PUT blob with 501 — write:false means no write surface at all', async () => {
      // Blob upload is the one route that accepts a 16MB body. Leaving it open on
      // a node advertising write:false would contradict the capability and defeat
      // the point of the role (a minimal attack surface).
      const liteRelay = await createRelay({ store, identity: RELAY_IDENTITY, write: false });
      const res = await liteRelay.app.request('http://localhost/content/someid/blob/somecid', {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream', authorization: 'DFOS fake' },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(res.status).toBe(501);
    });

    it('still serves blob DOWNLOAD on a write:false node (reads are unaffected)', async () => {
      // Negative control: write:false gates writes only. A blob read must reach the
      // route (404 for an unknown chain), never 501.
      const liteRelay = await createRelay({ store, identity: RELAY_IDENTITY, write: false });
      const res = await liteRelay.app.request('http://localhost/content/someid/blob');
      expect(res.status).not.toBe(501);
    });
  });

  // ---------------------------------------------------------------------------
  // CORS — parity with the Go relay (byte-for-byte header values)
  // ---------------------------------------------------------------------------

  describe('CORS', () => {
    it('should emit the CORS policy headers on proof-plane GET responses', async () => {
      const res = await req('/.well-known/dfos-relay');
      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      expect(res.headers.get('access-control-allow-methods')).toBe('GET, POST, PUT, OPTIONS');
      expect(res.headers.get('access-control-allow-headers')).toBe('Content-Type, Authorization');
    });

    it('should answer OPTIONS preflight with 204 and the CORS headers', async () => {
      const res = await req('/proof/v1/identities/did:dfos:example/log', { method: 'OPTIONS' });
      expect(res.status).toBe(204);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      expect(res.headers.get('access-control-allow-methods')).toBe('GET, POST, PUT, OPTIONS');
      expect(res.headers.get('access-control-allow-headers')).toBe('Content-Type, Authorization');
    });

    it('should emit CORS headers even on 404 proof-plane reads', async () => {
      const res = await req('/proof/v1/identities/did:dfos:doesnotexist');
      expect(res.status).toBe(404);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
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

      const res = await req(`/proof/v1/identities/${identity.did}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.did).toBe(identity.did);
      expect(body.headCID).toBeDefined();
      expect(body.state.isDeleted).toBe(false);
    });

    it('should return 404 for unknown identity', async () => {
      const res = await req('/proof/v1/identities/did:dfos:unknown000000000000');
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
      const chainRes = await req(`/proof/v1/identities/${identity.did}`);
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
      const chainRes = await req(`/proof/v1/identities/${identity.did}`);
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
      const chainRes = await req(`/proof/v1/identities/${identity.did}`);
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
  // services discovery vocabulary + countersign relation (0.11.0)
  // ---------------------------------------------------------------------------

  describe('services + countersign relation', () => {
    const ANCHOR = 'cv7n8vkvr64cctf3294h9k4eanhff8z'; // 31-char content id

    // mirror createIdentity() but carry a services set on the genesis op
    const createIdentityWithServices = async (services: ServiceEntry[] | undefined) => {
      const controller = makeKey();
      const authKey = makeKey();
      const createOp: IdentityOperation = {
        version: 1,
        type: 'create',
        authKeys: [authKey.key],
        assertKeys: [],
        controllerKeys: [controller.key],
        createdAt: ts(),
        services,
      };
      const { jwsToken, operationCID } = await signIdentityOperation({
        operation: createOp,
        signer: controller.signer,
        keyId: controller.keyId,
      });
      const encoded = await dagCborCanonicalEncode(createOp);
      const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
      const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
      return { did, controller, authKey, jwsToken, operationCID };
    };

    const signServicesUpdate = async (
      identity: Awaited<ReturnType<typeof createIdentityWithServices>>,
      previousOperationCID: string,
      services: ServiceEntry[] | undefined,
      offset: number,
    ) => {
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID,
        authKeys: [identity.authKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(offset),
        services,
      };
      return signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
    };

    it('projects and serves a genesis services set', async () => {
      const id = await createIdentityWithServices([
        { id: 'relay', type: 'DfosRelay', endpoint: 'https://relay.dfos.com' },
        { id: 'avatar', type: 'ContentAnchor', label: 'avatar', anchor: ANCHOR },
      ]);
      await postOps([id.jwsToken]);

      const body = await json(await req(`/proof/v1/identities/${id.did}`));
      expect(body.state.services).toHaveLength(2);
      const relay = body.state.services.find((s: { id: string }) => s.id === 'relay');
      expect(relay.type).toBe('DfosRelay');
      expect(relay.endpoint).toBe('https://relay.dfos.com');
      const anchor = body.state.services.find((s: { id: string }) => s.id === 'avatar');
      expect(anchor.type).toBe('ContentAnchor');
      expect(anchor.label).toBe('avatar');
      expect(anchor.anchor).toBe(ANCHOR);
    });

    it('replaces the full set on update and clears it when omitted', async () => {
      const id = await createIdentityWithServices([
        { id: 'old', type: 'DfosRelay', endpoint: 'https://old.example.com' },
      ]);
      await postOps([id.jwsToken]);

      // full-state replace — the old entry must disappear
      const { jwsToken: replaceToken, operationCID: replaceCID } = await signServicesUpdate(
        id,
        id.operationCID,
        [{ id: 'new', type: 'DfosRelay', endpoint: 'https://new.example.com' }],
        2,
      );
      await postOps([replaceToken]);
      let body = await json(await req(`/proof/v1/identities/${id.did}`));
      expect(body.state.services).toHaveLength(1);
      expect(body.state.services[0].id).toBe('new');

      // service-less update clears the set entirely
      const { jwsToken: clearToken } = await signServicesUpdate(id, replaceCID, undefined, 3);
      await postOps([clearToken]);
      body = await json(await req(`/proof/v1/identities/${id.did}`));
      expect(body.state.services).toHaveLength(0);
    });

    it('rejects an invalid ContentAnchor entry (missing label)', async () => {
      const id = await createIdentityWithServices([
        { id: 'x', type: 'ContentAnchor', anchor: ANCHOR },
      ]);
      const body = await json(await postOps([id.jwsToken]));
      expect(body.results[0].status).toBe('rejected');
    });

    it('round-trips a countersignature relation tag', async () => {
      const author = await createIdentity();
      await postOps([author.jwsToken]);
      const witness = await createIdentity();
      await postOps([witness.jwsToken]);

      const payload: CountersignPayload = {
        version: 1,
        type: 'countersign',
        did: witness.did,
        targetCID: author.operationCID,
        relation: 'endorses',
        createdAt: ts(2),
      };
      const { jwsToken: csToken } = await signCountersignature({
        payload,
        signer: witness.authKey.signer,
        kid: `${witness.did}#${witness.authKey.keyId}`,
      });
      await postOps([csToken]);

      const body = await json(await req(`/proof/v1/countersignatures/${author.operationCID}`));
      expect(body.countersignatures).toHaveLength(1);
      const decoded = decodeJwsUnsafe(body.countersignatures[0].jwsToken);
      expect(decoded?.payload.relation).toBe('endorses');
      expect(body.countersignatures[0].cid).toBe(decoded?.header.cid);
    });
  });

  // ---------------------------------------------------------------------------
  // universal DID resolver (DIF /1.0/identifiers — DID-core projection)
  // ---------------------------------------------------------------------------

  describe('universal DID resolver', () => {
    const ANCHOR = 'cv7n8vkvr64cctf3294h9k4eanhff8z'; // 31-char content id

    const resolve = (did: string) => req(`/1.0/identifiers/${did}`);

    // genesis carrying an explicit services set (mirrors createIdentity)
    const createIdentityWithServices = async (services: ServiceEntry[] | undefined) => {
      const controller = makeKey();
      const authKey = makeKey();
      const createOp: IdentityOperation = {
        version: 1,
        type: 'create',
        authKeys: [authKey.key],
        assertKeys: [],
        controllerKeys: [controller.key],
        createdAt: ts(),
        services,
      };
      const { jwsToken, operationCID } = await signIdentityOperation({
        operation: createOp,
        signer: controller.signer,
        keyId: controller.keyId,
      });
      const encoded = await dagCborCanonicalEncode(createOp);
      const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
      const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
      return { did, controller, authKey, jwsToken, operationCID };
    };

    it('resolves a live identity into a DID Document + DIF envelope', async () => {
      const id = await createIdentity();
      await postOps([id.jwsToken]);

      const res = await resolve(id.did);
      expect(res.status).toBe(200);
      const body = await json(res);

      expect(body['@context']).toBe('https://w3id.org/did-resolution/v1');
      expect(body.didResolutionMetadata.contentType).toBe('application/did+ld+json');

      const doc = body.didDocument;
      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
      ]);
      expect(doc.id).toBe(id.did);
      expect(doc.controller).toBe(id.did);

      const authVm = `${id.did}#${id.authKey.keyId}`;
      const ctrlVm = `${id.did}#${id.controller.keyId}`;
      expect(doc.verificationMethod).toHaveLength(2);
      const authEntry = doc.verificationMethod.find((v: { id: string }) => v.id === authVm);
      expect(authEntry.type).toBe('Multikey');
      expect(authEntry.controller).toBe(id.did);
      expect(authEntry.publicKeyMultibase).toBe(id.authKey.key.publicKeyMultibase);
      expect(doc.authentication).toEqual([authVm]);
      expect(doc.capabilityInvocation).toEqual([ctrlVm]);
      expect(doc.assertionMethod).toEqual([]);

      expect(body.didDocumentMetadata.operationCount).toBe(1);
      expect(body.didDocumentMetadata.deactivated).toBe(false);
      expect(body.didDocumentMetadata.created).toBeDefined();
      expect(body.didDocumentMetadata.updated).toBeDefined();
    });

    it('dedups a key shared across roles into a single verification method', async () => {
      // one key serving auth + assert + controller (the common case)
      const shared = makeKey();
      const createOp: IdentityOperation = {
        version: 1,
        type: 'create',
        authKeys: [shared.key],
        assertKeys: [shared.key],
        controllerKeys: [shared.key],
        createdAt: ts(),
      };
      const { jwsToken } = await signIdentityOperation({
        operation: createOp,
        signer: shared.signer,
        keyId: shared.keyId,
      });
      const encoded = await dagCborCanonicalEncode(createOp);
      const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
      const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
      await postOps([jwsToken]);

      const doc = (await json(await resolve(did))).didDocument;
      const vm = `${did}#${shared.keyId}`;
      expect(doc.verificationMethod).toHaveLength(1);
      expect(doc.verificationMethod[0].id).toBe(vm);
      expect(doc.authentication).toEqual([vm]);
      expect(doc.assertionMethod).toEqual([vm]);
      expect(doc.capabilityInvocation).toEqual([vm]);
    });

    it('projects services (DfosRelay + ContentAnchor) into the service array', async () => {
      const id = await createIdentityWithServices([
        { id: 'relay', type: 'DfosRelay', endpoint: 'https://relay.dfos.com' },
        { id: 'avatar', type: 'ContentAnchor', label: 'avatar', anchor: ANCHOR },
      ]);
      await postOps([id.jwsToken]);

      const doc = (await json(await resolve(id.did))).didDocument;
      const relay = doc.service.find((s: { id: string }) => s.id === `${id.did}#relay`);
      expect(relay).toEqual({
        id: `${id.did}#relay`,
        type: 'DfosRelay',
        serviceEndpoint: 'https://relay.dfos.com',
      });
      const anchor = doc.service.find((s: { id: string }) => s.id === `${id.did}#avatar`);
      expect(anchor).toEqual({
        id: `${id.did}#avatar`,
        type: 'ContentAnchor',
        serviceEndpoint: ANCHOR,
        label: 'avatar',
      });
    });

    it('projects a DfosAuthorizationServer entry exactly as it projects a DfosRelay', async () => {
      // SIWD's authorize origin is an open-namespace type whose `endpoint` member
      // mirrors DfosRelay's, so the projection is the same three keys in the same
      // order — the Go twin emits byte-identical output (did_document.go).
      const id = await createIdentityWithServices([
        {
          id: 'svc_authz',
          type: 'DfosAuthorizationServer',
          endpoint: 'https://app.dfos.com',
        } as unknown as ServiceEntry,
      ]);
      await postOps([id.jwsToken]);

      const doc = (await json(await resolve(id.did))).didDocument;
      const authz = doc.service.find((s: { id: string }) => s.id === `${id.did}#svc_authz`);
      expect(authz).toEqual({
        id: `${id.did}#svc_authz`,
        type: 'DfosAuthorizationServer',
        serviceEndpoint: 'https://app.dfos.com',
      });
      // mapped, NOT preserved verbatim: the raw `endpoint` member is gone
      expect(Object.keys(authz)).toEqual(['id', 'type', 'serviceEndpoint']);
    });

    it('preserves an unrecognized service type verbatim, re-anchoring only the id', async () => {
      // §4.5 MUST-ignore-unknown: a type the relay does not recognize keeps all
      // of its fields; only the entry id is re-anchored to a DID-URL fragment.
      const id = await createIdentityWithServices([
        {
          id: 'gateway',
          type: 'DfosDocumentGateway',
          endpoint: 'https://gw.dfos.com',
          weight: 7,
        } as unknown as ServiceEntry,
      ]);
      await postOps([id.jwsToken]);

      const doc = (await json(await resolve(id.did))).didDocument;
      const gw = doc.service.find((s: { id: string }) => s.id === `${id.did}#gateway`);
      expect(gw).toEqual({
        id: `${id.did}#gateway`,
        type: 'DfosDocumentGateway',
        endpoint: 'https://gw.dfos.com',
        weight: 7,
      });
      // NOT mapped into serviceEndpoint (that projection is for recognized types only)
      expect(gw.serviceEndpoint).toBeUndefined();
    });

    it('omits the service array entirely when there are no services', async () => {
      const id = await createIdentity();
      await postOps([id.jwsToken]);
      const doc = (await json(await resolve(id.did))).didDocument;
      expect(doc.service).toBeUndefined();
    });

    it('resolves a deactivated identity to 200 with empty verification methods', async () => {
      const id = await createIdentity();
      await postOps([id.jwsToken]);

      // sign + append a delete op from the controller key
      const deleteOp: IdentityOperation = {
        version: 1,
        type: 'delete',
        previousOperationCID: id.operationCID,
        createdAt: ts(1),
      };
      const { jwsToken: deleteToken } = await signIdentityOperation({
        operation: deleteOp,
        signer: id.controller.signer,
        keyId: id.controller.keyId,
        identityDID: id.did,
      });
      await postOps([deleteToken]);

      const res = await resolve(id.did);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.didDocumentMetadata.deactivated).toBe(true);
      expect(body.didDocumentMetadata.operationCount).toBe(2);
      expect(body.didDocument.verificationMethod).toEqual([]);
      // §5.4: keyless sealed identity omits every relationship + services
      expect(body.didDocument.authentication).toBeUndefined();
      expect(body.didDocument.assertionMethod).toBeUndefined();
      expect(body.didDocument.capabilityInvocation).toBeUndefined();
      expect(body.didDocument.service).toBeUndefined();
    });

    it('returns 404 notFound for an unknown but well-formed did', async () => {
      const id = await createIdentity(); // never posted
      const res = await resolve(id.did);
      expect(res.status).toBe(404);
      const body = await json(res);
      expect(body.didResolutionMetadata.error).toBe('notFound');
      expect(body.didDocument).toBeNull();
    });

    it('returns 400 invalidDid for a wrong-width did:dfos', async () => {
      const res = await resolve('did:dfos:tooshort');
      expect(res.status).toBe(400);
      const body = await json(res);
      expect(body.didResolutionMetadata.error).toBe('invalidDid');
      expect(body.didDocument).toBeNull();
    });

    it('returns 400 invalidDid for a legacy 22-char did:dfos', async () => {
      const res = await resolve('did:dfos:cnnnft9f8a2rn938d6nkz3'); // 22 chars
      expect(res.status).toBe(400);
      expect((await json(res)).didResolutionMetadata.error).toBe('invalidDid');
    });

    it('returns 400 invalidDid for a non-dfos method', async () => {
      const res = await resolve('did:web:example.com');
      expect(res.status).toBe(400);
      expect((await json(res)).didResolutionMetadata.error).toBe('invalidDid');
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

      const res = await req(`/proof/v1/content/${contentId}`);
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

      const res = await req(`/proof/v1/operations/${identity.operationCID}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.cid).toBe(identity.operationCID);
      expect(body.jwsToken).toBe(identity.jwsToken);
      expect(body.chainType).toBe('identity');
    });

    it('should return 404 for unknown operation', async () => {
      const res = await req(
        '/proof/v1/operations/bafyreibogus000000000000000000000000000000000000000000000',
      );
      expect(res.status).toBe(404);
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
      const csRes = await req(`/proof/v1/countersignatures/${content.operationCID}`);
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
      const csRes = await req(`/proof/v1/countersignatures/${content.operationCID}`);
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
      const csRes = await req(`/proof/v1/countersignatures/${content.operationCID}`);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(2);

      // resubmit both — count must not change
      await postOps([cs1, cs2]);
      const csRes2 = await req(`/proof/v1/countersignatures/${content.operationCID}`);
      const csBody2 = await json(csRes2);
      expect(csBody2.countersignatures).toHaveLength(2);
    });

    it('paginates countersignatures by countersignature CID', async () => {
      const author = await createIdentity();
      const witnesses = await Promise.all([createIdentity(), createIdentity(), createIdentity()]);
      const content = await createContentOp(author);

      await postOps([author.jwsToken, ...witnesses.map((w) => w.jwsToken), content.jwsToken]);

      const tokens: string[] = [];
      for (const [i, witness] of witnesses.entries()) {
        const { jwsToken } = await signCountersignature({
          payload: {
            version: 1,
            type: 'countersign',
            did: witness.did,
            targetCID: content.operationCID,
            createdAt: ts(2 + i),
          },
          signer: witness.authKey.signer,
          kid: `${witness.did}#${witness.authKey.keyId}`,
        });
        tokens.push(jwsToken);
      }

      await postOps(tokens);

      const page1 = await json(
        await req(`/proof/v1/countersignatures/${content.operationCID}?limit=2`),
      );
      expect(page1.countersignatures).toHaveLength(2);
      expect(typeof page1.next).toBe('string');
      expect(page1.next.length).toBeGreaterThan(0);

      const page2 = await json(
        await req(
          `/proof/v1/countersignatures/${content.operationCID}?after=${encodeURIComponent(
            page1.next,
          )}&limit=2`,
        ),
      );
      expect(page2.countersignatures).toHaveLength(1);
      expect(page2.next).toBeNull();

      const all = [...page1.countersignatures, ...page2.countersignatures];
      expect(new Set(all.map((row: { jwsToken: string }) => row.jwsToken)).size).toBe(3);

      const cids = all.map((row: { cid: string }) => row.cid);
      expect(new Set(cids).size).toBe(3);
      expect(cids).toEqual([...cids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

      // keyset: an `after` that is not a present key resumes at the next greater
      // key instead of truncating to an empty page
      const between = `${cids[0]}0`; // lexically between cids[0] and cids[1]
      const resumed = await json(
        await req(
          `/proof/v1/countersignatures/${content.operationCID}?after=${encodeURIComponent(between)}`,
        ),
      );
      expect(resumed.countersignatures.map((r: { cid: string }) => r.cid)).toEqual(cids.slice(1));
    });

    it('should accept a countersignature targeting an identity operation CID', async () => {
      const subject = await createIdentity();
      const witness = await createIdentity();
      await postOps([subject.jwsToken, witness.jwsToken]);

      // witness creates a countersign targeting the subject's genesis identity CID
      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: idCsToken } = await signCountersignature({
        payload: {
          version: 1,
          type: 'countersign',
          did: witness.did,
          targetCID: subject.operationCID,
          createdAt: ts(3),
        },
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      const res = await postOps([idCsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('new');
      expect(body.results[0].kind).toBe('countersign');
      expect(body.results[0].chainId).toBe(subject.operationCID);

      // query countersignatures via the general countersig route
      const csRes = await req(`/proof/v1/countersignatures/${subject.operationCID}`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // countersignature query endpoints
  // ---------------------------------------------------------------------------

  describe('countersignature query', () => {
    it('should return 404 for countersigs on unknown CID', async () => {
      const res = await req(
        '/proof/v1/countersignatures/bafyreibogus000000000000000000000000000000000000000000000',
      );
      expect(res.status).toBe(404);
    });

    it('should return empty array for operation with no countersigs', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // query countersigs on the identity genesis op — nobody has countersigned it
      const csRes = await req(`/proof/v1/countersignatures/${identity.operationCID}`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(0);
      expect(csBody.next).toBeNull();
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

      // encode the document as the blob (must match documentCID)
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));

      // upload
      const uploadRes = await putBlob(contentId, content.operationCID, identity, docBytes);
      expect(uploadRes.status).toBe(200);

      // download as creator (no credential needed)
      const downloadRes = await reqAs(`/content/${contentId}/blob`, identity);
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

      // upload wrong bytes — doesn't match documentCID
      const uploadRes = await putBlob(
        contentId,
        content.operationCID,
        identity,
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, reader, { headers: { 'x-credential': readCredential } });
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

      // try to download as reader without credential
      const res = await reqAs(`/content/${contentId}/blob`, reader);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const res = await reqAs(`/content/${contentId}/blob`, reader, { headers: { 'x-credential': fakeCredential } });
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

      // create a content chain BEFORE key rotation so it definitely exists
      const content = await createContentOp(identity);
      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

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

      // A proof signed by the OLD (rotated-out) key is 401: key resolution for an
      // identity proof is CURRENT-STATE, which is exactly how rotation revokes a
      // compromised key's ability to speak in the identity's name.
      const chainLookup = await reqAs(`/content/${contentId}/blob`, identity);
      expect(chainLookup.status).toBe(401);

      // The NEW key authenticates (404 because no blob is stored, not 401).
      const newAuthRes = await reqAs(`/content/${contentId}/blob`, identity, {
        keyOverride: newAuthKey,
      });
      expect(newAuthRes.status).toBe(404);
    });

    it('should accept per-request credential signed with rotated-out key', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, reader, { headers: { 'x-credential': readCredential } });
      expect(downloadRes.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  // identity delete lifecycle
  // ---------------------------------------------------------------------------

  describe('identity delete', () => {
    it('restores authentication after an explicit restore operation', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      const initial = await json(await postOps([identity.jwsToken, content.jwsToken]));
      const contentId = initial.results.find(
        (result: { kind: string }) => result.kind === 'content-op',
      ).chainId;

      const authenticatedReadStatus = async () =>
        (await reqAs(`/content/${contentId}/blob`, identity)).status;
      expect(await authenticatedReadStatus()).toBe(404);

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
      expect((await json(await postOps([deleteToken]))).results[0].status).toBe('new');
      expect(await authenticatedReadStatus()).toBe(401);

      const restore: IdentityOperation = {
        version: 1,
        type: 'restore',
        previousOperationCID: deleteCID,
        createdAt: ts(3),
      };
      const { jwsToken: restoreToken } = await signIdentityOperation({
        operation: restore,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
      expect((await json(await postOps([restoreToken]))).results[0].status).toBe('new');

      const chain = await store.getIdentityChain(identity.did);
      expect(chain?.state.isDeleted).toBe(false);
      expect(await authenticatedReadStatus()).toBe(404);

      const { jwsToken: artifactToken } = await signArtifact({
        payload: {
          version: 1,
          type: 'artifact',
          did: identity.did,
          content: { $schema: 'test/v1', title: 'after restore' },
          createdAt: ts(4),
        },
        signer: identity.authKey.signer,
        kid: `${identity.did}#${identity.authKey.keyId}`,
      });
      expect((await json(await postOps([artifactToken]))).results[0].status).toBe('new');
    });

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
      const chainRes = await req(`/proof/v1/identities/${identity.did}`);
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
      const chainRes = await req(`/proof/v1/content/${contentId}`);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, identity, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, identity);
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
      const chainRes = await req(`/proof/v1/content/${contentId}`);
      const chain = await json(chainRes);
      expect(chain.state.currentDocumentCID).toBe(doc2Encoded.cid.toString());

      // chain log should contain all 3 operations (genesis + both fork branches)
      const logRes = await req(`/proof/v1/content/${contentId}/log`);
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
      const chainRes = await req(`/proof/v1/content/${contentId}`);
      const chain = await json(chainRes);
      expect(chain.state.currentDocumentCID).toBe(docBEncoded.cid.toString());

      // now submit in reverse order on a fresh relay to prove order-independence
      const store2 = new MemoryRelayStore();
      const relay2 = await createRelay({ store: store2 });
      const req2 = (path: string, init?: RequestInit) =>
        relay2.app.request(`http://localhost${path}`, init);
      const postOps2 = (ops: string[]) =>
        req2('/proof/v1/operations', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operations: ops }),
        });

      // submit identity + genesis + B first, then A
      await postOps2([identity.jwsToken, content.jwsToken]);
      await postOps2([tokenB]);
      await postOps2([tokenA]);

      // same head regardless of ingestion order
      const chainRes2 = await req2(`/proof/v1/content/${contentId}`);
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
      const logRes = await req(`/proof/v1/content/${contentId}/log`);
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
      const chainRes = await req(`/proof/v1/content/${contentId}`);
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
      const newDocBytes = new TextEncoder().encode(JSON.stringify(newDoc));
      const uploadRes = await putBlob(contentId, updateCID, delegate, newDocBytes);
      expect(uploadRes.status).toBe(200);

      // verify download works at the delegate's operation ref
      const downloadRes = await reqAs(`/content/${contentId}/blob/${updateCID}`, creator);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      const uploadRes = await putBlob(contentId, content.operationCID, bystander, docBytes);
      expect(uploadRes.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // identity proof edge cases
  //
  // The rules the retired auth token asserted, carried forward: its `aud` became
  // the HOST BINDING, its `exp` became the RELAY-OWNED freshness window, and its
  // lifetime ceiling became unnecessary — a presenter can no longer choose how
  // long its own credential lives.
  // ---------------------------------------------------------------------------

  describe('identity proof edge cases', () => {
    const seedBlob = async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);
      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, identity, docBytes);
      return { identity, content, contentId, docBytes };
    };

    it('rejects a proof bound to a DIFFERENT authority', async () => {
      const { identity, contentId } = await seedBlob();
      const res = await reqAs(`/content/${contentId}/blob`, identity, {
        host: 'other-relay.example.com',
      });
      expect(res.status).toBe(401);
    });

    it('rejects a proof older than the relay-owned acceptance window', async () => {
      const { identity, contentId } = await seedBlob();
      const res = await reqAs(`/content/${contentId}/blob`, identity, {
        iat: Math.floor(Date.now() / 1000) - 3600,
      });
      expect(res.status).toBe(401);
    });

    it('rejects a proof forward-dated beyond the clock-skew allowance', async () => {
      const { identity, contentId } = await seedBlob();
      const res = await reqAs(`/content/${contentId}/blob`, identity, {
        iat: Math.floor(Date.now() / 1000) + 3600,
      });
      expect(res.status).toBe(401);
    });

    it('rejects a proof bound to a DIFFERENT path — one proof, one request', async () => {
      const { identity, contentId, content } = await seedBlob();
      // Signed for the head path, presented at the ref path.
      const proof = await identityProof(identity, {
        method: 'GET',
        path: `/content/${contentId}/blob`,
      });
      const res = await req(`/content/${contentId}/blob/${content.operationCID}`, {
        headers: { authorization: proofHeader(proof) },
      });
      expect(res.status).toBe(401);
    });

    it('rejects a Bearer token — the relay owns no other authentication grammar', async () => {
      const { contentId } = await seedBlob();
      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: 'Bearer anything-at-all' },
      });
      expect(res.status).toBe(401);
    });

    it('accepts the DFOS scheme case-insensitively (RFC 9110)', async () => {
      const { identity, contentId } = await seedBlob();
      const proof = await identityProof(identity, {
        method: 'GET',
        path: `/content/${contentId}/blob`,
      });
      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `dfos ${proof}` },
      });
      expect(res.status).toBe(200);
    });

    it('answers 503 — never 401, never a header fallback — when no authority is configured', async () => {
      const { identity, contentId } = await seedBlob();
      const unconfigured = await createRelay({ store, identity: RELAY_IDENTITY });
      const proof = await identityProof(identity, {
        method: 'GET',
        path: `/content/${contentId}/blob`,
      });
      const res = await unconfigured.app.request(`http://localhost/content/${contentId}/blob`, {
        headers: { authorization: proofHeader(proof) },
      });
      // The operator omitted the host binding; blaming the caller (401) would be
      // a lie, and reading the authority off the request would remove the binding.
      expect(res.status).toBe(503);
    });
  });

  // ---------------------------------------------------------------------------
  // jti replay discipline (write-shaped surfaces)
  // ---------------------------------------------------------------------------

  describe('jti on write-shaped proofs', () => {
    const seedChain = async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);
      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      return { identity, content, contentId, docBytes };
    };

    it('rejects a blob upload whose proof carries NO jti', async () => {
      const { identity, content, contentId, docBytes } = await seedChain();
      const res = await reqAs(`/content/${contentId}/blob/${content.operationCID}`, identity, {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream' },
        body: docBytes,
        jti: false,
      });
      expect(res.status).toBe(401);
    });

    it('rejects a REPLAYED jti on blob upload, and accepts a fresh one', async () => {
      const { identity, content, contentId, docBytes } = await seedChain();
      const path = `/content/${contentId}/blob/${content.operationCID}`;
      const proof = await identityProof(identity, {
        method: 'PUT',
        path,
        body: docBytes,
        jti: 'replay-me-once',
      });
      const headers = {
        authorization: proofHeader(proof),
        'content-type': 'application/octet-stream',
      };
      const first = await req(path, { method: 'PUT', headers, body: docBytes });
      expect(first.status).toBe(200);

      // The byte-identical request inside the freshness window is a REPLAY: the
      // relay recorded (presenter, jti) with insert-if-absent, and the second
      // insert fails. Ingestion being idempotent does not make this free — the
      // admission layer already spent on it.
      const replay = await req(path, { method: 'PUT', headers, body: docBytes });
      expect(replay.status).toBe(401);

      // A fresh jti over the same bytes is a new request, not a replay.
      const fresh = await reqAs(path, identity, {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream' },
        body: docBytes,
      });
      expect(fresh.status).toBe(200);
    });

    it('rejects a jti over the 256-byte cap', async () => {
      const { identity, content, contentId, docBytes } = await seedChain();
      const res = await reqAs(`/content/${contentId}/blob/${content.operationCID}`, identity, {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream' },
        body: docBytes,
        jti: 'x'.repeat(257),
      });
      expect(res.status).toBe(401);
    });

    it('expires cache entries with the freshness window, so a stale jti is reusable', async () => {
      // The entry's whole job is to cover the window in which the PROOF is still
      // acceptable; past that the proof is stale on its own. Two proofs a full
      // window apart may therefore share a jti — which this asserts by reusing
      // one after the first proof has aged out of acceptance.
      const { identity, content, contentId, docBytes } = await seedChain();
      const path = `/content/${contentId}/blob/${content.operationCID}`;
      const stale = await identityProof(identity, {
        method: 'PUT',
        path,
        body: docBytes,
        jti: 'shared-across-windows',
        iat: Math.floor(Date.now() / 1000) - 3600,
      });
      const staleRes = await req(path, {
        method: 'PUT',
        headers: {
          authorization: proofHeader(stale),
          'content-type': 'application/octet-stream',
        },
        body: docBytes,
      });
      // Refused for staleness — and, crucially, the jti was NOT recorded, since
      // freshness is checked before the cache is touched.
      expect(staleRes.status).toBe(401);

      const fresh = await reqAs(path, identity, {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream' },
        body: docBytes,
        jti: 'shared-across-windows',
      });
      expect(fresh.status).toBe(200);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, identity, docBytes);

      // download at the genesis operation CID ref
      const refRes = await reqAs(`/content/${contentId}/blob/${content.operationCID}`, identity);
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

      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, identity, docBytes);

      const res = await reqAs(`/content/${contentId}/blob/head`, identity);
      expect(res.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  // error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('should reject invalid JSON body', async () => {
      const res = await req('/proof/v1/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: 'not json',
      });
      expect(res.status).toBe(400);
    });

    it('should reject empty operations array', async () => {
      const res = await req('/proof/v1/operations', {
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
  // DoS body caps (mirrors the Go twin's 16MB MaxBytesReader)
  // ---------------------------------------------------------------------------

  describe('request body caps', () => {
    const oversizedChunkedRequest = (path: string, method: 'POST' | 'PUT') => {
      const chunk = new Uint8Array(8 * 1024 * 1024);
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(chunk);
          controller.enqueue(chunk);
          controller.enqueue(new Uint8Array([0]));
          controller.close();
        },
      });
      const request = new Request(`http://localhost${path}`, {
        method,
        headers: { 'content-type': 'application/octet-stream' },
        body,
        duplex: 'half',
      } as RequestInit & { duplex: 'half' });
      return app.app.fetch(request);
    };

    it('should reject POST /operations with an oversized Content-Length (413)', async () => {
      const res = await req('/proof/v1/operations', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(17 * 1024 * 1024), // > 16MB cap
        },
        body: JSON.stringify({ operations: ['x'] }),
      });
      expect(res.status).toBe(413);
    });

    it('should reject chunked POST /operations while buffering at 16MB (413)', async () => {
      const res = await oversizedChunkedRequest('/proof/v1/operations', 'POST');
      expect(res.status).toBe(413);
    });

    it('should reject chunked PUT blob while buffering at 16MB before auth (413)', async () => {
      const res = await oversizedChunkedRequest('/content/anychain/blob/anyop', 'PUT');
      expect(res.status).toBe(413);
    });

    it('should reject PUT blob with an oversized Content-Length (413) before auth', async () => {
      // No auth header — the 413 must fire BEFORE the 401, proving the cap is
      // checked first (protects the pre-auth path).
      const res = await req('/content/anychain/blob/anyop', {
        method: 'PUT',
        headers: {
          'content-type': 'application/octet-stream',
          'content-length': String(17 * 1024 * 1024),
        },
        body: new Uint8Array(8),
      });
      expect(res.status).toBe(413);
    });

    it('should accept a normal-sized POST /operations (cap not over-eager)', async () => {
      const identity = await createIdentity();
      const res = await req('/proof/v1/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operations: [identity.jwsToken] }),
      });
      expect(res.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  // gossip chunking (twin parity with Go's TestGossipChunksLargeBatches)
  // ---------------------------------------------------------------------------

  describe('gossip chunking', () => {
    it('chunkOps splits a run into batches no larger than the cap (the real split guard)', () => {
      // Directly exercise the split gossip() applies. The HTTP /operations cap
      // (100) means a single gossip() call never receives >100 ops, so the
      // integration test below can't force the split branch; this does, and
      // mirrors Go's TestGossipChunksLargeBatches which calls gossipOps directly.
      const ops = Array.from({ length: 250 }, (_, i) => `op-${i}`);
      const chunks = chunkOps(ops, 100);
      expect(chunks.map((c) => c.length)).toEqual([100, 100, 50]);
      expect(chunks.flat()).toEqual(ops); // no loss, no reorder
      expect(chunkOps([], 100)).toEqual([]);
      expect(chunkOps(['a', 'b'], 2).map((c) => c.length)).toEqual([2]);
    });

    it('gossip submits chunked batches (each <= cap) covering every op', async () => {
      // A chunk-recording peer client: capture the size of each submitOperations
      // batch. A >100 gossip run must be split (Go's maxGossipBatch=100) so the
      // receiver's IngestBody.max(100) never 400s and silently drops the batch.
      const batches: number[] = [];
      const chunkRecorder: PeerClient = {
        async getIdentityLog() {
          return null;
        },
        async getContentLog() {
          return null;
        },
        async getOperationLog() {
          return null;
        },
        async submitOperations(_peerUrl, operations) {
          batches.push(operations.length);
        },
      };

      const gossipStore = new MemoryRelayStore();
      const gossipIdentity = await bootstrapRelayIdentity(gossipStore);
      const gossipApp = await createRelay({
        store: gossipStore,
        identity: gossipIdentity,
        peers: [{ url: 'http://peer-a' }],
        peerClient: chunkRecorder,
      });

      // Wiring + coverage check (the chunkOps test above guards the split): feed
      // 250 tokens through three ≤100-op POSTs and assert gossip actually submits,
      // every submitted batch is <= the cap, and all ops are gossiped at least once.
      const tokens: string[] = [];
      for (let i = 0; i < 250; i++) {
        const id = await createIdentity();
        tokens.push(id.jwsToken);
      }
      for (let i = 0; i < tokens.length; i += 100) {
        await gossipApp.app.request('http://localhost/proof/v1/operations', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operations: tokens.slice(i, i + 100) }),
        });
      }

      expect(batches.length).toBeGreaterThan(0);
      for (const n of batches) {
        expect(n).toBeLessThanOrEqual(100);
      }
      // every op gossiped at least once
      const totalGossiped = batches.reduce((a, b) => a + b, 0);
      expect(totalGossiped).toBeGreaterThanOrEqual(250);
      // 250 real Ed25519 identity genesis operations, verified for real. That is
      // seconds of honest work, and it sits right on the 5s default when the
      // suite runs its files in parallel — an explicit budget, not a slower test.
    }, 30_000);

    it('submitOperations logs a non-2xx response without throwing', async () => {
      // The real HTTP peer client must observe a dropped batch (res.ok check)
      // but never throw — sync is the consistency backstop.
      const { createHttpPeerClient } = await import('../src');
      const client = createHttpPeerClient();
      const warnings: unknown[][] = [];
      const origWarn = console.warn;
      console.warn = (...args: unknown[]) => warnings.push(args);
      try {
        // a relay that 400s any over-100 batch — point at the in-process app via
        // a tiny fetch shim is overkill; instead hit a URL that returns non-2xx.
        // Use the app directly through a global fetch patch.
        const origFetch = globalThis.fetch;
        globalThis.fetch = (async () =>
          new Response('bad', { status: 400 })) as typeof globalThis.fetch;
        try {
          await client.submitOperations('http://peer-a', ['op1']);
        } finally {
          globalThis.fetch = origFetch;
        }
      } finally {
        console.warn = origWarn;
      }
      expect(warnings.length).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // twin-divergence: prf empty/non-string elements must be rejected (parity)
  // ---------------------------------------------------------------------------

  describe('prf hard-reject (twin parity)', () => {
    it('should reject a public credential with an empty-string prf element', async () => {
      // Build a credential whose prf is ["<parent>", ""]. TS rejects at decode
      // (MAX_PRF=1 → length 2 > 1) and so must Go (ParsePrf hard-rejects the
      // empty element). This is the cross-twin vector for the prf-empty-filter
      // divergence: byte-identical credential, BOTH twins reject.
      const issuer = await createIdentity();
      await postOps([issuer.jwsToken]);

      // a valid parent credential to put in prf[0]
      const now = Math.floor(Date.now() / 1000);
      const parent = await createDFOSCredential({
        issuerDID: issuer.did,
        audienceDID: '*',
        att: [{ resource: 'chain:abc', action: 'read' }],
        exp: now + 3600,
        signer: issuer.authKey.signer,
        keyId: issuer.authKey.keyId,
        iat: now,
      });

      // hand-build a credential payload with prf:["<parent>", ""] and sign it.
      const payload = {
        version: 1,
        type: 'DFOSCredential',
        iss: issuer.did,
        aud: '*',
        att: [{ resource: 'chain:abc', action: 'read' }],
        prf: [parent, ''],
        exp: now + 1800,
        iat: now,
      };
      const encoded = await dagCborCanonicalEncode(payload as unknown as Record<string, unknown>);
      const cid = encoded.cid.toString();
      const header = {
        alg: 'EdDSA',
        typ: 'did:dfos:credential',
        kid: `${issuer.did}#${issuer.authKey.keyId}`,
        cid,
      };
      const enc = (o: unknown) =>
        Buffer.from(JSON.stringify(o)).toString('base64url').replace(/=+$/, '');
      const signingInput = `${enc(header)}.${enc(payload)}`;
      const sig = await issuer.authKey.signer(new TextEncoder().encode(signingInput));
      const badCredential = `${signingInput}.${Buffer.from(sig).toString('base64url').replace(/=+$/, '')}`;

      const res = await postOps([badCredential]);
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
      const res = await req('/proof/v1/log');
      expect(res.status).toBe(200);
      const body = await json(res);
      // relay bootstrap ingests 2 operations: identity genesis + profile artifact
      expect(body.entries).toHaveLength(2);
      expect(body.entries[0].kind).toBe('identity-op');
      expect(body.entries[1].kind).toBe('artifact');
    });

    it('should return ingested operations in order', async () => {
      // snapshot the initial log cursor so we can paginate past bootstrap entries
      const initialRes = await req('/proof/v1/log');
      const initialBody = await json(initialRes);
      const bootstrapCursor = initialBody.entries[initialBody.entries.length - 1].cid;

      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // read only entries after the bootstrap
      const res = await req(`/proof/v1/log?after=${bootstrapCursor}`);
      const body = await json(res);
      expect(body.entries.length).toBe(2);
      expect(body.entries[0].kind).toBe('identity-op');
      expect(body.entries[1].kind).toBe('content-op');
    });

    it('should paginate with cursor', async () => {
      // snapshot the initial log cursor so we can paginate past bootstrap entries
      const initialRes = await req('/proof/v1/log');
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
      const res1 = await req(`/proof/v1/log?after=${bootstrapCursor}&limit=2`);
      const body1 = await json(res1);
      expect(body1.entries).toHaveLength(2);
      expect(body1.next).not.toBeNull();
      expect(body1).not.toHaveProperty('cursor');

      // final partial page: caught up → `next` null (shared envelope contract);
      // a puller persists its position from the last entry's cid instead
      const res2 = await req(`/proof/v1/log?after=${body1.next}`);
      const body2 = await json(res2);
      expect(body2.entries).toHaveLength(1);
      expect(body2.next).toBeNull();

      // resuming from the last ingested entry's cid returns an empty page
      const lastCid = body2.entries[0].cid;
      const res3 = await req(`/proof/v1/log?after=${lastCid}`);
      const body3 = await json(res3);
      expect(body3.entries).toEqual([]);
      expect(body3.next).toBeNull();
    });

    it('rejects an unknown cursor with 400 (relay-local cursors)', async () => {
      const res = await req('/proof/v1/log?after=nonexistent');
      expect(res.status).toBe(400);
      const body = await json(res);
      expect(body.error).toBeDefined();
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

      const res = await req(`/proof/v1/content/${contentId}/log`);
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

      const res = await req(`/proof/v1/content/${contentId}/log`);
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
      const res1 = await req(`/proof/v1/content/${contentId}/log?limit=2`);
      const body1 = await json(res1);
      expect(body1.entries).toHaveLength(2);
      expect(body1.next).not.toBeNull();
      expect(body1).not.toHaveProperty('cursor');

      // read remainder
      const res2 = await req(`/proof/v1/content/${contentId}/log?after=${body1.next}`);
      const body2 = await json(res2);
      expect(body2.entries).toHaveLength(1);
      expect(body2.next).toBeNull();
      expect(body2).not.toHaveProperty('cursor');
    });

    it('should return 404 for unknown content log', async () => {
      const res = await req('/proof/v1/content/unknown-content-id/log');
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
          authorization: 'DFOS fake',
        },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(res.status).toBe(501);
    });

    it('should return 501 for blob download when content: false', async () => {
      const noContentRelay = await createRelay({ store, identity: RELAY_IDENTITY, content: false });

      const res = await noContentRelay.app.request('http://localhost/content/someid/blob', {
        headers: { authorization: 'DFOS fake' },
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

      const res = await req(`/proof/v1/identities/${identity.did}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect('log' in body).toBe(false);
    });

    it('identity response should include headCID', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/proof/v1/identities/${identity.did}`);
      const body = await json(res);
      expect(typeof body.headCID).toBe('string');
    });

    it('content response should NOT include log field', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      const res = await req(`/proof/v1/content/${contentId}`);
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

      const res = await req(`/proof/v1/content/${contentId}`);
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
        localReq('/proof/v1/operations', {
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

        const res = await localReq(`/proof/v1/identities/${identity.did}`);
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

        const res = await localReq('/proof/v1/identities/did:dfos:nonexistent');
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

        const res = await localReq(`/proof/v1/identities/${identity.did}`);
        expect(res.status).toBe(200);

        // verify the full chain was ingested (both ops in local store)
        const chain = await localStore.getIdentityChain(identity.did);
        expect(chain).toBeDefined();
        expect(chain!.log).toHaveLength(2);
      });

      it('restarts each identity read-through walk once when a peer rejects a mid-walk cursor', async () => {
        const identity = await createIdentity();
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
        const update = await signIdentityOperation({
          operation: updateOp,
          signer: identity.controller.signer,
          keyId: identity.controller.keyId,
          identityDID: identity.did,
        });

        for (const path of [
          `/proof/v1/identities/${identity.did}`,
          `/1.0/identifiers/${identity.did}`,
        ]) {
          const afters: Array<string | undefined> = [];
          const peerClient: PeerClient = {
            async getIdentityLog(_peerUrl, _did, params) {
              afters.push(params?.after);
              if (afters.length === 2) return 'invalid-cursor';
              if (afters.length <= 3) {
                return {
                  entries: [{ cid: identity.operationCID, jwsToken: identity.jwsToken }],
                  next: 'page-one',
                };
              }
              return {
                entries: [{ cid: update.operationCID, jwsToken: update.jwsToken }],
                next: null,
              };
            },
            async getContentLog() {
              return null;
            },
            async getOperationLog() {
              return null;
            },
            async submitOperations() {},
          };
          const localStore = new MemoryRelayStore();
          const relay = await createRelay({
            store: localStore,
            identity: RELAY_IDENTITY,
            peers: [{ url: 'http://peer-a' }],
            peerClient,
          });
          expect((await relay.app.request(path)).status).toBe(200);
          expect(afters).toEqual([undefined, 'page-one', undefined, 'page-one']);
          expect((await localStore.getIdentityChain(identity.did))?.log).toHaveLength(2);
        }
      });

      it('abandons an identity peer after its restarted walk rejects a second cursor', async () => {
        const identity = await createIdentity();
        const afters: Array<string | undefined> = [];
        const peerClient: PeerClient = {
          async getIdentityLog(_peerUrl, _did, params) {
            afters.push(params?.after);
            if (params?.after) return 'invalid-cursor';
            return {
              entries: [{ cid: identity.operationCID, jwsToken: identity.jwsToken }],
              next: 'page-one',
            };
          },
          async getContentLog() {
            return null;
          },
          async getOperationLog() {
            return null;
          },
          async submitOperations() {},
        };
        const localStore = new MemoryRelayStore();
        const relay = await createRelay({
          store: localStore,
          identity: RELAY_IDENTITY,
          peers: [{ url: 'http://peer-a' }],
          peerClient,
        });

        expect((await relay.app.request(`/proof/v1/identities/${identity.did}`)).status).toBe(200);
        expect(afters).toEqual([undefined, 'page-one', undefined, 'page-one']);
        expect((await localStore.getIdentityChain(identity.did))?.log).toHaveLength(1);
      });

      it('continues both identity read-through routes to the next peer after abandonment', async () => {
        const identity = await createIdentity();
        const newAuthKey = makeKey();
        const update = await signIdentityOperation({
          operation: {
            version: 1,
            type: 'update',
            previousOperationCID: identity.operationCID,
            authKeys: [newAuthKey.key],
            assertKeys: [],
            controllerKeys: [identity.controller.key],
            createdAt: ts(1),
          },
          signer: identity.controller.signer,
          keyId: identity.controller.keyId,
          identityDID: identity.did,
        });

        for (const path of [
          `/proof/v1/identities/${identity.did}`,
          `/1.0/identifiers/${identity.did}`,
        ]) {
          const calls: Array<{ peerUrl: string; after?: string }> = [];
          const peerClient: PeerClient = {
            async getIdentityLog(peerUrl, _did, params) {
              calls.push({ peerUrl, ...(params?.after ? { after: params.after } : {}) });
              if (peerUrl === 'http://peer-a') {
                if (params?.after) return 'invalid-cursor';
                return {
                  entries: [{ cid: identity.operationCID, jwsToken: identity.jwsToken }],
                  next: 'page-one',
                };
              }
              return {
                entries: [
                  { cid: identity.operationCID, jwsToken: identity.jwsToken },
                  { cid: update.operationCID, jwsToken: update.jwsToken },
                ],
                next: null,
              };
            },
            async getContentLog() {
              return null;
            },
            async getOperationLog() {
              return null;
            },
            async submitOperations() {},
          };
          const localStore = new MemoryRelayStore();
          const relay = await createRelay({
            store: localStore,
            identity: RELAY_IDENTITY,
            peers: [{ url: 'http://peer-a' }, { url: 'http://peer-b' }],
            peerClient,
          });

          expect((await relay.app.request(path)).status).toBe(200);
          expect(calls.map((call) => call.peerUrl)).toEqual([
            'http://peer-a',
            'http://peer-a',
            'http://peer-a',
            'http://peer-a',
            'http://peer-b',
          ]);
          expect((await localStore.getIdentityChain(identity.did))?.log).toHaveLength(2);
        }
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

        const res = await localReq(`/proof/v1/content/${contentId}`);
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

        const res = await localReq(`/proof/v1/content/${contentId}`);
        expect(res.status).toBe(200);

        // verify the full chain was ingested (both ops in local store)
        const chain = await localStore.getContentChain(contentId);
        expect(chain).toBeDefined();
        expect(chain!.log).toHaveLength(2);
      });

      it('restarts content read-through once when a peer rejects a mid-walk cursor', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        const content = await createContentOp(identity);
        const genesisResults = await ingestOperations(
          [identity.jwsToken, content.jwsToken],
          peerStore,
        );
        const contentId = genesisResults.find((result) => result.kind === 'content-op')!.chainId!;
        const newDocEncoded = await dagCborCanonicalEncode({ type: 'post', title: 'updated' });
        const update = await signContentOperation({
          operation: {
            version: 1,
            type: 'update',
            did: identity.did,
            previousOperationCID: content.operationCID,
            documentCID: newDocEncoded.cid.toString(),
            baseDocumentCID: null,
            createdAt: ts(2),
            note: null,
          },
          signer: identity.authKey.signer,
          kid: `${identity.did}#${identity.authKey.keyId}`,
        });
        const afters: Array<string | undefined> = [];
        const peerClient: PeerClient = {
          async getIdentityLog() {
            return null;
          },
          async getContentLog(_peerUrl, _contentId, params) {
            afters.push(params?.after);
            if (afters.length === 2) return 'invalid-cursor';
            if (afters.length <= 3) {
              return {
                entries: [{ cid: content.operationCID, jwsToken: content.jwsToken }],
                next: 'page-one',
              };
            }
            return {
              entries: [{ cid: update.operationCID, jwsToken: update.jwsToken }],
              next: null,
            };
          },
          async getOperationLog() {
            return null;
          },
          async submitOperations() {},
        };
        const localStore = new MemoryRelayStore();
        await ingestOperations([identity.jwsToken], localStore);
        const relay = await createRelay({
          store: localStore,
          identity: RELAY_IDENTITY,
          peers: [{ url: 'http://peer-a' }],
          peerClient,
        });
        expect((await relay.app.request(`/proof/v1/content/${contentId}`)).status).toBe(200);
        expect(afters).toEqual([undefined, 'page-one', undefined, 'page-one']);
        expect((await localStore.getContentChain(contentId))?.log).toHaveLength(2);
      });

      it('should not consult peers with readThrough: false', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore);

        const { req: localReq } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a', readThrough: false }],
        });

        const res = await localReq(`/proof/v1/identities/${identity.did}`);
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

        const res = await relay.app.request(`http://localhost/proof/v1/identities/${identity.did}`);
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

      it('persists only peer-supplied cursors — never fabricated ones', async () => {
        const peerStore = new MemoryRelayStore();
        const identity = await createIdentity();
        await ingestOperations([identity.jwsToken], peerStore, {
          logEnabled: true,
        });

        const { relay, localStore } = await createPeeredRelay({
          peerStore,
          peers: [{ url: 'http://peer-a' }],
        });

        await relay.syncFromPeers();

        // single op < page size → final partial page → `next` null → the puller
        // retains its (absent) persisted cursor rather than fabricating one from
        // the last entry's CID (a fabricated cursor would 400 against a relay
        // whose cursor format is not a bare CID, e.g. production's opaque token).
        const cursor = await localStore.getPeerCursor('http://peer-a');
        expect(cursor).toBeUndefined();

        // the op still ingested, and a second sync is idempotent
        expect(await localStore.getIdentityChain(identity.did)).toBeDefined();
        await relay.syncFromPeers();
        expect(await localStore.getIdentityChain(identity.did)).toBeDefined();
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

      it('aborts after two invalid-cursor responses without destroying persisted progress', async () => {
        const localStore = new MemoryRelayStore();
        await localStore.setPeerCursor('http://peer-a', 'persisted-high-water');
        let attempts = 0;
        const peerClient: PeerClient = {
          async getIdentityLog() {
            return null;
          },
          async getContentLog() {
            return null;
          },
          async getOperationLog() {
            attempts += 1;
            return 'invalid-cursor';
          },
          async submitOperations() {},
        };
        const relay = await createRelay({
          store: localStore,
          identity: RELAY_IDENTITY,
          peers: [{ url: 'http://peer-a' }],
          peerClient,
        });

        await relay.syncFromPeers();

        expect(attempts).toBe(2);
        expect(await localStore.getPeerCursor('http://peer-a')).toBe('persisted-high-water');
      });

      it('restarts a genuinely wiped peer once and persists from-scratch progress', async () => {
        const identity = await createIdentity();
        const localStore = new MemoryRelayStore();
        await localStore.setPeerCursor('http://peer-a', 'stale-high-water');
        const afters: Array<string | undefined> = [];
        const peerClient: PeerClient = {
          async getIdentityLog() {
            return null;
          },
          async getContentLog() {
            return null;
          },
          async getOperationLog(_peerUrl, params) {
            afters.push(params?.after);
            if (params?.after === 'stale-high-water') return 'invalid-cursor';
            if (!params?.after) {
              return {
                entries: [{ cid: identity.operationCID, jwsToken: identity.jwsToken }],
                next: 'fresh-high-water',
              };
            }
            return { entries: [], next: null };
          },
          async submitOperations() {},
        };
        const relay = await createRelay({
          store: localStore,
          identity: RELAY_IDENTITY,
          peers: [{ url: 'http://peer-a' }],
          peerClient,
        });

        await relay.syncFromPeers();

        expect(afters).toEqual(['stale-high-water', undefined, 'fresh-high-water']);
        expect(await localStore.getPeerCursor('http://peer-a')).toBe('fresh-high-water');
        expect(await localStore.getIdentityChain(identity.did)).toBeDefined();
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
  // revocation status (/revocations/v1, own clock)
  // ---------------------------------------------------------------------------

  describe('revocation status', () => {
    /** Ingest an identity, mint a credential, revoke it. Returns the pieces. */
    const revokeFreshCredential = async () => {
      const issuer = await createIdentity();
      await postOps([issuer.jwsToken]);

      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: issuer.did,
        audienceDID: '*',
        att: [{ resource: `chain:someContentId`, action: 'read' }],
        exp: now + 3600,
        signer: issuer.authKey.signer,
        keyId: issuer.authKey.keyId,
        iat: now,
      });
      const credentialCID = decodeDFOSCredentialUnsafe(credential)!.header.cid;

      const { jwsToken: revocationJws } = await signRevocation({
        issuerDID: issuer.did,
        credentialCID,
        signer: issuer.authKey.signer,
        keyId: issuer.authKey.keyId,
      });
      const res = await postOps([credential, revocationJws]);
      const body = await json(res);
      expect(body.results[1].status).toBe('new');
      expect(body.results[1].kind).toBe('revocation');

      return { issuer, credential, credentialCID, revocationJws };
    };

    const revokeCredentialForIssuer = async (
      issuer: Awaited<ReturnType<typeof createIdentity>>,
      resource: string,
    ) => {
      const now = Math.floor(Date.now() / 1000);
      const credential = await createDFOSCredential({
        issuerDID: issuer.did,
        audienceDID: '*',
        att: [{ resource, action: 'read' }],
        exp: now + 3600,
        signer: issuer.authKey.signer,
        keyId: issuer.authKey.keyId,
        iat: now,
      });
      const credentialCID = decodeDFOSCredentialUnsafe(credential)!.header.cid;
      const { jwsToken } = await signRevocation({
        issuerDID: issuer.did,
        credentialCID,
        signer: issuer.authKey.signer,
        keyId: issuer.authKey.keyId,
      });
      const res = await postOps([credential, jwsToken]);
      const body = await json(res);
      expect(body.results[1].status).toBe('new');
      expect(body.results[1].kind).toBe('revocation');
      return { credentialCID, revocationJws: jwsToken };
    };

    const byRevocationOrder = (
      a: { credentialCID: string; revocationJws: string },
      b: { credentialCID: string; revocationJws: string },
    ) => {
      if (a.credentialCID === b.credentialCID) return 0;
      return a.credentialCID < b.credentialCID ? -1 : 1;
    };

    it('returns revoked:true with the self-proving revocation JWS', async () => {
      const { issuer, credentialCID, revocationJws } = await revokeFreshCredential();

      const res = await req(`/revocations/v1/credential/${credentialCID}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body).toEqual({ credentialCID, revoked: true, revocation: revocationJws });

      // the JWS is the proof — it decodes to the revoked CID and the issuer
      const decoded = decodeJwsUnsafe(body.revocation)!;
      expect(decoded.header.typ).toBe('did:dfos:revocation');
      expect((decoded.payload as Record<string, unknown>)['credentialCID']).toBe(credentialCID);
      expect((decoded.payload as Record<string, unknown>)['did']).toBe(issuer.did);
    });

    it('returns revoked:false (no revocation key) for an unknown credential CID', async () => {
      // well-formed dag-cbor CID the relay has never seen — honest known-nothing
      const unknownCID = `bafyrei${'a'.repeat(52)}`;
      const res = await req(`/revocations/v1/credential/${unknownCID}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body).toEqual({ credentialCID: unknownCID, revoked: false });
      expect('revocation' in body).toBe(false);
    });

    it('returns 400 for a malformed credential CID', async () => {
      const res = await req('/revocations/v1/credential/not-a-cid');
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('invalid credential CID');
    });

    it('lists all revocations for an issuer, sorted by credentialCID', async () => {
      const issuer = await createIdentity();
      await postOps([issuer.jwsToken]);

      const revA = await revokeCredentialForIssuer(issuer, 'chain:contentA');
      const revB = await revokeCredentialForIssuer(issuer, 'chain:contentB');
      const expected = [revA, revB].sort(byRevocationOrder);

      const res = await req(`/revocations/v1/issuer/${issuer.did}`);
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body).toEqual({
        did: issuer.did,
        revocations: expected.map((r) => ({
          credentialCID: r.credentialCID,
          revocation: r.revocationJws,
        })),
        next: null,
      });
    });

    it('paginates issuer revocations with credentialCID cursors', async () => {
      const issuer = await createIdentity();
      await postOps([issuer.jwsToken]);

      const revocations = [
        await revokeCredentialForIssuer(issuer, 'chain:pageA'),
        await revokeCredentialForIssuer(issuer, 'chain:pageB'),
        await revokeCredentialForIssuer(issuer, 'chain:pageC'),
      ].sort(byRevocationOrder);

      const firstRes = await req(`/revocations/v1/issuer/${issuer.did}?limit=2`);
      expect(firstRes.status).toBe(200);
      const firstPage = await json(firstRes);
      expect(firstPage.revocations).toHaveLength(2);
      expect(typeof firstPage.next).toBe('string');
      expect(firstPage.next).toBe(firstPage.revocations[1].credentialCID);

      const secondRes = await req(
        `/revocations/v1/issuer/${issuer.did}?after=${firstPage.next}&limit=2`,
      );
      expect(secondRes.status).toBe(200);
      const secondPage = await json(secondRes);
      expect(secondPage.revocations).toHaveLength(1);
      expect(secondPage.next).toBeNull();

      const paged = [...firstPage.revocations, ...secondPage.revocations];
      expect(paged.map((r) => r.credentialCID)).toEqual(revocations.map((r) => r.credentialCID));
      expect([...new Set(paged.map((r) => r.credentialCID))].sort()).toEqual(
        revocations.map((r) => r.credentialCID).sort(),
      );

      expect(paged.map((row) => row.credentialCID)).toEqual(
        paged.map((row) => row.credentialCID).sort(),
      );
    });

    it('resumes issuer revocations strictly after an unknown credentialCID cursor', async () => {
      const issuer = await createIdentity();
      await postOps([issuer.jwsToken]);
      const revocations = [
        await revokeCredentialForIssuer(issuer, 'chain:keysetA'),
        await revokeCredentialForIssuer(issuer, 'chain:keysetB'),
        await revokeCredentialForIssuer(issuer, 'chain:keysetC'),
      ].sort(byRevocationOrder);
      // Appending a byte to the first fixed-width CID produces an absent key
      // strictly between the first and second rows.
      const after = `${revocations[0]!.credentialCID}~`;
      const response = await req(
        `/revocations/v1/issuer/${issuer.did}?after=${encodeURIComponent(after)}`,
      );
      expect(response.status).toBe(200);
      const body = await json(response);
      expect(body.revocations.map((row: { credentialCID: string }) => row.credentialCID)).toEqual(
        revocations.filter((row) => row.credentialCID > after).map((row) => row.credentialCID),
      );
    });

    it('returns an empty array for an issuer with no revocations', async () => {
      const issuer = await createIdentity(); // never revoked anything
      const res = await req(`/revocations/v1/issuer/${issuer.did}`);
      expect(res.status).toBe(200);
      expect(await json(res)).toEqual({ did: issuer.did, revocations: [], next: null });
    });

    it('returns 400 for a malformed DID', async () => {
      const res = await req('/revocations/v1/issuer/did:dfos:tooshort');
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('invalid DID');
    });

    it('advertises the revocations capability in the well-known', async () => {
      const body = await json(await req('/.well-known/dfos-relay'));
      expect(body.capabilities.revocations).toBe(true);
    });

    it('gates both routes first and advertises false when revocations are disabled', async () => {
      const disabled = await createRelay({
        store,
        identity: RELAY_IDENTITY,
        revocations: false,
      });
      const disabledReq = (path: string) => disabled.app.request(`http://localhost${path}`);

      // Deliberately malformed params prove the capability gate fires before
      // validation (and therefore before any store lookup).
      for (const path of [
        '/revocations/v1/credential/not-a-cid',
        '/revocations/v1/issuer/not-a-did',
      ]) {
        const res = await disabledReq(path);
        expect(res.status).toBe(501);
        expect(await json(res)).toEqual({ error: 'revocation status not available' });
      }

      const body = await json(await disabledReq('/.well-known/dfos-relay'));
      expect(body.capabilities.revocations).toBe(false);
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
    it('should serve only the current head to standing-auth readers', async () => {
      const creator = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;
      // upload the genesis blob
      const genesisBytes = new TextEncoder().encode(JSON.stringify(content.document));
      const genesisUpload = await putBlob(
        contentId,
        content.operationCID,
        creator,
        genesisBytes,
      );
      expect(genesisUpload.status).toBe(200);

      // update the chain and upload the new head blob
      const headDocument = { type: 'post', title: 'current head', body: 'updated content' };
      const headEncoded = await dagCborCanonicalEncode(
        headDocument as unknown as Record<string, unknown>,
      );
      const updateOp: ContentOperation = {
        version: 1,
        type: 'update',
        did: creator.did,
        previousOperationCID: content.operationCID,
        documentCID: headEncoded.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
      };
      const { jwsToken: updateToken, operationCID: headOperationCID } = await signContentOperation({
        operation: updateOp,
        signer: creator.authKey.signer,
        kid: `${creator.did}#${creator.authKey.keyId}`,
      });
      await postOps([updateToken]);

      const headBytes = new TextEncoder().encode(JSON.stringify(headDocument));
      const headUpload = await putBlob(contentId, headOperationCID, creator, headBytes);
      expect(headUpload.status).toBe(200);

      // mint a standing public read grant
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

      const anonymousHead = await req(`/content/${contentId}/blob`);
      expect(anonymousHead.status).toBe(200);
      expect(new Uint8Array(await anonymousHead.arrayBuffer())).toEqual(headBytes);

      const anonymousGenesis = await req(`/content/${contentId}/blob/${content.operationCID}`);
      expect(anonymousGenesis.status).toBe(401);

      const anonymousHeadRef = await req(`/content/${contentId}/blob/${headOperationCID}`);
      expect(anonymousHeadRef.status).toBe(200);
      expect(new Uint8Array(await anonymousHeadRef.arrayBuffer())).toEqual(headBytes);

      const creatorGenesis = await reqAs(`/content/${contentId}/blob/${content.operationCID}`, creator);
      expect(creatorGenesis.status).toBe(200);
      expect(new Uint8Array(await creatorGenesis.arrayBuffer())).toEqual(genesisBytes);

      // a stranger proving only their own identity must NOT reach the non-head
      // revision: the standing public grant conveys head-only publicness, so the
      // authenticated path denies the genesis ref (403).
      const stranger = await createIdentity();
      await postOps([stranger.jwsToken]);
      const strangerGenesis = await reqAs(
        `/content/${contentId}/blob/${content.operationCID}`,
        stranger,
      );
      expect(strangerGenesis.status).toBe(403);

      // nor by replaying the public credential JWS as a per-request bearer.
      const strangerGenesisWithCred = await reqAs(`/content/${contentId}/blob/${content.operationCID}`, stranger, { headers: { 'x-credential': publicCred  } });
      expect(strangerGenesisWithCred.status).toBe(403);
    });

    it('should grant read access via stored public credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const ingestRes = await postOps([content.jwsToken]);
      const contentId = (await json(ingestRes)).results[0].chainId;

      // upload blob as creator
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, reader);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, reader);
      expect(downloadRes.status).toBe(403);
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
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await putBlob(contentId, content.operationCID, creator, docBytes);

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
      const downloadRes = await reqAs(`/content/${contentId}/blob`, member, { headers: { 'x-credential': childCredential } });
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
      const downloadRes2 = await reqAs(`/content/${contentId}/blob`, member, { headers: { 'x-credential': childCredential } });
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

      const docBytes1 = new TextEncoder().encode(JSON.stringify(content1.document));
      await putBlob(contentId1, content1.operationCID, creator, docBytes1);

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
      await putBlob(contentId2, content2.operationCID, creator, docBytes2);

      // reader can download blob from first content chain (standing auth)
      const dl1 = await reqAs(`/content/${contentId1}/blob`, reader);
      expect(dl1.status).toBe(200);

      // reader can download blob from second content chain (standing auth)
      const dl2 = await reqAs(`/content/${contentId2}/blob`, reader);
      expect(dl2.status).toBe(200);
    });
  });
});

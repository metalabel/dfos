/*

  STORE CONTRACT

  The three contracts a store can implement, and what the relay derives from
  which of them it does: atomic commit, capabilities as a fact about the store's
  type, the index projection as a cursor-driven worker, and the issuer scoping
  on a revocation's removal of a standing grant.

*/

import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  signRevocation,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
  signApiIdentityRequest,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import {
  bootstrapRelayIdentity,
  createRelay,
  ingestOperations,
  isIndexReadStore,
  isIndexWriteStore,
  isRelayWriteStore,
  isSigningStore,
  MemoryRelayStore,
  projectIndex,
  type CommitBatch,
  type RelayReadStore,
  type RelayStore,
} from '../src';

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

const createIdentityOp = async () => {
  const controller = makeKey();
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [controller.key],
    assertKeys: [controller.key],
    controllerKeys: [controller.key],
    // An hour back: every verification with a committed basis resolves the signer
    // in the state as of that basis, and an identity has no state before its own
    // genesis.
    createdAt: ts(-60),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(operation);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  return {
    did: deriveChainIdentifier(encoded.cid.bytes, 'did:dfos'),
    key: controller,
    jwsToken,
    operationCID,
  };
};

type TestIdentity = Awaited<ReturnType<typeof createIdentityOp>>;

const contentOp = async (identity: TestIdentity, document: Record<string, unknown>, offset = 1) => {
  const encoded = await dagCborCanonicalEncode(document);
  const operation: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID: encoded.cid.toString(),
    baseDocumentCID: null,
    createdAt: ts(offset),
    note: null,
  };
  return signContentOperation({
    operation,
    signer: identity.key.signer,
    kid: `${identity.did}#${identity.key.keyId}`,
  });
};

const publicReadGrant = async (identity: TestIdentity, resource: string) => {
  const now = Math.floor(Date.now() / 1000);
  const credential = await createDFOSCredential({
    issuerDID: identity.did,
    audienceDID: '*',
    att: [{ resource, action: 'read' }],
    exp: now + 3600,
    signer: identity.key.signer,
    keyId: identity.key.keyId,
    iat: now,
  });
  return {
    credential,
    credentialCID: decodeDFOSCredentialUnsafe(credential)!.header.cid as string,
  };
};

/**
 * A store that implements the READ contract and nothing else — the shape the
 * platform's Postgres projection actually has. Every member here is implemented
 * for real; the point is that the members it does NOT have are absent rather
 * than present-and-throwing.
 */
const readOnlyStore = (backing: MemoryRelayStore): RelayReadStore => ({
  getOperation: (cid) => backing.getOperation(cid),
  getIdentityChain: (did) => backing.getIdentityChain(did),
  getContentChain: (contentId) => backing.getContentChain(contentId),
  getIdentityStateAtCID: (did, cid) => backing.getIdentityStateAtCID(did, cid),
  getContentStateAtCID: (contentId, cid) => backing.getContentStateAtCID(contentId, cid),
  getBlob: (key) => backing.getBlob(key),
  getCountersignatures: (cid) => backing.getCountersignatures(cid),
  readLog: (params) => backing.readLog(params),
  getStats: () => backing.getStats(),
  isCredentialRevoked: (issuer, cid, asOf) => backing.isCredentialRevoked(issuer, cid, asOf),
  getRevocationForCredential: (cid) => backing.getRevocationForCredential(cid),
  getRevocationsByIssuer: (did) => backing.getRevocationsByIssuer(did),
  getPublicCredentials: (resource) => backing.getPublicCredentials(resource),
  getPublicCredentialByCID: (cid) => backing.getPublicCredentialByCID(cid),
});

// -----------------------------------------------------------------------------
// atomic commit
// -----------------------------------------------------------------------------

describe('commit is atomic', () => {
  it('leaves no partial state when the whole commit fails, and keeps the raw op', async () => {
    // A store that accepts the identity genesis and then faults on the content
    // operation. The old contract would already have written the operation row
    // and the chain head by the time the log append failed; here the whole
    // batch is one call, so a failure writes nothing.
    class FailingContentStore extends MemoryRelayStore {
      failContent = false;
      override async commit(batch: CommitBatch) {
        if (
          this.failContent &&
          batch.kind === 'operation' &&
          batch.operation.chainType === 'content'
        ) {
          throw new Error('database is locked');
        }
        return super.commit(batch);
      }
    }

    const store = new FailingContentStore();
    const identity = await createIdentityOp();
    expect((await ingestOperations([identity.jwsToken], store))[0]!.status).toBe('new');

    const content = await contentOp(identity, { $schema: 'example/post', title: 'atomic' });
    store.failContent = true;
    const [result] = await ingestOperations([content.jwsToken], store);

    expect(result!.status).toBe('rejected');
    // A store fault is NOT a verdict about the operation: retryable, so the
    // sequencer keeps the raw op instead of deleting the only copy.
    expect(result!.storeFault).toBe(true);
    expect(result!.dependencyMissing).toBeUndefined();

    // nothing landed
    expect(await store.getOperation(content.operationCID)).toBeUndefined();
    const log = await store.readLog({ limit: 100 });
    expect(log!.entries.map((entry) => entry.cid)).toEqual([identity.operationCID]);

    // and the same op succeeds once the store is well again
    store.failContent = false;
    expect((await ingestOperations([content.jwsToken], store))[0]!.status).toBe('new');
    expect(await store.getOperation(content.operationCID)).toBeDefined();
  });

  it('never exposes an operation without its log entry — the apply block does not yield', async () => {
    // WHAT THE ATOMICITY CLAUSE IS FOR, on the reference store: not "the commit
    // throws at the top" (the test above) but "a commit interrupted PARTWAY is
    // never observable". In a single-threaded store the only interruption is a
    // yield, so the property is that the apply block defers nothing: it reads
    // the batch, validates all of it, and applies all of it in one turn. This
    // reads the store at the first boundary after the batch starts — where a
    // concurrent read route, which takes no lock, would read it. A mutator that
    // actually deferred (an async store member doing real work) would show the
    // operation row here without its log entry, and fail.
    const store = new MemoryRelayStore();
    const identity = await createIdentityOp();

    const pending = store.commit({
      kind: 'operation',
      operation: {
        cid: identity.operationCID,
        jwsToken: identity.jwsToken,
        chainType: 'identity',
        chainId: identity.did,
      },
      identityChain: {
        did: identity.did,
        log: [identity.jwsToken],
        state: {
          did: identity.did,
          isDeleted: false,
          authKeys: [identity.key.key],
          assertKeys: [identity.key.key],
          controllerKeys: [identity.key.key],
          services: [],
        },
        lastCreatedAt: ts(),
        headCID: identity.operationCID,
      },
      logEntry: {
        cid: identity.operationCID,
        jwsToken: identity.jwsToken,
        kind: 'identity-op',
        chainId: identity.did,
        ingestedAt: new Date().toISOString(),
      },
    });

    // Read BEFORE awaiting the commit: whatever a concurrent request would see
    // at the first yield after the batch started.
    const observed = {
      operation: await store.getOperation(identity.operationCID),
      chain: await store.getIdentityChain(identity.did),
      log: (await store.readLog({ limit: 100 }))!.entries.map((entry) => entry.cid),
    };
    expect(await pending).toBe('new');

    expect(observed.operation).toBeDefined();
    expect(observed.chain).toBeDefined();
    expect(observed.log).toContain(identity.operationCID);
  });

  it('answers duplicate and writes nothing when the operation CID is already held', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentityOp();
    await ingestOperations([identity.jwsToken], store);

    const before = (await store.readLog({ limit: 100 }))!.entries.length;
    const result = await store.commit({
      kind: 'operation',
      operation: {
        cid: identity.operationCID,
        jwsToken: identity.jwsToken,
        chainType: 'identity',
        chainId: identity.did,
      },
      logEntry: {
        cid: identity.operationCID,
        jwsToken: identity.jwsToken,
        kind: 'identity-op',
        chainId: identity.did,
        ingestedAt: new Date().toISOString(),
      },
    });

    expect(result).toBe('duplicate');
    expect((await store.readLog({ limit: 100 }))!.entries.length).toBe(before);
  });

  it('refuses a batch whose log entry describes a different operation', async () => {
    const store = new MemoryRelayStore();
    await expect(
      store.commit({
        kind: 'operation',
        operation: { cid: 'op-a', jwsToken: 'a', chainType: 'artifact', chainId: 'did:dfos:x' },
        logEntry: {
          cid: 'op-b',
          jwsToken: 'b',
          kind: 'artifact',
          chainId: 'did:dfos:x',
          ingestedAt: ts(),
        },
      }),
    ).rejects.toThrow('does not describe the committed operation');
    expect(await store.getOperation('op-a')).toBeUndefined();
  });
});

// -----------------------------------------------------------------------------
// derived capabilities
// -----------------------------------------------------------------------------

describe('capabilities are derived from the store', () => {
  it('reads a memory store as write + index + writer state, and a read-only store as none', () => {
    const memory = new MemoryRelayStore();
    expect(isRelayWriteStore(memory)).toBe(true);
    expect(isIndexReadStore(memory)).toBe(true);
    expect(isIndexWriteStore(memory)).toBe(true);
    expect(isSigningStore(memory)).toBe(true);

    const readOnly = readOnlyStore(memory) as RelayStore;
    expect(isRelayWriteStore(readOnly)).toBe(false);
    expect(isIndexReadStore(readOnly)).toBe(false);
    expect(isIndexWriteStore(readOnly)).toBe(false);
    expect(isSigningStore(readOnly)).toBe(false);
  });

  it('advertises write:false and index:false over a read-only store, with no throwing stubs', async () => {
    const backing = new MemoryRelayStore();
    const identity = await bootstrapRelayIdentity(backing);
    const relay = await createRelay({ store: readOnlyStore(backing), identity });

    const wellKnown = (await (
      await relay.app.request('http://localhost/.well-known/dfos-relay')
    ).json()) as {
      capabilities: Record<string, boolean>;
      ingestion: string;
      stats: { pendingOps: number };
    };
    expect(wellKnown.capabilities.write).toBe(false);
    expect(wellKnown.capabilities.index).toBe(false);
    expect(wellKnown.capabilities.signing).toBe(false);
    expect(wellKnown.capabilities.proof).toBe(true);
    expect(wellKnown.ingestion).toBe('closed');
    // Not -1: the store has no sequencer to be behind, and says so rather than
    // reporting an error it never had.
    expect(wellKnown.stats.pendingOps).toBe(0);

    // the write surfaces are closed, and the reads still work
    expect(
      (
        await relay.app.request('http://localhost/proof/v1/operations', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operations: ['x'] }),
        })
      ).status,
    ).toBe(501);
    expect((await relay.app.request('http://localhost/index/v0/identities')).status).toBe(501);
    expect((await relay.app.request('http://localhost/proof/v1/log')).status).toBe(200);
    expect(
      (await relay.app.request(`http://localhost/proof/v1/identities/${identity.did}`)).status,
    ).toBe(200);
  });

  it('serves index queries for a store that has no projection side', async () => {
    // The supported "someone else maintains my index" shape: the read side is
    // implemented, the write side is not, and the relay simply does no
    // projection work.
    const backing = new MemoryRelayStore();
    const identity = await bootstrapRelayIdentity(backing);
    const queryOnly = {
      ...readOnlyStore(backing),
      queryIndexIdentities: backing.queryIndexIdentities.bind(backing),
      queryIndexContent: backing.queryIndexContent.bind(backing),
      queryIndexCredits: backing.queryIndexCredits.bind(backing),
      queryIndexArtifacts: backing.queryIndexArtifacts.bind(backing),
      queryIndexCountersignatures: backing.queryIndexCountersignatures.bind(backing),
      queryIndexCredentials: backing.queryIndexCredentials.bind(backing),
      queryIndexOperations: backing.queryIndexOperations.bind(backing),
      getIndexIdentityDIDsByProfileAnchor:
        backing.getIndexIdentityDIDsByProfileAnchor.bind(backing),
      getIndexContentIdsByDocumentCID: backing.getIndexContentIdsByDocumentCID.bind(backing),
    } as RelayStore;

    expect(isIndexReadStore(queryOnly)).toBe(true);
    expect(isIndexWriteStore(queryOnly)).toBe(false);

    const relay = await createRelay({ store: queryOnly, identity });
    expect((await relay.app.request('http://localhost/index/v0/identities')).status).toBe(200);
    expect(await relay.projectIndex()).toEqual({ projected: 0, swept: 0, caughtUp: true });
  });

  it('refuses a configuration that claims a capability the store cannot back', async () => {
    const backing = new MemoryRelayStore();
    const identity = await bootstrapRelayIdentity(backing);
    const store = readOnlyStore(backing);

    await expect(createRelay({ store, identity, write: true })).rejects.toThrow(
      'write capability requires a store implementing commit',
    );
    await expect(createRelay({ store, identity, index: true })).rejects.toThrow(
      'index capability requires a store implementing IndexReadStore',
    );
    await expect(createRelay({ store, identity, signing: true })).rejects.toThrow(
      'signing capability requires a store implementing SigningStore',
    );
    await expect(createRelay({ store, peers: [{ url: 'http://peer' }] })).rejects.toThrow(
      'peering requires a writing store',
    );
    await expect(createRelay({ store })).rejects.toThrow(
      'a relay over a read-only store must be given an identity',
    );
  });

  it('turns the index off with the log it projects from', async () => {
    // The index this relay maintains is a projection of the operation log and
    // has no other input. With `log: false` no commit carries a log entry, so
    // the projection would never see anything — and a relay that advertised
    // `index: true` while answering every query with an empty page forever is
    // exactly the lie derived capabilities exist to prevent.
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, log: false });

    const wellKnown = (await (
      await relay.app.request('http://localhost/.well-known/dfos-relay')
    ).json()) as { capabilities: Record<string, boolean> };
    expect(wellKnown.capabilities.log).toBe(false);
    expect(wellKnown.capabilities.index).toBe(false);

    const identity = await createIdentityOp();
    const posted = await relay.app.request('http://localhost/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations: [identity.jwsToken] }),
    });
    expect(posted.status).toBe(200);
    // the routes answer capability-not-supported, not an empty page
    expect(
      (await relay.app.request(`http://localhost/index/v0/identities?did=${identity.did}`)).status,
    ).toBe(501);
    expect((await relay.app.request('http://localhost/proof/v1/log')).status).toBe(501);
    // and the proof plane still answers for the operation it accepted
    expect(
      (await relay.app.request(`http://localhost/proof/v1/identities/${identity.did}`)).status,
    ).toBe(200);

    await expect(
      createRelay({ store: new MemoryRelayStore(), log: false, index: true }),
    ).rejects.toThrow('index capability requires the operation log');
  });

  it('keeps the index over a log-less relay when something else maintains the rows', async () => {
    // The other half of the same rule: a store with no projection side has no
    // feed to lose, so `log: false` says nothing about its index.
    const backing = new MemoryRelayStore();
    const identity = await bootstrapRelayIdentity(backing);
    const queryOnly = {
      ...readOnlyStore(backing),
      queryIndexIdentities: backing.queryIndexIdentities.bind(backing),
      queryIndexContent: backing.queryIndexContent.bind(backing),
      queryIndexCredits: backing.queryIndexCredits.bind(backing),
      queryIndexArtifacts: backing.queryIndexArtifacts.bind(backing),
      queryIndexCountersignatures: backing.queryIndexCountersignatures.bind(backing),
      queryIndexCredentials: backing.queryIndexCredentials.bind(backing),
      queryIndexOperations: backing.queryIndexOperations.bind(backing),
      getIndexIdentityDIDsByProfileAnchor:
        backing.getIndexIdentityDIDsByProfileAnchor.bind(backing),
      getIndexContentIdsByDocumentCID: backing.getIndexContentIdsByDocumentCID.bind(backing),
    } as RelayStore;

    const relay = await createRelay({ store: queryOnly, identity, log: false });
    expect((await relay.app.request('http://localhost/index/v0/identities')).status).toBe(200);
    expect((await relay.app.request('http://localhost/proof/v1/log')).status).toBe(501);
  });
});

// -----------------------------------------------------------------------------
// the projection worker
// -----------------------------------------------------------------------------

describe('index projection worker', () => {
  it('walks the log from the stored cursor, one budget at a time', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, indexProjection: 'external' });

    const first = await createIdentityOp();
    const second = await createIdentityOp();
    await ingestOperations([first.jwsToken, second.jwsToken], store);

    // external mode: nothing has projected yet
    expect(await store.queryIndexOperations({ order: 'ingestedAt.desc', limit: 100 })).toEqual([]);

    const one = await projectIndex(store, { budget: 1 });
    expect(one.projected).toBe(1);
    expect(one.caughtUp).toBe(false);
    expect((await store.getIndexCursor()).logCursor).not.toBeNull();
    expect(
      (await store.queryIndexOperations({ order: 'ingestedAt.desc', limit: 100 })).length,
    ).toBe(1);

    // subsequent runs resume from the cursor rather than restarting
    let guard = 0;
    let run = await projectIndex(store, { budget: 1 });
    while (!run.caughtUp && guard++ < 20) run = await projectIndex(store, { budget: 1 });
    expect(run.caughtUp).toBe(true);

    const projectedCids = (
      await store.queryIndexOperations({ order: 'ingestedAt.desc', limit: 100 })
    ).map((row) => row.cid);
    const logCids = (await store.readLog({ limit: 100 }))!.entries.map((entry) => entry.cid);
    expect(new Set(projectedCids)).toEqual(new Set(logCids));

    // a caught-up run is a no-op
    expect(await projectIndex(store, { budget: 100 })).toEqual({
      projected: 0,
      swept: 0,
      caughtUp: true,
    });
    // and the relay's own handle drives the same worker
    expect((await relay.projectIndex()).caughtUp).toBe(true);
  });

  it('recomputes a content row after its blob lands, in external mode too', async () => {
    // A BLOB ARRIVAL IS NOT ON THE LOG. The worker's whole feed is `readLog`, so
    // an external drain — however often it runs — never reaches the moment a
    // document's bytes land, and the rows that project that document would keep
    // reporting docSchema: null forever. The blob route therefore recomputes
    // them itself in every mode; it is bounded by the documentCID reverse
    // lookup, not a fan-out.
    const store = new MemoryRelayStore();
    const relayIdentity = await bootstrapRelayIdentity(store);
    const relay = await createRelay({
      store,
      identity: relayIdentity,
      authority: 'localhost',
      indexProjection: 'external',
    });

    const creator = await createIdentityOp();
    await ingestOperations([creator.jwsToken], store);
    const document = { $schema: 'example/post', title: 'late bytes' };
    const post = await contentOp(creator, document);
    const [created] = await ingestOperations([post.jwsToken], store);
    const contentId = created!.chainId!;

    // the external worker catches the log up; the bytes are not there yet
    let guard = 0;
    while (!(await relay.projectIndex()).caughtUp && guard++ < 20);
    const before = (await store.queryIndexContent({ limit: 100 })).find(
      (row) => row.contentId === contentId,
    );
    expect(before?.docSchema).toBeNull();

    const path = `/content/${contentId}/blob/${post.operationCID}`;
    const body = new TextEncoder().encode(JSON.stringify(document));
    const { proof } = await signApiIdentityRequest({
      method: 'PUT',
      host: 'localhost',
      path,
      body,
      kid: `${creator.did}#${creator.key.keyId}`,
      sign: creator.key.signer,
      extraMembers: { jti: 'store-contract-blob-external' },
    });
    const uploaded = await relay.app.request(`http://localhost${path}`, {
      method: 'PUT',
      headers: { authorization: `DFOS ${proof}`, 'content-type': 'application/octet-stream' },
      body,
    });
    expect(uploaded.status).toBe(200);

    // NO further drain: the log has nothing new on it, and the row is right.
    expect((await relay.projectIndex()).caughtUp).toBe(true);
    const after = (await store.queryIndexContent({ limit: 100 })).find(
      (row) => row.contentId === contentId,
    );
    expect(after?.docSchema).toBe('example/post');
  });

  it('drains a chain:* fan-out across runs under a row budget', async () => {
    const store = new MemoryRelayStore();
    await createRelay({ store, indexProjection: 'external' });

    const creator = await createIdentityOp();
    await ingestOperations([creator.jwsToken], store);
    const posts = [];
    for (let i = 0; i < 4; i++) {
      const op = await contentOp(creator, { $schema: 'example/post', title: `p${i}` }, i + 1);
      await ingestOperations([op.jwsToken], store);
      posts.push(op);
    }
    // catch up so the content rows exist before the wildcard grant lands
    let guard = 0;
    while (!(await projectIndex(store, { budget: 100 })).caughtUp && guard++ < 20);

    const { credential } = await publicReadGrant(creator, 'chain:*');
    await ingestOperations([credential], store);

    // The wildcard grant schedules a full-corpus sweep. It is CARRIED ON THE
    // CURSOR, so a budget that cannot finish it leaves a resumable remainder
    // instead of stalling the relay for the length of the corpus.
    const first = await projectIndex(store, { budget: 2 });
    expect(first.caughtUp).toBe(false);
    expect((await store.getIndexCursor()).sweep).not.toBeNull();

    guard = 0;
    let run = await projectIndex(store, { budget: 2 });
    while (!run.caughtUp && guard++ < 20) run = await projectIndex(store, { budget: 2 });
    expect(run.caughtUp).toBe(true);
    expect((await store.getIndexCursor()).sweep).toBeNull();

    const rows = await store.queryIndexContent({ limit: 100 });
    expect(rows.length).toBe(posts.length);
    expect(rows.every((row) => row.publicRead)).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// issuer-scoped revocation
// -----------------------------------------------------------------------------

describe('a revocation only reaches its own issuer’s grants', () => {
  it('does not drop a standing grant issued by someone else', async () => {
    // Revocation is issuer-scoped everywhere else (`isCredentialRevoked` is
    // keyed on the pair), but the removal of the held grant was keyed on the
    // credential CID alone — so any identity could un-publish anyone's public
    // content by signing a revocation that named its credential CID.
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store });
    const req = (path: string) => relay.app.request(`http://localhost${path}`);

    const creator = await createIdentityOp();
    const stranger = await createIdentityOp();
    await ingestOperations([creator.jwsToken, stranger.jwsToken], store);

    const post = await contentOp(creator, { $schema: 'example/post', title: 'public' });
    const [created] = await ingestOperations([post.jwsToken], store);
    const contentId = created!.chainId!;

    const { credential, credentialCID } = await publicReadGrant(creator, `chain:${contentId}`);
    await ingestOperations([credential], store);
    expect(await store.getPublicCredentialByCID(credentialCID)).toBeDefined();

    // the stranger revokes the creator's credential
    const { jwsToken } = await signRevocation({
      issuerDID: stranger.did,
      credentialCID,
      signer: stranger.key.signer,
      keyId: stranger.key.keyId,
    });
    const [revoked] = await ingestOperations([jwsToken], store);
    expect(revoked!.status).toBe('new');

    // the grant survives, and the content is still publicly readable
    expect(await store.getPublicCredentialByCID(credentialCID)).toBeDefined();
    expect(await store.getPublicCredentials(`chain:${contentId}`)).toHaveLength(1);
    expect((await req(`/content/${contentId}/blob`)).status).not.toBe(403);

    // the issuer's own revocation does drop it
    const own = await signRevocation({
      issuerDID: creator.did,
      credentialCID,
      signer: creator.key.signer,
      keyId: creator.key.keyId,
    });
    expect((await ingestOperations([own.jwsToken], store))[0]!.status).toBe('new');
    expect(await store.getPublicCredentialByCID(credentialCID)).toBeUndefined();
  });
});

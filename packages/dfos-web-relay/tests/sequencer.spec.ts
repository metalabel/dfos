import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { FORK_POINT_STATE_ERROR_PREFIX, ingestOperations } from '../src/ingest';
import { isDependencyFailure, sequenceOps } from '../src/sequencer';
import { MemoryRelayStore } from '../src/store';
import type { RelayStore } from '../src/types';

/*

  SEQUENCER — structured dependency-failure discriminator (WP-3)

  The sequencer no longer substring-matches the human-readable error string to
  classify a rejection as retryable. It branches on the structured
  `dependencyMissing` flag set by the ingest producer. These tests:

  (1) drive REAL operations through `ingestOperations` and assert the structured
      flag (replacing the old vacuous hand-built-string test);
  (2) assert the shared FORK_POINT_STATE_ERROR_PREFIX constant is what the
      producer actually emits (kills string drift / the #56 colon mismatch);
  (3) assert CID-less durability: a bad-signature genesis op becomes durably
      rejected (carries a CID, dependencyMissing=false) instead of being
      re-verified every tick forever;
  (4) assert dependency convergence: an op ingested before its dependency stays
      pending (retryable), then sequences once the dependency arrives.

*/

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

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
  const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, authKey, jwsToken, operationCID };
};

const createContentOp = async (identity: Awaited<ReturnType<typeof createIdentity>>) => {
  const document = { type: 'post', title: 'hello', body: 'world' };
  const docEncoded = await dagCborCanonicalEncode(document as unknown as Record<string, unknown>);
  const documentCID = docEncoded.cid.toString();
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID,
    baseDocumentCID: null,
    createdAt: ts(1),
    note: null,
  };
  const kid = `${identity.did}#${identity.authKey.keyId}`;
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer: identity.authKey.signer,
    kid,
  });
  return { jwsToken, operationCID, documentCID };
};

/** Corrupt the signature segment of a JWS token while keeping a valid CID-bearing header/payload. */
const corruptSignature = (jws: string): string => {
  const parts = jws.split('.');
  const sig = parts[2]!;
  // flip one char in the signature so verification fails but the payload (→ CID) is intact
  const flipped = sig[0] === 'A' ? 'B' + sig.slice(1) : 'A' + sig.slice(1);
  return `${parts[0]}.${parts[1]}.${flipped}`;
};

// ---------------------------------------------------------------------------
// isDependencyFailure (structured)
// ---------------------------------------------------------------------------

describe('isDependencyFailure (structured discriminator)', () => {
  it('branches on the dependencyMissing flag, not the error string', () => {
    expect(isDependencyFailure({ dependencyMissing: true })).toBe(true);
    expect(isDependencyFailure({ dependencyMissing: false })).toBe(false);
    expect(isDependencyFailure({})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (3) CID-less durability — bad signature genesis op
// ---------------------------------------------------------------------------

describe('CID-less durability', () => {
  it('durably rejects a bad-signature genesis identity op (carries a CID, not retryable)', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    const corrupt = corruptSignature(identity.jwsToken);

    const [res] = await ingestOperations([corrupt], store);
    expect(res!.status).toBe('rejected');
    // the rejection must carry the computed CID so the sequencer can durably
    // reject it (not skip it forever via `if (!res.cid) continue`)
    expect(res!.cid).not.toBe('');
    // identity genesis verify failures are self-contained → permanent, not dep
    expect(res!.dependencyMissing).toBeFalsy();
  });

  it('durably rejects a bad-signature genesis content op (carries a CID)', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);
    const content = await createContentOp(identity);
    const corrupt = corruptSignature(content.jwsToken);

    const [res] = await ingestOperations([corrupt], store);
    expect(res!.status).toBe('rejected');
    expect(res!.cid).not.toBe('');
    expect(res!.dependencyMissing).toBeFalsy();
  });

  it('marks the bad-sig op rejected through sequenceOps (not re-verified every tick)', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    const corrupt = corruptSignature(identity.jwsToken);

    // seed the raw store the way the relay does
    const decoded = (await import('@metalabel/dfos-protocol/crypto')).decodeJwsUnsafe(corrupt);
    const cid = (await dagCborCanonicalEncode(decoded!.payload)).cid.toString();
    await store.putRawOp(cid, corrupt);

    const { result } = await sequenceOps(store);
    expect(result.rejected).toBe(1);
    expect(result.pending).toBe(0);

    // a second sequencer pass finds nothing pending — the op was durably rejected
    const { result: second } = await sequenceOps(store);
    expect(second.rejected).toBe(0);
    expect(second.pending).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// (4) dependency convergence — op before its dependency
// ---------------------------------------------------------------------------

describe('dependency convergence', () => {
  it('content-op-before-key stays pending, then sequences once the identity arrives', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    const content = await createContentOp(identity);

    // ingest the content op BEFORE its signing identity is resolvable
    const [pendingRes] = await ingestOperations([content.jwsToken], store);
    expect(pendingRes!.status).toBe('rejected');
    expect(pendingRes!.dependencyMissing).toBe(true);
    expect(pendingRes!.cid).not.toBe('');

    // now ingest the identity, then re-ingest the content op — it sequences
    await ingestOperations([identity.jwsToken], store);
    const [resolved] = await ingestOperations([content.jwsToken], store);
    expect(resolved!.status).toBe('new');
  });

  it('content extension before its previous op stays pending (dependencyMissing)', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);
    const content = await createContentOp(identity);

    // build an update whose previousOperationCID is the (not-yet-ingested) genesis
    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: identity.did,
      previousOperationCID: content.operationCID,
      documentCID: content.documentCID,
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

    const [pending] = await ingestOperations([updateToken], store);
    expect(pending!.status).toBe('rejected');
    expect(pending!.dependencyMissing).toBe(true);

    // ingest the genesis, then the update sequences
    await ingestOperations([content.jwsToken], store);
    const [resolved] = await ingestOperations([updateToken], store);
    expect(resolved!.status).toBe('new');
  });
});

// ---------------------------------------------------------------------------
// (2) fork-point state-failure → dependencyMissing, via shared constant
// ---------------------------------------------------------------------------

/** Wrap a store, forcing fork-point state computation to fail (snapshot-replay gap). */
const withBrokenForkState = (inner: RelayStore): RelayStore =>
  new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === 'getIdentityStateAtCID' || prop === 'getContentStateAtCID') {
        return async () => null;
      }
      return Reflect.get(target, prop, receiver);
    },
  });

describe('fork-point state failure', () => {
  it('classifies a fork-point state failure as dependencyMissing using the shared prefix', async () => {
    const base = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], base);

    // build two competing identity updates off the same previous (a fork)
    const newKeyA = makeKey();
    const updateA: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: identity.operationCID,
      authKeys: [newKeyA.key],
      assertKeys: [],
      controllerKeys: [identity.controller.key],
      createdAt: ts(2),
    };
    const { jwsToken: tokenA } = await signIdentityOperation({
      operation: updateA,
      signer: identity.controller.signer,
      keyId: identity.controller.keyId,
      identityDID: identity.did,
    });
    await ingestOperations([tokenA], base);

    // a second update off the SAME previous → fork path → loads fork state
    const newKeyB = makeKey();
    const updateB: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: identity.operationCID,
      authKeys: [newKeyB.key],
      assertKeys: [],
      controllerKeys: [identity.controller.key],
      createdAt: ts(3),
    };
    const { jwsToken: tokenB } = await signIdentityOperation({
      operation: updateB,
      signer: identity.controller.signer,
      keyId: identity.controller.keyId,
      identityDID: identity.did,
    });

    // drive the fork op through a store whose fork-state computation fails
    const broken = withBrokenForkState(base);
    const [res] = await ingestOperations([tokenB], broken);
    expect(res!.status).toBe('rejected');
    expect(res!.dependencyMissing).toBe(true);
    expect(res!.cid).not.toBe('');
    // the producer emits the SHARED constant — byte-identity guards string drift
    expect(res!.error!.startsWith(FORK_POINT_STATE_ERROR_PREFIX)).toBe(true);
  });

  it('the shared fork-point prefix matches the Go twin literal byte-for-byte', () => {
    // Go: ForkPointStateErrorPrefix in sequencer.go
    expect(FORK_POINT_STATE_ERROR_PREFIX).toBe('failed to compute state at fork point: ');
  });
});

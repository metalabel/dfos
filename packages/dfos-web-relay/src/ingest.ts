/*

  INGESTION PIPELINE

  Classify, dependency-sort, and verify incoming JWS operations.

  All proof plane artifacts — identity ops, content ops, beacons, and
  countersignatures — enter through the same pipeline. The relay classifies
  each token by its JWS `typ` header, dependency-sorts so identity chains
  are processed before content chains that reference them, then verifies
  and stores each operation incrementally.

  Fork policy: first-seen-wins. If an operation CID already exists, it is
  silently accepted (idempotent). If a chain has diverged (previousCID
  mismatch), the new operation is rejected.

*/

import {
  decodeMultikey,
  verifyBeacon,
  verifyBeaconCountersignature,
  verifyContentChain,
  verifyCountersignature,
  verifyIdentityChain,
  type VerifiedBeacon,
} from '@metalabel/dfos-protocol/chain';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { IngestionResult, RelayStore, StoredContentChain, StoredIdentityChain } from './types';

// -----------------------------------------------------------------------------
// classification
// -----------------------------------------------------------------------------

type OperationKind =
  | 'identity-op'
  | 'content-op'
  | 'beacon'
  | 'countersig'
  | 'beacon-countersig'
  | 'unknown';

interface ClassifiedOperation {
  jwsToken: string;
  kind: OperationKind;
  /** DID referenced in the operation (from payload.did or kid) */
  referencedDID: string | null;
  /** For content ops — the DID from the payload that signs the operation */
  signerDID: string | null;
  /** Sort priority: identity ops first, then beacons, then content ops, then countersigs */
  priority: number;
  /** Operation CID from the JWS header — used for intra-kind topological sorting */
  operationCID: string | null;
  /** For intra-kind topological sorting — the previousOperationCID if present */
  previousCID: string | null;
  /** Original submission index — used to return results in submission order */
  originalIndex: number;
}

const classify = (jwsToken: string): ClassifiedOperation => {
  const unknown: ClassifiedOperation = {
    jwsToken,
    kind: 'unknown',
    referencedDID: null,
    signerDID: null,
    priority: 99,
    operationCID: null,
    previousCID: null,
    originalIndex: 0,
  };

  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return unknown;

  const typ = decoded.header.typ;
  const payload = decoded.payload as Record<string, unknown>;
  const kid = decoded.header.kid;

  if (!kid || typeof kid !== 'string') return unknown;

  // common fields extracted once
  const kidDID = kid.includes('#') ? kid.substring(0, kid.indexOf('#')) : null;
  const operationCID = typeof decoded.header.cid === 'string' ? decoded.header.cid : null;
  const previousCID =
    typeof payload['previousOperationCID'] === 'string' ? payload['previousOperationCID'] : null;
  const base = { jwsToken, operationCID, previousCID, originalIndex: 0 };

  if (typ === 'did:dfos:identity-op') {
    return { ...base, kind: 'identity-op', referencedDID: kidDID, signerDID: null, priority: 0 };
  }

  if (typ === 'did:dfos:content-op') {
    const opDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    if (opDID && kidDID && kidDID !== opDID) {
      return {
        ...base,
        kind: 'countersig',
        referencedDID: opDID,
        signerDID: kidDID,
        priority: 3,
        previousCID: null,
      };
    }
    return { ...base, kind: 'content-op', referencedDID: null, signerDID: opDID, priority: 2 };
  }

  if (typ === 'did:dfos:beacon') {
    const beaconDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    if (beaconDID && kidDID && kidDID !== beaconDID) {
      return {
        ...base,
        kind: 'beacon-countersig',
        referencedDID: beaconDID,
        signerDID: kidDID,
        priority: 3,
        previousCID: null,
      };
    }
    return {
      ...base,
      kind: 'beacon',
      referencedDID: beaconDID,
      signerDID: null,
      priority: 1,
      previousCID: null,
    };
  }

  return unknown;
};

// -----------------------------------------------------------------------------
// key resolution
// -----------------------------------------------------------------------------

/**
 * Create a key resolver that looks up Ed25519 public keys from identity chains
 * in the store. Used for chain re-verification during ingestion.
 *
 * Searches all keys that have ever appeared in the identity chain log, not just
 * current state. This is necessary because re-verifying a full content chain log
 * needs to resolve keys from operations signed before a key rotation.
 *
 * CID fidelity invariant: countersignature ingestion derives the operation CID
 * by re-encoding the decoded payload via dagCborCanonicalEncode. This relies on
 * the JWS decode round-trip preserving payload fidelity through JSON→CBOR→JSON→CBOR.
 * The protocol library's canonical encoding (dag-cbor + sha-256) guarantees
 * deterministic CIDs for identical payloads.
 */
export const createKeyResolver =
  (store: RelayStore) =>
  async (kid: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);

    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);

    const identity = await store.getIdentityChain(did);
    if (!identity) throw new Error(`unknown identity: ${did}`);

    // first check current state (fast path)
    const currentKeys = [
      ...identity.state.authKeys,
      ...identity.state.assertKeys,
      ...identity.state.controllerKeys,
    ];
    const currentKey = currentKeys.find((k) => k.id === keyId);
    if (currentKey) return decodeMultikey(currentKey.publicKeyMultibase).keyBytes;

    // search historical keys from the identity chain log — handles rotated-out keys
    for (const token of identity.log) {
      const decoded = decodeJwsUnsafe(token);
      if (!decoded) continue;
      const payload = decoded.payload as Record<string, unknown>;
      const opType = payload['type'];
      if (opType !== 'create' && opType !== 'update') continue;

      const keyArrays = ['authKeys', 'assertKeys', 'controllerKeys'] as const;
      for (const arrayName of keyArrays) {
        const keys = payload[arrayName];
        if (!Array.isArray(keys)) continue;
        for (const k of keys) {
          if (
            k &&
            typeof k === 'object' &&
            'id' in k &&
            k.id === keyId &&
            'publicKeyMultibase' in k
          ) {
            return decodeMultikey(k.publicKeyMultibase as string).keyBytes;
          }
        }
      }
    }

    throw new Error(`unknown key ${keyId} on identity ${did}`);
  };

/**
 * Create a key resolver that only resolves current-state keys.
 *
 * Used for live authentication (auth tokens, credentials) where rotated-out
 * keys must NOT be accepted. After a key rotation, the old key should no
 * longer authenticate new requests.
 */
export const createCurrentKeyResolver =
  (store: RelayStore) =>
  async (kid: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);

    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);

    const identity = await store.getIdentityChain(did);
    if (!identity) throw new Error(`unknown identity: ${did}`);

    const currentKeys = [
      ...identity.state.authKeys,
      ...identity.state.assertKeys,
      ...identity.state.controllerKeys,
    ];
    const currentKey = currentKeys.find((k) => k.id === keyId);
    if (currentKey) return decodeMultikey(currentKey.publicKeyMultibase).keyBytes;

    throw new Error(`unknown key ${keyId} on identity ${did}`);
  };

// -----------------------------------------------------------------------------
// individual verifiers
// -----------------------------------------------------------------------------

const ingestIdentityOp = async (jwsToken: string, store: RelayStore): Promise<IngestionResult> => {
  // decode to get the operation CID
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const cid = encoded.cid.toString();

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      // Same CID but different JWS — a re-sign of the same payload.
      // Ed25519 is deterministic, so a different token means a different key or header.
      return {
        cid,
        status: 'rejected',
        error: 'operation already exists with a different signature',
      };
    }
    return { cid, status: 'accepted', kind: 'identity-op', chainId: existing.chainId };
  }

  // determine if this is a genesis or extension
  const opType = (payload as Record<string, unknown>)['type'];
  const isGenesis = opType === 'create';

  if (isGenesis) {
    // verify as a new single-operation chain
    const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] });
    const chain: StoredIdentityChain = { did: identity.did, log: [jwsToken], state: identity };
    await store.putIdentityChain(chain);
    await store.putOperation({ cid, jwsToken, chainType: 'identity', chainId: identity.did });
    return { cid, status: 'accepted', kind: 'identity-op', chainId: identity.did };
  }

  // extension — find existing chain via kid DID
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) return { cid, status: 'rejected', error: 'non-genesis kid must be a DID URL' };
  const did = kid.substring(0, hashIdx);

  const chain = await store.getIdentityChain(did);
  if (!chain) return { cid, status: 'rejected', error: `unknown identity: ${did}` };

  // verify full chain including new operation
  const newLog = [...chain.log, jwsToken];
  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: newLog });
  const updated: StoredIdentityChain = { did: identity.did, log: newLog, state: identity };
  await store.putIdentityChain(updated);
  await store.putOperation({ cid, jwsToken, chainType: 'identity', chainId: did });
  return { cid, status: 'accepted', kind: 'identity-op', chainId: did };
};

const ingestContentOp = async (jwsToken: string, store: RelayStore): Promise<IngestionResult> => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const cid = encoded.cid.toString();

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      // Same CID but different JWS — self-countersign attempt. The witness
      // DID matches the author DID so this is semantically meaningless.
      return {
        cid,
        status: 'rejected',
        error: 'operation already exists with a different signature',
      };
    }
    return { cid, status: 'accepted', kind: 'content-op', chainId: existing.chainId };
  }

  // reject content operations from deleted identities — deletion revokes
  // all authority, including outstanding DFOSContentWrite credentials
  const signerDID = (payload as Record<string, unknown>)['did'];
  if (typeof signerDID === 'string') {
    const signerIdentity = await store.getIdentityChain(signerDID);
    if (signerIdentity?.state.isDeleted) {
      return { cid, status: 'rejected', error: 'signer identity is deleted' };
    }
  }

  const resolveKey = createKeyResolver(store);
  const opType = (payload as Record<string, unknown>)['type'];
  const isGenesis = opType === 'create';

  if (isGenesis) {
    const content = await verifyContentChain({
      log: [jwsToken],
      resolveKey,
      enforceAuthorization: true,
    });
    const chain: StoredContentChain = {
      contentId: content.contentId,
      genesisCID: content.genesisCID,
      log: [jwsToken],
      state: content,
    };
    await store.putContentChain(chain);
    await store.putOperation({ cid, jwsToken, chainType: 'content', chainId: content.contentId });
    return { cid, status: 'accepted', kind: 'content-op', chainId: content.contentId };
  }

  // extension — need to find the existing chain via previousOperationCID
  const previousCID = (payload as Record<string, unknown>)['previousOperationCID'];
  if (typeof previousCID !== 'string') {
    return { cid, status: 'rejected', error: 'missing previousOperationCID' };
  }

  const prevOp = await store.getOperation(previousCID);
  if (!prevOp)
    return { cid, status: 'rejected', error: `unknown previous operation: ${previousCID}` };
  if (prevOp.chainType !== 'content') {
    return { cid, status: 'rejected', error: 'previousOperationCID is not a content operation' };
  }

  const chain = await store.getContentChain(prevOp.chainId);
  if (!chain)
    return { cid, status: 'rejected', error: `content chain not found: ${prevOp.chainId}` };

  // reject if the content creator's identity is deleted — this also blocks
  // delegates holding DFOSContentWrite credentials from a deleted creator
  const creatorIdentity = await store.getIdentityChain(chain.state.creatorDID);
  if (creatorIdentity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'content creator identity is deleted' };
  }

  // first-seen-wins: reject if chain head has moved past the expected previous
  if (chain.state.headCID !== previousCID) {
    return { cid, status: 'rejected', error: 'chain has diverged (first-seen-wins)' };
  }

  const newLog = [...chain.log, jwsToken];
  const content = await verifyContentChain({
    log: newLog,
    resolveKey,
    enforceAuthorization: true,
  });
  const updated: StoredContentChain = {
    contentId: content.contentId,
    genesisCID: content.genesisCID,
    log: newLog,
    state: content,
  };
  await store.putContentChain(updated);
  await store.putOperation({ cid, jwsToken, chainType: 'content', chainId: content.contentId });
  return { cid, status: 'accepted', kind: 'content-op', chainId: content.contentId };
};

const ingestBeacon = async (jwsToken: string, store: RelayStore): Promise<IngestionResult> => {
  const resolveKey = createKeyResolver(store);

  let verified: VerifiedBeacon;
  try {
    verified = await verifyBeacon({ jwsToken, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const did = verified.payload.did;
  const cid = verified.beaconCID;

  // reject beacons from deleted identities — deletion means the identity
  // stops being an active participant, even though keys persist in state
  const identity = await store.getIdentityChain(did);
  if (identity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'identity is deleted' };
  }

  // replace-on-newer: only store if this beacon is more recent
  const existing = await store.getBeacon(did);
  if (existing) {
    const existingTime = new Date(existing.state.payload.createdAt).getTime();
    const newTime = new Date(verified.payload.createdAt).getTime();
    if (newTime <= existingTime) {
      return { cid, status: 'accepted', kind: 'beacon', chainId: did };
    }
  }

  await store.putBeacon({ did, jwsToken, beaconCID: cid, state: verified });
  return { cid, status: 'accepted', kind: 'beacon', chainId: did };
};

const ingestCountersig = async (jwsToken: string, store: RelayStore): Promise<IngestionResult> => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const operationCID = encoded.cid.toString();

  // the operation must already exist in the store
  const existingOp = await store.getOperation(operationCID);
  if (!existingOp) {
    return { cid: operationCID, status: 'rejected', error: `unknown operation: ${operationCID}` };
  }

  const resolveKey = createKeyResolver(store);
  try {
    await verifyCountersignature({ jwsToken, expectedCID: operationCID, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: operationCID, status: 'rejected', error: message };
  }

  await store.addCountersignature(operationCID, jwsToken);
  return {
    cid: operationCID,
    status: 'accepted',
    kind: 'countersig',
    chainId: existingOp.chainId,
  };
};

const ingestBeaconCountersig = async (
  jwsToken: string,
  store: RelayStore,
): Promise<IngestionResult> => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const beaconCID = encoded.cid.toString();

  // the beacon must already exist in the store
  const beaconDID =
    typeof (payload as Record<string, unknown>)['did'] === 'string'
      ? ((payload as Record<string, unknown>)['did'] as string)
      : null;
  if (!beaconDID) {
    return { cid: beaconCID, status: 'rejected', error: 'missing beacon DID' };
  }

  const existingBeacon = await store.getBeacon(beaconDID);
  if (!existingBeacon) {
    return { cid: beaconCID, status: 'rejected', error: `unknown beacon for DID: ${beaconDID}` };
  }

  // verify the countersig is for the stored beacon's CID
  if (existingBeacon.beaconCID !== beaconCID) {
    return {
      cid: beaconCID,
      status: 'rejected',
      error: 'beacon countersignature CID does not match current beacon',
    };
  }

  const resolveKey = createKeyResolver(store);
  try {
    await verifyBeaconCountersignature({
      jwsToken,
      expectedCID: beaconCID,
      resolveKey,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: beaconCID, status: 'rejected', error: message };
  }

  await store.addCountersignature(beaconCID, jwsToken);
  return {
    cid: beaconCID,
    status: 'accepted',
    kind: 'beacon-countersig',
    chainId: beaconDID,
  };
};

// -----------------------------------------------------------------------------
// topological sort
// -----------------------------------------------------------------------------

/**
 * Sort classified operations: first by kind priority (identity → beacon →
 * content → countersig), then topologically within each kind so that
 * dependent operations (e.g. identity create before update, content create
 * before update) are processed in the correct order.
 *
 * Within a priority bucket: genesis ops (no previousCID) come first, then
 * ops are ordered by chaining their previousCID links.
 */
const dependencySort = (ops: ClassifiedOperation[]): ClassifiedOperation[] => {
  const buckets = new Map<number, ClassifiedOperation[]>();
  for (const op of ops) {
    const bucket = buckets.get(op.priority) ?? [];
    bucket.push(op);
    buckets.set(op.priority, bucket);
  }

  const result: ClassifiedOperation[] = [];
  const sortedPriorities = [...buckets.keys()].sort((a, b) => a - b);

  for (const priority of sortedPriorities) {
    const bucket = buckets.get(priority)!;
    if ((priority === 0 || priority === 2) && bucket.length > 1) {
      result.push(...topologicalSortBucket(bucket));
    } else {
      result.push(...bucket);
    }
  }

  return result;
};

/**
 * Kahn's algorithm topological sort within a priority bucket.
 *
 * Uses operationCID (from JWS header) and previousCID to build a dependency
 * graph. Genesis ops (no previousCID) have in-degree 0. Each op's previousCID
 * references the operationCID it depends on — if that dependency is in the
 * same batch, the dependent op must wait.
 *
 * Ops whose previousCID references something NOT in this batch (already in
 * the store) also have in-degree 0 — they're ready immediately.
 */
const topologicalSortBucket = (ops: ClassifiedOperation[]): ClassifiedOperation[] => {
  if (ops.length <= 1) return ops;

  // build set of operationCIDs present in this batch
  const cidToOp = new Map<string, ClassifiedOperation>();
  for (const op of ops) {
    if (op.operationCID) cidToOp.set(op.operationCID, op);
  }

  // in-degree: 1 if this op depends on another op IN the batch, 0 otherwise
  const inDegree = new Map<ClassifiedOperation, number>();
  // adjacency: operationCID → ops in this batch that depend on it
  const dependents = new Map<string, ClassifiedOperation[]>();

  for (const op of ops) {
    const depInBatch = op.previousCID !== null && cidToOp.has(op.previousCID);
    inDegree.set(op, depInBatch ? 1 : 0);

    if (depInBatch) {
      const list = dependents.get(op.previousCID!) ?? [];
      list.push(op);
      dependents.set(op.previousCID!, list);
    }
  }

  // process zero in-degree ops first, release dependents as we go
  const queue: ClassifiedOperation[] = ops.filter((op) => inDegree.get(op) === 0);
  const sorted: ClassifiedOperation[] = [];

  while (queue.length > 0) {
    const op = queue.shift()!;
    sorted.push(op);

    if (op.operationCID) {
      for (const dep of dependents.get(op.operationCID) ?? []) {
        const deg = inDegree.get(dep)! - 1;
        inDegree.set(dep, deg);
        if (deg === 0) queue.push(dep);
      }
    }
  }

  // append any unplaceable ops (cycle, missing CID) at the end
  if (sorted.length < ops.length) {
    const placed = new Set(sorted);
    for (const op of ops) {
      if (!placed.has(op)) sorted.push(op);
    }
  }

  return sorted;
};

// -----------------------------------------------------------------------------
// main pipeline
// -----------------------------------------------------------------------------

/**
 * Ingest a batch of JWS operations
 *
 * Classifies, dependency-sorts, and processes each token. Identity operations
 * are processed first so content chains and beacons can resolve their keys.
 * Within each kind, genesis operations are processed before extensions.
 */
export const ingestOperations = async (
  tokens: string[],
  store: RelayStore,
): Promise<IngestionResult[]> => {
  // classify all tokens, preserving submission order
  const classified = tokens.map((token, i) => ({ ...classify(token), originalIndex: i }));

  // dependency sort: identity ops → beacons → content ops → countersigs
  // with intra-kind topological ordering
  const sorted = dependencySort(classified);

  // process in dependency order, then re-sort results to submission order
  const indexedResults: { index: number; result: IngestionResult }[] = [];

  for (const op of sorted) {
    try {
      let result: IngestionResult;
      switch (op.kind) {
        case 'identity-op':
          result = await ingestIdentityOp(op.jwsToken, store);
          break;
        case 'content-op':
          result = await ingestContentOp(op.jwsToken, store);
          break;
        case 'beacon':
          result = await ingestBeacon(op.jwsToken, store);
          break;
        case 'countersig':
          result = await ingestCountersig(op.jwsToken, store);
          break;
        case 'beacon-countersig':
          result = await ingestBeaconCountersig(op.jwsToken, store);
          break;
        default:
          result = { cid: '', status: 'rejected', error: 'unrecognized operation type' };
      }
      indexedResults.push({ index: op.originalIndex, result });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unexpected error';
      indexedResults.push({
        index: op.originalIndex,
        result: { cid: '', status: 'rejected', error: message },
      });
    }
  }

  // return results in original submission order
  return indexedResults.sort((a, b) => a.index - b.index).map((r) => r.result);
};

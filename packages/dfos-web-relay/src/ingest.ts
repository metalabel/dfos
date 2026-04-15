/*

  INGESTION PIPELINE

  Classify, dependency-sort, and verify incoming JWS operations.

  All proof plane artifacts — identity ops, content ops, beacons, and
  countersignatures — enter through the same pipeline. The relay classifies
  each token by its JWS `typ` header, dependency-sorts so identity chains
  are processed before content chains that reference them, then verifies
  and stores each operation incrementally.

  Fork policy: forks are accepted. If an extension's parentCID exists
  anywhere in the chain (not just at head), the fork is accepted and the
  head is recomputed via deterministic selection (highest createdAt, then
  lexicographic highest CID).

*/

import {
  decodeMultikey,
  verifyArtifact,
  verifyBeacon,
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
  verifyCountersignature,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
  verifyRevocation,
  type VerifiedBeacon,
  type VerifiedCountersignature,
  type VerifiedRevocation,
} from '@metalabel/dfos-protocol/chain';
import {
  verifyDFOSCredential,
  type VerifiedDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { IngestionResult, RelayStore, StoredContentChain, StoredIdentityChain } from './types';

// -----------------------------------------------------------------------------
// temporal guard
// -----------------------------------------------------------------------------

/** Maximum allowed clock skew for operation timestamps (24 hours in ms) */
const MAX_FUTURE_TIMESTAMP_MS = 24 * 60 * 60 * 1000;

/** Reject operations with createdAt more than 24 hours in the future */
const isFutureTimestamp = (createdAt: string): boolean => {
  const ts = new Date(createdAt).getTime();
  if (isNaN(ts)) return false; // invalid dates rejected by protocol verification
  return ts > Date.now() + MAX_FUTURE_TIMESTAMP_MS;
};

// -----------------------------------------------------------------------------
// classification
// -----------------------------------------------------------------------------

type ClassificationKind =
  | 'identity-op'
  | 'content-op'
  | 'beacon'
  | 'countersign'
  | 'artifact'
  | 'revocation'
  | 'credential'
  | 'unknown';

interface ClassifiedOperation {
  jwsToken: string;
  kind: ClassificationKind;
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
    return { ...base, kind: 'content-op', referencedDID: null, signerDID: opDID, priority: 2 };
  }

  if (typ === 'did:dfos:beacon') {
    const beaconDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    return {
      ...base,
      kind: 'beacon',
      referencedDID: beaconDID,
      signerDID: null,
      priority: 1,
      previousCID: null,
    };
  }

  if (typ === 'did:dfos:countersign') {
    const witnessDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    return {
      ...base,
      kind: 'countersign',
      referencedDID: witnessDID,
      signerDID: null,
      priority: 3, // processed last — target must already be ingested
      previousCID: null,
    };
  }

  if (typ === 'did:dfos:artifact') {
    const artifactDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    return {
      ...base,
      kind: 'artifact',
      referencedDID: artifactDID,
      signerDID: null,
      priority: 1, // same as beacons — needs identity keys resolved first
      previousCID: null,
    };
  }

  if (typ === 'did:dfos:revocation') {
    const revocationDID = typeof payload['did'] === 'string' ? payload['did'] : null;
    return {
      ...base,
      kind: 'revocation',
      referencedDID: revocationDID,
      signerDID: null,
      priority: 1, // same as beacons — needs identity keys to verify
      previousCID: null,
    };
  }

  if (typ === 'did:dfos:credential') {
    const aud = typeof payload['aud'] === 'string' ? payload['aud'] : null;
    // only ingest public credentials (aud: "*"), silently ignore private ones
    if (aud !== '*') return unknown;
    return {
      ...base,
      kind: 'credential',
      referencedDID: kidDID,
      signerDID: null,
      priority: 1, // needs identity keys to verify
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
 * Create an identity resolver that includes all historical keys.
 *
 * Credentials are long-lived artifacts — their validity persists across key
 * rotations. This resolver walks the full identity chain log to collect all
 * keys that have ever appeared in create and update operations, ensuring
 * credentials signed by rotated-out keys still verify. Revocation (not key
 * rotation) is the invalidation mechanism.
 *
 * Used for credential verification at both ingestion and access-check time.
 */
export const createHistoricalIdentityResolver = (store: RelayStore) => async (did: string) => {
  const chain = await store.getIdentityChain(did);
  if (!chain) return undefined;

  const { state, log } = chain;
  const keyMaps = {
    authKeys: new Map(state.authKeys.map((k) => [k.id, k])),
    assertKeys: new Map(state.assertKeys.map((k) => [k.id, k])),
    controllerKeys: new Map(state.controllerKeys.map((k) => [k.id, k])),
  };

  for (const token of log) {
    const decoded = decodeJwsUnsafe(token);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    const opType = payload['type'];
    if (opType !== 'create' && opType !== 'update') continue;

    for (const arrayName of ['authKeys', 'assertKeys', 'controllerKeys'] as const) {
      const keys = payload[arrayName];
      if (!Array.isArray(keys)) continue;
      const map = keyMaps[arrayName];
      for (const k of keys) {
        if (
          k &&
          typeof k === 'object' &&
          'id' in k &&
          'publicKeyMultibase' in k &&
          !map.has((k as { id: string }).id)
        ) {
          map.set(
            (k as { id: string }).id,
            k as { id: string; type: 'Multikey'; publicKeyMultibase: string },
          );
        }
      }
    }
  }

  return {
    ...state,
    authKeys: [...keyMaps.authKeys.values()],
    assertKeys: [...keyMaps.assertKeys.values()],
    controllerKeys: [...keyMaps.controllerKeys.values()],
  };
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

const ingestIdentityOp = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  // decode to get the operation CID
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const cid = encoded.cid.toString();

  // temporal guard: reject operations with timestamps too far in the future
  const createdAtVal = (payload as Record<string, unknown>)['createdAt'];
  if (typeof createdAtVal === 'string' && isFutureTimestamp(createdAtVal)) {
    return { cid, status: 'rejected', error: 'createdAt is too far in the future' };
  }

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'operation already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'identity-op', chainId: existing.chainId };
  }

  // determine if this is a genesis or extension
  const opType = (payload as Record<string, unknown>)['type'];
  const isGenesis = opType === 'create';

  if (isGenesis) {
    const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] });
    const createdAt = (payload as Record<string, unknown>)['createdAt'] as string;
    const chain: StoredIdentityChain = {
      did: identity.did,
      log: [jwsToken],
      headCID: cid,
      lastCreatedAt: createdAt,
      state: identity,
    };
    await store.putIdentityChain(chain);
    await store.putOperation({ cid, jwsToken, chainType: 'identity', chainId: identity.did });
    if (logEnabled) {
      await store.appendToLog({ cid, jwsToken, kind: 'identity-op', chainId: identity.did });
    }
    return { cid, status: 'new', kind: 'identity-op', chainId: identity.did };
  }

  // extension — find existing chain via kid DID
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) return { cid, status: 'rejected', error: 'non-genesis kid must be a DID URL' };
  const did = kid.substring(0, hashIdx);

  const chain = await store.getIdentityChain(did);
  if (!chain) return { cid, status: 'rejected', error: `unknown identity: ${did}` };

  // extract previousOperationCID from payload
  const previousCID =
    typeof (payload as Record<string, unknown>)['previousOperationCID'] === 'string'
      ? ((payload as Record<string, unknown>)['previousOperationCID'] as string)
      : null;

  if (previousCID === chain.headCID) {
    // linear extension (fast path) — O(1) from trusted head state
    const extResult = await verifyIdentityExtensionFromTrustedState({
      currentState: chain.state,
      headCID: chain.headCID,
      lastCreatedAt: chain.lastCreatedAt,
      newOp: jwsToken,
    });
    const updated: StoredIdentityChain = {
      did: chain.did,
      log: [...chain.log, jwsToken],
      headCID: extResult.operationCID,
      lastCreatedAt: extResult.createdAt,
      state: extResult.state,
    };
    await store.putIdentityChain(updated);
    await store.putOperation({ cid, jwsToken, chainType: 'identity', chainId: did });
    if (logEnabled) {
      await store.appendToLog({ cid, jwsToken, kind: 'identity-op', chainId: did });
    }
    return { cid, status: 'new', kind: 'identity-op', chainId: did };
  }

  // fork path — check if previousCID exists in chain operations
  if (!previousCID || !chainLogContainsCID(chain.log, previousCID)) {
    return { cid, status: 'rejected', error: 'unknown previous operation in identity chain' };
  }

  // load state at fork point and verify extension against it
  const forkState = await store.getIdentityStateAtCID(did, previousCID);
  if (!forkState) {
    return { cid, status: 'rejected', error: 'failed to compute state at fork point' };
  }

  const extResult = await verifyIdentityExtensionFromTrustedState({
    currentState: forkState.state,
    headCID: previousCID,
    lastCreatedAt: forkState.lastCreatedAt,
    newOp: jwsToken,
  });

  // add to log and recompute head
  const updatedLog = [...chain.log, jwsToken];
  const head = selectDeterministicHead(updatedLog);

  let headState = chain.state;
  let headLastCreatedAt = chain.lastCreatedAt;
  let headCID = chain.headCID;

  if (head.cid === cid) {
    // the new fork extension became the head
    headState = extResult.state;
    headLastCreatedAt = extResult.createdAt;
    headCID = cid;
  } else {
    headCID = head.cid;
    headLastCreatedAt = head.createdAt;
  }

  const updated: StoredIdentityChain = {
    did: chain.did,
    log: updatedLog,
    headCID,
    lastCreatedAt: headLastCreatedAt,
    state: headState,
  };
  await store.putIdentityChain(updated);
  await store.putOperation({ cid, jwsToken, chainType: 'identity', chainId: did });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'identity-op', chainId: did });
  }
  return { cid, status: 'new', kind: 'identity-op', chainId: did };
};

const ingestContentOp = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return { cid: '', status: 'rejected', error: 'failed to decode JWS' };

  const payload = decoded.payload;
  const encoded = await dagCborCanonicalEncode(payload);
  const cid = encoded.cid.toString();

  // temporal guard: reject operations with timestamps too far in the future
  const createdAtVal = (payload as Record<string, unknown>)['createdAt'];
  if (typeof createdAtVal === 'string' && isFutureTimestamp(createdAtVal)) {
    return { cid, status: 'rejected', error: 'createdAt is too far in the future' };
  }

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'operation already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'content-op', chainId: existing.chainId };
  }

  // reject content operations from deleted identities
  const signerDID = (payload as Record<string, unknown>)['did'];
  if (typeof signerDID === 'string') {
    const signerIdentity = await store.getIdentityChain(signerDID);
    if (signerIdentity?.state.isDeleted) {
      return { cid, status: 'rejected', error: 'signer identity is deleted' };
    }
  }

  const resolveKey = createKeyResolver(store);
  const resolveIdentity = createHistoricalIdentityResolver(store);
  const opType = (payload as Record<string, unknown>)['type'];
  const isGenesis = opType === 'create';

  if (isGenesis) {
    const content = await verifyContentChain({
      log: [jwsToken],
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });
    const createdAt = (payload as Record<string, unknown>)['createdAt'] as string;
    const chain: StoredContentChain = {
      contentId: content.contentId,
      genesisCID: content.genesisCID,
      log: [jwsToken],
      lastCreatedAt: createdAt,
      state: content,
    };
    await store.putContentChain(chain);
    await store.putOperation({ cid, jwsToken, chainType: 'content', chainId: content.contentId });
    if (logEnabled) {
      await store.appendToLog({ cid, jwsToken, kind: 'content-op', chainId: content.contentId });
    }
    return { cid, status: 'new', kind: 'content-op', chainId: content.contentId };
  }

  // extension — find the existing chain via previousOperationCID
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

  // reject if the content creator's identity is deleted
  const creatorIdentity = await store.getIdentityChain(chain.state.creatorDID);
  if (creatorIdentity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'content creator identity is deleted' };
  }

  if (chain.state.headCID === previousCID) {
    // linear extension (fast path) — O(1) from trusted head state
    const extResult = await verifyContentExtensionFromTrustedState({
      currentState: chain.state,
      lastCreatedAt: chain.lastCreatedAt,
      newOp: jwsToken,
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });
    const updated: StoredContentChain = {
      contentId: chain.contentId,
      genesisCID: chain.genesisCID,
      log: [...chain.log, jwsToken],
      lastCreatedAt: extResult.createdAt,
      state: extResult.state,
    };
    await store.putContentChain(updated);
    await store.putOperation({ cid, jwsToken, chainType: 'content', chainId: chain.contentId });
    if (logEnabled) {
      await store.appendToLog({ cid, jwsToken, kind: 'content-op', chainId: chain.contentId });
    }
    return { cid, status: 'new', kind: 'content-op', chainId: chain.contentId };
  }

  // fork path — check if previousCID exists in chain operations
  if (!chainLogContainsCID(chain.log, previousCID)) {
    return { cid, status: 'rejected', error: 'unknown previous operation in content chain' };
  }

  // load state at fork point and verify extension against it
  const forkState = await store.getContentStateAtCID(chain.contentId, previousCID);
  if (!forkState) {
    return { cid, status: 'rejected', error: 'failed to compute state at fork point' };
  }

  const extResult = await verifyContentExtensionFromTrustedState({
    currentState: forkState.state,
    lastCreatedAt: forkState.lastCreatedAt,
    newOp: jwsToken,
    resolveKey,
    enforceAuthorization: true,
    resolveIdentity,
  });

  // add to log and recompute head
  const updatedLog = [...chain.log, jwsToken];
  const head = selectDeterministicHead(updatedLog);

  let headState = chain.state;
  let headLastCreatedAt = chain.lastCreatedAt;

  if (head.cid === cid) {
    headState = extResult.state;
    headLastCreatedAt = extResult.createdAt;
  }

  const updated: StoredContentChain = {
    contentId: chain.contentId,
    genesisCID: chain.genesisCID,
    log: updatedLog,
    lastCreatedAt: headLastCreatedAt,
    state: headState,
  };
  await store.putContentChain(updated);
  await store.putOperation({ cid, jwsToken, chainType: 'content', chainId: chain.contentId });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'content-op', chainId: chain.contentId });
  }
  return { cid, status: 'new', kind: 'content-op', chainId: chain.contentId };
};

const ingestBeacon = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const resolveKey = createKeyResolver(store);

  let verified: VerifiedBeacon;
  try {
    verified = await verifyBeacon({ jwsToken, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const did = verified.did;
  const cid = verified.beaconCID;

  // reject beacons from deleted identities
  const identity = await store.getIdentityChain(did);
  if (identity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'identity is deleted' };
  }

  // replace-on-newer: only store if this beacon is more recent
  const existing = await store.getBeacon(did);
  if (existing) {
    const existingTime = new Date(existing.state.createdAt).getTime();
    const newTime = new Date(verified.createdAt).getTime();
    if (newTime <= existingTime) {
      return { cid, status: 'duplicate', kind: 'beacon', chainId: did };
    }
  }

  await store.putBeacon({ did, jwsToken, beaconCID: cid, state: verified });
  await store.putOperation({ cid, jwsToken, chainType: 'beacon', chainId: did });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'beacon', chainId: did });
  }
  return { cid, status: 'new', kind: 'beacon', chainId: did };
};

const ingestCountersign = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const resolveKey = createKeyResolver(store);

  let verified: VerifiedCountersignature;
  try {
    verified = await verifyCountersignature({ jwsToken, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const cid = verified.countersignCID;
  const { witnessDID, targetCID } = verified;

  // idempotent: already stored
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'countersign already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'countersign', chainId: targetCID };
  }

  // target must exist
  const targetOp = await store.getOperation(targetCID);
  if (!targetOp) {
    return { cid, status: 'rejected', error: `unknown target operation: ${targetCID}` };
  }

  // witness must differ from target author
  let targetAuthorDID: string | null = null;
  if (targetOp.chainType === 'identity') {
    targetAuthorDID = targetOp.chainId;
  } else {
    const targetDecoded = decodeJwsUnsafe(targetOp.jwsToken);
    if (targetDecoded) {
      const targetPayload = targetDecoded.payload as Record<string, unknown>;
      targetAuthorDID = typeof targetPayload['did'] === 'string' ? targetPayload['did'] : null;
    }
  }

  if (targetAuthorDID && witnessDID === targetAuthorDID) {
    return { cid, status: 'rejected', error: 'witness DID must differ from target author DID' };
  }

  // reject countersigns from deleted witnesses
  const witnessIdentity = await store.getIdentityChain(witnessDID);
  if (witnessIdentity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'witness identity is deleted' };
  }

  // dedup: one countersign per witness per target
  const existingCountersigns = await store.getCountersignatures(targetCID);
  for (const csJws of existingCountersigns) {
    const csDecoded = decodeJwsUnsafe(csJws);
    if (!csDecoded) continue;
    const csPayload = csDecoded.payload as Record<string, unknown>;
    if (csPayload['did'] === witnessDID) {
      return { cid, status: 'duplicate', kind: 'countersign', chainId: targetCID };
    }
  }

  await store.putOperation({ cid, jwsToken, chainType: 'countersign', chainId: targetCID });
  await store.addCountersignature(targetCID, jwsToken);
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'countersign', chainId: targetCID });
  }
  return { cid, status: 'new', kind: 'countersign', chainId: targetCID };
};

const ingestArtifact = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const resolveKey = createKeyResolver(store);

  let verified;
  try {
    verified = await verifyArtifact({ jwsToken, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const cid = verified.artifactCID;
  const did = verified.payload.did;

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'artifact already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'artifact', chainId: did };
  }

  // reject artifacts from deleted identities
  const identity = await store.getIdentityChain(did);
  if (identity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'identity is deleted' };
  }

  await store.putOperation({ cid, jwsToken, chainType: 'artifact', chainId: did });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'artifact', chainId: did });
  }
  return { cid, status: 'new', kind: 'artifact', chainId: did };
};

const ingestRevocation = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const resolveKey = createKeyResolver(store);

  let verified: VerifiedRevocation;
  try {
    verified = await verifyRevocation({ jwsToken, resolveKey });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const cid = verified.revocationCID;
  const did = verified.did;

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'revocation already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'revocation', chainId: did };
  }

  // reject revocations from deleted identities
  const identity = await store.getIdentityChain(did);
  if (identity?.state.isDeleted) {
    return { cid, status: 'rejected', error: 'identity is deleted' };
  }

  // add to revocation set
  await store.addRevocation({
    cid,
    issuerDID: did,
    credentialCID: verified.credentialCID,
    jwsToken,
  });

  // if the revoked credential was a stored public credential, remove it
  await store.removePublicCredential(verified.credentialCID);

  await store.putOperation({ cid, jwsToken, chainType: 'revocation', chainId: did });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'revocation', chainId: did });
  }
  return { cid, status: 'new', kind: 'revocation', chainId: did };
};

const ingestPublicCredential = async (
  jwsToken: string,
  store: RelayStore,
  logEnabled: boolean,
): Promise<IngestionResult> => {
  const resolveIdentity = createHistoricalIdentityResolver(store);

  let verified: VerifiedDFOSCredential;
  try {
    verified = await verifyDFOSCredential(jwsToken, { resolveIdentity });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'verification failed';
    return { cid: '', status: 'rejected', error: message };
  }

  const cid = verified.credentialCID;

  // only ingest public credentials
  if (verified.aud !== '*') {
    return { cid: '', status: 'rejected', error: 'not a public credential' };
  }

  // idempotent: already stored (exact same JWS token)
  const existing = await store.getOperation(cid);
  if (existing) {
    if (existing.jwsToken !== jwsToken) {
      return {
        cid,
        status: 'rejected',
        error: 'credential already exists with a different signature',
      };
    }
    return { cid, status: 'duplicate', kind: 'credential', chainId: verified.iss };
  }

  // check if already revoked (scoped to credential issuer)
  const revoked = await store.isCredentialRevoked(verified.iss, cid);
  if (revoked) {
    return { cid, status: 'rejected', error: 'credential is revoked' };
  }

  // store as standing authorization
  await store.addPublicCredential({
    cid,
    issuerDID: verified.iss,
    att: verified.att,
    exp: verified.exp,
    jwsToken,
  });

  await store.putOperation({ cid, jwsToken, chainType: 'credential', chainId: verified.iss });
  if (logEnabled) {
    await store.appendToLog({ cid, jwsToken, kind: 'credential', chainId: verified.iss });
  }
  return { cid, status: 'new', kind: 'credential', chainId: verified.iss };
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
// fork helpers
// -----------------------------------------------------------------------------

/** Check if a chain log (JWS tokens) contains an operation with the given CID */
const chainLogContainsCID = (log: string[], targetCID: string): boolean => {
  for (const jws of log) {
    const decoded = decodeJwsUnsafe(jws);
    if (!decoded) continue;
    if (decoded.header.cid === targetCID) return true;
  }
  return false;
};

/**
 * Select the deterministic head from a chain log.
 *
 * Tips are operations with no children. Among tips, select:
 * 1. Highest createdAt
 * 2. Lexicographic highest CID as tiebreaker
 *
 * Deterministic across relays given the same operations.
 */
const selectDeterministicHead = (log: string[]): { cid: string; createdAt: string } => {
  const ops: { cid: string; previousCID: string | null; createdAt: string }[] = [];
  const hasChild = new Set<string>();

  for (const jws of log) {
    const decoded = decodeJwsUnsafe(jws);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    const cid = typeof decoded.header.cid === 'string' ? decoded.header.cid : '';
    const previousCID =
      typeof payload['previousOperationCID'] === 'string' ? payload['previousOperationCID'] : null;
    const createdAt = typeof payload['createdAt'] === 'string' ? payload['createdAt'] : '';
    ops.push({ cid, previousCID, createdAt });
    if (previousCID) hasChild.add(previousCID);
  }

  const tips = ops.filter((op) => !hasChild.has(op.cid));

  // sort: highest createdAt first, then lexicographic highest CID
  tips.sort((a, b) => {
    if (a.createdAt !== b.createdAt) return b.createdAt.localeCompare(a.createdAt);
    return b.cid.localeCompare(a.cid);
  });

  return tips[0] ?? { cid: '', createdAt: '' };
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
  options?: { logEnabled?: boolean },
): Promise<IngestionResult[]> => {
  const logEnabled = options?.logEnabled !== false;

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
          result = await ingestIdentityOp(op.jwsToken, store, logEnabled);
          break;
        case 'content-op':
          result = await ingestContentOp(op.jwsToken, store, logEnabled);
          break;
        case 'beacon':
          result = await ingestBeacon(op.jwsToken, store, logEnabled);
          break;
        case 'countersign':
          result = await ingestCountersign(op.jwsToken, store, logEnabled);
          break;
        case 'artifact':
          result = await ingestArtifact(op.jwsToken, store, logEnabled);
          break;
        case 'revocation':
          result = await ingestRevocation(op.jwsToken, store, logEnabled);
          break;
        case 'credential':
          result = await ingestPublicCredential(op.jwsToken, store, logEnabled);
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

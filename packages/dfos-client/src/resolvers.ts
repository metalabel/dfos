/*

  RESOLVERS

  The cache-the-log / verify-forward core, and the bound protocol-lib callbacks
  built on top of it. This module contains ZERO verification logic of its own —
  every proof comes from @metalabel/dfos-protocol. What it adds is orchestration:
  fetch logs (via transport), cache the LOG (never a terminal verified state),
  and verify FORWARD from the trusted prefix using the protocol's O(1) extension
  verifiers. Rotation costs one op; the cache is never stale-wrong.

*/

import {
  decodeMultikey,
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
  type MultikeyPublicKey,
  type VerifiedContentChain,
  type VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { PeerClient } from '@metalabel/dfos-web-relay';
import { contentPager, fanOutLog, identityPager, type FanOutResult } from './transport';
import type { Callbacks, CallOptions, Provenance, RevChecker, Store } from './types';

const DID_PREFIX = 'did:dfos';

// -----------------------------------------------------------------------------
// cache shape
// -----------------------------------------------------------------------------

interface CachedChain<T> {
  log: string[];
  state: T;
  headCID: string;
  lastCreatedAt: string;
}

const opMeta = (jws: string): { cid: string; createdAt: string } => {
  const decoded = decodeJwsUnsafe(jws);
  const cid = typeof decoded?.header.cid === 'string' ? decoded.header.cid : '';
  const createdAt =
    typeof (decoded?.payload as Record<string, unknown>)?.['createdAt'] === 'string'
      ? ((decoded?.payload as Record<string, unknown>)['createdAt'] as string)
      : '';
  return { cid, createdAt };
};

// -----------------------------------------------------------------------------
// key extraction (mirrors the relay's createKeyResolver / historical resolver,
// but sourced from a cached, verified log instead of a RelayStore)
// -----------------------------------------------------------------------------

const allCurrentKeys = (state: VerifiedIdentity): MultikeyPublicKey[] => [
  ...state.authKeys,
  ...state.assertKeys,
  ...state.controllerKeys,
];

/** Merge every key that ever appeared in a create/update op — credential validity
 * persists across rotations, so credential verification needs historical keys. */
const mergeHistoricalIdentity = (state: VerifiedIdentity, log: string[]): VerifiedIdentity => {
  const maps = {
    authKeys: new Map(state.authKeys.map((k) => [k.id, k])),
    assertKeys: new Map(state.assertKeys.map((k) => [k.id, k])),
    controllerKeys: new Map(state.controllerKeys.map((k) => [k.id, k])),
  };
  for (const jws of log) {
    const decoded = decodeJwsUnsafe(jws);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    if (payload['type'] !== 'create' && payload['type'] !== 'update') continue;
    for (const field of ['authKeys', 'assertKeys', 'controllerKeys'] as const) {
      const keys = payload[field];
      if (!Array.isArray(keys)) continue;
      for (const k of keys) {
        if (k && typeof k === 'object' && 'id' in k && 'publicKeyMultibase' in k) {
          const id = (k as { id: string }).id;
          if (!maps[field].has(id)) maps[field].set(id, k as MultikeyPublicKey);
        }
      }
    }
  }
  return {
    ...state,
    authKeys: [...maps.authKeys.values()],
    assertKeys: [...maps.assertKeys.values()],
    controllerKeys: [...maps.controllerKeys.values()],
  };
};

const keyBytesFor = (state: VerifiedIdentity, log: string[], keyId: string): Uint8Array | null => {
  const current = allCurrentKeys(state).find((k) => k.id === keyId);
  if (current) return decodeMultikey(current.publicKeyMultibase).keyBytes;
  for (const jws of log) {
    const decoded = decodeJwsUnsafe(jws);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    if (payload['type'] !== 'create' && payload['type'] !== 'update') continue;
    for (const field of ['authKeys', 'assertKeys', 'controllerKeys'] as const) {
      const keys = payload[field];
      if (!Array.isArray(keys)) continue;
      for (const k of keys) {
        if (
          k &&
          typeof k === 'object' &&
          'id' in k &&
          k.id === keyId &&
          'publicKeyMultibase' in k
        ) {
          return decodeMultikey((k as { publicKeyMultibase: string }).publicKeyMultibase).keyBytes;
        }
      }
    }
  }
  return null;
};

// -----------------------------------------------------------------------------
// resolvers factory
// -----------------------------------------------------------------------------

export interface ResolverDeps {
  relays: string[];
  quorum: number;
  store: Store;
  peerClient: PeerClient;
  isRevoked: RevChecker;
}

export interface IdentityResolution {
  state: VerifiedIdentity;
  log: string[];
  provenance: Provenance;
}

export interface ContentResolution {
  state: VerifiedContentChain;
  log: string[];
  provenance: Provenance;
}

/** The internal resolver surface — the client and the free `resolvers()` both use it. */
export interface Resolvers {
  getIdentityChain(did: string, options?: CallOptions): Promise<IdentityResolution>;
  getContentChain(contentId: string, options?: CallOptions): Promise<ContentResolution>;
  callbacks(): Callbacks;
}

export const createResolvers = (deps: ResolverDeps): Resolvers => {
  const relaysFor = (o?: CallOptions) => o?.relays ?? deps.relays;

  const getIdentityChain = async (
    did: string,
    options?: CallOptions,
  ): Promise<IdentityResolution> => {
    const key = `identity:${did}`;
    const cached = options?.fresh
      ? undefined
      : ((await deps.store.get(key)) as CachedChain<VerifiedIdentity> | undefined);

    const fetched: FanOutResult = await fanOutLog(
      identityPager(deps.peerClient, did),
      relaysFor(options),
      deps.quorum,
      cached?.headCID,
    );

    // every relay failed
    if (fetched.provenance.answeredBy === '' && fetched.entries.length === 0) {
      if (cached) {
        return {
          state: cached.state,
          log: cached.log,
          provenance: { ...fetched.provenance, fromCache: true },
        };
      }
      throw new Error(`identity not found on any relay: ${did}`);
    }

    if (!cached) {
      const log = fetched.entries.map((e) => e.jwsToken);
      if (log.length === 0) throw new Error(`identity not found: ${did}`);
      const state = await verifyIdentityChain({ didPrefix: DID_PREFIX, log });
      const last = opMeta(log[log.length - 1]!);
      await deps.store.set(key, {
        log,
        state,
        headCID: last.cid,
        lastCreatedAt: last.createdAt,
      } satisfies CachedChain<VerifiedIdentity>);
      return { state, log, provenance: fetched.provenance };
    }

    // verify forward from the trusted prefix
    let state = cached.state;
    let headCID = cached.headCID;
    let lastCreatedAt = cached.lastCreatedAt;
    const log = [...cached.log];
    for (const entry of fetched.entries) {
      const r = await verifyIdentityExtensionFromTrustedState({
        currentState: state,
        headCID,
        lastCreatedAt,
        newOp: entry.jwsToken,
      });
      state = r.state;
      headCID = r.operationCID;
      lastCreatedAt = r.createdAt;
      log.push(entry.jwsToken);
    }
    if (fetched.entries.length > 0) {
      await deps.store.set(key, {
        log,
        state,
        headCID,
        lastCreatedAt,
      } satisfies CachedChain<VerifiedIdentity>);
    }
    return { state, log, provenance: fetched.provenance };
  };

  // the bound protocol-lib callbacks — the trunk product
  const resolveIdentity = async (did: string): Promise<VerifiedIdentity | undefined> => {
    try {
      const { state, log } = await getIdentityChain(did);
      return mergeHistoricalIdentity(state, log);
    } catch {
      return undefined;
    }
  };

  const resolveKey = async (kid: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);
    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);
    const { state, log } = await getIdentityChain(did);
    const bytes = keyBytesFor(state, log, keyId);
    if (!bytes) throw new Error(`unknown key ${keyId} on identity ${did}`);
    return bytes;
  };

  const callbacks = (): Callbacks => ({
    resolveKey,
    resolveIdentity,
    isRevoked: deps.isRevoked,
  });

  const getContentChain = async (
    contentId: string,
    options?: CallOptions,
  ): Promise<ContentResolution> => {
    const key = `content:${contentId}`;
    const cached = options?.fresh
      ? undefined
      : ((await deps.store.get(key)) as CachedChain<VerifiedContentChain> | undefined);

    const fetched: FanOutResult = await fanOutLog(
      contentPager(deps.peerClient, contentId),
      relaysFor(options),
      deps.quorum,
      cached?.headCID,
    );

    if (fetched.provenance.answeredBy === '' && fetched.entries.length === 0) {
      if (cached) {
        return {
          state: cached.state,
          log: cached.log,
          provenance: { ...fetched.provenance, fromCache: true },
        };
      }
      throw new Error(`content not found on any relay: ${contentId}`);
    }

    if (!cached) {
      const log = fetched.entries.map((e) => e.jwsToken);
      if (log.length === 0) throw new Error(`content not found: ${contentId}`);
      const state = await verifyContentChain({
        log,
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
        isRevoked: deps.isRevoked,
      });
      const last = opMeta(log[log.length - 1]!);
      await deps.store.set(key, {
        log,
        state,
        headCID: last.cid,
        lastCreatedAt: last.createdAt,
      } satisfies CachedChain<VerifiedContentChain>);
      return { state, log, provenance: fetched.provenance };
    }

    let state = cached.state;
    let lastCreatedAt = cached.lastCreatedAt;
    const log = [...cached.log];
    for (const entry of fetched.entries) {
      const r = await verifyContentExtensionFromTrustedState({
        currentState: state,
        lastCreatedAt,
        newOp: entry.jwsToken,
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
        isRevoked: deps.isRevoked,
      });
      state = r.state;
      lastCreatedAt = r.createdAt;
      log.push(entry.jwsToken);
    }
    if (fetched.entries.length > 0) {
      await deps.store.set(key, {
        log,
        state,
        headCID: state.headCID,
        lastCreatedAt,
      } satisfies CachedChain<VerifiedContentChain>);
    }
    return { state, log, provenance: fetched.provenance };
  };

  return { getIdentityChain, getContentChain, callbacks };
};

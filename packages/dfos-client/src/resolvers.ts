/*

  RESOLVERS

  The cache-the-log / verify-forward core, and the bound protocol-lib callbacks
  built on top of it. This module contains ZERO verification logic of its own —
  every proof comes from @metalabel/dfos-protocol. What it adds is orchestration:
  fully drain logs from zero (via transport), require their JWS tokens to match
  the trusted cached prefix, then verify only the suffix using the protocol's
  O(1) extension verifiers. Rotation costs one verification op; the cache is
  never stale-wrong.

  Trust rules enforced here:
  - a candidate log that fails verification is failed over, not fatal (transport
    handles the failover; verification is the candidate filter)
  - the cache is only written back when the answer both VERIFIED and met quorum —
    a failed-quorum minority answer never becomes the trusted prefix
  - `tipUnverified` is true whenever a full relay answer exactly matches the
    cached log, or when the answer comes from cache alone — tip freshness is
    never PROVEN in v1

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
import type { PeerClient } from '@metalabel/dfos-web-relay/peer-client';
import {
  contentPager,
  fanOutLog,
  identityPager,
  normalizeRelays,
  StaleAnswerError,
} from './transport';
import type { Callbacks, CallOptions, LogOp, Provenance, RevChecker, Store } from './types';

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

/** The store key one chain's verified prefix is filed under. The ONE place the
 *  format lives — the resolvers write it and `discardCachedChain` deletes it. */
const cacheKey = (kind: 'identity' | 'content', id: string): string => `${kind}:${id}`;

// -----------------------------------------------------------------------------
// divergence — the live log CONTRADICTS the verified prefix
// -----------------------------------------------------------------------------

/**
 * The relays' log for a chain disagrees with the verified prefix this client
 * cached: at a position the cache already covers, the operation served is not
 * the operation this client proved. Distinct from `StaleAnswerError` (a relay
 * merely behind) and from a failed proof (a chain that does not verify) — here
 * two histories contradict each other about what already happened, so verifying
 * forward from the trusted prefix is not a thing that can be done.
 *
 * NOTHING IS DISCARDED HERE. Dropping a verified prefix is a decision about
 * trust, not an error path: a client that healed itself silently would erase the
 * only evidence that a rewrite happened, which is the whole reason the prefix is
 * pinned. `client.discardCachedChain()` is the explicit undo, and it is the
 * caller's to call.
 *
 * The error is thrown as a CANDIDATE FILTER, inside the fan-out. A fan-out where
 * every relay diverges surfaces its own error carrying this one as `cause`, so
 * callers reach it with `divergenceErrorFrom(err)` rather than a bare
 * `instanceof` on what they caught.
 */
export class DivergenceError extends Error {
  readonly chainType: 'identity' | 'content';
  readonly chainId: string;
  /** Head CID of the verified prefix this client holds. */
  readonly cachedHeadCID: string;
  /**
   * Head CID of the log the relays served, as that operation's own JWS header
   * names it — orientation for a human, never a proof. Empty when the served log
   * was empty or its head named no CID.
   */
  readonly liveHeadCID: string;

  constructor(input: {
    chainType: 'identity' | 'content';
    chainId: string;
    cachedHeadCID: string;
    liveHeadCID: string;
  }) {
    super(`${input.chainType} log diverges from the verified cached prefix: ${input.chainId}`);
    // survives bundlers that rewrite class names, and cross-realm callers where
    // `instanceof` is already unreliable
    this.name = 'DivergenceError';
    this.chainType = input.chainType;
    this.chainId = input.chainId;
    this.cachedHeadCID = input.cachedHeadCID;
    this.liveHeadCID = input.liveHeadCID;
  }
}

/** How far down a `cause` chain to look. A content read whose creator identity
 *  diverges nests two fan-out wrappers; nothing nests deeper than that. */
const CAUSE_DEPTH = 8;

/**
 * Find the `DivergenceError` behind a caught error, walking the `cause` chain —
 * the fan-out wraps a candidate's verification failure, and a content read wraps
 * the identity read inside it. Returns `undefined` when the failure was anything
 * else, so a caller can branch on the answer instead of matching message text.
 */
export const divergenceErrorFrom = (err: unknown): DivergenceError | undefined => {
  let cursor = err;
  for (let depth = 0; depth < CAUSE_DEPTH && cursor instanceof Error; depth++) {
    if (cursor instanceof DivergenceError) return cursor;
    cursor = cursor.cause;
  }
  return undefined;
};

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

/**
 * HAS-EVER-PROVED, as the chain walk already computed it.
 *
 * WHAT THIS REPLACED, AND WHY IT HAD TO GO. Both helpers below used to re-walk
 * the raw log and take every key any `create` or `update` DECLARED. That rule is
 * now wrong in both directions at once:
 *
 *  - A DECLARATION IS NOT A DEMONSTRATION. Anyone can write anyone's public key
 *    into their own chain; only a possession proof admits it. Resolving against
 *    declarations would let a stranger have clients verify signatures against a
 *    key they do not hold, simply by naming it.
 *  - A PROVED KEY STAYS RESOLVABLE FOREVER. Credential validity persists across
 *    rotations — revocation, not rotation, is the invalidation mechanism — so
 *    dropping to current effective state alone would silently un-verify every
 *    artifact signed before a rotation.
 *
 * `verifyIdentityChain` folds exactly that set onto `provedKeys`. Re-deriving it
 * here meant maintaining a second answer to the same question under a rule that
 * quietly disagreed with the chain's, which is the drift this package exists to
 * avoid — the relay's twin of this code went the same way.
 *
 * An absent `provedKeys` reads as current effective state: exactly right for any
 * chain with no void memberships, and the only reading available for a cached
 * state that predates the member.
 */
const provedKeys = (state: VerifiedIdentity): MultikeyPublicKey[] => {
  const proved = state.provedKeys ?? state;
  return [...proved.authKeys, ...proved.assertKeys, ...proved.controllerKeys];
};

/** The identity as long-lived artifacts must see it: every key ever proved. */
const historicalIdentity = (state: VerifiedIdentity): VerifiedIdentity => ({
  ...state,
  ...(state.provedKeys ?? {
    authKeys: state.authKeys,
    assertKeys: state.assertKeys,
    controllerKeys: state.controllerKeys,
  }),
});

const keyBytesFor = (state: VerifiedIdentity, keyId: string): Uint8Array | null => {
  const key = provedKeys(state).find((k) => k.id === keyId);
  return key ? decodeMultikey(key.publicKeyMultibase).keyBytes : null;
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
  /** True when cache is the only answer or a full relay log exactly matches it. */
  tipUnverified: boolean;
}

export interface ContentResolution {
  state: VerifiedContentChain;
  log: string[];
  provenance: Provenance;
  /** True when cache is the only answer or a full relay log exactly matches it. */
  tipUnverified: boolean;
}

/** A verified chain candidate — the output of a verifyCandidate closure. */
interface VerifiedCandidate<T> {
  state: T;
  log: string[];
  headCID: string;
  lastCreatedAt: string;
}

/** The internal resolver surface — the client and the free `resolvers()` both use it. */
export interface Resolvers {
  getIdentityChain(did: string, options?: CallOptions): Promise<IdentityResolution>;
  getContentChain(contentId: string, options?: CallOptions): Promise<ContentResolution>;
  discardCachedChain(kind: 'identity' | 'content', id: string): Promise<boolean>;
  callbacks(): Callbacks;
}

export const createResolvers = (deps: ResolverDeps): Resolvers => {
  const relaysFor = (o?: CallOptions) => normalizeRelays(o?.relays ?? deps.relays);

  const getIdentityChain = async (
    did: string,
    options?: CallOptions,
  ): Promise<IdentityResolution> => {
    const key = cacheKey('identity', did);
    const cached = options?.fresh
      ? undefined
      : ((await deps.store.get(key)) as CachedChain<VerifiedIdentity> | undefined);

    // verification IS the candidate filter: full verify from genesis when cold,
    // O(1) verify-forward from the trusted prefix when cached
    const verifyCandidate = async (
      entries: LogOp[],
    ): Promise<VerifiedCandidate<VerifiedIdentity>> => {
      if (!cached) {
        const log = entries.map((e) => e.jwsToken);
        if (log.length === 0) throw new Error(`identity not found: ${did}`);
        const state = await verifyIdentityChain({ didPrefix: DID_PREFIX, log });
        // BIND to the requested id: verifyIdentityChain derives the DID from
        // whatever genesis op it was handed — a relay that serves a DIFFERENT
        // (internally valid) chain under this DID must not resolve as `did`.
        if (state.did !== did) {
          throw new Error(`relay served a mismatched identity: asked ${did}, got ${state.did}`);
        }
        const last = opMeta(log[log.length - 1]!);
        return { state, log, headCID: last.cid, lastCreatedAt: last.createdAt };
      }
      // consistency is judged over the OVERLAP: a mismatched token is a
      // fork/forgery claim and fails the candidate outright, while a
      // consistent-but-shorter answer is just a relay with no new information
      // (behind, mid-resync) — fail over like a transport miss so a fresher
      // relay can win and the cache fallback stays reachable
      if (
        cached.log.some((jws, index) => index < entries.length && entries[index]!.jwsToken !== jws)
      ) {
        throw new DivergenceError({
          chainType: 'identity',
          chainId: did,
          cachedHeadCID: cached.headCID,
          liveHeadCID: opMeta(entries[entries.length - 1]?.jwsToken ?? '').cid,
        });
      }
      if (entries.length < cached.log.length) {
        throw new StaleAnswerError(`identity log is behind the verified cached prefix: ${did}`);
      }
      let state = cached.state;
      let headCID = cached.headCID;
      let lastCreatedAt = cached.lastCreatedAt;
      const log = [...cached.log];
      for (const entry of entries.slice(cached.log.length)) {
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
      return { state, log, headCID, lastCreatedAt };
    };

    const fetched = await fanOutLog(
      identityPager(deps.peerClient, did),
      relaysFor(options),
      deps.quorum,
      verifyCandidate,
    );

    if (fetched.outcome === 'unreachable') {
      if (cached) {
        return {
          state: cached.state,
          log: cached.log,
          provenance: { ...fetched.provenance, fromCache: true },
          tipUnverified: true,
        };
      }
      throw new Error(`identity not found on any relay: ${did}`);
    }

    const candidate = fetched.value!;
    // cache only an answer that both verified AND met quorum — a minority
    // answer must never become the trusted prefix
    if (fetched.provenance.agreed && (!cached || candidate.log.length > cached.log.length)) {
      await deps.store.set(key, {
        log: candidate.log,
        state: candidate.state,
        headCID: candidate.headCID,
        lastCreatedAt: candidate.lastCreatedAt,
      } satisfies CachedChain<VerifiedIdentity>);
    }
    return {
      state: candidate.state,
      log: candidate.log,
      provenance: fetched.provenance,
      // an unchanged full answer is still a relay CLAIM of freshness, not proof
      tipUnverified: cached !== undefined && candidate.log.length === cached.log.length,
    };
  };

  // the bound protocol-lib callbacks — the trunk product
  const resolveIdentity = async (did: string): Promise<VerifiedIdentity | undefined> => {
    try {
      const { state } = await getIdentityChain(did);
      return historicalIdentity(state);
    } catch {
      return undefined;
    }
  };

  const resolveKey = async (kid: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);
    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);
    const { state } = await getIdentityChain(did);
    const bytes = keyBytesFor(state, keyId);
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
    const key = cacheKey('content', contentId);
    const cached = options?.fresh
      ? undefined
      : ((await deps.store.get(key)) as CachedChain<VerifiedContentChain> | undefined);

    const verifyCandidate = async (
      entries: LogOp[],
    ): Promise<VerifiedCandidate<VerifiedContentChain>> => {
      if (!cached) {
        const log = entries.map((e) => e.jwsToken);
        if (log.length === 0) throw new Error(`content not found: ${contentId}`);
        const state = await verifyContentChain({
          log,
          resolveKey,
          enforceAuthorization: true,
          resolveIdentity,
          isRevoked: deps.isRevoked,
        });
        // BIND to the requested id: contentId is derived from the genesis op
        // CID inside verifyContentChain — reject a relay that serves a different
        // valid chain under this contentId.
        if (state.contentId !== contentId) {
          throw new Error(
            `relay served a mismatched content chain: asked ${contentId}, got ${state.contentId}`,
          );
        }
        const last = opMeta(log[log.length - 1]!);
        return { state, log, headCID: last.cid, lastCreatedAt: last.createdAt };
      }
      // overlap-consistency rule — see the identity resolver's twin above
      if (
        cached.log.some((jws, index) => index < entries.length && entries[index]!.jwsToken !== jws)
      ) {
        throw new DivergenceError({
          chainType: 'content',
          chainId: contentId,
          cachedHeadCID: cached.headCID,
          liveHeadCID: opMeta(entries[entries.length - 1]?.jwsToken ?? '').cid,
        });
      }
      if (entries.length < cached.log.length) {
        throw new StaleAnswerError(
          `content log is behind the verified cached prefix: ${contentId}`,
        );
      }
      let state = cached.state;
      let lastCreatedAt = cached.lastCreatedAt;
      const log = [...cached.log];
      for (const entry of entries.slice(cached.log.length)) {
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
      return { state, log, headCID: state.headCID, lastCreatedAt };
    };

    const fetched = await fanOutLog(
      contentPager(deps.peerClient, contentId),
      relaysFor(options),
      deps.quorum,
      verifyCandidate,
    );

    if (fetched.outcome === 'unreachable') {
      if (cached) {
        return {
          state: cached.state,
          log: cached.log,
          provenance: { ...fetched.provenance, fromCache: true },
          tipUnverified: true,
        };
      }
      throw new Error(`content not found on any relay: ${contentId}`);
    }

    const candidate = fetched.value!;
    if (fetched.provenance.agreed && (!cached || candidate.log.length > cached.log.length)) {
      await deps.store.set(key, {
        log: candidate.log,
        state: candidate.state,
        headCID: candidate.headCID,
        lastCreatedAt: candidate.lastCreatedAt,
      } satisfies CachedChain<VerifiedContentChain>);
    }
    return {
      state: candidate.state,
      log: candidate.log,
      provenance: fetched.provenance,
      tipUnverified: cached !== undefined && candidate.log.length === cached.log.length,
    };
  };

  /**
   * Forget the verified prefix for ONE chain. Narrow by construction — it names
   * a single store key and touches nothing else — idempotent, and a no-op when
   * that chain was never cached. The next read of the chain is a cold one: the
   * log drains from zero and every signature and CID is verified again.
   *
   * Reports whether the cache was actually asked to forget: `false` means the
   * configured store has no `delete` seam, which is a real answer a caller can
   * show rather than a silent nothing. Both bundled stores have one.
   */
  const discardCachedChain = async (kind: 'identity' | 'content', id: string): Promise<boolean> => {
    const remove = deps.store.delete?.bind(deps.store);
    if (!remove) return false;
    await remove(cacheKey(kind, id));
    return true;
  };

  return { getIdentityChain, getContentChain, discardCachedChain, callbacks };
};

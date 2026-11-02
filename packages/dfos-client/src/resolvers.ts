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
  - a content log is a DAG: the cache pins the SET of operations it verified,
    not a prefix, and credential authority on every surviving op is re-asked on
    every read because deletion and backdated revocation can withdraw it

*/

import { isDependencyMissing, markDependencyMissing } from '@metalabel/dfos-protocol';
import {
  decodeMultikey,
  IdentityStateNoSeenKeysError,
  recheckContentAuthorization,
  verifyContentDag,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
  type ContentDagNode,
  type ContentDagRejection,
  type MultikeyPublicKey,
  type VerifiedContentChain,
  type VerifiedContentDag,
} from '@metalabel/dfos-protocol/chain';
import { CredentialVerificationError } from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { PeerClient } from '@metalabel/dfos-web-relay/peer-client';
import {
  contentPager,
  digestOpSet,
  fanOutLog,
  identityPager,
  normalizeRelays,
  StaleAnswerError,
} from './transport';
import type {
  CachedContentSummary,
  Callbacks,
  CallOptions,
  EffectiveIdentity,
  EverProvedIdentity,
  LogOp,
  Provenance,
  RevChecker,
  Store,
} from './types';

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

/**
 * A content chain's cache row. `log` is every operation that VERIFIED, in served
 * order, and the pin is the SET of them: a later read must still serve every
 * one. `rejected` lists the served operations that did not verify; they are
 * never pinned. `nodes` memoizes each surviving operation's verified state so an
 * operation not yet seen verifies against its parent's state, whichever branch
 * it extends. Both extra members are absent on a row written before content
 * resolution was DAG-aware; such a row's `log` is its head lineage.
 */
interface CachedContentChain extends CachedChain<VerifiedContentChain> {
  headLineage?: string[];
  nodes?: Record<string, ContentDagNode>;
  rejected?: ContentDagRejection[];
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

/** The served operations that verified, in served order, each once. */
const survivors = (log: string[], dag: VerifiedContentDag): string[] => {
  const seen = new Set<string>();
  return log.filter((jws) => {
    const cid = opMeta(jws).cid;
    // own keys only: a header CID is attacker-chosen, and `constructor` is inherited
    if (!Object.hasOwn(dag.nodes, cid) || seen.has(cid)) return false;
    seen.add(cid);
    return true;
  });
};

// -----------------------------------------------------------------------------
// key extraction (mirrors the relay's as-of resolver, but sourced from a cached,
// verified log instead of a RelayStore)
// -----------------------------------------------------------------------------

/**
 * HAS-EVER-PROVED, as the chain walk already computed it. One surface takes it:
 * a credit claim, which runs no temporal check and so resolves the claimant's
 * key against every key that chain has ever held (PROTOCOL, Time basis). Every
 * other surface has a basis and resolves against the effective state as of it.
 *
 * HAS-EVER-PROVED, NOT HAS-EVER-DECLARED. Anyone can write anyone's public key
 * into their own chain; only a possession proof admits it. Resolving against
 * declarations would let a stranger have clients verify signatures against a key
 * they do not hold, simply by naming it. `verifyIdentityChain` folds exactly the
 * proved set onto `provedKeys`, so nothing here re-walks the raw log.
 *
 * An absent `provedKeys` reads as current effective state: exactly right for any
 * chain with no void memberships, and the only reading available for a cached
 * state that predates the member.
 */
/** The identity as a credit claim must see it: every key ever proved. */
const historicalIdentity = (state: EffectiveIdentity): EverProvedIdentity => ({
  ...state,
  resolution: 'ever-proved',
  ...(state.provedKeys ?? {
    authKeys: state.authKeys,
    assertKeys: state.assertKeys,
    controllerKeys: state.controllerKeys,
  }),
});

const keyBytesFor = (state: EffectiveIdentity, keyId: string): Uint8Array | null => {
  const key = [...state.authKeys, ...state.assertKeys, ...state.controllerKeys].find(
    (k) => k.id === keyId,
  );
  return key ? decodeMultikey(key.publicKeyMultibase).keyBytes : null;
};

// -----------------------------------------------------------------------------
// determinate rejection — the basis itself is invalid, not the lookup
// -----------------------------------------------------------------------------

/**
 * The basis names an instant BEFORE this chain's genesis, so the identity
 * provably had no state then.
 *
 * A `CredentialVerificationError` on purpose: this is a verdict about the
 * artifact being checked, and every classifier downstream — the api-auth phase
 * split, a relay's durable-reject rule — already routes that class as final.
 * Returning `undefined` instead would mark it a dependency miss, and a
 * dependency miss is retried forever against an answer that cannot change.
 */
export class NoStateAsOfError extends CredentialVerificationError {}

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
  state: EffectiveIdentity;
  log: string[];
  provenance: Provenance;
  /** True when cache is the only answer or a full relay log exactly matches it. */
  tipUnverified: boolean;
}

export interface ContentResolution {
  state: VerifiedContentChain;
  /** Every served operation that verified, all branches, in served order. */
  log: string[];
  /** The selected head's lineage, genesis first — the operations `state` folds. */
  headLineage: string[];
  /** Served operations that failed verification, each dropped with its subtree. */
  rejected: ContentDagRejection[];
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
  recheckContentAuthority(contentId: string): Promise<CachedContentSummary | undefined>;
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
      : ((await deps.store.get(key)) as CachedChain<EffectiveIdentity> | undefined);

    // verification IS the candidate filter: full verify from genesis when cold,
    // O(1) verify-forward from the trusted prefix when cached
    const verifyCandidate = async (
      entries: LogOp[],
    ): Promise<VerifiedCandidate<EffectiveIdentity>> => {
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
      try {
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
      } catch (e) {
        // A DURABLE CACHE OUTLIVES THE SHAPE IT WAS WRITTEN IN. A row persisted
        // before `seenKeys` existed carries no id-to-material binding, and the
        // extension verifier refuses such a state outright rather than answering
        // from a reading that cannot reconstruct one. Replaying the log is
        // exactly what it asks the caller to do, and the cache write below
        // persists the replayed state — which carries the binding — so an
        // identity pays this once rather than failing every update forever.
        if (!(e instanceof IdentityStateNoSeenKeysError)) throw e;
        const full = entries.map((entry) => entry.jwsToken);
        const replayed = await verifyIdentityChain({ didPrefix: DID_PREFIX, log: full });
        if (replayed.did !== did) {
          throw new Error(`relay served a mismatched identity: asked ${did}, got ${replayed.did}`);
        }
        const last = opMeta(full[full.length - 1]!);
        return { state: replayed, log: full, headCID: last.cid, lastCreatedAt: last.createdAt };
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
      } satisfies CachedChain<EffectiveIdentity>);
    }
    return {
      state: candidate.state,
      log: candidate.log,
      provenance: fetched.provenance,
      // an unchanged full answer is still a relay CLAIM of freshness, not proof
      tipUnverified: cached !== undefined && candidate.log.length === cached.log.length,
    };
  };

  /**
   * The identity's state AS OF `basis` (PROTOCOL, Time basis). Head state when
   * the chain's last operation is dated at or before the basis, or when there is
   * no basis at all; otherwise the log is re-verified to fold the prefix the
   * basis names. Deletion reads head state either way, because a deleted issuer
   * is invalid retroactively.
   *
   * ONLY THE RE-WALK BRANCH IS DETERMINATE, and the answer carries which one it
   * is — the same rule the relay's own resolver states (dfos-web-relay
   * `resolveIdentityAsOf`). An operation dated AFTER the basis proves this log
   * holds every operation the basis names, because `createdAt` strictly
   * increases; a chain ending at or before it proves nothing of the sort. A key
   * missing from an indeterminate answer is a retryable dependency miss, and
   * from a determinate one a verdict.
   */
  const stateAsOf = async (
    resolution: { state: EffectiveIdentity; log: string[] },
    basis?: string,
  ): Promise<EffectiveIdentity> => {
    const { state, log } = resolution;
    const last = log[log.length - 1];
    if (basis === undefined || last === undefined || opMeta(last).createdAt <= basis) return state;
    const first = log[0];
    // A basis before genesis names an instant this identity had no state at, and
    // no later arrival can change that. Answered HERE rather than read off
    // `verifyIdentityChain`'s message, so the verdict is structural.
    if (first !== undefined && basis < opMeta(first).createdAt) {
      throw new NoStateAsOfError(`identity has no state as of ${basis}`);
    }
    const asOf = await verifyIdentityChain({ didPrefix: DID_PREFIX, log, asOf: basis });
    return { ...asOf, isDeleted: state.isDeleted, basisDeterminate: true };
  };

  // the bound protocol-lib callbacks — the trunk product
  const resolveIdentity = async (
    did: string,
    basis?: string,
  ): Promise<EffectiveIdentity | undefined> => {
    try {
      return await stateAsOf(await getIdentityChain(did), basis);
    } catch (err) {
      // A DETERMINATE REJECTION IS AN ANSWER. `undefined` means "this resolver
      // does not hold the chain", which every protocol consumer reads as a
      // retryable dependency miss — so collapsing a verdict into it makes an
      // unappealable rejection look like a relay that may catch up.
      if (err instanceof NoStateAsOfError) throw err;
      return undefined;
    }
  };

  const resolveKey = async (kid: string, basis?: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);
    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);
    const state = await stateAsOf(await getIdentityChain(did), basis);
    const bytes = keyBytesFor(state, keyId);
    if (!bytes) throw new Error(`unknown key ${keyId} on identity ${did}`);
    return bytes;
  };

  /**
   * The claimant's identity with every key it has ever proved — the credit-claim
   * carve-out. A claim runs no temporal check, so it has no basis and binds a
   * chain rather than a moment (PROTOCOL, Time basis).
   */
  const resolveClaimantIdentity = async (did: string): Promise<EverProvedIdentity | undefined> => {
    try {
      const { state } = await getIdentityChain(did);
      return historicalIdentity(state);
    } catch {
      return undefined;
    }
  };

  const callbacks = (): Callbacks => ({
    resolveKey,
    resolveIdentity,
    resolveClaimantIdentity,
    isRevoked: deps.isRevoked,
  });

  /**
   * THE FOLD'S BOUNDARY: a lookup that failed is not a verdict. The content DAG
   * drops an operation that fails and re-selects the head, so a signer this
   * client could not resolve, or a revocation status it could not obtain, must
   * reach it marked as a dependency miss — otherwise a lookup that may succeed
   * later reads as proof the operation is invalid, and an older head is served
   * as verified. Only a determinate answer stays a verdict: `NoStateAsOfError`,
   * and a key absent from a state the basis pinned (`basisDeterminate`). When in
   * doubt it is a miss.
   */
  const resolveFoldKey = async (kid: string, basis?: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`kid must be a DID URL: ${kid}`);
    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);
    let state: EffectiveIdentity;
    try {
      state = await stateAsOf(await getIdentityChain(did), basis);
    } catch (err) {
      if (err instanceof NoStateAsOfError || isDependencyMissing(err)) throw err;
      const message = err instanceof Error ? err.message : 'unknown error';
      throw markDependencyMissing(
        new Error(`signer identity unresolvable: ${did}: ${message}`, { cause: err }),
      );
    }
    const bytes = keyBytesFor(state, keyId);
    if (bytes) return bytes;
    const unknown = new Error(`unknown key ${keyId} on identity ${did}`);
    throw state.basisDeterminate === true ? unknown : markDependencyMissing(unknown);
  };

  /** A revocation checker that cannot answer has not answered: a miss. */
  const isRevokedForFold: RevChecker = async (issuerDID, credentialCID, asOfUnix) => {
    try {
      return await deps.isRevoked(issuerDID, credentialCID, asOfUnix);
    } catch (err) {
      if (isDependencyMissing(err)) throw err;
      const message = err instanceof Error ? err.message : 'unknown error';
      throw markDependencyMissing(new Error(message, { cause: err }));
    }
  };

  const verifyContentLog = async (
    contentId: string,
    log: string[],
    known?: Record<string, ContentDagNode>,
  ): Promise<VerifiedContentDag> => {
    const dag = await verifyContentDag({
      log,
      resolveKey: resolveFoldKey,
      enforceAuthorization: true,
      resolveIdentity,
      isRevoked: isRevokedForFold,
      ...(known ? { known } : {}),
    });
    // BIND to the requested id: contentId is derived from the genesis op CID
    // inside the verify — reject a relay that serves a different valid chain
    // under this contentId.
    if (dag.head.contentId !== contentId) {
      throw new Error(
        `relay served a mismatched content chain: asked ${contentId}, got ${dag.head.contentId}`,
      );
    }
    return dag;
  };

  /**
   * Re-ask the authority behind every delegated operation this client vouches
   * for — every surviving operation on every branch, since the trusted log
   * exposes them all, not only the head lineage. Signatures and CIDs are
   * immutable and stay verified; a credential's issuer can be deleted, and a
   * revocation dated at or before an operation can arrive after this client
   * cached it. The one implementation both the warm read and
   * `recheckContentAuthority` run.
   */
  const recheckSurvivors = (contentId: string, state: VerifiedContentChain, verified: string[]) =>
    recheckContentAuthorization({
      log: verified,
      creatorDID: state.creatorDID,
      contentId,
      resolveIdentity,
      isRevoked: isRevokedForFold,
    });

  const getContentChain = async (
    contentId: string,
    options?: CallOptions,
  ): Promise<ContentResolution> => {
    const key = cacheKey('content', contentId);
    const cached = options?.fresh
      ? undefined
      : ((await deps.store.get(key)) as CachedContentChain | undefined);

    type ContentCandidate = VerifiedCandidate<VerifiedContentChain> & {
      headLineage: string[];
      nodes: Record<string, ContentDagNode>;
      rejected: ContentDagRejection[];
      /** The cached nodes were set aside and the log verified cold. */
      recomputed: boolean;
    };
    const candidateFrom = (
      dag: VerifiedContentDag,
      log: string[],
      recomputed: boolean,
    ): ContentCandidate => ({
      state: dag.head,
      log: survivors(log, dag),
      headCID: dag.head.headCID,
      lastCreatedAt: dag.headCreatedAt,
      headLineage: dag.headLineage,
      nodes: dag.nodes,
      rejected: dag.rejected,
      recomputed,
    });

    const verifyCandidate = async (entries: LogOp[]): Promise<ContentCandidate> => {
      const log = entries.map((e) => e.jwsToken);
      // one CID, two tokens: refused outright, before any cached node is reused
      const served = new Map<string, string>();
      for (const jws of log) {
        const cid = opMeta(jws).cid;
        const prior = served.get(cid);
        if (prior !== undefined && prior !== jws) {
          throw new Error(`content log serves conflicting operations under CID ${cid}`);
        }
        served.set(cid, jws);
      }
      if (!cached) {
        if (log.length === 0) throw new Error(`content not found: ${contentId}`);
        return candidateFrom(await verifyContentLog(contentId, log), log, false);
      }
      // SET INCLUSION, not a prefix: a content log enumerates every branch, in
      // no order the pin can rely on. Every operation this client verified must
      // still be served, byte for byte. A served set that is a strict subset of
      // the cached one carries no new information (a relay behind, mid-resync)
      // and fails over like a transport miss; one that drops a cached operation
      // while serving operations this client has not seen contradicts it.
      const divergence = (): DivergenceError =>
        new DivergenceError({
          chainType: 'content',
          chainId: contentId,
          cachedHeadCID: cached.headCID,
          liveHeadCID: opMeta(entries[entries.length - 1]?.jwsToken ?? '').cid,
        });
      // what this client has already seen: the pinned set, plus the operations
      // it rejected, which are not pinned but are not news either
      const cachedCIDs = new Set<string>((cached.rejected ?? []).map((r) => r.cid));
      let missing = false;
      for (const jws of cached.log) {
        const cid = opMeta(jws).cid;
        cachedCIDs.add(cid);
        const token = served.get(cid);
        if (token === undefined) missing = true;
        else if (token !== jws) throw divergence();
      }
      if (missing) {
        if ([...served.keys()].every((cid) => cachedCIDs.has(cid))) {
          throw new StaleAnswerError(
            `content log is behind the verified cached prefix: ${contentId}`,
          );
        }
        throw divergence();
      }
      const dag = await verifyContentLog(contentId, log, cached.nodes);
      try {
        await recheckSurvivors(contentId, dag.head, survivors(log, dag));
      } catch (err) {
        if (isDependencyMissing(err)) throw err;
        // AUTHORITY WAS WITHDRAWN from an operation the cache vouched for. Fold
        // the log cold, exactly as a reader without this cache would: the
        // operation drops with its subtree and the head re-selects, so a warm
        // and a cold read of the same log agree.
        return candidateFrom(await verifyContentLog(contentId, log), log, true);
      }
      return candidateFrom(dag, log, false);
    };

    const fetched = await fanOutLog(
      contentPager(deps.peerClient, contentId),
      relaysFor(options),
      deps.quorum,
      verifyCandidate,
      // a content log enumerates branches in no fixed order: relays agree on the set
      digestOpSet,
    );

    if (fetched.outcome === 'unreachable') {
      if (cached) {
        return {
          state: cached.state,
          log: cached.log,
          headLineage: cached.headLineage ?? cached.log,
          rejected: cached.rejected ?? [],
          provenance: { ...fetched.provenance, fromCache: true },
          tipUnverified: true,
        };
      }
      throw new Error(`content not found on any relay: ${contentId}`);
    }

    const candidate = fetched.value!;
    const changed =
      !cached ||
      cached.nodes === undefined ||
      candidate.recomputed ||
      candidate.log.length !== cached.log.length ||
      candidate.rejected.length !== (cached.rejected?.length ?? 0);
    if (fetched.provenance.agreed && changed) {
      await deps.store.set(key, {
        log: candidate.log,
        state: candidate.state,
        headCID: candidate.headCID,
        lastCreatedAt: candidate.lastCreatedAt,
        headLineage: candidate.headLineage,
        nodes: candidate.nodes,
        rejected: candidate.rejected,
      } satisfies CachedContentChain);
    }
    return {
      state: candidate.state,
      log: candidate.log,
      headLineage: candidate.headLineage,
      rejected: candidate.rejected,
      provenance: fetched.provenance,
      // the cache pins a set, so equal length means no operation verified that
      // this client had not already verified
      tipUnverified: cached !== undefined && candidate.log.length === cached.log.length,
    };
  };

  /**
   * Re-ask credential authority on a cached content chain's surviving ops
   * without draining its log. Answers what the cached chain holds when its
   * authority holds, `undefined` when nothing is cached; a throw is the
   * authority failing (or, when marked as a dependency miss, failing to be
   * checked).
   */
  const recheckContentAuthority = async (
    contentId: string,
  ): Promise<CachedContentSummary | undefined> => {
    const cached = (await deps.store.get(cacheKey('content', contentId))) as
      CachedContentChain | undefined;
    if (!cached) return undefined;
    await recheckSurvivors(contentId, cached.state, cached.log);
    return { opCount: cached.log.length, rejected: cached.rejected ?? [] };
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

  return {
    getIdentityChain,
    getContentChain,
    recheckContentAuthority,
    discardCachedChain,
    callbacks,
  };
};

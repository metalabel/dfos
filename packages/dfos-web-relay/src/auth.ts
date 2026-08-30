/*

  AUTH

  Identity-proof authentication (AuthN) and DFOS credential verification
  (AuthZ) for relay requests.

  THE RELAY OWNS NO AUTHENTICATION GRAMMAR. Every authenticated request consumes
  the API-AUTH envelope family — `Authorization: DFOS <did:dfos:identity-proof
  JWS>` — verified by the reference helpers in
  `@metalabel/dfos-protocol/credentials`. The DID-signed JWT auth token this
  module used to carry is GONE: a bearer JWT with a self-chosen lifetime was a
  replayable credential for any request to any route, where an identity proof
  binds ONE method, host, path, and body inside a window the RELAY owns.

  See specs/WEB-RELAY.md "Authentication" and specs/API-AUTH.md
  "The Identity Proof".

*/

import {
  ApiRequestVerifyError,
  invalidProof,
  matchesResource,
  parseDfosAuthorization,
  verifyDelegationChain,
  verifyDFOSCredential,
  verifyIdentityProofEnvelope,
  type ProofPresenterState,
  type ResolveProofPresenter,
  type VerifiedDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import { isValidDfosDid } from './did-document';
import { createHistoricalIdentityResolver } from './ingest';
import type { RelayStore } from './types';

/**
 * Acceptance window `W` — how old an identity proof may be, in seconds.
 * "The freshness window is the relay's to own" (WEB-RELAY.md, Authentication).
 */
export const DEFAULT_PROOF_WINDOW_SECONDS = 60;

/** Clock-skew allowance `S` — how forward-dated a proof may be, in seconds. */
export const DEFAULT_PROOF_SKEW_SECONDS = 60;

/**
 * Cap on the `jti` member, in UTF-8 bytes.
 *
 * A replay cache keyed on a caller-chosen string is a caller-controlled memory
 * allocation, so the key needs a bound. 256 bytes is generous for any UUID,
 * ULID, or random token and is enforced IDENTICALLY by the Go twin — a jti one
 * relay accepts and the other refuses would fork the admission decision.
 */
export const MAX_JTI_BYTES = 256;

const JTI_ENCODER = new TextEncoder();

// -----------------------------------------------------------------------------
// current-state key resolution
// -----------------------------------------------------------------------------

/**
 * Resolve a presenter to its CURRENT identity state, from THIS relay's local
 * store.
 *
 * CURRENT-STATE ONLY, deliberately (WEB-RELAY.md, Key Resolution): after a key
 * rotation the old key immediately stops authenticating, which is how a
 * presenter whose key is compromised revokes that key's ability to speak in its
 * name. A deleted identity has no live-authentication standing at all — the
 * envelope verifier turns `isDeleted` into a 401.
 *
 * A store read that FAILS is not an answer of "unknown identity": it throws, and
 * the envelope verifier reports it as unverifiable (503), never as a judgment
 * about the caller.
 */
export const createCurrentStateProofResolver =
  (store: RelayStore): ResolveProofPresenter =>
  async (did: string): Promise<ProofPresenterState | null> => {
    // A `kid` whose DID is not a canonical did:dfos is INVALID (401), not
    // unverifiable — and it is refused BEFORE the store read, so a flood of
    // garbage kids costs a regex rather than a lookup per request.
    if (!isValidDfosDid(did)) {
      throw invalidProof('identity proof kid does not name a canonical did:dfos');
    }
    const identity = await store.getIdentityChain(did);
    if (!identity) return null;
    return {
      isDeleted: identity.state.isDeleted,
      // Any CURRENT key role may sign a proof (API-AUTH.md, "Key resolution is
      // current-state") — auth, assert, or controller. CURRENT means EFFECTIVE:
      // these arrays carry only memberships a possession proof admitted, so a
      // key the chain declared and nothing proved cannot authenticate. Neither
      // `provedKeys` (has-ever — it would resurrect a rotated-out key) nor
      // `declared` (it would admit a void one) belongs on this path.
      keys: [
        ...identity.state.authKeys,
        ...identity.state.assertKeys,
        ...identity.state.controllerKeys,
      ],
    };
  };

// -----------------------------------------------------------------------------
// jti replay cache
// -----------------------------------------------------------------------------

/**
 * The `jti` replay cache — REQUIRED on every write-shaped proof (WEB-RELAY.md,
 * Authentication).
 *
 * WHY A WRITE-SHAPED SURFACE CANNOT BORROW ITS REPLAY POSTURE FROM DOWNSTREAM
 * IDEMPOTENCY: the admission ladder runs POLICY before full verification, so the
 * relay grants admission-layer effects (quota spend, reputation attribution)
 * before it knows whether the payload is a harmless duplicate. Ingestion being
 * idempotent does not make a replayed submission free.
 *
 * The primitive is ATOMIC INSERT-IF-ABSENT (accept iff newly inserted), not the
 * check-and-delete a server-minted nonce would use — the verifier never held the
 * client-chosen jti beforehand. Entries expire after the freshness window
 * (W + S): past that the proof itself is stale, so the cache entry protects
 * nothing.
 *
 * This in-memory implementation is per-process. The interface is what a
 * store-backed implementation replaces, so a multi-process deployment swaps the
 * store without touching a route.
 */
export interface JtiReplayCache {
  /**
   * Record (presenter, jti) if absent. Returns true when newly inserted (the
   * proof is fresh), false when the pair was already seen (a replay).
   */
  insertIfAbsent(presenterDID: string, jti: string, nowMs: number, ttlSeconds: number): boolean;
}

export const createJtiReplayCache = (): JtiReplayCache => {
  // key -> expiry (unix ms). A Map is insertion-ordered, so the prune below can
  // stop at the first live entry: everything before it expired earlier.
  const seen = new Map<string, number>();

  return {
    insertIfAbsent(presenterDID, jti, nowMs, ttlSeconds) {
      // Prune before the lookup, so an expired entry never reports a replay.
      for (const [key, expiresAt] of seen) {
        if (expiresAt > nowMs) break;
        seen.delete(key);
      }
      // Newline-joined: a DID cannot contain one, so no (did, jti) pair can be
      // spelled two ways or collide with another pair's concatenation.
      const key = `${presenterDID}\n${jti}`;
      const existing = seen.get(key);
      if (existing !== undefined && existing > nowMs) return false;
      seen.set(key, nowMs + ttlSeconds * 1000);
      return true;
    },
  };
};

// -----------------------------------------------------------------------------
// identity-proof authentication
// -----------------------------------------------------------------------------

/** A verified identity proof, as the routes consume it. */
export interface AuthenticatedPrincipal {
  /** THE PRINCIPAL — the proof's `kid` DID. Who the request is from. */
  did: string;
  /** The full `kid` DID URL, key fragment included. */
  kid: string;
  /** The proof's issued-at, unix seconds. */
  iat: number;
}

export type IdentityProofOutcome =
  | { ok: true; principal: AuthenticatedPrincipal }
  /** No `Authorization` header at all — anonymous, which some routes permit. */
  | { ok: true; principal: null }
  | { ok: false; status: number; error: string };

export interface AuthenticateIdentityProofOptions {
  /** The raw `Authorization` header, if any. */
  authHeader: string | undefined;
  /** The received request method. */
  method: string;
  /**
   * The received ORIGIN-FORM request target — path plus query string, byte for
   * byte. Never a route template and never a normalization.
   */
  path: string;
  /** The received body octets. */
  body: Uint8Array;
  /**
   * THE RELAY'S OWN CONFIGURED AUTHORITY — `undefined` when the operator did not
   * configure one, which makes every authenticated route answer 503. The host
   * binding is NEVER read from a request header (WEB-RELAY.md, Authentication):
   * a relay that fell back to `Host` would have no host binding at all.
   */
  authority: string | undefined;
  store: RelayStore;
  /**
   * Whether this surface is WRITE-SHAPED and therefore REQUIRES `jti`. Ingestion
   * and blob upload are; blob reads and the mailbox poll are not (they rely on
   * the freshness window alone, per API-AUTH's accepted bound).
   */
  requireJti: boolean;
  /** The replay cache. Required whenever `requireJti` is true. */
  replayCache?: JtiReplayCache;
  windowSeconds?: number;
  skewSeconds?: number;
  /**
   * THE VERIFIER'S HASH CAP IS THIS DEPLOYMENT'S TRANSPORT CAP, ALWAYS.
   *
   * Bounds the body the envelope verifier is willing to SHA-256; over-cap is an
   * INVALID-proof verdict, which every caller renders as a bare
   * `401 authentication required`. Left unset it takes the library default
   * (1 MiB) — so a route that buffers more than that MUST pass its own read cap
   * here, or every authenticated write between the two numbers dies at a 401
   * that says nothing about size. The body is already bounded before it arrives
   * (each route caps its own read), so this is a belt-and-braces bound on an
   * in-hand buffer, never the thing that lets an unbounded body through.
   */
  maxBodyBytes?: number;
  now?: () => number;
}

/**
 * Authenticate one request against the API-AUTH identity proof.
 *
 * Returns `{ ok: true, principal: null }` when NO `Authorization` header is
 * present — anonymity is a valid admission mode on ingestion, and the caller
 * decides whether its route permits it. A header that is present but not this
 * family (a stale `Bearer` JWT, say) is a 401: the relay owns no other
 * authentication grammar, and silently treating it as anonymous would hide a
 * client that thinks it is authenticated from a relay that disagrees.
 */
export const authenticateIdentityProof = async (
  options: AuthenticateIdentityProofOptions,
): Promise<IdentityProofOutcome> => {
  if (options.authHeader === undefined || options.authHeader.trim() === '') {
    return { ok: true, principal: null };
  }
  const token = parseDfosAuthorization(options.authHeader);
  if (!token) {
    return { ok: false, status: 401, error: 'authentication required' };
  }
  if (!options.authority) {
    // A 503, never a 401 or a fallback: the host binding is the deployment's to
    // supply, and a relay that cannot supply it cannot authenticate ANYTHING.
    // Answering 401 would blame the caller for the operator's omission, and
    // reading the authority off the request would remove the binding entirely.
    return {
      ok: false,
      status: 503,
      error: 'relay authority is not configured; authenticated routes are unavailable',
    };
  }

  const windowSeconds = options.windowSeconds ?? DEFAULT_PROOF_WINDOW_SECONDS;
  const skewSeconds = options.skewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;

  let verified;
  try {
    verified = await verifyIdentityProofEnvelope(
      {
        proof: token,
        host: options.authority,
        method: options.method,
        path: options.path,
        body: options.body,
        windowSeconds,
        skewSeconds,
        ...(options.maxBodyBytes !== undefined ? { maxBodyBytes: options.maxBodyBytes } : {}),
        ...(options.now ? { now: options.now } : {}),
      },
      createCurrentStateProofResolver(options.store),
    );
  } catch (err) {
    if (err instanceof ApiRequestVerifyError) {
      // invalid -> 401, unverifiable -> 503, config -> 503 (the operator's
      // condition, reported as a server condition rather than leaking a 500 body
      // shaped differently from every other relay error).
      const status = err.reason === 'invalid' ? err.status : 503;
      return {
        ok: false,
        status,
        error: err.reason === 'invalid' ? 'authentication required' : 'authentication unavailable',
      };
    }
    return { ok: false, status: 503, error: 'authentication unavailable' };
  }

  if (options.requireJti) {
    // jti is an UNKNOWN member to the envelope verifier (MUST-ignore-unknown),
    // read here, AFTER verification, off the decoded payload the signature
    // already covers. The canonical member set stays closed.
    const jti = verified.rawPayload['jti'];
    if (typeof jti !== 'string' || jti === '') {
      return { ok: false, status: 401, error: 'authentication required' };
    }
    if (JTI_ENCODER.encode(jti).length > MAX_JTI_BYTES) {
      return { ok: false, status: 401, error: 'authentication required' };
    }
    const cache = options.replayCache;
    if (!cache) {
      return { ok: false, status: 503, error: 'authentication unavailable' };
    }
    const nowMs = options.now ? options.now() : Date.now();
    if (!cache.insertIfAbsent(verified.presenterDID, jti, nowMs, windowSeconds + skewSeconds)) {
      return { ok: false, status: 401, error: 'authentication required' };
    }
  }

  return {
    ok: true,
    principal: { did: verified.presenterDID, kid: verified.kid, iat: verified.payload.iat },
  };
};

// -----------------------------------------------------------------------------
// content access verification
// -----------------------------------------------------------------------------

export interface AccessVerification {
  granted: boolean;
  source: 'public-credential' | 'request-credential' | 'creator' | 'none';
  credential?: VerifiedDFOSCredential;
}

/**
 * Check if a valid public standing credential exists for the given content.
 *
 * This is used at the route level to allow unauthenticated reads when public
 * credentials exist — matching the Go relay's `hasPublicStandingAuth`.
 */
export const hasPublicStandingAuth = async (
  contentId: string,
  action: 'read' | 'write',
  store: RelayStore,
): Promise<boolean> => {
  const resource = `chain:${contentId}`;
  const publicCreds = await store.getPublicCredentials(resource);
  if (publicCreds.length === 0) return false;

  const chain = await store.getContentChain(contentId);
  if (!chain) return false;

  const resolveIdentity = createHistoricalIdentityResolver(store);
  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  for (const credJws of publicCreds) {
    try {
      const cred = await verifyDFOSCredential(credJws, { resolveIdentity });

      // check revocation
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) continue;

      // check resource + action match
      const covers = await matchesResource(cred.att, resource, action);
      if (!covers) continue;

      // verify delegation chain roots at creator
      await verifyDelegationChain(cred, {
        resolveIdentity,
        rootDID: chain.state.creatorDID,
        isRevoked,
      });

      return true;
    } catch {
      continue;
    }
  }

  return false;
};

/**
 * Verify content access for a specific resource
 *
 * Checks in order:
 * 1. Is the requester the content creator? → granted
 * 2. Does a stored public credential cover this resource? → granted
 * 3. Does the per-request credential (Authorization header) cover this resource? → granted
 * 4. None → denied
 */
export const verifyContentAccess = async (options: {
  /** Per-request credential JWS (from X-Credential header) */
  credentialJWS?: string;
  /** The resource being accessed, e.g., "chain:<contentId>" */
  requestedResource: string;
  /** The action being requested */
  action: 'read' | 'write';
  store: RelayStore;
  /** The DID of the content chain creator (root authority) */
  creatorDID: string;
  /** The identity-proven DID making the request (the proof's `kid` DID) */
  requesterDID?: string;
  /**
   * Whether public (aud '*') grants count for this request. A standing public
   * grant asserts the publicness of a chain's CURRENT head only, so a request
   * for a non-head document sets this false: access then requires the creator
   * or a credential scoped to the requester's audience — never a public grant
   * (stored or presented). Defaults true (head reads and every other caller).
   */
  allowPublicGrant?: boolean;
}): Promise<AccessVerification> => {
  const { credentialJWS, requestedResource, action, store, creatorDID, requesterDID } = options;
  const allowPublicGrant = options.allowPublicGrant ?? true;

  // 1. creator always has access
  if (requesterDID && requesterDID === creatorDID) {
    return { granted: true, source: 'creator' };
  }

  // shared helpers for credential verification
  const resolveIdentity = createHistoricalIdentityResolver(store);

  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  // 2. check stored public credentials — these are standing public (aud '*')
  // grants, which convey head-only publicness, so they are skipped for a
  // non-head request (allowPublicGrant === false).
  if (allowPublicGrant) {
    const publicCreds = await store.getPublicCredentials(requestedResource);
    for (const credJws of publicCreds) {
      try {
        const cred = await verifyDFOSCredential(credJws, { resolveIdentity });

        // check revocation (scoped to credential issuer)
        const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
        if (leafRevoked) continue;

        // check resource + action match
        const covers = await matchesResource(cred.att, requestedResource, action);
        if (!covers) continue;

        // verify delegation chain roots at creator (with revocation at every level)
        await verifyDelegationChain(cred, { resolveIdentity, rootDID: creatorDID, isRevoked });

        return { granted: true, source: 'public-credential' as const, credential: cred };
      } catch {
        continue; // invalid credential, skip
      }
    }
  }

  // 3. check per-request credential
  if (credentialJWS) {
    try {
      const cred = await verifyDFOSCredential(credentialJWS, { resolveIdentity });

      // check revocation (scoped to credential issuer)
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) {
        return { granted: false, source: 'none' };
      }

      // verify delegation chain roots at creator (with revocation at every level)
      await verifyDelegationChain(cred, { resolveIdentity, rootDID: creatorDID, isRevoked });

      // audience verification. A public (aud '*') credential presented per
      // request acts as a bearer capability — accepted only where public grants
      // count (head reads); for a non-head request it conveys nothing, exactly
      // as the stored standing grant above. A scoped credential must name the
      // requester as its audience.
      if (cred.aud === '*') {
        if (!allowPublicGrant) {
          return { granted: false, source: 'none' };
        }
      } else {
        if (!requesterDID || cred.aud !== requesterDID) {
          return { granted: false, source: 'none' };
        }
      }

      // check resource + action match
      const covers = await matchesResource(cred.att, requestedResource, action);
      if (!covers) {
        return { granted: false, source: 'none' };
      }

      return { granted: true, source: 'request-credential' as const, credential: cred };
    } catch {
      return { granted: false, source: 'none' };
    }
  }

  return { granted: false, source: 'none' };
};

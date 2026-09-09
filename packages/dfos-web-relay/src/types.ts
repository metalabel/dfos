/*

  TYPES

  Core types for the DFOS web relay

*/

import type {
  DeclaredKeyState,
  VerifiedContentChain,
  VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';
import type { Attenuation } from '@metalabel/dfos-protocol/credentials';
import { base64urlDecode, base64urlEncode } from '@metalabel/dfos-protocol/crypto';
import type { JtiReplayCache } from './auth';
import type {
  IndexArtifactRow,
  IndexContentRow,
  IndexCountersignatureQueryRow,
  IndexCredentialQueryRow,
  IndexCreditCursor,
  IndexCreditRow,
  IndexIdentityRow,
  IndexOperationRow,
  IndexOrder,
  IndexOrderedCursor,
  IndexRecencyOrder,
} from './index-routes';

/**
 * Namespaces every frozen proof-plane route under one prefix so the two version
 * clocks (proof v1 / document 0.x) are legible in the URL and each plane
 * mounts/proxies by prefix. Frozen with protocol v1; MUST stay in byte-sync
 * with the Go relay (proofBasePath in routes.go) and the clients. Document gateway
 * routes (/content/{id}/blob*) and .well-known stay at root on their own clock.
 */
export const PROOF_BASE_PATH = '/proof/v1';

// -----------------------------------------------------------------------------
// key state
// -----------------------------------------------------------------------------

/**
 * THE HAS-EVER-PROVED KEY STATE of a verified identity — the ONE reading of
 * `provedKeys` shared by every relay surface that asks "was this key ever true?"
 *
 * Three key states now travel on a VerifiedIdentity and each answers a different
 * question, so the relay picks deliberately rather than by habit:
 *
 *  - The ordinary `authKeys`/`assertKeys`/`controllerKeys` arrays are EFFECTIVE
 *    state — what is true NOW. Live authentication, first admission, and the DID
 *    document's verification methods read these and nothing else.
 *  - `provedKeys` is HAS-EVER-PROVED — what was EVER true. Historical key
 *    resolution (long-lived artifacts across a rotation) and the `key=` reverse
 *    index read this.
 *  - `declared` is what the chain SAYS, void memberships included. Exactly one
 *    surface wants it — signer admission — and that surface lives in the
 *    protocol library's chain walk, never here.
 *
 * `provedKeys` is optional on VerifiedIdentity because a caller may hand the
 * extension verifier a hand-built state. An absent member reads as "what is
 * effective now is what was proved", which is exactly correct for any chain with
 * no void memberships and is the only reading available for a state that never
 * recorded the difference — the same fallback the protocol library takes.
 */
export const provedKeyState = (state: VerifiedIdentity): DeclaredKeyState =>
  state.provedKeys ?? {
    authKeys: state.authKeys,
    assertKeys: state.assertKeys,
    controllerKeys: state.controllerKeys,
  };

// -----------------------------------------------------------------------------
// relay options
// -----------------------------------------------------------------------------

export interface RelayIdentity {
  /** The relay's DID */
  did: string;
  /** Profile artifact JWS token (signed by the relay DID) */
  profileArtifactJws: string;
  /**
   * The relay's own signing key id, and a signer over raw bytes.
   *
   * OPTIONAL, and the only thing they enable is the relay signing an IDENTITY
   * PROOF of its own — gossip-out announces itself as a named peer rather than
   * anonymously (RELAY.md, Relay identity and profile: "a gossiping peer authenticates
   * like any client: anonymously, or with an identity proof signed by its own
   * DID"). A relay constructed from a DID and a profile alone still runs; it
   * simply gossips anonymously.
   */
  keyId?: string;
  sign?: (message: Uint8Array) => Promise<Uint8Array>;
}

/**
 * The advertised ingestion admission mode (RELAY.md, Admission).
 *
 * - `open` — anonymous submissions admitted, subject to policy.
 * - `proof-required` — anonymous refused at the policy step (403).
 * - `closed` — no external ingestion; `POST /proof/v1/operations` answers 501,
 *   exactly as under `capabilities.write: false`.
 *
 * Advertisement is a HINT; the policy decision is the authority.
 */
export type IngestionMode = 'open' | 'proof-required' | 'closed';

/**
 * The admitted spellings, as a runtime value.
 *
 * The union above guards COMPILED callers only. A JS consumer — or a mode read
 * out of a config file — can hand `createRelay` a misspelling, and the routes
 * special-case only `closed` and `proof-required`, so a typo would serve OPEN
 * while advertising garbage in the well-known. `createRelay` checks against this
 * set and refuses, exactly as the Go twin's NewRelay does.
 */
export const INGESTION_MODES: readonly IngestionMode[] = ['open', 'proof-required', 'closed'];

/**
 * The relay-local admission policy — step 3 of the ingestion ladder.
 *
 * Called with the identity-proven principal DID, or `null` for an anonymous
 * submission. Returning false is a request-level refusal (403): nothing in the
 * batch is examined further and no per-item results are produced. THROWING is a
 * policy that could not be evaluated, which FAILS CLOSED (503 — the server's
 * condition, not a judgment on the caller).
 *
 * Policy CONTENT is operator-defined and out of the spec: one relay admits only
 * DIDs its operator recognizes, another is open-anonymous under quotas, another
 * is allowlist-only. "My peers" is one possible policy set, not a separate
 * authentication scheme.
 */
export type AdmissionPolicy = (principal: string | null) => boolean | Promise<boolean>;

/**
 * How this deployment answers the well-known's optional `openapi` field
 * (RELAY.md, The well-known document). Serving a document is SHOULD, never MUST;
 * an unset option means the relay serves none and omits the field.
 *
 * - `{ url }` — ADVERTISE ONLY. The document lives somewhere else (a docs site,
 *   a CDN); the relay registers no route and advertises the URL verbatim,
 *   absolute or root-relative.
 * - `{ document, route? }` — SERVE AND ADVERTISE. The relay registers an ungated
 *   `GET` at `route` (default `/openapi.json`) returning the given document as
 *   JSON, and advertises that path. `@metalabel/dfos-web-relay/openapi.json` is
 *   the canonical document for this package's own route table:
 *
 *   ```ts
 *   import document from '@metalabel/dfos-web-relay/openapi.json';
 *   const relay = await createRelay({ store, openapi: { document } });
 *   ```
 *
 *   A CONFIGURED `route` IS VALIDATED AT CONSTRUCTION. It must be a literal
 *   absolute path that does not fall under a surface the relay itself serves —
 *   the document route is registered before every plane, and Hono answers
 *   first-match, so `route: '/proof/v1/log'` would serve the document where the
 *   operation log belongs. `createRelay` throws and names the collision rather
 *   than mounting a relay that 200s a conformance probe with a document.
 *
 *   THE SERVED COPY DESCRIBES THIS RELAY. The canonical document names no
 *   `servers` — it describes the surface every relay serves, not the address of
 *   one — and the served copy's is written from `authority`, so a client reading
 *   it resolves operations against this deployment. With no `authority`
 *   configured the member stays absent, and OpenAPI resolves against the URL the
 *   document was fetched from, which is this relay either way. Under a custom
 *   `route` the document's own path entry is relocated to that route as well, so
 *   the served copy does not describe itself at a path that 404s. The caller's
 *   document object is never mutated. See `./openapi.ts`.
 *
 * The document is DISCOVERY, NEVER AUTHORITY — the routes, capability gates, and
 * auth rules the spec fixes govern regardless of what an advertised document
 * says, so nothing here is consulted when serving a request.
 *
 * THE QUIET DEFAULT IS DELIBERATE, AND THE TWO REFERENCE TWINS DIFFER HERE. This
 * package is a library embedded in someone else's app, so it mounts no route and
 * omits the field until its caller opts in; the Go twin is what `dfos serve`
 * runs as a deployed relay, and serves + advertises its embedded copy
 * unconditionally. Both defaults are conformant under the spec's SHOULD — do not
 * "fix" the asymmetry by unifying them (dfos-web-relay-go/openapi.go carries the
 * same note from the other end, and relay-conformance's parity server opts this
 * twin in as a consequence of the choice, not as a workaround).
 */
export type RelayOpenApiOption =
  | { url: string; document?: never; route?: never }
  | { document: unknown; route?: string; url?: never };

export interface RelayOptions {
  /** Storage backend */
  store: RelayStore;
  /** Pre-created relay identity — if omitted, a JIT identity and profile are generated */
  identity?: RelayIdentity;
  /** Whether content plane routes are enabled (default: true) */
  content?: boolean;
  /**
   * Whether the global operation log is enabled (default: true). With `false`,
   * `GET /proof/v1/log` answers 501 and no commit carries a log entry — which
   * also turns off an index this relay would maintain, since the projection
   * reads the log and nothing else.
   */
  log?: boolean;
  /** Whether the revocation status route family is enabled (default: true) */
  revocations?: boolean;
  /**
   * Whether the index query family is enabled (default: true, when the store
   * implements `IndexReadStore` and the projection has a feed). An explicit
   * `true` the deployment cannot back — a store without the queries, or
   * `log: false` over a store this relay would maintain the index for — is a
   * configuration error and throws at construction.
   */
  index?: boolean;
  /**
   * Who advances the `/index/v0` projection off the operation log.
   *
   * - `inline` (default) — the relay drains the log projection after each
   *   accepted ingest batch. Each pass is budget-bounded and resumable from the
   *   persisted cursor; nothing about it runs inside a commit.
   * - `external` — the relay never drains the log itself. The operator calls
   *   `projectIndex` on the created relay from a timer or a worker.
   *
   * ONE PASS IS NOT A CHOICE IN EITHER MODE: after a document blob lands, the
   * relay recomputes the content rows that project it. Nothing on the operation
   * log marks a blob arrival, so no amount of external draining reaches it. That
   * pass is bounded by a reverse lookup on the documentCID.
   *
   * Inert when the store does not implement `IndexWriteStore`: such a store
   * serves index queries from rows something else maintains.
   */
  indexProjection?: 'inline' | 'external';
  /**
   * Whether this relay accepts writes (default: true). When false, it is a LITE
   * pull-only proof node: POST /proof/v1/operations is rejected (501), so neither
   * client writes nor peer gossip-in are accepted. The node still ingests by
   * PULLING from peers (syncFromPeers polls their /log).
   */
  write?: boolean;
  /** Whether the ephemeral signing mailbox is enabled (default: false) */
  signing?: boolean;
  /** Peer relay configurations */
  peers?: PeerConfig[];
  /** Injected peer client — if omitted, a default HTTP implementation is used */
  peerClient?: PeerClient;
  /**
   * THE RELAY'S OWN CONFIGURED AUTHORITY — the `host` an identity proof must
   * bind to (`relay.example.com`, or `host:port` on a non-default port).
   *
   * IT IS NEVER READ FROM A REQUEST. `Host`, `X-Forwarded-Host`, and the request
   * URL's authority are all attacker-supplied; a relay that compared a proof's
   * `host` against a request header would have no host binding at all.
   *
   * MULTI-AUTHORITY DEPLOYMENTS. A relay serving several hostnames "selects the
   * expected one from its own configuration" (RELAY.md, Authentication).
   * This option is that selection, made at construction: front the origins with
   * one relay instance per authority, or have the front door route each
   * authority to the instance configured for it. There is deliberately no
   * accept-any-of-these list — accepting a proof bound to authority A on a
   * request served as authority B is exactly the cross-origin replay the binding
   * exists to stop.
   *
   * WHEN UNSET, every authenticated route answers 503: the relay cannot
   * authenticate anything, and says so rather than blaming the caller (401) or
   * inventing a binding from the request.
   */
  authority?: string;
  /**
   * Acceptance window `W` for identity proofs, seconds (default 60). The
   * freshness window is the relay's to own; `W + S` MUST NOT exceed 300.
   */
  proofWindowSeconds?: number;
  /** Clock-skew allowance `S` for identity proofs, seconds (default 60). */
  proofSkewSeconds?: number;
  /**
   * The advertised ingestion admission mode. Explicit wins; when absent it
   * derives from `write` — `true` reads as `"open"`, `false` as `"closed"`.
   * `"closed"` makes `POST /proof/v1/operations` answer 501.
   */
  ingestion?: IngestionMode;
  /**
   * The relay-local admission policy evaluated at step 3 of the ingestion
   * ladder. Default: admit everything (today's behavior).
   */
  admissionPolicy?: AdmissionPolicy;
  /**
   * The `jti` replay cache backing write-shaped identity proofs.
   *
   * DEFAULT: the in-memory `createJtiReplayCache()`, which is PER-PROCESS — it
   * refuses a replay only against the process that saw the original. A
   * multi-process deployment (several workers behind one authority, or a
   * serverless runtime with no process to hold state) injects an implementation
   * whose `insertIfAbsent` is atomic across the fleet — a shared store's
   * insert-if-absent, `SET NX PX`, a conditional put — so the replay window is
   * the deployment's, not one worker's.
   */
  replayCache?: JtiReplayCache;
  /**
   * Whether gossip-out attaches an identity proof signed by the relay's OWN DID
   * (RELAY.md, Relay identity and profile: "a gossiping peer authenticates like any
   * client: anonymously, or with an identity proof signed by its own DID").
   *
   * DEFAULT OFF, deliberately — and this is the one place the obvious default is
   * the wrong one. Signing looks free because a default-open peer admits
   * anonymous submissions anyway, so a proof "can only help". It cannot: a
   * presented proof is no longer optional to the receiver. A peer that has never
   * ingested this relay's identity chain answers **503** (unresolvable
   * presenter), and a peer with no configured authority answers 503 as well — so
   * turning this on unilaterally converts pushes that were being ACCEPTED into
   * pushes that are refused, against exactly the peers least likely to know us.
   * Anonymous is the interoperable default; a named peer is a deliberate pairing
   * between operators who have already made each other resolvable.
   *
   * Requires a signing key (`identity.sign`), which the JIT bootstrap produces;
   * without one the flag is inert and gossip stays anonymous.
   *
   * Sync-in and read-through are READS and stay public — nothing to sign.
   */
  gossipIdentityProof?: boolean;
  /**
   * OpenAPI document advertisement (and optional serving). See
   * `RelayOpenApiOption`. Absent: no route is registered and the well-known
   * omits the `openapi` field.
   */
  openapi?: RelayOpenApiOption;
}

// -----------------------------------------------------------------------------
// peering
// -----------------------------------------------------------------------------

export interface PeerConfig {
  url: string;
  /** Push new ops to this peer (default: true) */
  gossip?: boolean;
  /** Fetch from this peer on local 404 (default: true) */
  readThrough?: boolean;
  /** Poll this peer's /log for background sync (default: true) */
  sync?: boolean;
}

/** A log entry returned by a peer — CID and JWS token */
export interface PeerLogEntry {
  cid: string;
  jwsToken: string;
  /**
   * Relay-asserted operation kind. Global /log entries carry it; chain logs
   * omit it. A ROUTING HINT for indexers/browsers, never a verification
   * input — folds re-derive everything from the JWS itself.
   */
  kind?: string;
  /**
   * Relay-asserted chain identifier — DID for identity/artifact ops, contentId
   * for content ops, targetCID for countersigns, issuer DID for credentials.
   * Same hint-only status as `kind`.
   */
  chainId?: string;
}

/**
 * Sign an identity proof over the exact request a gossip push is about to make.
 * Returns the compact JWS, or null when the relay holds no signing key.
 */
export type GossipProofSigner = (request: {
  method: string;
  host: string;
  path: string;
  body: Uint8Array;
}) => Promise<string | null>;

/** Injected peer transport — the relay expresses intent, the caller decides transport */
export interface PeerClient {
  /** Fetch identity chain log from a peer */
  getIdentityLog(
    peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /** Fetch content chain log from a peer */
  getContentLog(
    peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /**
   * Fetch global operation log from a peer. Returns the page, `null` on any
   * transport/peer failure, or `'invalid-cursor'` when the peer explicitly
   * rejected the `after` cursor (400) — cursors are relay-local, so a peer that
   * wiped or rebuilt its log invalidates ours; the sync loop resets and
   * re-syncs from the start (ingestion is idempotent).
   */
  getOperationLog(
    peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /**
   * Push operations to a peer (fire-and-forget).
   *
   * `signProof`, when supplied, mints the identity proof this push rides with.
   * It is a CALLBACK rather than a header because the proof binds `bodyHash`:
   * only the transport knows the exact octets it is about to send, so only the
   * transport can ask for a proof over them. A client that ignores it gossips
   * anonymously, which is what every mock in the test suite does.
   */
  submitOperations(
    peerUrl: string,
    operations: string[],
    options?: { signProof?: GossipProofSigner },
  ): Promise<void>;
}

// -----------------------------------------------------------------------------
// stored artifacts
// -----------------------------------------------------------------------------

export interface StoredIdentityChain {
  did: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
  /** CID of the most recent operation */
  headCID: string;
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  state: VerifiedIdentity;
}

export interface StoredContentChain {
  contentId: string;
  genesisCID: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  state: VerifiedContentChain;
}

export interface StoredOperation {
  cid: string;
  jwsToken: string;
  /** Which chain type this operation belongs to */
  chainType: 'identity' | 'content' | 'artifact' | 'countersign' | 'revocation' | 'credential';
  /** The chain identifier — DID for identity/artifact, contentId for content, targetCID for countersign */
  chainId: string;
}

/** Key for blob storage — deduplicates across chains sharing the same document */
export interface BlobKey {
  creatorDID: string;
  documentCID: string;
}

// -----------------------------------------------------------------------------
// operation log
// -----------------------------------------------------------------------------

/**
 * A single entry in the global append-only operation log.
 *
 * `ingestedAt` is THE receipt stamp for the operation, read from the wall clock
 * exactly once, at commit. The log is the relay's record of what it accepted and
 * in what order, so it is the honest place for that clock read — and because the
 * index projection walks this log, every index surface (operations, artifacts,
 * countersignatures, credentials) sources one receipt time for one operation
 * rather than reading the clock again per surface. It is store state, not wire
 * state: `GET /proof/v1/log` serves `{cid, jwsToken, kind, chainId}` and nothing
 * more.
 */
export interface LogEntry {
  cid: string;
  jwsToken: string;
  kind: OperationKind;
  chainId: string;
  ingestedAt: string;
}

/** A peer this relay is configured to talk to, surfaced in the well-known for mesh discovery. */
export interface RelayPeerInfo {
  /** The peer relay's base URL. */
  endpoint: string;
}

/** Optional operational statistics a store MAY compute for the well-known response. */
export interface RelayStats {
  /** Total operations in the global log. */
  opCount: number;
  /** Operation counts bucketed by primitive kind (all six keys always present). */
  countsByKind: {
    identity: number;
    content: number;
    artifact: number;
    credential: number;
    countersign: number;
    revocation: number;
  };
  /** createdAt of the oldest operation in the log (log position), or null when empty. */
  oldestOpAt: string | null;
  /** CID of the newest operation in the log (the tip), or null when empty. */
  headCid: string | null;
}

/** All operation kinds in the protocol */
export type OperationKind =
  'identity-op' | 'content-op' | 'artifact' | 'countersign' | 'revocation' | 'credential';

// -----------------------------------------------------------------------------
// revocations + public credentials
// -----------------------------------------------------------------------------

export interface StoredRevocation {
  cid: string;
  issuerDID: string;
  credentialCID: string;
  jwsToken: string;
  /**
   * The revocation's own signed `createdAt` (ISO 8601), taken from the VERIFIED
   * payload at ingest — never re-decoded unverified. Persisting it is what makes
   * as-of revocation answerable: it is the boundary that separates operations a
   * revocation reaches (signed before it) from operations it does not.
   */
  createdAt: string;
}

export interface StoredPublicCredential {
  cid: string;
  issuerDID: string;
  att: Attenuation[];
  exp: number;
  jwsToken: string;
  createdAt: string;
  ingestedAt: string;
}

/**
 * Content ids named by a public credential's attenuations (`chain:<contentId>`
 * resources). `wildcard` means it grants `chain:*`, which covers every chain and
 * therefore fans out to all content rows.
 *
 * Lives here, on the leaf module both consumers already import: the projection
 * worker reads it to size a credential's fan-out, and ingestion reads it to
 * report what a revocation reached.
 */
export const contentIdsFromCredential = (
  credential: Pick<StoredPublicCredential, 'att'>,
): { wildcard: boolean; contentIds: string[] } => {
  const contentIds: string[] = [];
  let wildcard = false;
  for (const entry of credential.att) {
    if (entry.resource === 'chain:*') wildcard = true;
    else if (entry.resource.startsWith('chain:')) {
      contentIds.push(entry.resource.slice('chain:'.length));
    }
  }
  return { wildcard, contentIds };
};

export interface StoredCountersignature {
  cid: string;
  targetCID: string;
  witnessDID: string;
  relation: string | null;
  jwsToken: string;
}

export type OpOrigin = 'direct' | 'peer';

export interface PendingOp {
  jwsToken: string;
  origin: OpOrigin;
  /**
   * This row's KEYSET POSITION in the pending set, opaque to the caller and
   * defined by the store. The sequencer passes the last row's cursor back to
   * resume past it, which is what keeps a block of permanently
   * dependency-missing rows from hiding the rest of the queue behind it.
   */
  cursor: string;
}

/** Ephemeral courier state for one sign request. */
export interface StoredSignRequest {
  cid: string;
  request: string;
  requesterDID: string;
  subjectDID: string;
  payloadTyp: string;
  payloadBytes: Uint8Array;
  expiresAt: string;
  depositedAt: string;
  declined: boolean;
  response?: string;
}

export type SigningPutResult = 'created' | 'identical' | 'conflict' | 'not-found' | 'capacity';
export type SigningDeclineResult = 'declined' | 'responded' | 'not-found';

export interface SigningCursor {
  subjectDID: string;
  depositedAt: string;
  cid: string;
}

const signingCursorEncoder = new TextEncoder();
const signingCursorDecoder = new TextDecoder('utf-8', { fatal: true });

/** Unpadded base64url of `<subjectDID>|<depositedAt-ISO-millis>|<cid>`. */
export const encodeSigningCursor = (cursor: SigningCursor): string =>
  base64urlEncode(
    signingCursorEncoder.encode(`${cursor.subjectDID}|${cursor.depositedAt}|${cursor.cid}`),
  );

export const decodeSigningCursor = (raw: string): SigningCursor | undefined => {
  try {
    const bytes = base64urlDecode(raw);
    if (base64urlEncode(bytes) !== raw) return undefined;
    const decoded = signingCursorDecoder.decode(bytes);
    const firstSeparator = decoded.indexOf('|');
    const secondSeparator = decoded.indexOf('|', firstSeparator + 1);
    if (
      firstSeparator <= 0 ||
      secondSeparator <= firstSeparator + 1 ||
      secondSeparator !== decoded.lastIndexOf('|') ||
      secondSeparator === decoded.length - 1
    ) {
      return undefined;
    }
    const subjectDID = decoded.slice(0, firstSeparator);
    const depositedAt = decoded.slice(firstSeparator + 1, secondSeparator);
    const cid = decoded.slice(secondSeparator + 1);
    if (new Date(depositedAt).toISOString() !== depositedAt) return undefined;
    return { subjectDID, depositedAt, cid };
  } catch {
    return undefined;
  }
};

// -----------------------------------------------------------------------------
// relay store contracts
// -----------------------------------------------------------------------------

/*

  THREE CONTRACTS, NOT ONE, AND NO OPTIONAL MEMBERS.

  `RelayReadStore` is every read a route performs. `RelayWriteStore` adds ONE
  method — `commit` — and is what a relay that accepts operations needs.
  `IndexReadStore` / `IndexWriteStore` are the optional index profile: the query
  side and the projection side, split because a store can serve one without the
  other (a store whose index is maintained by an external worker implements the
  queries and not the writes).

  The split exists because the single fat interface was not implementable. Its
  only production consumer serves the reads for real and answers ~22 write
  members by throwing, which is not an implementation — it is a runtime promise
  that those members are never called. A contract you satisfy by throwing tells
  you nothing at construction time, so `createRelay` could not know what the
  store could actually do and probed members one call at a time.

  With the split, what a store can do is a fact about its TYPE, checked once at
  construction (see `isRelayWriteStore` and friends) and turned into the
  advertised capabilities. Nothing in this package probes `store.x?.()`.

*/

/**
 * EVERY READ A ROUTE PERFORMS. The base contract: implement this and the relay
 * serves the whole proof plane, the content plane, the log, and the revocation
 * routes — read-only.
 *
 * Concurrency contract: single-threaded JS does NOT make a store safe. Applying
 * an operation is a read-verify-write span with real yield points inside it (the
 * WebCrypto verify is one), so two overlapping ingests read the same chain head
 * and the second write erases the first. Serializing that span is the RELAY's
 * job, not the store's: every ingestion entry point, the sequencer, and the blob
 * write hold the per-store chain-state lock (`withChainStateLock` in ingest.ts),
 * the twin of the Go relay's `ingestMu`. That lock spans one process. A store
 * shared across processes is outside its reach and must add its own optimistic
 * concurrency (compare-and-swap on the chain head CID) or pessimistic locking.
 *
 * FAIL CLOSED. A read that cannot be answered THROWS. It never returns
 * `undefined`/`null`/`false` to mean "the store is unwell": absence and failure
 * are different answers, and ingestion classifies them differently — absence is
 * a verdict, a throw is retryable (see `StoreReadError` in ./ingest).
 */
export interface RelayReadStore {
  // --- operations ---

  getOperation(cid: string): Promise<StoredOperation | undefined>;

  // --- chains ---

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;

  /**
   * Materialized identity state at a specific operation CID, or null when the
   * CID is not in this chain's log. Fork verification needs state at the fork
   * point to check signer authority and createdAt ordering. Implementations
   * decide how: replay from genesis, or replay from the nearest snapshot.
   */
  getIdentityStateAtCID(
    did: string,
    cid: string,
  ): Promise<{ state: VerifiedIdentity; lastCreatedAt: string } | null>;

  /** Same for content chains. */
  getContentStateAtCID(
    contentId: string,
    cid: string,
  ): Promise<{ state: VerifiedContentChain; lastCreatedAt: string } | null>;

  // --- blobs (content plane) ---

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;

  // --- countersignatures ---

  /** The accepted countersignatures over one operation, deduped one per witness. */
  getCountersignatures(operationCID: string): Promise<string[]>;

  // --- operation log ---

  /**
   * Page the global append-only log by relay-local cursor. Cursors are the
   * relay's own ingestion order, so a cursor this log never issued returns
   * `null` — the route maps that to 400, never a silently empty page.
   */
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; next: string | null } | null>;

  /** Operational statistics over the global log, for the well-known response. */
  getStats(): Promise<RelayStats>;

  // --- revocations ---

  /**
   * Has this credential been revoked by this issuer?
   *
   * With `asOfUnix` omitted **or `<= 0`** this is the FRESHNESS answer — "revoked
   * as far as this relay knows right now" — which is what acceptance gates
   * (ingest, live read-path authorization) ask. With a positive `asOfUnix` it is
   * the VALIDITY answer: true only if the revocation's own signed `createdAt` is
   * at or before `asOfUnix`, which is what verifying already-committed history
   * asks.
   *
   * `<= 0` is timeless because the Go twin uses `0` as its in-band sentinel and
   * cannot express "as of epoch 0"; treating a non-positive instant as timeless
   * in both keeps the twins from answering that degenerate input oppositely.
   *
   * **Implementors: accept and honor the third parameter.** JS/TS arity is
   * permissive, so a two-parameter implementation still satisfies this type — and
   * silently degrades every as-of query to the timeless answer. That direction is
   * safe (it over-rejects rather than over-admits) but it reintroduces the
   * retroactive-invalidation behavior the parameter exists to fix.
   */
  isCredentialRevoked(
    issuerDID: string,
    credentialCID: string,
    asOfUnix?: number,
  ): Promise<boolean>;
  /**
   * The stored revocation for a credential CID, any issuer. Serves
   * `/revocations/v1/credential/:credentialCID`. If more than one issuer has
   * revoked the same CID, implementations MUST return the one with the
   * lexicographically smallest issuerDID so the answer is deterministic across
   * stores and twins.
   */
  getRevocationForCredential(credentialCID: string): Promise<StoredRevocation | undefined>;
  /**
   * Every stored revocation issued by a DID, sorted by credentialCID ascending
   * (the frozen v1 keyset order). Serves `/revocations/v1/issuer/:did`.
   */
  getRevocationsByIssuer(issuerDID: string): Promise<StoredRevocation[]>;

  // --- public credentials (standing authorization) ---

  /**
   * Held public credentials covering a resource. A `chain:*` grant covers every
   * `chain:` resource and is returned for any of them.
   */
  getPublicCredentials(resource: string): Promise<string[]>;
  /** One held public credential by CID. */
  getPublicCredentialByCID(cid: string): Promise<StoredPublicCredential | undefined>;
}

/**
 * ONE ACCEPTED OPERATION, AND EVERYTHING IT IMPLIES.
 *
 * The write contract used to be ~14 put/add/remove members that ingestion called
 * in sequence, so "an operation was accepted" was a shape a store had to infer
 * from a run of unrelated calls it could not see the end of — and a fault
 * halfway through left the store holding half an operation with no way to know
 * it. This describes the whole effect up front so a store can persist it in one
 * transaction or not at all.
 *
 * Exactly one operation per commit. The members present are a function of the
 * operation's kind:
 *
 *  - identity op   → `operation`, `identityChain`, `logEntry`
 *  - content op    → `operation`, `contentChain`, `logEntry`
 *  - artifact      → `operation`, `logEntry`
 *  - countersign   → `operation`, `countersignature`, `logEntry`
 *  - credential    → `operation`, `publicCredential`, `logEntry`
 *  - revocation    → `operation`, `revocation`, `removePublicCredential`, `logEntry`
 *
 * `logEntry` is absent when the relay runs with the global log disabled.
 */
export interface OperationCommit {
  kind: 'operation';
  /** The operation row. Its `cid` is the commit's idempotency key. */
  operation: StoredOperation;
  /** The global-log append. Absent when the relay's log is disabled. */
  logEntry?: LogEntry;
  /** The identity chain's new head, log and state, whole. */
  identityChain?: StoredIdentityChain;
  /** The content chain's new head, log and state, whole. */
  contentChain?: StoredContentChain;
  /** Add this countersignature to the target's set (one per witness per target). */
  countersignature?: { targetCID: string; jwsToken: string };
  /** Add this revocation to the revocation set (earliest boundary wins). */
  revocation?: StoredRevocation;
  /** Add this credential as standing public authorization. */
  publicCredential?: StoredPublicCredential;
  /**
   * Drop a held standing grant, ISSUER-SCOPED: the store removes the credential
   * only when the held row's `issuerDID` equals `issuerDID` here.
   *
   * Scoping is the whole point. Revocation is only meaningful from a credential's
   * own issuer (`isCredentialRevoked` is keyed on the pair), but the removal used
   * to be keyed on the credential CID alone — so any identity could sign a
   * revocation naming someone else's credential CID and the relay would drop the
   * held grant, un-publishing public content it had no authority over. The store
   * enforces the pairing.
   */
  removePublicCredential?: { issuerDID: string; credentialCID: string };
}

/** A document blob landing on the content plane, out of band from its operation. */
export interface BlobCommit {
  kind: 'blob';
  key: BlobKey;
  bytes: Uint8Array;
}

/**
 * One atomic unit of relay write. A discriminated union because the content
 * plane accepts bytes that no single operation carries: a document blob arrives
 * on its own route, often after the operation that referenced it.
 */
export type CommitBatch = OperationCommit | BlobCommit;

/**
 * `new` — the batch was persisted. `duplicate` — this operation CID was already
 * held and NOTHING was written.
 *
 * The duplicate answer is the race backstop, not the primary check: ingestion
 * still reads for an existing operation before it verifies, because it must
 * distinguish "same op" from "same CID, different signature". A store that
 * cannot detect the race may always answer `new`, and idempotent writes make
 * that correct — but a store that CAN detect it makes concurrent submission of
 * one operation safe without a relay-wide lock. A blob commit always answers
 * `new`: blob bytes are content-addressed, so a rewrite is a no-op.
 */
export type CommitResult = 'new' | 'duplicate';

/**
 * A store that accepts writes. ONE method: the relay describes an accepted
 * operation, the store persists all of it or none of it.
 *
 * ATOMICITY IS THE CONTRACT. A partial commit is a corrupt relay: an operation
 * in `operations` but not in the log is invisible to every puller forever, and a
 * chain head advanced without its operation row breaks fork verification. If the
 * commit throws, the store MUST have persisted nothing; the relay classifies a
 * throw as retryable and keeps the raw operation for a later pass.
 */
export interface RelayWriteStore extends RelayReadStore {
  commit(batch: CommitBatch): Promise<CommitResult>;
}

// -----------------------------------------------------------------------------
// index profile (optional)
// -----------------------------------------------------------------------------

/**
 * THE QUERY SIDE of the index profile: the nine reads behind `/index/v0`.
 *
 * Queries push their filters and keyset cursor into the store so a page costs
 * O(page), never O(corpus): rows come back ascending by natural key, strictly
 * greater than `after` (bytewise), capped at `limit`. The route layer computes
 * `next = rows.length === limit ? key(last) : null`. Row VALUES are a pure
 * function of chain state + held blobs + standing credentials, so a recompute
 * always converges to the same row regardless of when it runs — that is what
 * makes incremental projection and a full rebuild interchangeable.
 *
 * A store implementing this and NOT `IndexWriteStore` serves the index from rows
 * some other process maintains. That is a supported shape, and the relay does no
 * projection work for it.
 */
export interface IndexReadStore {
  /**
   * Page identity projection rows ascending by DID, `did > after`, length <=
   * limit. `hasPublicProfile` (≡ profile != null && profile.publicRead) filters
   * to identities that expose a public profile; `did` is an exact point lookup;
   * `nameContains` filters by case-insensitive substring over projected
   * `profile.name`.
   *
   * `key` is the HAS-EVER-PROVED reverse lookup: keep rows whose chain ever
   * PROVED this public key into any role (`auth` / `assert` / `controller`) at
   * any point in its history — current or long since rotated out. A key some
   * chain merely DECLARED never matches: no possession proof admitted it, the
   * membership is void, and indexing it would let a stranger burn a key they do
   * not hold. Matched byte-for-byte as an opaque multibase string (a value no
   * chain ever proved simply matches nothing; no format validation, no 400), and
   * it never excludes deleted rows.
   */
  queryIndexIdentities(q: {
    did?: string;
    key?: string;
    hasPublicProfile?: boolean;
    nameContains?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexIdentityRow[]>;
  /**
   * Page content projection rows ascending by contentId, `contentId > after`,
   * length <= limit, filtered by any provided point ID, actor, document,
   * visibility, or deletion predicate.
   */
  queryIndexContent(q: {
    contentId?: string;
    creator?: string;
    signer?: string;
    docSchema?: string;
    documentCID?: string;
    publicRead?: boolean;
    isDeleted?: boolean;
    titleContains?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexContentRow[]>;
  /** Page public-head credit rows by the opaque (contentId, position) cursor. */
  queryIndexCredits(q: {
    did?: string;
    contentId?: string;
    role?: string;
    after?: IndexCreditCursor;
    limit: number;
  }): Promise<IndexCreditRow[]>;
  /** Page standalone artifact projections by CID or recency order. */
  queryIndexArtifacts(q: {
    cid?: string;
    signer?: string;
    docSchema?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexArtifactRow[]>;
  /**
   * Page countersignature projection rows for one witness ascending by cid,
   * `cid > after`, length <= limit. Reflects the store's ACCEPTED countersign
   * set (deduped one-per-witness-per-target), never raw ops.
   */
  queryIndexCountersignatures(q: {
    witness: string;
    relation?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexCountersignatureQueryRow[]>;
  /**
   * Page held public credentials by lexical cid or the selected recency
   * composite, filtered by issuer, resource, and/or action exact match. For
   * chain resources, the `chain:*` bucket is unioned as an amber discovery hint.
   *
   * Served from the HELD credential set, not from a projection table — a
   * standing grant is authoritative state, and this route is a view of it.
   */
  queryIndexCredentials(q: {
    issuer?: string;
    resource?: string;
    action?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexCredentialQueryRow[]>;
  /**
   * Page relay-held operations in non-authoritative recency order.
   *
   * `signerKey` is the key-addressed actor filter: keep rows whose signature
   * verified against this exact multibase public key AT INGEST. The value is the
   * key the row's `kid` resolved to when the operation was accepted, stored
   * verbatim as the identity chain declared it — resolution is never repeated at
   * query time, and nothing here normalizes or re-encodes the string. Matched
   * byte-for-byte as an opaque value, and ANDed with the other filters. A row
   * whose signer key did not resolve carries no key and matches no `signerKey`.
   */
  queryIndexOperations(q: {
    kind?: OperationKind;
    chainId?: string;
    signerKey?: string;
    orderedAfter?: IndexOrderedCursor;
    order: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexOperationRow[]>;
  /**
   * Reverse lookup: DIDs of identity projection rows whose `profile.anchor`
   * equals the given contentId. Powers the "content changed → recompute the
   * identities anchored on it" cascade.
   */
  getIndexIdentityDIDsByProfileAnchor(contentId: string): Promise<string[]>;
  /**
   * Reverse lookup: contentIds of content projection rows whose
   * `currentDocumentCID` equals the given documentCID. Powers the "blob landed
   * → recompute the content rows that project that document" cascade.
   */
  getIndexContentIdsByDocumentCID(documentCID: string): Promise<string[]>;
}

/** One projection write: whatever rows a projection run recomputed. */
export interface IndexRowBatch {
  identities?: IndexIdentityRow[];
  content?: IndexContentRow[];
  /** Complete public-head credit row set per contentId — REPLACES that set. */
  credits?: { contentId: string; rows: IndexCreditRow[] }[];
  artifacts?: IndexArtifactRow[];
  countersignatures?: (IndexCountersignatureQueryRow & { witnessDID: string })[];
  operations?: IndexOperationRow[];
  /**
   * The multibase public key one accepted operation's signature verified
   * against, keyed by operation CID — the stored column behind `signerKey=`.
   * Stored VERBATIM: the filter is an opaque byte match.
   */
  operationSignerKeys?: { cid: string; publicKeyMultibase: string }[];
  /**
   * Has-ever-proved reverse rows: `(publicKeyMultibase, did, keyId)` for every
   * key an accepted identity operation left PROVED. UPSERTS, NEVER DELETED — a
   * rotation removes nothing and a deleted identity keeps its rows. Append-only
   * plus a monotonic `provedKeys` is what makes the accumulated table equal the
   * head state's `provedKeys`, so incremental projection and a full rebuild
   * agree. A key an operation merely DECLARED is never recorded: no possession
   * proof admitted it, so recording it would let a stranger burn a key they do
   * not hold.
   */
  identityKeys?: { did: string; publicKeyMultibase: string; keyId: string }[];
  /** Accepted content-operation signers, added to each chain's signer set. */
  contentSigners?: { contentId: string; did: string }[];
}

/** A resumable full-corpus sweep. `after` is the last contentId recomputed. */
export interface IndexSweepState {
  /** `all` recomputes every content row; `public` only the currently-public ones. */
  scope: 'all' | 'public';
  after: string | null;
}

/**
 * Where the projection worker got to. Persisted, so a run resumes rather than
 * restarts.
 *
 * `logCursor` is the CID of the last operation-log entry projected; `null`
 * before the first run. `sweep` is a full-corpus recompute in progress: some
 * operations (a `chain:*` grant, an identity delete or restore) change the
 * visibility of rows they never name, and draining that in one pass is the
 * unbounded stall this cursor exists to break up.
 */
export interface IndexCursor {
  logCursor: string | null;
  sweep: IndexSweepState | null;
}

/**
 * THE PROJECTION SIDE of the index profile. A store implementing it lets this
 * package run the projection worker (see `projectIndex` in ./index-projection);
 * a store that omits it keeps its index current some other way.
 */
export interface IndexWriteStore {
  /** Apply one projection run's recomputed rows. */
  applyIndexRows(rows: IndexRowBatch): Promise<void>;
  getIndexCursor(): Promise<IndexCursor | undefined>;
  setIndexCursor(cursor: IndexCursor): Promise<void>;
}

// -----------------------------------------------------------------------------
// signing profile (optional)
// -----------------------------------------------------------------------------

/** The ephemeral courier state behind the optional signing mailbox. */
export interface SigningStore {
  getSignRequest(cid: string, now: number): Promise<StoredSignRequest | undefined>;
  pruneExpiredSignRequests(now: number): Promise<void>;
  putSignRequest(request: StoredSignRequest, now: number): Promise<SigningPutResult>;
  listPendingSignRequests(params: {
    subjectDID: string;
    after?: string;
    limit: number;
    now: number;
  }): Promise<{ requests: StoredSignRequest[]; next: string | null } | null>;
  putSignResponse(cid: string, response: string, now: number): Promise<SigningPutResult>;
  declineSignRequest(cid: string, now: number): Promise<SigningDeclineResult>;
}

// -----------------------------------------------------------------------------
// writer-internal state
// -----------------------------------------------------------------------------

/**
 * INTERNAL TO A RELAY THAT WRITES. Not part of the store contract a store
 * implementor reads: raw-op durability, the sequencer's pending set, and peer
 * sync cursors are bookkeeping this package keeps for itself, and a store that
 * never accepts writes and configures no peers has nothing to keep.
 *
 * The reference in-memory store implements it because the reference relay both
 * writes and peers. It is exported so an embedder building a durable writing
 * relay can implement it deliberately, not because a store needs it to be
 * useful.
 *
 * BE PRECISE ABOUT WHAT MOVED. This state left the contract every integration
 * reads — a read-only store, and the platform's Postgres projection, now name
 * none of it — but it is still an interface a durable WRITING relay implements,
 * and still a precondition for `write`. Holding the raw-op buffer and the peer
 * cursors inside this package would mean owning durability for them, which is
 * the store's job. So the separation is by AUDIENCE, not by ownership.
 */
export interface RelayWriterState {
  /** Store a raw JWS token by CID and durable origin — absent origin is direct. */
  putRawOp(cid: string, jwsToken: string, origin?: OpOrigin): Promise<void>;
  /**
   * JWS tokens and durable origins for unsequenced (pending) ops, in a stable
   * total order, resuming strictly after the keyset cursor of a previously
   * returned row ('' starts at the head).
   *
   * THE CURSOR IS NOT AN OPTIMIZATION. Without it, a caller that fetches the
   * oldest N pending rows always fetches THE SAME N: an op whose dependency this
   * relay will never hold stays pending forever, and enough of them fill the
   * window permanently, so every row behind them — including a freshly
   * pull-synced op whose dependency has since landed — is never selected and
   * peer ingestion stops converging while direct POSTs keep working.
   */
  getUnsequencedOps(after: string, limit: number): Promise<PendingOp[]>;
  markOpsSequenced(cids: string[]): Promise<void>;
  markOpRejected(cid: string, reason: string): Promise<void>;
  countUnsequenced(): Promise<number>;
  /** Reset all non-rejected raw ops to pending (re-sequence). */
  resetSequencer(): Promise<void>;
  getPeerCursor(peerUrl: string): Promise<string | undefined>;
  setPeerCursor(peerUrl: string, cursor: string): Promise<void>;
}

// -----------------------------------------------------------------------------
// what createRelay accepts, and how it reads a store's shape
// -----------------------------------------------------------------------------

/**
 * The store `createRelay` accepts: at minimum a `RelayReadStore`, plus whichever
 * further contracts the implementation satisfies.
 *
 * The optionality lives HERE, in the option type, and nowhere else. Each further
 * contract is all-or-nothing — a store either implements `RelayWriteStore` or it
 * does not — and `createRelay` resolves which ones hold ONCE at construction
 * with the guards below, then holds narrowed references. No route probes a
 * member.
 */
export type RelayStore = RelayReadStore &
  Partial<Omit<RelayWriteStore, keyof RelayReadStore>> &
  Partial<IndexReadStore> &
  Partial<IndexWriteStore> &
  Partial<SigningStore> &
  Partial<RelayWriterState>;

/** A writing store: it can commit. */
export const isRelayWriteStore = (store: RelayStore): store is RelayStore & RelayWriteStore =>
  typeof store.commit === 'function';

/** An index-serving store: it answers the nine `/index/v0` queries. */
export const isIndexReadStore = (store: RelayStore): store is RelayStore & IndexReadStore =>
  typeof store.queryIndexIdentities === 'function' &&
  typeof store.queryIndexContent === 'function' &&
  typeof store.queryIndexCredits === 'function' &&
  typeof store.queryIndexArtifacts === 'function' &&
  typeof store.queryIndexCountersignatures === 'function' &&
  typeof store.queryIndexCredentials === 'function' &&
  typeof store.queryIndexOperations === 'function' &&
  typeof store.getIndexIdentityDIDsByProfileAnchor === 'function' &&
  typeof store.getIndexContentIdsByDocumentCID === 'function';

/** An index-projecting store: this package can run the projection worker on it. */
export const isIndexWriteStore = (store: RelayStore): store is RelayStore & IndexWriteStore =>
  typeof store.applyIndexRows === 'function' &&
  typeof store.getIndexCursor === 'function' &&
  typeof store.setIndexCursor === 'function';

/** A signing-mailbox store. */
export const isSigningStore = (store: RelayStore): store is RelayStore & SigningStore =>
  typeof store.getSignRequest === 'function' &&
  typeof store.pruneExpiredSignRequests === 'function' &&
  typeof store.putSignRequest === 'function' &&
  typeof store.listPendingSignRequests === 'function' &&
  typeof store.putSignResponse === 'function' &&
  typeof store.declineSignRequest === 'function';

/** A store holding this package's writer-internal bookkeeping. */
export const isRelayWriterState = (store: RelayStore): store is RelayStore & RelayWriterState =>
  typeof store.putRawOp === 'function' &&
  typeof store.getUnsequencedOps === 'function' &&
  typeof store.markOpsSequenced === 'function' &&
  typeof store.markOpRejected === 'function' &&
  typeof store.countUnsequenced === 'function' &&
  typeof store.resetSequencer === 'function' &&
  typeof store.getPeerCursor === 'function' &&
  typeof store.setPeerCursor === 'function';
// -----------------------------------------------------------------------------
// ingestion result
// -----------------------------------------------------------------------------

/** Result of a sequencer run */
export interface SequenceResult {
  sequenced: number;
  rejected: number;
  pending: number;
}

export interface IngestionResult {
  cid: string;
  status: 'new' | 'duplicate' | 'rejected';
  error?: string;
  /** What was ingested */
  kind?: OperationKind;
  /** Chain identifier if applicable */
  chainId?: string;
  /**
   * The public grant a revocation actually reached, ISSUER-SCOPED: absent when
   * this relay holds no such credential, and absent when it holds one that a
   * DIFFERENT issuer granted (a foreign revocation reaches nothing, so reporting
   * a grant would be a lie). The `revokedGrant` field of the ingestion response.
   */
  revokedGrant?: { wildcard: boolean; contentIds: string[] };
  /**
   * Structured dependency-failure signal. When true, the rejection is due to a
   * missing dependency that may arrive later via sync or gossip, so the
   * sequencer must keep the op pending (retryable) rather than durably reject
   * it. This is the discriminator the sequencer branches on — NOT substring
   * matching of the human-readable `error` string.
   */
  dependencyMissing?: boolean;
  /**
   * Structured store-fault signal. When true, the rejection is not a verdict
   * about the operation at all: a store call failed, so nothing was decided and
   * nothing was persisted. Retryable for the same reason and with more urgency
   * than a missing dependency — a permanent rejection DELETES the raw op, and a
   * momentary store fault must never be able to destroy a valid operation.
   */
  storeFault?: boolean;
}

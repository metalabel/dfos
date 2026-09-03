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
   * anonymously (WEB-RELAY.md, Relay Identity: "a gossiping peer authenticates
   * like any client: anonymously, or with an identity proof signed by its own
   * DID"). A relay constructed from a DID and a profile alone still runs; it
   * simply gossips anonymously.
   */
  keyId?: string;
  sign?: (message: Uint8Array) => Promise<Uint8Array>;
}

/**
 * The advertised ingestion admission mode (WEB-RELAY.md, Ingestion Admission).
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
 * (WEB-RELAY.md, Well-Known Endpoint). Serving a document is SHOULD, never MUST;
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
  /** Whether the global operation log is enabled (default: true) */
  log?: boolean;
  /** Whether the revocation status route family is enabled (default: true) */
  revocations?: boolean;
  /** Whether the index query family is enabled (default: true) */
  index?: boolean;
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
   * expected one from its own configuration" (WEB-RELAY.md, Authentication).
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
   * (WEB-RELAY.md, Relay Identity: "a gossiping peer authenticates like any
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

/** A single entry in the global append-only operation log */
export interface LogEntry {
  cid: string;
  jwsToken: string;
  kind: OperationKind;
  chainId: string;
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
  | 'identity-op'
  | 'content-op'
  | 'artifact'
  | 'countersign'
  | 'revocation'
  | 'credential';

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
// relay store interface
// -----------------------------------------------------------------------------

/**
 * Storage backend for a DFOS web relay
 *
 * Implementations handle persistence (memory, SQLite, Postgres, S3, etc.).
 * The relay core handles verification — the store just reads and writes.
 *
 * Concurrency contract: the in-memory store is safe under single-threaded JS.
 * Durable implementations must enforce optimistic concurrency (compare-and-swap
 * on chain head CID) or pessimistic locking to prevent concurrent extensions
 * from silently overwriting each other.
 */
export interface RelayStore {
  // --- signing mailbox (ephemeral courier state) ---

  getSignRequest?(cid: string, now: number): Promise<StoredSignRequest | undefined>;
  pruneExpiredSignRequests?(now: number): Promise<void>;
  putSignRequest?(request: StoredSignRequest, now: number): Promise<SigningPutResult>;
  listPendingSignRequests?(params: {
    subjectDID: string;
    after?: string;
    limit: number;
    now: number;
  }): Promise<{ requests: StoredSignRequest[]; next: string | null } | null>;
  putSignResponse?(cid: string, response: string, now: number): Promise<SigningPutResult>;
  declineSignRequest?(cid: string, now: number): Promise<SigningDeclineResult>;

  // --- operations ---

  getOperation(cid: string): Promise<StoredOperation | undefined>;
  putOperation(op: StoredOperation): Promise<void>;

  // --- identity chains ---

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  putIdentityChain(chain: StoredIdentityChain): Promise<void>;

  // --- content chains ---

  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;
  putContentChain(chain: StoredContentChain): Promise<void>;

  // --- blobs (content plane) ---

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  // --- countersignatures ---
  // Implementations MUST deduplicate by witness DID per target CID.

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  // --- operation log ---
  // Global append-only log of all accepted operations. CID-based cursor pagination.
  // Cursors are relay-local (per-relay ingestion order): readLog resolves `after`
  // positionally and returns null for a cursor this log does not contain — the
  // route maps that to 400, never a silently empty page.

  appendToLog(entry: LogEntry): Promise<void>;
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; next: string | null } | null>;
  /**
   * Optional: compute operational statistics over the global log for the well-known
   * response. A store that omits this leaves opCount/countsByKind/oldestOpAt/headCid
   * out of the well-known (pendingOps still reports). Reference stores implement it.
   */
  getStats?(): Promise<RelayStats>;

  // --- chain state at arbitrary CID (snapshot-backed) ---

  /**
   * Get the materialized identity state at a specific operation CID.
   *
   * Used by fork verification — the ingestion pipeline needs state at the fork
   * point to verify signer authority and createdAt ordering.
   *
   * Implementations decide how to compute this:
   * - MemoryStore: replay from genesis (chains are short in tests)
   * - SQLiteStore: check snapshot table, replay from nearest snapshot
   *
   * Returns null if the CID is not in this chain's log.
   */
  getIdentityStateAtCID(
    did: string,
    cid: string,
  ): Promise<{ state: VerifiedIdentity; lastCreatedAt: string } | null>;

  /** Same for content chains */
  getContentStateAtCID(
    contentId: string,
    cid: string,
  ): Promise<{ state: VerifiedContentChain; lastCreatedAt: string } | null>;

  // --- revocations ---

  /** Get all revoked credential CIDs for an issuer */
  getRevocations(issuerDID: string): Promise<string[]>;
  /** Add a revocation to the revocation set */
  addRevocation(revocation: StoredRevocation): Promise<void>;
  /**
   * Check if a specific credential CID has been revoked by a specific issuer.
   *
   * With `asOfUnix` omitted **or `<= 0`** this is the FRESHNESS answer — "revoked
   * as far as this relay knows right now" — which is what acceptance gates
   * (ingest, live read-path authorization) ask. With a positive `asOfUnix` it is
   * the VALIDITY answer: true only if the revocation's own signed `createdAt` is at
   * or before `asOfUnix`, which is what verifying already-committed history asks.
   * See CREDENTIALS.md "Revocation Scope".
   *
   * `<= 0` is timeless because the Go twin uses `0` as its in-band sentinel and
   * cannot express "as of epoch 0"; treating a non-positive instant as timeless in
   * both keeps the twins from answering that degenerate input oppositely. The
   * practical effect is that an operation dated at or before 1970 gets the
   * stricter (timeless) answer everywhere.
   *
   * **Implementors: accept and honor the third parameter.** JS/TS arity is
   * permissive, so a two-parameter implementation still satisfies this type — and
   * silently degrades every as-of query to the timeless answer. That direction is
   * safe (it over-rejects rather than over-admits) but it reintroduces exactly the
   * retroactive-invalidation behavior the parameter exists to fix: history that was
   * valid when it was signed starts failing verification as soon as any credential
   * in it is revoked. A store that genuinely cannot answer the as-of question
   * should document that rather than quietly ignore the argument.
   */
  isCredentialRevoked(
    issuerDID: string,
    credentialCID: string,
    asOfUnix?: number,
  ): Promise<boolean>;
  /**
   * Get the stored revocation for a credential CID, any issuer. Serves the
   * `/revocations/v1/credential/:credentialCID` status route. If more than one
   * issuer has revoked the same CID (possible — the set is keyed by
   * (issuerDID, credentialCID) and issuer-only enforcement happens at
   * credential verification, not ingest), implementations MUST return the one
   * with the lexicographically smallest issuerDID so the answer is
   * deterministic across stores and twins.
   */
  getRevocationForCredential(credentialCID: string): Promise<StoredRevocation | undefined>;
  /**
   * Get all stored revocations issued by a DID, sorted by credentialCID
   * ascending (deterministic across stores and twins — the frozen v1 keyset
   * order). Serves the
   * `/revocations/v1/issuer/:did` listing route.
   */
  getRevocationsByIssuer(issuerDID: string): Promise<StoredRevocation[]>;

  // --- index (v0) materialized projection ---
  //
  // The /index/v0 query family is served from materialized projection rows that
  // the ingestion pipeline maintains incrementally (see index-maintenance.ts).
  // Queries push their filters and keyset cursor into the store so a page costs
  // O(page), never O(corpus): rows come back ascending by natural key, strictly
  // greater than `after` (bytewise), and capped at `limit`. The route layer
  // computes `next = rows.length === limit ? key(last) : null`. Row VALUES are a
  // pure function of chain state + held blobs + standing credentials, so a
  // recompute always converges to the same row regardless of when it runs — that
  // is what makes incremental maintenance and a full rebuild interchangeable.

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
   * byte-for-byte as an opaque value (a key no accepted operation was signed
   * with simply matches nothing; no format validation, no 400), and ANDed with
   * the other filters. A row whose signer key did not resolve at ingest carries
   * no key and therefore matches no `signerKey` value.
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
   * Optional: read one relay-held operation row by CID. Index maintenance uses
   * it to source an artifact row's `ingestedAt` from the operation log's
   * receipt stamp, so the two index surfaces report one receipt time for the
   * same op (mirrors the Go twin); absent, maintenance falls back to the wall
   * clock.
   */
  getIndexOperationRow?(cid: string): Promise<IndexOperationRow | undefined>;

  /** Upsert an identity projection row by DID. */
  putIndexIdentityRow(row: IndexIdentityRow): Promise<void>;
  /** Upsert a content projection row by contentId. */
  putIndexContentRow(row: IndexContentRow): Promise<void>;
  /** Replace one content chain's complete public-head credit row set. */
  putIndexCreditRows(contentId: string, rows: IndexCreditRow[]): Promise<void>;
  /** Upsert a standalone artifact projection row by CID. */
  putIndexArtifactRow(row: IndexArtifactRow): Promise<void>;
  /** Add one accepted content-operation signer to a chain's signer set. */
  putIndexContentSigner(contentId: string, did: string): Promise<void>;
  /**
   * Record one public key an accepted identity operation left PROVED — the
   * `(publicKeyMultibase, did, keyId)` reverse row backing `key=` on
   * /index/v0/identities.
   *
   * Called once per entry of the chain's `provedKeys` after every accepted
   * identity operation, so the table accumulates has-ever-proved rather than
   * head state — a rotated-out key stays findable, which is the case the filter
   * exists for. A key an operation merely DECLARED is NOT recorded: no
   * possession proof admitted it, so it publishes no link between chains, and
   * recording it would let a stranger burn a key they do not hold.
   *
   * Rows are UPSERTS and are NEVER DELETED: a rotation removes nothing, a
   * deleted identity keeps its rows. Append-only plus a monotonic `provedKeys`
   * is what makes the accumulated table equal the head state's `provedKeys`, so
   * incremental maintenance and a full rebuild agree. `publicKeyMultibase` is
   * stored verbatim.
   */
  putIndexIdentityKey(did: string, publicKeyMultibase: string, keyId: string): Promise<void>;
  /**
   * Record the public key ONE accepted operation's signature verified against —
   * the stored column behind `signerKey=` on /index/v0/operations.
   *
   * Called once per accepted operation of every kind (identity-op, content-op,
   * artifact, countersign, revocation, credential), keyed by the same operation
   * CID the operation index row carries, with `publicKeyMultibase` stored
   * VERBATIM as the identity chain declared it — the identical string
   * `putIndexIdentityKey` records, so `key=` on /index/v0/identities and
   * `signerKey=` here speak one alphabet.
   *
   * It is written at ingest precisely so the filter never re-decodes the corpus:
   * the row retains what verification already computed. An operation whose
   * signer key does not resolve records nothing, and the row then matches no
   * `signerKey` value (it still enumerates unfiltered). A persistent store
   * repopulates the column for a pre-existing corpus through its versioned
   * projection rebuild, replaying the op log; the in-memory reference store's
   * projection is born with the process and has no corpus to backfill.
   */
  putIndexOperationSignerKey(cid: string, publicKeyMultibase: string): Promise<void>;
  /**
   * Upsert a countersignature projection row by cid. The `witnessDID` column is
   * stored (never echoed in the row body) so witness-scoped queries stay O(page).
   */
  putIndexCountersignatureRow(
    row: IndexCountersignatureQueryRow & { witnessDID: string },
  ): Promise<void>;

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

  // --- public credentials (standing authorization) ---

  /** Get public credentials covering a specific resource */
  getPublicCredentials(resource: string): Promise<string[]>;
  /** Get a stored public credential by CID */
  getPublicCredentialByCID(cid: string): Promise<StoredPublicCredential | undefined>;
  /** Add a public credential as standing authorization */
  addPublicCredential(credential: StoredPublicCredential): Promise<void>;
  /** Remove a public credential (e.g., after revocation) */
  removePublicCredential(credentialCID: string): Promise<void>;

  // --- peer sync state ---

  /** Get last-synced log cursor for a peer relay */
  getPeerCursor(peerUrl: string): Promise<string | undefined>;
  /** Update last-synced log cursor for a peer relay */
  setPeerCursor(peerUrl: string, cursor: string): Promise<void>;

  // --- raw ops (content-addressed store for all received operations) ---

  /** Store a raw JWS token by CID and durable origin — absent origin defaults to direct */
  putRawOp(cid: string, jwsToken: string, origin?: OpOrigin): Promise<void>;
  /** Return JWS tokens and durable origins for unsequenced (pending) ops */
  getUnsequencedOps(limit: number): Promise<PendingOp[]>;
  /** Mark ops as successfully sequenced */
  markOpsSequenced(cids: string[]): Promise<void>;
  /** Mark an op as permanently rejected */
  markOpRejected(cid: string, reason: string): Promise<void>;
  /** Count of pending (unsequenced) raw ops */
  countUnsequenced(): Promise<number>;
  /** Reset all non-rejected raw ops to pending (re-sequence) */
  resetSequencer(): Promise<void>;
}

export type SigningStore = RelayStore &
  Required<
    Pick<
      RelayStore,
      | 'getSignRequest'
      | 'pruneExpiredSignRequests'
      | 'putSignRequest'
      | 'listPendingSignRequests'
      | 'putSignResponse'
      | 'declineSignRequest'
    >
  >;

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
  /** Revoked public grant scope; undefined when the credential was not held */
  revokedGrant?: { wildcard: boolean; contentIds: string[] };
  /**
   * Structured dependency-failure signal. When true, the rejection is due to a
   * missing dependency that may arrive later via sync or gossip, so the
   * sequencer must keep the op pending (retryable) rather than durably reject
   * it. This is the discriminator the sequencer branches on — NOT substring
   * matching of the human-readable `error` string.
   */
  dependencyMissing?: boolean;
}

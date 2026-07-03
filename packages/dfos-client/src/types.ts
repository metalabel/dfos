/*

  TYPES

  The whole public type surface. The acceptance test for this file: a reviewer
  can hold it in their head. Every `value` here is a protocol-lib proven type,
  untouched — the client adds trust-as-data and provenance around it, never a
  reimplementation of verification.

*/

import type { VerifiedContentChain, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import type { VerifiedDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import type { PeerClient } from '@metalabel/dfos-web-relay';

// -----------------------------------------------------------------------------
// trust + provenance (data, never exceptions)
// -----------------------------------------------------------------------------

/**
 * The two axes v1 genuinely cannot check:
 * - `revocation` — no non-checking revocation feed was wired, so a credential's
 *   revocation status is unknown (honest, not proven-unrevoked).
 * - `tip` — the answer came from cache without a live relay confirming the head,
 *   so we cannot assert we hold the true tip.
 */
export type UnverifiableAxis = 'revocation' | 'tip';

/** Trust is DATA. `ok` = the value verified; `unverifiable` lists honest gaps. */
export interface Trust {
  ok: boolean;
  unverifiable?: UnverifiableAxis[];
}

/** One relay's answer to a fan-out. `digest` is a content digest for quorum. */
export interface RelayResponse {
  url: string;
  ok: boolean;
  digest: string;
}

/** Where an answer came from and whether relays agreed. Stays thin. */
export interface Provenance {
  answeredBy: string;
  responses: RelayResponse[];
  agreed: boolean;
  fromCache: boolean;
}

/** A proven value wrapped in trust + provenance. */
export interface Resolved<T> {
  value: T;
  trust: Trust;
  provenance: Provenance;
}

// -----------------------------------------------------------------------------
// verify (no-throw decision one-liner)
// -----------------------------------------------------------------------------

/** No-throw verification outcome. `ok` routes the decision; `error` explains a no. */
export interface VerifyResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
  unverifiable?: UnverifiableAxis[];
}

// -----------------------------------------------------------------------------
// resolved projections (only to the depth verification already required)
// -----------------------------------------------------------------------------

export interface ResolvedContent {
  chain: VerifiedContentChain;
  /** The creator identity — resolved as a side effect of key resolution. */
  creator: VerifiedIdentity;
  /** The current document blob, when fetched. */
  document?: DocumentBlob;
}

export interface ResolvedCredential {
  credential: VerifiedDFOSCredential;
  /** The issuer identity, verified. */
  issuer: VerifiedIdentity;
  /** Revocation status per the effective revocation checker (see Trust.unverifiable). */
  revoked: boolean;
}

export interface DocumentBlob {
  bytes: Uint8Array;
  documentCID: string;
  mediaType?: string;
  /** The parsed document if it was JSON — the on-wire form relays store. */
  decoded?: unknown;
  /** Whether the fetched bytes re-derive to `documentCID` (content-address check). */
  integrity: boolean;
}

/** Discriminated result of the paste-a-string dispatcher. */
export type Resolution =
  | ({ kind: 'identity' } & Resolved<VerifiedIdentity>)
  | ({ kind: 'content' } & Resolved<ResolvedContent>)
  | ({ kind: 'credential' } & Resolved<ResolvedCredential>);

// -----------------------------------------------------------------------------
// protocol-lib callbacks — the product
// -----------------------------------------------------------------------------

/** Check whether a credential has been revoked. Default: `() => false` (honest). */
export type RevChecker = (issuerDID: string, credentialCID: string) => Promise<boolean>;

/**
 * The bound protocol-lib callbacks — spread straight into `verifyContentChain`,
 * `verifyDFOSCredential`, or any DFOS verifier. This is the trunk product.
 */
export interface Callbacks {
  resolveKey: (kid: string) => Promise<Uint8Array>;
  resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
  isRevoked: RevChecker;
}

// -----------------------------------------------------------------------------
// store (cache the LOG, verify forward — never cache a terminal verified state)
// -----------------------------------------------------------------------------

/**
 * A minimal async key/value cache. Values are JSON-serializable records the
 * client owns; consumers never construct them. `memoryStore()` is the default;
 * `indexedDbStore()` (behind `./store`) is the only heavy, browser-only adapter.
 */
export interface Store {
  get(key: string): Promise<unknown | undefined>;
  set(key: string, value: unknown): Promise<void>;
}

// -----------------------------------------------------------------------------
// raw floor
// -----------------------------------------------------------------------------

/** A raw JWS operation from a relay log — cid + token, unverified until folded. */
export interface LogOp {
  cid: string;
  jwsToken: string;
}

/** A page of the global operation log — a seam, not a sync engine (v1). */
export interface GlobalLogPage {
  entries: LogOp[];
  cursor: string | null;
  provenance: Provenance;
}

/** Parsed `/.well-known/dfos-relay` body, passed through untouched. */
export interface RelayHealth {
  url: string;
  ok: boolean;
  did?: string;
  capabilities?: Record<string, unknown>;
  [key: string]: unknown;
}

// -----------------------------------------------------------------------------
// config + client
// -----------------------------------------------------------------------------

/** Per-call overrides. */
export interface CallOptions {
  /** Override the client's relay set for this call. */
  relays?: string[];
  /** Bypass the cache and re-fetch from genesis. */
  fresh?: boolean;
}

export interface ClientConfig {
  /** Ordered, untrusted relay URLs. IMMUTABLE — a relay switch is a new client. */
  relays: string[];
  /** Cache backend. Default `memoryStore()`. */
  store?: Store;
  /** Distinct-digest agreement threshold. Default 1 (first-wins). */
  quorum?: number;
  /** Revocation checker. Default `() => false` (honest — status is unverifiable). */
  isRevoked?: RevChecker;
  /** Injected fetch for blob/health/revocation calls. Default `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Clock injection (unix ms). Default `Date.now`. */
  now?: () => number;
  /** Injected log transport. Default `createHttpPeerClient()`. */
  peerClient?: PeerClient;
}

export interface Client {
  /** The bound protocol-lib callbacks — spread into any verifier. */
  callbacks(options?: CallOptions): Callbacks;

  /** Paste-a-string dispatcher → a typed, trust-wrapped resolution. */
  resolve(ref: string, options?: CallOptions): Promise<Resolution>;

  identity(did: string, options?: CallOptions): Promise<Resolved<VerifiedIdentity>>;
  content(contentId: string, options?: CallOptions): Promise<Resolved<ResolvedContent>>;
  credential(jws: string, options?: CallOptions): Promise<Resolved<ResolvedCredential>>;
  document(contentId: string, options?: CallOptions): Promise<Resolved<DocumentBlob>>;

  /** No-throw, self-routing "is this legit". */
  verify(jws: string, options?: CallOptions): Promise<VerifyResult<unknown>>;

  /** Raw floor. */
  log(kind: 'identity' | 'content', id: string, options?: CallOptions): Promise<Resolved<LogOp[]>>;
  globalLog(cursor?: string, options?: CallOptions): Promise<GlobalLogPage>;
  health(options?: CallOptions): Promise<RelayHealth[]>;
}

# Changelog

All notable changes to `@metalabel/dfos-protocol` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

DFOS packages release in lockstep: every published `@metalabel/*` package and Go
module shares a single version, cut together from a `v*` tag. An entry here
describes the protocol-package surface of that release.

## [Unreleased]

### Added

- **Index v0 iteration 2 — "actor, clock, name"** (#190, spec; implementation
  in TS + Go + conformance). The `/index/v0` contract gains its fence — _the
  index knows who acted, when, and what things call themselves; nothing
  else_ — and three surfaces inside it: the well-known projections table is
  reframed as the **display-name registry** with row 2 `post/v1 → title`
  (nullable `title` on content rows, circuit breakers identical to profile
  `name`); **`order=genesisAt.desc|headAt.desc`** time-ordered enumeration on
  `/index/v0/identities` and `/index/v0/content` (composite keyset, opaque
  cursor tokens, lexical default unchanged); and a **`signer=`** actor filter
  on `/index/v0/content` (chains where the DID signed ≥1 accepted operation,
  branch-inclusive, includes the creator). Go SQLite schema adds
  `index_content.title`, a `content_signers` table, and ordering indexes;
  `IndexProjectionVersion` bumps to 2, so SQLite relays rebuild the index on
  first boot after upgrading.

## [0.21.0] — 2026-07-07

The second (and last planned) pre-adoption amendment to `post/v1`, plus
identity-index ergonomics. The `post/v1` breaking window closes for good when
post chains are first publicly served.

### Added

- **`?nameContains=` substring filter on the identity index** —
  `/index/v0/identities` gains case-insensitive substring matching on the
  indexed profile name (TS + Go). (#187)

### Changed

- **`post/v1` second pre-adoption amendment** — amended in place before public
  serving: `topics` is removed (mutable taxonomy doesn't belong in immutable
  documents), `format` is narrowed to `short-post` / `long-post` (comments and
  replies will be their own schema with target linkage), `body` is declared
  CommonMark markdown, and optional `publishedAt` records the author-asserted
  publication time separately from operation `createdAt` — author-revisable, so
  deliberate back-dating is an ordinary audited amend. (#188)

### Fixed

- **`IndexCredentialRow` re-exported from the `dfos-web-relay` package
  root.** (#186)

## [0.20.0] — 2026-07-06

The first `post/v1` pre-adoption amendment, plus public-credential discovery
on the index namespace.

### Added

- **`/index/v0/credentials`** — public-credential discovery by issuer and
  resource, including `chain:*` union semantics (TS + Go, conformance-locked
  3-way). (#184)
- **`documentCID` exact-match filter on `/index/v0/content`.** (#182)

### Changed

- **`post/v1` pre-adoption amendment** — amended in place while zero `post/v1`
  documents existed on any chain. `createdByDID` is replaced by ordered
  `credits: [{did, label?}]` (first entry = primary author), `cover` and
  `attachments` now use the standard Media object `{ uri, cid?, href? }`, and the
  legacy `{ id, uri? }` post-media shape is removed. `CONTENT-MODEL.md` now
  documents the Authorship lattice (assertion -> claim-operation proof ->
  sovereign). (#183)

## [0.19.0] — 2026-07-05

### Added

- **Materialized O(page) `/index/v0` projection** — the reference relay (TS +
  Go) serves index queries from an incrementally-maintained projection instead
  of scanning the op log per request. (#175)

## [0.18.0] — 2026-07-05

### Added

- **`/index/v0` — non-authoritative query namespace** — spec plus reference
  implementation of the relay-asserted discovery routes (identities, content,
  operations); everything served is re-verifiable against the proof plane.
  (#172, #173)

## [0.17.0] — 2026-07-04

The last pre-adoption breaking amendment to the reference relay wire — a
single, deliberate break that froze the non-proof surfaces before external
adoption, so the freeze protects adopters. (#165, docs sync #166, conformance
guardrails #167)

### Added

- **Well-known enrichment** — `peers[]` plus `stats.{opCount,countsByKind,oldestOpAt,headCid}`
  via an optional store capability. Additive and non-breaking.

### Changed

- **`/revocations/v1` frozen at v1** — the revocation status family is promoted
  to a frozen v1 contract, and its issuer feed is now bounded with a
  `limit` + `after` + `next` cursor ordered by revocation `createdAt`
  (tiebreak `credentialCID`). Every list route now uses one cursor paradigm; the
  countersignature read returns `{ cid, countersignatures, next }`.

### Removed

- **Operation-scoped countersignature route** —
  `GET /proof/v1/operations/:cid/countersignatures`; the primary
  `/proof/v1/countersignatures/:cid` route serves any CID-addressable target.
- **Documents route and store surface** — `GET /content/:contentId/documents`
  is removed; compose `/proof/v1/content/:contentId/log` with the blob routes
  instead. `getDocuments` / `StoredDocument` are removed from the store
  interface.

## [0.16.0] — 2026-07-03

Protocol-package additions (a new `./fold` subpath, the `index/v1` standard
schema, and the Media object + `profile/v1` avatar vocabulary) plus
lockstep-pending relay and documentation work, all additive atop frozen v1.
The headline lockstep surface is the reference relay's `/revocations/v1`
query routes (below) — the read plane that makes credential revocation
observable to zero-trust callers. The private `dfos-client` gains a
revocation checker wired to those routes, and the private `dfos-explorer`
surfaces per-relay revocation-feed honesty; neither is published (they ride
the published `dfos-protocol` + `dfos-web-relay` pair).

### Added

- **Global-log read ergonomics (`dfos-web-relay` + `dfos-client`)** —
  `PeerLogEntry` and `LogOp` now carry the relay's per-entry `kind` / `chainId`
  as typed OPTIONAL fields (the global `/log` has always served them; the types
  dropped them). Documented as relay-asserted routing hints for
  indexers/browsers — never a verification input. `client.globalLog` gains a
  `limit` option (1–1000, clamped to the relay window; default 100 unchanged)
  so sync engines can pull big pages. Driven by the dfos-explorer full-log
  sync, the client's first real consumer. (#154)
- **`@metalabel/dfos-explorer` scaffolded (private, local-only)** — a
  client-side-only chain explorer over untrusted relays: two-beat
  claim→verified views for identities / content / operations / credentials,
  full-log sync into a normalized IndexedDB local index (chains fold offline),
  in-tab canonical fold for `index/v1` chains, Media object integrity
  re-hashing, per-relay revocation-feed honesty, quorum + provenance as
  first-class UI. A nav-resilient global sync engine with live progress and an
  opt-in background auto-sync scheduler, JIT chain indexing on visit, verified
  profile rendering + a relay browser, byte-accurate index storage stats, and
  related-credential surfacing on content chains round it out. Not published,
  not deployed — the first full consumer of `@metalabel/dfos-client`. (#149,
  #150, #151, #152, #153, #155, #156, #157, #158, #159, #160, #161)
- **`@metalabel/dfos-web-relay/peer-client` subpath export** — a lightweight,
  server-free entry for relay CONSUMERS: `createHttpPeerClient` (which now accepts
  an optional injected `fetch` for timeouts/retries/tests), the `PROOF_BASE_PATH` /
  `REVOCATIONS_BASE_PATH` route-prefix constants, and the `PeerClient` /
  `PeerLogEntry` types. Importing it pulls none of the relay server graph (no hono,
  no zod, no stores). Purely additive — the root export is unchanged. First
  consumer: `@metalabel/dfos-client`. (#147)
- **`@metalabel/dfos-client` scaffolded (private, pre-release)** — the high-level
  read client: resolve + verify orchestration over untrusted relays, trust-as-data
  (`Resolved<T>`), quorum by response digest, cache-the-log + verify-forward,
  `./siwd` (canonical signing-input byte contract + no-throw verifier) and
  `./store` (memory + IndexedDB) subpaths. Not published — ships with a future
  stamped release. (#147)
- **Media object + `profile/v1` additive `avatar` field** — the content model now
  defines the canonical **Media object** shape `{ uri, cid?, href? }`: `uri`
  (required) is the canonical reference — an `attachment://<id>` ref (opaque,
  host-scoped, resolution host/gateway-dependent, no integrity of its own) or any
  other URI; `cid` (optional) is a verifiable commitment to the bytes — CIDv1, raw
  codec (`0x55`), sha2-256, base32 lowercase (`bafkrei…`), computed over the media
  bytes exactly as stored/served; `href` (optional) is a non-normative resolution
  hint with no integrity promise. First consumer: `profile/v1` gains an OPTIONAL
  `avatar` field of the Media shape — strictly additive, existing avatar-less
  profile documents remain valid (no `profile/v2`). `post/v1`'s legacy `{ id, uri? }`
  media shape is unchanged within its version. Content-schema `0.x` clock only; no
  wire change, no gateway primitive. (#148)
- **Canonical fold library + `index/v1` standard schema** — a new
  `@metalabel/dfos-protocol/fold` subpath exporting pure functions over
  already-verified operations (zero crypto or network imports): `linearize(ops)`
  (deterministic total order over ALL operations in a chain's log — every branch —
  `createdAt` ascending with operation-CID ascending tiebreak, the head-selection
  comparator generalized so the head-preferred op sorts last and last-applied wins),
  `foldLwwMap(deltas)` (generic LWW-Map fold), and `foldIndexV1(ops)` (the
  `index/v1` fold). Ships with the new hosted **`index/v1`** standard schema — an
  index chain is an LWW-Map of content refs folded via the canonical fold, with
  `set`/`remove` deltas, optional `{ label, order }` entry metadata, and unknown
  delta shapes skipped deterministically (forward compat). The reference relay's
  deterministic head selection now imports the shared comparator
  (`compareHeadPreference`) so head selection and the fold cannot drift —
  behavior-identical, no wire change. Specced in `CONTENT-MODEL.md` (the Canonical
  Fold and Index sections) on the content-schema `0.x` clock; the frozen v1 wire is
  untouched. (#146)
- **Relay revocation-status query routes** — a new own-clock `/revocations/v1` route
  family on the reference relay: `GET /revocations/v1/credential/:cid` (status of a
  single credential — the signed revocation operation if revoked, an honest not-found
  otherwise) and `GET /revocations/v1/issuer/:did` (revocations published by an
  issuer). Answers are self-proving: every positive response carries the revocation
  JWS, so a zero-trust caller re-verifies the issuer's signature instead of trusting
  the relay's word — and absence is never proof of non-revocation. Advertised via a
  new `capabilities.revocations` flag; a relay without the index reports `false` and
  501s the routes, mirroring the content/log capability semantics. Implemented
  identically in the TypeScript relay and the Go twin, with conformance and
  dual-relay byte-parity coverage. (#143)

### Changed

- **Relay store interface — breaking for store implementers.** The relay storage
  interface gained two revocation-query methods to back the routes above:
  `getRevocationForCredential` / `getRevocationsByIssuer` on the TypeScript
  `RelayStore` interface, and their twins `GetRevocationForCredential` /
  `GetRevocationsByIssuer` on the Go `Store` interface. Third-party store
  implementations must add them. This is a relay-embedding surface change only — the
  v1 wire remains frozen and no corpus re-mint is required. (#143)
- **Documentation drift pass** — OpenAPI corrections (capabilities shape,
  `ContentChainResponse`, `stats.pendingOps`), the `WEB-RELAY.md` documents-endpoint
  cursor pagination and the credential `chainId` indexer note, and a
  `DOCUMENT-GATEWAY.md` blob byte-encoding pin. Prose only; no normative spec
  semantics changed. (#142)

## [0.15.0] — 2026-07-01

No protocol-package changes. Lockstep release that makes `did:dfos` publicly
resolvable: the reference relay gains a **universal resolver** at
`GET /1.0/identifiers/:did` — a root-level route on the DIF driver's own `1.0`
clock, returning a DIF resolution-result envelope wrapping a W3C DID Document
projected from verified identity state. Read-only, self-certifying, zero new
crypto; implemented identically in the TypeScript relay and the Go twin with
dual-relay byte-parity coverage (#141). Ships alongside a public-repo prose
audit (#139) and the rename of the discussion space to "DFOS" (#140).

## [0.14.4] — 2026-06-30

No protocol-package changes. Lockstep release with a CLI fix: concurrent `dfos`
invocations now serialize on a cross-process state lock, closing a config/keystore
write race under parallel `identity create` (#138).

## [0.14.3] — 2026-06-29

No protocol-package changes. Lockstep release with a relay fix: the operation-log
endpoint returns a resume cursor on its final (partial) page, ending the
anti-entropy tail re-pull between meshed relays (#137).

## [0.14.2] — 2026-06-29

No protocol-package changes. Lockstep release with a relay fix: gossip-pushed and
directly-written content now materializes on follower relays (#136).

## [0.14.1] — 2026-06-29

No protocol-package changes. Lockstep release with relay/CLI fixes: event-driven
content materialization removes the follower's steady-state CPU peg (#134), and
`credential grant` now actually publishes the minted credential (#135).

## [0.14.0] — 2026-06-29

No protocol-package changes. Lockstep release that introduces the **content plane**
on the reference relay — all additive, atop frozen v1: eager content-byte
materialization for followers (`CONTENT_FOLLOW`, #131), follow hardening with
triggers / circuit-breaker / GC (#132), real-HTTP content-following conformance
(#133), and a batch of relay anti-entropy fixes (#116–#120).

## [0.13.6] — 2026-06-28

### Added

- **did:dfos well-formedness validation** — malformed and non-canonical-width DIDs
  are rejected at parse time, identically in TS and Go. Valid v1 DIDs are
  unaffected; the 31-character canonical width is unchanged. (#122)

## [0.13.3] – [0.13.5] — 2026-06-26

No protocol-package changes. Lockstep releases with relay, site, and CLI work
(profile content chains, write-disabled conformance, deploy fixes).

## [0.13.2] — 2026-06-25

### Changed

- **`profile/v1` content schema** is now `{name?, description?, links?}` — media
  fields dropped, a `links` array added. This is a content-model vocabulary change
  on the schema library's own `0.x` clock, not a core-wire change. (#115)

## [0.13.1] — 2026-06-25

No protocol-package changes. Lockstep release with a relay packaging fix (inline
version; drop `createRequire(import.meta.url)`, #114).

## [0.13.0] — 2026-06-24

The final **pre-v1-freeze breaking pass**: the v1 wire surface is narrowed and the
last cross-implementation determinism forks are pinned, after which the v1 core is
frozen. Every entry is a pre-v1 breaking wire change — adopting it requires a corpus
re-mint, never an automatic update.

### Changed

- **[BREAKING]** Narrowed the v1 wire surface: dropped the `note` field, relabeled
  `baseDocumentCID`, and pinned + tightened the anchor grammar, so TS and Go agree
  by construction. (#110)
- **[BREAKING]** Converged credential `action` canonicalization — TS now drops empty
  elements to match Go — and pinned the grammar normatively. (#107)
- Pinned three determinism grammars normatively as v1-freeze preparation (#104), and
  corrected the delegation depth-limit wording to **16 credentials, not 16 hops**
  (#102).

## [0.12.0] — 2026-06-23

Completes the proof-layer **bounds refactor**: the per-field string-length caps
collapse into a single aggregate op-size bound, the cardinality caps are raised, and
the remaining cross-implementation validity forks (artifact `$schema`, delegation
depth) are closed so TS and Go agree by construction. Every entry is a pre-v1
breaking wire change — adopting it requires a corpus re-mint, never an automatic
update.

### Changed

- **[BREAKING]** Raised the keys-per-role cardinality cap from 16 to **256** (each of
  `authKeys`/`assertKeys`/`controllerKeys`) and the `services` entry cap from 16 to
  **256**, with the canonical `services` byte cap raised 8192 → **32768** so 256
  entries are reachable. These are generous cardinality bounds; the op-size cap
  (65536) remains the real byte arbiter. Validity-determining and enforced
  identically in TS and Go. (#90)
- **[BREAKING]** Collapsed the per-field string-length caps on identity and content
  operations into a single aggregate **65536-byte (64 KiB)** bound on the
  dag-cbor-encoded operation payload, measured over the exact bytes the CID commits
  to. The dropped caps (`did≤256`, `key.id≤64`, multibase `≤128`, `prevCID≤256`,
  `documentCID≤256`, `note≤256`) were TS-only with no spec mandate and forked
  validity — the Go relay accepted ops TS rejected. The aggregate bound is
  identical-by-construction across implementations. Credentials are exempt: they are
  bounded by delegation depth, and a max-depth chain legitimately exceeds 64 KiB. (#87)
- **[BREAKING]** Pinned the delegation-chain depth boundary to **≤16 credentials —
  the 17th is rejected** — identically in TS and Go. Go previously accepted a
  17-credential chain that its `> 16` guard let through while TS rejected it; the Go
  guard moved to `>= 16` so both verifiers agree on the cutoff. Maximum delegation
  depth is validity-determining: a disagreement here forks authorization validity. (#86)

### Removed

- **[BREAKING]** Removed the per-field string-length caps on `services` entries
  (`id`/`type`/`endpoint`/`label`) — they were a defensive measure with no
  cross-implementation backing that forked validity across TS and Go. Entry fields
  are now only required to be non-empty; the single aggregate 32768-byte services
  cap is the bound. Finishes the per-field length-zoo collapse started in #87. (#90)
- **[BREAKING]** Removed the TS-only 256-char length cap on artifact `$schema`.
  Artifacts are now bounded solely by the aggregate 16384-byte payload cap
  (`MAX_ARTIFACT_PAYLOAD_SIZE`); the per-field cap forked artifact validity
  between TS and Go (TS rejected a 257+ char `$schema` that Go accepted) and is
  gone — TS and Go now enforce identical artifact validity. (#92)

## [0.11.0]

### Added

- Identity-chain `services` discovery vocabulary — an optional, controller-signed
  full-state `services` field on identity create/update operations, projected onto
  resolved identity state. Recognized types `DfosRelay` (relay locator) and
  `ContentAnchor` (content-chain contentId or artifact CID), with an open namespace
  for unknown types (preserved and ignored). Capped at 16 entries and 8192
  canonical-CBOR bytes. (#77, #78)
- Optional open-namespace `relation` tag on countersignatures — a 1–64 char string
  naming the nature of the attestation (e.g. `endorses`, `coauthors`, `witnessed`,
  `holds`, `received`). Omitting it is CID-neutral. (#78)

### Removed

- Removed the `beacon` and `manifest` primitives from the protocol. (#78)

## [0.10.0]

### Changed

- **BREAKING:** Widened the `did:dfos` / content-id identifier from 22 to 31
  characters over the 19-symbol alphabet, raising entropy to ~2^131.6 (above the
  128-bit floor; was ~2^93.4). Adopting this width requires a corpus re-mint. (#71)

## [0.9.0]

Baseline of this changelog. Earlier history predates the changelog and is
recorded in the git log and GitHub releases.

[Unreleased]: https://github.com/metalabel/dfos/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/metalabel/dfos/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/metalabel/dfos/compare/v0.14.4...v0.15.0
[0.14.4]: https://github.com/metalabel/dfos/compare/v0.14.3...v0.14.4
[0.14.3]: https://github.com/metalabel/dfos/compare/v0.14.2...v0.14.3
[0.14.2]: https://github.com/metalabel/dfos/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/metalabel/dfos/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/metalabel/dfos/compare/v0.13.6...v0.14.0
[0.13.6]: https://github.com/metalabel/dfos/compare/v0.13.5...v0.13.6

[0.13.3] – [0.13.5]: https://github.com/metalabel/dfos/compare/v0.13.2...v0.13.5
[0.13.2]: https://github.com/metalabel/dfos/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/metalabel/dfos/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/metalabel/dfos/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/metalabel/dfos/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/metalabel/dfos/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/metalabel/dfos/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/metalabel/dfos/releases/tag/v0.9.0

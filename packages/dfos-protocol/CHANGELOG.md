# Changelog

All notable changes to `@metalabel/dfos-protocol` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

DFOS packages release in lockstep: every published `@metalabel/*` package and Go
module shares a single version, cut together from a `v*` tag. An entry here
describes the protocol-package surface of that release.

## [Unreleased]

No protocol-package (`@metalabel/dfos-protocol`) changes. Lockstep-pending relay and
documentation work, all additive atop frozen v1.

### Added

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

[Unreleased]: https://github.com/metalabel/dfos/compare/v0.15.0...HEAD
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

# Changelog

All notable changes to `@metalabel/dfos-protocol` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

DFOS packages release in lockstep: every published `@metalabel/*` package and Go
module shares a single version, cut together from a `v*` tag. An entry here
describes the protocol-package surface of that release.

## [Unreleased]

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

[Unreleased]: https://github.com/metalabel/dfos/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/metalabel/dfos/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/metalabel/dfos/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/metalabel/dfos/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/metalabel/dfos/releases/tag/v0.9.0

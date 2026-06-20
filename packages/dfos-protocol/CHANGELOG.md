# Changelog

All notable changes to `@metalabel/dfos-protocol` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

DFOS packages release in lockstep: every published `@metalabel/*` package and Go
module shares a single version, cut together from a `v*` tag. An entry here
describes the protocol-package surface of that release.

## [Unreleased]

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

[Unreleased]: https://github.com/metalabel/dfos/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/metalabel/dfos/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/metalabel/dfos/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/metalabel/dfos/releases/tag/v0.9.0

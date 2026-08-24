# DFOS Conformance

> **Status — companion document, no clock of its own.** This document defines no protocol rules; it tiers and indexes the normative MUST sets of the specs it cites, and is corrected in place as they evolve.

What it means to be a _conformant_ DFOS implementation, by tier, and how to prove it
against the existing proving corpora. This document defines no new protocol rules — it
points at the normative MUST sets already specified in
[PROTOCOL.md](https://protocol.dfos.com/spec),
[CREDENTIALS.md](https://protocol.dfos.com/credentials),
[CREDITS.md](https://protocol.dfos.com/credits),
[WEB-RELAY.md](https://protocol.dfos.com/web-relay),
[DID-METHOD.md](https://protocol.dfos.com/did-method), and
[SIGNING.md](https://protocol.dfos.com/signing) (`0.x`), and binds each tier to the tests
that exercise it.

This spec is under active review. Discuss it in the [DFOS](https://nce.dfos.com) space.

---

## Conformance Tiers

Three roles. They compose: a relay is also a verifier; a signer relies on a verifier to
be checkable. Each tier's normative MUST set lives in the referenced spec sections — this
document points, it does not restate every rule.

### Tier 1 — Verifier

A verifier consumes signed objects and decides accept/reject. It implements:

- **Signature Verification Profile** — `alg: "EdDSA"` exact-match, `crit` rejection,
  no header-key-trust (`jwk`/`x5c` rejected), canonical scalar `S < L`, 64-byte length
  (PROTOCOL.md "Signature Verification Profile" §1–§4, `specs/PROTOCOL.md`). Applies
  to **every** verification path.
- **Identity chain verification** — genesis bootstrap, signer-validity against prior
  controller state, `previousOperationCID` linkage, `createdAt` ordering, `header.cid`
  consistency, terminal-state enforcement (PROTOCOL.md "Verification → Identity Chain",
  `specs/PROTOCOL.md`; "Identity Chain Signer Validity", `specs/PROTOCOL.md`;
  DID-METHOD.md §5.2.1, `specs/DID-METHOD.md`).
- **Content chain verification** — valid EdDSA signature, `kid`-DID matches payload `did`,
  CID integrity, chain linkage, terminal state, and creator-sovereignty authorization when
  `enforceAuthorization` is enabled (PROTOCOL.md "Verification → Content Chain",
  `specs/PROTOCOL.md`; "Content Chain Signer Model", `specs/PROTOCOL.md`).
- **Services projection** — project the identity-chain `services` array into verified
  identity state as full-state discovery vocabulary: enforce ≤ 256 entries, `id`s unique
  within the set, the 32768-byte CBOR-encoded cap, and recognized-type structure
  (`DfosRelay` requires `endpoint`, `ContentAnchor` requires `label` + `anchor`); preserve
  but ignore unrecognized `type`s (MUST-ignore-unknown) (PROTOCOL.md "Services",
  `specs/PROTOCOL.md`).
- **Derivation** — DID/CID/multikey: dag-cbor canonical encoding with integer (not float)
  number encoding, CIDv1 construction, the 19-char/31-length ID alphabet, W3C Multikey
  (PROTOCOL.md "CID Construction", `specs/PROTOCOL.md`; "Number Encoding",
  `specs/PROTOCOL.md`; "ID Alphabet", `specs/PROTOCOL.md`; "Multikey Encoding",
  `specs/PROTOCOL.md`).
- **Credential verification** (if it consumes credentials) — delegation walk, monotonic
  attenuation, linear (single-parent) `prf`, expiry narrowing against a deterministic time
  basis, depth limit, revocation at every level (CREDENTIALS.md "Verification Walk" /
  "Attenuation Rules" / "Revocation", `specs/CREDENTIALS.md`, `specs/CREDENTIALS.md`,
  `specs/CREDENTIALS.md`).
- **Credit-claim verification** (if it renders attribution) — the 4096-byte aggregate token
  cap checked before any decode, `typ` equal to `did:dfos:credit-claim`, the `cid` header
  present and re-derived, `kid`-DID equal to payload `did`, and the **full three-component
  bind** on `(contentId, did, role)` compared byte-exact against the hosting entry. Two
  rules are easy to get backwards and are normative: verification MUST NOT consult the
  claimant's `isDeleted` state (a tombstoned claimant's credit still verifies — attribution
  is history, authorization is standing), and the **`invalid` vs `unverifiable`** verdicts
  MUST stay distinct, with neither rendered as `unclaimed` (CREDITS.md "Verification
  Algorithm" / "Verification States" / "Two-Way Binding", `specs/CREDITS.md`).
- **Sign-request envelope verification** (if it consumes sign requests; SIGNING `0.x`) —
  the 8192-byte token cap checked before any decode, the profile header gates, `typ`
  exactly `did:dfos:sign-request`, payload schema, unpadded-base64url target bytes
  (non-empty, ≤ 4096), `kid`-DID equal to payload `did`, **current-state** requester
  resolution (the auth-token rule, not the credential rule — deliberate), signature, CID
  integrity, the ≤ 7-day temporal window, and the same structural `invalid` vs
  `unverifiable` verdict split (SIGNING.md "Verification Algorithm", `specs/SIGNING.md`).

### Tier 2 — Signer

A signer emits well-formed envelopes that a Tier-1 verifier accepts. It implements:

- **JWS Envelope Format** — signing input construction, signing order (derive CID before
  signing, embed in protected header) (PROTOCOL.md "JWS Envelope Format" / "`cid` Header",
  `specs/PROTOCOL.md`, `specs/PROTOCOL.md`).
- **`kid` rules** — bare key ID for identity genesis, DID URL otherwise; content ops always
  DID URL (PROTOCOL.md "kid Rules", `specs/PROTOCOL.md`).
- **`cid` header** — present on every operation JWS, artifacts, countersignatures,
  credentials, revocations, credit claims, and sign-request envelopes; absent on
  auth-token JWTs (PROTOCOL.md "`cid` Header", `specs/PROTOCOL.md`).
- **Credit-claim emission** (if it signs attribution) — derive `kid` from the claimant DID
  so a `kid`↔`did` mismatch is unrepresentable, bind to the chain's 31-char `contentId`
  (never a `documentCID` or head CID), omit `asOfDocumentCID` rather than emitting it empty,
  and refuse to emit a token over the 4096-byte cap. A signer MUST NOT mint a claim its own
  verifier would reject (CREDITS.md "The Credit Claim Envelope", `specs/CREDITS.md`).
- **Canonicalization discipline** — integer number bounds, no Unicode normalization, no
  duplicate keys (PROTOCOL.md "Number Encoding" / "String Encoding" / "JSON Payload
  Canonicalization", `specs/PROTOCOL.md`, `specs/PROTOCOL.md`, `specs/PROTOCOL.md`).
- **WYSIWYS signer obligations** (if it signs on request; SIGNING `0.x`) — the heaviest
  signer MUST set in the corpus: subject-is-self, refuse unimplemented `payloadTyp`s,
  strict target-schema validation with **no unknown fields**, re-canonicalize-and-
  byte-compare against the decoded input, render only from the validated parse, sign the
  **original** bytes (SIGNING.md "Signer Obligations (WYSIWYS)", `specs/SIGNING.md`).
  The adversarial canonicalization vector set shipped with the reference packages
  (duplicate keys, non-shortest numbers, permuted order, whitespace, unicode escapes,
  unknown fields, sub-second timestamps) is the proving corpus; an independent signer
  copies it wholesale.

### Tier 3 — Relay

A relay ingests, sequences, and serves. It implements:

- **Ingestion** — single `POST /proof/v1/operations` endpoint, `typ`-based classification,
  dependency sort, per-type verification, store-then-verify convergence (WEB-RELAY.md
  "Operation Ingestion" / "Convergence", `specs/WEB-RELAY.md`, `specs/WEB-RELAY.md`).
- **Sequencing & fork handling** — content-chain fork acceptance and deterministic head
  selection, identity-chain linearity (permanent refusal of conflicting extensions),
  ingestion statuses, deletion + restore semantics (WEB-RELAY.md "Fork Acceptance" /
  "Identity Linearity and Order Authority" / "Ingestion Statuses" / "Deletion Semantics",
  `specs/WEB-RELAY.md`).
- **Capability / feature flags + 501 semantics** — the well-known response advertises
  capabilities; unsupported optional features return **501 Not Implemented** (not 404)
  (WEB-RELAY.md "Well-Known Endpoint", `specs/WEB-RELAY.md`; "Two Planes",
  `specs/WEB-RELAY.md`). The `revocations` gate is currently proven by in-package unit
  tests in both reference relays; no disabled-mode live serve variant exists yet (the
  conformance suite's disabled tests self-skip unless a relay advertises `false`).
- **Index (`/index/v0`)** (if served) — the optional, non-authoritative identity,
  content, countersignature, credential, and credit projections; actor/name/public-read
  filters; deterministic ordering; and complete keyset/ordered-cursor walks live in the
  relay tier on the index family's own `0.x` clock (WEB-RELAY.md "Index (v0)",
  `specs/WEB-RELAY.md`). The credits family additionally carries the credit projection's
  public-only / head-only / full-replace rules — rows exist only for publicly readable,
  non-deleted chains with held head bytes, and a chain's row set always restates the
  current head document or is empty. A relay advertising `capabilities.index: false` returns **501
  Not Implemented** from every `/index/v0/*` route while adjacent proof/content surfaces
  remain available. Given the same accepted operations and held blobs, parity means the
  reference relays serve byte-identical canonicalized-JSON rows, ordering, filters, and
  cursor pages.
- **List-route pagination envelope** — `limit` (default 100, max 1000, clamp above max) +
  `after` + `next`, with the per-route cursor behavior (relay-local 400 / transparent
  keyset / opaque token) as specified per route (WEB-RELAY.md "Error Responses" and each
  route's section, `specs/WEB-RELAY.md`).

**The content plane is OPTIONAL.** A compliant relay **always** serves the proof plane
(`capabilities.proof: false` is not a valid value); when `capabilities.content: false`,
all content-plane routes return 501 (WEB-RELAY.md "Well-Known Endpoint",
`specs/WEB-RELAY.md`). Proof-plane-only is a fully conformant relay. The content plane is
the [document gateway](https://protocol.dfos.com/document-gateway), an optional service on
its own `0.x` clock — outside the v1 conformance tiers.

**Writes are OPTIONAL too.** A lite (pull-only) proof node MAY advertise
`capabilities.write: false`, in which case every write route returns **501 Not
Implemented** — `POST /proof/v1/operations` and the content-plane blob upload
`PUT /content/{contentId}/blob/{ref}` — while read routes on both planes remain
conformant; the node stays current
by pulling peers' logs (WEB-RELAY.md "Lite (pull-only) node"). So a conformant proof node
need not accept writes — only serve and verify them. A read-only node cannot be seeded by
the suite (its POSTs 501), so the write-disabled variant verifies it by **recomputing from
the log**: it pulls a served chain's log and independently re-derives the head and state,
asserting the relay's served state matches. The served state must be reproducible from the
served operations alone — which needs no write.

---

## Proving Corpora

Each tier maps to an existing test suite. The mapping is deliberately honest about what
each suite actually exercises.

| Tier              | Corpus                                          | What it proves                                               |
| ----------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| Verifier / Signer | `packages/protocol-verify` (5 languages)        | Single-JWS primitives: signature, field equality, derivation |
| Verifier / Signer | `packages/dfos-protocol/tests` (TS)             | Full chain/authz semantics                                   |
| Verifier / Signer | PROTOCOL.md "Deterministic Reference Artifacts" | Reproducible reference vectors from fixed seeds              |
| Relay             | `packages/relay-conformance` (Go)               | HTTP integration against any live relay                      |

### Verifier / signer corpora

- **`packages/protocol-verify`** — the five-language re-derivation suite (TypeScript, Go,
  Python, Rust, Swift). Each suite is **standalone**: native crypto only, no DFOS library
  imports, reference constants hardcoded inline (the same deterministic values published in
  PROTOCOL.md). See `packages/protocol-verify/README.md`.
- **`packages/dfos-protocol/tests`** — the TypeScript reference test suite.
- **Deterministic reference artifacts** — PROTOCOL.md "Deterministic Reference Artifacts"
  (`specs/PROTOCOL.md`) and the "Verification Checklist for Independent Implementers"
  (`specs/PROTOCOL.md`) provide every value an implementer needs to self-check, derived
  from `SHA-256("dfos-protocol-reference-key-N")`.

**Honest coverage statement.** The cross-language `protocol-verify` suites prove
**single-JWS primitives** — signature verification, field equality, and derivation
(key, multikey, CID, DID, document CID, credential structure, number-encoding
determinism — the sections in `packages/protocol-verify/README.md`). They do **not**
all exercise the stateful chain semantics. Per the cross-language table in PROTOCOL.md,
the five `protocol-verify` suites all run the same primitive set (TypeScript 81, Go 20,
Rust 20, Python 82, Swift 19); the deep stateful chain-tier coverage lives separately in
the TypeScript reference suite (`dfos-protocol/tests`, 402) and the Go library suite.
**Chain linking,
content fork/head-selection, identity linearity, delete/restore semantics, and credential
expiry/delegation are exercised in the TypeScript and Go suites, not in all five
languages.** A claim of full chain-tier
conformance rests on the TS + Go corpora; the five-language suite proves the cryptographic
core is unambiguous across languages.

### Relay corpus

- **`packages/relay-conformance`** — a Go integration suite that runs against **any live
  relay endpoint** over HTTP. It exercises the relay-tier MUST set (ingestion, sequencing,
  content-fork acceptance, head convergence, identity linearity + restore, capability
  flags, 501 semantics, deletion semantics)
  against the running service rather than the library. Capability-gated variants self-skip
  unless the relay advertises the matching flag: the content-disabled suite (501 on every
  content route when `capabilities.content: false`), the write-disabled suite
  (`scripts/run-write-disabled.sh` — recompute-from-log read-only conformance when
  `capabilities.write: false`), the index-disabled suite
  (`scripts/run-index-disabled.sh` — 501 on every `/index/v0/*` route with adjacent
  surfaces unaffected), and the signing pair — enabled-behavior tests that run only when
  `capabilities.signing: true` (`scripts/run-signing.sh`), and a disabled suite asserting
  501 on every `/signing/v0/*` route when the flag is `false` or absent (SIGNING.md). The
  dual-relay parity harness (`scripts/run-parity.sh`) additionally compares index filter,
  ordered-query, and full multi-page cursor responses over the same fixture.
- **Content following** is inherently a **two-relay** behavior (a follower materializing an
  origin's bytes), so it is exercised in the Go relay library's race-tested in-package suite
  rather than the single-endpoint conformance corpus. An origin and an eager follower are
  wired over loopback HTTP; the suite asserts the full lifecycle —
  authorized-but-not-yet-materialized (blob `404`), then eventual
  materialization of content-address-verified bytes, then revoke (the serve gate denies
  while bytes are still cached), then GC reclamation — over the real `HttpPeerClient` and
  content-plane HTTP routes. See WEB-RELAY.md "Content Following".

---

## Self-Certification Procedure

A third party claims conformance by running the corpus that matches its tier. No central
authority grants conformance — the proofs are reproducible and the claim is self-certifying,
mirroring the protocol's own trust model.

1. **Verifier / signer.** Implement the Tier-1/Tier-2 MUST sets using your own crypto stack.
   Reproduce the deterministic reference artifacts (PROTOCOL.md "Verification Checklist",
   `specs/PROTOCOL.md`) and, ideally, add a suite to `packages/protocol-verify`
   following its "Adding a New Language" steps — hardcoding the same reference constants
   inline so the suite is standalone. Agreement across suites is the proof; divergence
   means the spec (or your implementation) is wrong.
2. **Relay.** Stand up your relay and run `packages/relay-conformance` against its endpoint.
   A passing run demonstrates the relay-tier MUST set against the live service. Declare
   your capability flags honestly in `/.well-known/dfos-relay`; a proof-plane-only relay
   is conformant.
3. **Scope your claim.** State which tier(s) you claim and which corpora you ran. Per the
   honest-coverage statement above, "verifier conformant via the five-language primitive
   suite" is a narrower claim than "chain-tier conformant via the TS/Go suites" — say which.

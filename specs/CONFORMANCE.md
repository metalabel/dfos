# DFOS Conformance

What it means to be a _conformant_ DFOS implementation, by tier, and how to prove it
against the existing proving corpora. This document defines no new protocol rules — it
points at the normative MUST sets already specified in
[PROTOCOL.md](https://protocol.dfos.com/spec),
[CREDENTIALS.md](https://protocol.dfos.com/credentials),
[WEB-RELAY.md](https://protocol.dfos.com/web-relay), and
[DID-METHOD.md](https://protocol.dfos.com/did-method), and binds each tier to the tests
that exercise it.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

---

## Conformance Tiers

Three roles. They compose: a relay is also a verifier; a signer relies on a verifier to
be checkable. Each tier's normative MUST set lives in the referenced spec sections — this
document points, it does not restate every rule.

### Tier 1 — Verifier

A verifier consumes signed objects and decides accept/reject. It implements:

- **Signature Verification Profile** — `alg: "EdDSA"` exact-match, `crit` rejection,
  no header-key-trust (`jwk`/`x5c` rejected), canonical scalar `S < L`, 64-byte length
  (PROTOCOL.md "Signature Verification Profile" §1–§4, `specs/PROTOCOL.md:443`). Applies
  to **every** verification path.
- **Identity chain verification** — genesis bootstrap, signer-validity against prior
  controller state, `previousOperationCID` linkage, `createdAt` ordering, `header.cid`
  consistency, terminal-state enforcement (PROTOCOL.md "Verification → Identity Chain",
  `specs/PROTOCOL.md:664`; "Identity Chain Signer Validity", `specs/PROTOCOL.md:96`;
  DID-METHOD.md §5.2.1, `specs/DID-METHOD.md:162`).
- **Content chain verification** — valid EdDSA signature, `kid`-DID matches payload `did`,
  CID integrity, chain linkage, terminal state, and creator-sovereignty authorization when
  `enforceAuthorization` is enabled (PROTOCOL.md "Verification → Content Chain",
  `specs/PROTOCOL.md:678`; "Content Chain Signer Model", `specs/PROTOCOL.md:102`).
- **Derivation** — DID/CID/multikey: dag-cbor canonical encoding with integer (not float)
  number encoding, CIDv1 construction, the 19-char/31-length ID alphabet, W3C Multikey
  (PROTOCOL.md "CID Construction", `specs/PROTOCOL.md:226`; "Number Encoding",
  `specs/PROTOCOL.md:241`; "ID Alphabet", `specs/PROTOCOL.md:186`; "Multikey Encoding",
  `specs/PROTOCOL.md:199`).
- **Credential verification** (if it consumes credentials) — delegation walk, monotonic
  attenuation, linear (single-parent) `prf`, expiry narrowing against a deterministic time
  basis, depth limit, revocation at every level (CREDENTIALS.md "Verification Walk" /
  "Attenuation Rules" / "Revocation", `specs/CREDENTIALS.md:136`, `specs/CREDENTIALS.md:154`,
  `specs/CREDENTIALS.md:270`).

### Tier 2 — Signer

A signer emits well-formed envelopes that a Tier-1 verifier accepts. It implements:

- **JWS Envelope Format** — signing input construction, signing order (derive CID before
  signing, embed in protected header) (PROTOCOL.md "JWS Envelope Format" / "`cid` Header",
  `specs/PROTOCOL.md:380`, `specs/PROTOCOL.md:405`).
- **`kid` rules** — bare key ID for identity genesis, DID URL otherwise; content ops always
  DID URL (PROTOCOL.md "kid Rules", `specs/PROTOCOL.md:390`).
- **`cid` header** — present on every operation JWS, beacons, credentials, revocations;
  absent on auth-token JWTs (PROTOCOL.md "`cid` Header", `specs/PROTOCOL.md:405`).
- **Canonicalization discipline** — integer number bounds, no Unicode normalization, no
  duplicate keys (PROTOCOL.md "Number Encoding" / "String Encoding" / "JSON Payload
  Canonicalization", `specs/PROTOCOL.md:241`, `specs/PROTOCOL.md:253`, `specs/PROTOCOL.md:257`).

### Tier 3 — Relay

A relay ingests, sequences, and serves. It implements:

- **Ingestion** — single `POST /operations` endpoint, `typ`-based classification,
  dependency sort, per-type verification, store-then-verify convergence (WEB-RELAY.md
  "Operation Ingestion" / "Convergence", `specs/WEB-RELAY.md:46`, `specs/WEB-RELAY.md:618`).
- **Sequencing & fork handling** — fork acceptance, deterministic head selection,
  ingestion statuses, deletion semantics (WEB-RELAY.md "Fork Acceptance" / "Ingestion
  Statuses" / "Deletion Semantics", `specs/WEB-RELAY.md:98`, `specs/WEB-RELAY.md:110`,
  `specs/WEB-RELAY.md:126`).
- **Capability / feature flags + 501 semantics** — the well-known response advertises
  capabilities; unsupported optional features return **501 Not Implemented** (not 404)
  (WEB-RELAY.md "Well-Known Endpoint", `specs/WEB-RELAY.md:252`; "Two Planes",
  `specs/WEB-RELAY.md:40`).

**The content plane is OPTIONAL.** A compliant relay **always** serves the proof plane
(`capabilities.proof: false` is not a valid value); when `capabilities.content: false`,
all content-plane routes return 501 (WEB-RELAY.md "Well-Known Endpoint",
`specs/WEB-RELAY.md:283`). Proof-plane-only is a fully conformant relay.

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
  (`specs/PROTOCOL.md:692`) and the "Verification Checklist for Independent Implementers"
  (`specs/PROTOCOL.md:959`) provide every value an implementer needs to self-check, derived
  from `SHA-256("dfos-protocol-reference-key-N")`.

**Honest coverage statement.** The cross-language `protocol-verify` suites prove
**single-JWS primitives** — signature verification, field equality, and derivation
(key, multikey, CID, DID, document CID, beacon, credential structure, number-encoding
determinism — the 11 sections in `packages/protocol-verify/README.md`). They do **not**
all exercise the stateful chain semantics. Per the cross-language table in PROTOCOL.md
(`specs/PROTOCOL.md:1050`), TypeScript and Go carry the deep suites (224 + 63 TS, 18 Go),
while Python and Swift run only the primitive checks (3 each). **Chain linking,
fork/head-selection, delete-terminality, and credential expiry/delegation are exercised
in the TypeScript and Go suites, not in all five languages.** A claim of full chain-tier
conformance rests on the TS + Go corpora; the five-language suite proves the cryptographic
core is unambiguous across languages.

### Relay corpus

- **`packages/relay-conformance`** — a Go integration suite that runs against **any live
  relay endpoint** over HTTP. It exercises the relay-tier MUST set (ingestion, sequencing,
  fork acceptance, head convergence, capability flags, 501 semantics, deletion semantics)
  against the running service rather than the library.

---

## Self-Certification Procedure

A third party claims conformance by running the corpus that matches its tier. No central
authority grants conformance — the proofs are reproducible and the claim is self-certifying,
mirroring the protocol's own trust model.

1. **Verifier / signer.** Implement the Tier-1/Tier-2 MUST sets using your own crypto stack.
   Reproduce the deterministic reference artifacts (PROTOCOL.md "Verification Checklist",
   `specs/PROTOCOL.md:959`) and, ideally, add a suite to `packages/protocol-verify`
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

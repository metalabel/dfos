# DFOS Threat Model

A consolidated map of the DFOS adversary model and trust boundaries. This document
does not introduce new protocol rules — it assembles the threat surface that is
already specified, in prose, across [PROTOCOL.md](https://protocol.dfos.com/spec),
[CREDENTIALS.md](https://protocol.dfos.com/credentials),
[WEB-RELAY.md](https://protocol.dfos.com/web-relay),
[DID-METHOD.md](https://protocol.dfos.com/did-method), and
[SIWD.md](https://protocol.dfos.com/siwd), and links each claim back to its source.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

---

## Trust Boundaries

DFOS has two planes with fundamentally different trust models.

### Proof plane — self-authenticating, trustless

The crypto core is the trust boundary (PROTOCOL.md "Protocol Overview", `specs/PROTOCOL.md`).
Identity chains, content chains, artifacts, countersignatures, credentials,
and revocations are all signed, content-addressed objects that anyone can verify with
a public key and any standard EdDSA + dag-cbor library. There is no privileged registry,
blockchain, or consensus layer; the identifier _is_ the trust anchor (DID-METHOD.md
"Abstract", `specs/DID-METHOD.md`). Verification is against the chain, not the source
— a `did:dfos` is verified by re-deriving it from the genesis CID (DID-METHOD.md §5.2.3,
`specs/DID-METHOD.md`). All proof-plane relay routes are unauthenticated; the
operations carry their own authentication (WEB-RELAY.md "Proof Plane", `specs/WEB-RELAY.md`).

Everything below the crypto core is cryptographically verified. Nothing above it needs
to be trusted to verify a proof.

### Content plane — honest-host, undisclosed-by-default

The protocol commits to content _hashes_, not plaintext — it does not encrypt
(README.md, `README.md`; PROTOCOL.md "Philosophy", `specs/PROTOCOL.md`).
Confidentiality of the underlying documents is enforced at the application layer by
whoever serves them. **The relay operator can read what it stores.** This is
undisclosed-by-default, _not_ end-to-end encrypted. The content plane never gossips;
blobs are stored by the relay that received them and served only to authorized readers
(WEB-RELAY.md "Content Plane", `specs/WEB-RELAY.md`). Content-plane access is
gated by an auth token plus (for non-creators) a read credential (WEB-RELAY.md
"Content Plane Access", `specs/WEB-RELAY.md`).

The security posture of a document is therefore the security posture of the relay
operator that holds it.

### Countersignatures live on the public proof plane

A countersignature is a proof-plane object (PROTOCOL.md "Countersignatures",
`specs/PROTOCOL.md`). Publishing one permanently and publicly links the witness
DID to its target: anyone can see that this identity attested to that operation. A
countersignature therefore MUST NOT be used to cross a public/private boundary —
witnessing a target that is meant to stay confined to a private context leaks the
witness↔target association onto the public plane, where it is immutable and gossiped.
If the fact of the attestation is itself sensitive, do not countersign.

---

## Adversary Classes

| Adversary                   | Can                                                                                       | Cannot                                                             | Pointer                                                 |
| --------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------- |
| Malicious/Byzantine relay   | Withhold, reorder, equivocate, censor, serve stale state, read stored content-plane blobs | Forge a chain or operation                                         | DID-METHOD.md §6.4 `specs/DID-METHOD.md`                |
| Malicious peer              | Push invalid/spam operations to peers                                                     | Have invalid operations accepted (each peer re-verifies, no trust) | WEB-RELAY.md "Peering" `specs/WEB-RELAY.md`             |
| Unauthenticated submitter   | POST arbitrary JWS to `/proof/v1/operations`; impose CPU + storage cost                   | Have malformed/unsigned ops accepted                               | WEB-RELAY.md "Operation Ingestion" `specs/WEB-RELAY.md` |
| Compromised custody/KMS key | Full, indistinguishable impersonation of the user                                         | Be detected on-chain (signature is valid Ed25519)                  | SIWD.md "Managed Signing Path" `specs/SIWD.md`          |
| Lost key                    | —                                                                                         | — (1-of-N availability vs. total loss)                             | DID-METHOD.md §6.2 `specs/DID-METHOD.md`                |

### Malicious / Byzantine relay

A relay is untrusted by construction. It can **withhold** a chain (denial of service),
**serve stale** state, **reorder** delivery, **equivocate** (serve different views to
different clients), and **censor** operations it dislikes. It can also **read** any
content-plane blob it stores (see Trust Boundaries).

What it **cannot** do is **forge**. Every ingest path re-derives the operation CID and
verifies the Ed25519 signature over the signed bytes (WEB-RELAY.md "Verification",
`specs/WEB-RELAY.md`); peers verify independently with no trust (WEB-RELAY.md
"Peering", `specs/WEB-RELAY.md`). An attacker who intercepts a chain request can
withhold, serve a stale chain, or serve a completely different chain — but a modified
or forged chain fails the self-certification check (DID-METHOD.md §6.4,
`specs/DID-METHOD.md`).

### Malicious peer

Peering carries no inter-relay trust: "No trust between relays, no coordination required"
(WEB-RELAY.md "Philosophy", `specs/WEB-RELAY.md`). A peer that gossips, is read
through, or is synced from has its operations fully re-verified locally before storage
(WEB-RELAY.md "Peering" / "Convergence", `specs/WEB-RELAY.md`, `specs/WEB-RELAY.md`).
A malicious peer can therefore only impose cost and noise, not corrupt state.

### Malicious / unauthenticated submitter

`POST /proof/v1/operations` is unauthenticated (WEB-RELAY.md "Quick Start" route table,
`specs/WEB-RELAY.md`); operations self-authenticate. An attacker can submit
arbitrary JWS tokens, imposing CPU (verification) and storage (store-then-verify
buffering, `specs/WEB-RELAY.md`) cost. Field-size ceilings bound per-operation
abuse (PROTOCOL.md "Operation Field Limits", `specs/PROTOCOL.md`), but
**protocol-layer rate limiting is explicitly deferred** to the deployment layer
(WEB-RELAY.md "What's Deferred", `specs/WEB-RELAY.md`).

### Compromised custody / KMS key

In the SIWD managed-signing path the platform holds the user's key material in a KMS
and signs on their behalf (SIWD.md "Managed Signing Path", `specs/SIWD.md`). A
compromise of that custody is **full impersonation** and is **indistinguishable on-chain**:
the signature is a valid Ed25519 signature by a key declared in the identity chain, so
it verifies identically to a sovereign signature (SIWD.md "Overview" / "Managed Signing
Path", `specs/SIWD.md`, `specs/SIWD.md`). The sovereign path avoids this by never
letting the platform touch the key (SIWD.md "Sovereign Signing Path", `specs/SIWD.md`).

### Lost key

There is no key pre-rotation and no recovery mechanism (DID-METHOD.md §6.2,
`specs/DID-METHOD.md`). The mitigation is **1-of-N availability**: each role set
holds up to 256 keys per role, and any one current key can authorize an operation, so an identity
can spread controller/auth keys across devices and rotate out a lost one from a survivor
(DID-METHOD.md §6.2, `specs/DID-METHOD.md`). This is availability, not recovery — it
requires registering additional keys _in advance_ while a controller key is still held.
It is symmetric with the compromise surface: every additional device key is also another
key to keep safe. Total loss of every key in a role set is unrecoverable.

---

## Self-Certification Binding Strength

`did:dfos` identifiers and content IDs are 31-character strings over a 19-symbol
alphabet (`2346789acdefhknrtvz`), derived as `customAlpha(SHA-256(genesis CID bytes))`
(PROTOCOL.md "ID Alphabet" / "Addressing", `specs/PROTOCOL.md`, `specs/PROTOCOL.md`;
DID-METHOD.md §3.1–§3.2, `specs/DID-METHOD.md`).

```
Identifier space:        19^31 ≈ 2^131.6 bits
Birthday collision:      ≈ 2^65.8
Targeted second-preimage ≈ 2^131.6
```

This is the binding strength **of the identifier**, which is below SHA-256's full
256-bit strength: the identifier truncates and re-encodes the hash. The full 32-byte
genesis CID and the operation signatures are unaffected — this parameter bounds only
how hard it is to find a _second_ chain that encodes to the same 31-character DID/content
ID, or two chains that collide.

This parameter (alphabet size × length) was **widened to 31 characters for v1** — the
targeted second-preimage cost (≈ 2^131.6) now sits above the 128-bit floor, and the
birthday-collision cost rises to ≈ 2^65.8. This is a settled decision for v1, not an open
parameter. See PROTOCOL.md "ID Alphabet" (`specs/PROTOCOL.md`) and DID-METHOD.md §3.1
(`specs/DID-METHOD.md`).

---

## Head Selection Is Convergent, Not Canonical

Deterministic head selection — highest `createdAt`, lexicographic-highest-CID tiebreak —
guarantees that any implementation with the same set of operations computes the same head,
regardless of ingestion order (PROTOCOL.md "Chain Validity", `specs/PROTOCOL.md`;
WEB-RELAY.md "Fork Acceptance", `specs/WEB-RELAY.md`). That is its entire job:
**convergence across implementations.**

It is **not** a canonical-truth or causal-ordering mechanism. `createdAt` is signer-asserted
and bounded only by the relay-enforced +24h future bound (PROTOCOL.md "Future timestamp
bound", `specs/PROTOCOL.md`; WEB-RELAY.md "Future timestamp guard", `specs/WEB-RELAY.md`).
Any current-key holder can therefore **bid** the head by choosing a `createdAt` up to 24
hours ahead — forks are valid, and the highest timestamp wins. Undeletion falls directly
out of this: a controller can fork from before a delete with a higher `createdAt` and make
the non-deleted branch the head (WEB-RELAY.md "Undeletion", `specs/WEB-RELAY.md`;
DID-METHOD.md §5.4, `specs/DID-METHOD.md`).

Head selection answers "which tip do all honest verifiers agree on?" — not "which tip is
true?" or "which happened first?". Semantic interpretation of forks (concurrency glitch,
intentional recovery, equivocation) is application-defined (PROTOCOL.md "Chain Validity",
`specs/PROTOCOL.md`; DID-METHOD.md §6.3 "Equivocation", `specs/DID-METHOD.md`).

---

## Explicitly-Accepted Residual Risks (v1)

These are known and deliberately accepted for v1.

- **No end-to-end encryption.** Content confidentiality is an application-layer concern;
  the relay operator can read stored blobs (README.md, `README.md`; PROTOCOL.md
  "Philosophy", `specs/PROTOCOL.md`; WEB-RELAY.md "Content Plane", `specs/WEB-RELAY.md`).
- **No protocol-layer rate limiting.** Anti-spam / rate limiting is an operational concern,
  pushed to the deployment layer (WEB-RELAY.md "What's Deferred", `specs/WEB-RELAY.md`).
  Blob size limits are likewise unenforced by the protocol (`specs/WEB-RELAY.md`).
- **Public (`aud: "*"`) write credential is a world-writable bearer.** Because `aud: "*"`
  matches any signer, a public credential granting `write` authorizes the _bearer_, not a
  named audience — anyone can attach it inline and write to the covered chains. Public
  credentials SHOULD be read-scoped (CREDENTIALS.md "Security: `aud: "*"` + write",
  `specs/CREDENTIALS.md`).
- **Same-relay auth-token replay until expiry.** Auth tokens are not content-addressed and
  not revocable; they are scoped to a relay via `aud` (preventing cross-relay replay) and
  rely on short lifetime for invalidation (CREDENTIALS.md "Relationship to Auth Tokens",
  `specs/CREDENTIALS.md`; WEB-RELAY.md "Relay Identity", `specs/WEB-RELAY.md`).
  Within the same relay, a captured token is replayable until it expires.
- **SIWD security controls live in the unimplemented third-party verifier.** Replay
  prevention (nonce), redirect-URI allowlisting, challenge-DID binding, and timestamp
  windows are obligations on the verifying third party, and SIWD has no reference
  implementation in this repository yet (SIWD.md note, `specs/SIWD.md`; SIWD.md
  "Security Considerations", `specs/SIWD.md`).

---

## Out of Scope

Mirroring [SECURITY.md](../SECURITY.md) "Scope": out of scope are vulnerabilities in
third-party dependencies (report upstream), and any issue that requires a compromised
host or a user's own private keys (`SECURITY.md` "Scope"). A compromised custody/KMS
key and a lost key are _modeled_ above as adversary classes for completeness, but their
_remediation_ (key hygiene, custody choice) is outside the protocol's integrity
guarantees. In scope for security reporting is anything that breaks integrity,
authenticity, or authorization — signing, JWS construction/verification, dag-cbor
canonical encoding, CID derivation, chain state-machine transitions, credential
verification, and relay auth (see SECURITY.md).

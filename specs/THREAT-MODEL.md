# DFOS Threat Model

> **Status — companion document, no clock of its own.** This document defines no protocol rules; it assembles the adversary model already specified across the normative specs, and is corrected in place as they evolve.

A consolidated map of the DFOS adversary model and trust boundaries. This document
does not introduce new protocol rules — it assembles the threat surface that is
already specified, in prose, across [PROTOCOL.md](https://protocol.dfos.com/spec),
[CREDENTIALS.md](https://protocol.dfos.com/credentials),
[WEB-RELAY.md](https://protocol.dfos.com/web-relay),
[DID-METHOD.md](https://protocol.dfos.com/did-method),
[SIGNING.md](https://protocol.dfos.com/signing),
[SIWD.md](https://protocol.dfos.com/siwd), and
[API-AUTH.md](https://protocol.dfos.com/api-auth), and links each claim back to its source.

This spec is under active review. Discuss it in the [DFOS](https://nce.dfos.com) space.

---

## Trust Boundaries

DFOS has two replicated planes with fundamentally different trust models. The
optional signing mailbox's courier state sits outside both.

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

One property is deliberately **not** carried by the crypto core alone: **currency**. A
signature proves who signed and that the bytes are intact — forever, from anywhere. Whether
a key is _still_ the signer's current key, or a head is _still_ the chain's current head, is
a statement about the freshest state a resolver has seen, and freshness is served, not
proven. Authenticity is trustless; currency is host-mediated — see _Authority currency_
below.

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

### Authority currency — honest-host arbitrated

The same honest-host split that governs content confidentiality governs **how current an
identity's authority is**. An identity chain's proofs verify trustlessly, but its _current
state_ — which keys are live, whether it is deleted — is resolved from whatever log the
chosen relay serves, as fresh as that relay's ingestion (SIWD.md "Staleness caveat",
`specs/SIWD.md`). The subject's own `services` relay list is the designated trust anchor:
resolving a subject through the relays it lists yields the currency the subject stands
behind, and running your own relay makes your authority fully self-sovereign — the
"own your data" escape hatch is structural, not aspirational.

Hosts enforce currency at the door: first admission of a new operation resolves its signer
against **current state** (WEB-RELAY.md "Key Resolution", `specs/WEB-RELAY.md`), so a
rotated-out key's authoring window ends at rotation, while committed history re-verifies
historically forever. Peer-log ingestion inherits the peer's admission discipline —
choosing peers is a trust decision, which is the model working as intended: this protocol
is **selectively trusting** (you pick your hosts and peers, and can be your own), not a
Byzantine-consensus network, and its guarantees are stated accordingly.

Relay resolution is not the only currency source: an identity chain can also arrive by
**carriage** inside an application's own well-known document — a second source with a
different trust texture, covered next.

### Carried identity chains — controller-attested currency

SIWD's app description MAY carry the application identity's full operation log in place
(SIWD.md "`identity_chain` — chain carriage", `specs/SIWD.md`), and any consumer that
encounters the document MAY fetch, verify, ingest, and re-serve that chain with no
registration or approval precondition. Signatures verify identically to a relay-fetched
chain — forgery is a non-issue — but the source is **controller-attested**: the consumer
holds identity state fetched on its own clock from an origin the application itself
controls, with no independent arbiter in the path. An identity whose `services` list
names no relay has no order authority at all — while a carried chain that does name a
`DfosRelay` still answers to that relay's committed order, however the chain was
obtained (WEB-RELAY.md "Identity Linearity and Order Authority", `specs/WEB-RELAY.md`).
The operational consequences are specified as the five carried-chain disciplines
(SIWD.md "Carried identity chains", `specs/SIWD.md`):

- **Rollback by prefix omission.** Serving yesterday's shorter chain resurrects a
  rotated-out key by omitting the rotation. The defense is monotonicity compared on the
  ordered operation-log CIDs — a fetch that is a proper prefix of previously observed
  state SHOULD be ignored; derived-state comparison does not catch this.
- **Signed divergence.** Two chains sharing a prefix and disagreeing after it both
  verify — the controller's key contradicting itself, indistinguishable from a
  compromised key. Acceptance is operator discretion; observed divergence SHOULD be
  logged. Where the `services` list names no relay, there is no home-relay order to
  defer to.
- **Staleness in both directions.** A carried chain is a snapshot at fetch time: the
  consumer's re-fetch cadence bounds new-key usability and rotated-key death at once.
- **Chain substitution at first encounter.** Identity operations are public data:
  HTTPS proves which origin served the document, never that the origin controls the
  identity the chain derives. A consumer ingesting into a store that also holds
  identities under its own authority MUST refuse or segregate a carried chain whose
  derived DID it already holds under that authority — re-fetches of previously carried
  state are the monotonicity discipline's ordinary case, but monotonicity begins only
  after a first accepted state and cannot defend the first encounter.
- **Discretionary retention.** Nothing obliges any consumer to ingest, retain, or keep
  re-serving a carried chain; removal — including abuse removal — is operator policy.

### Signing mailbox — ephemeral courier state outside both planes

Signing mailbox state is on neither plane: it is never gossiped, never folded, and
its retention is bounded by each request's own expiry. See
[SIGNING.md "Security Considerations"](https://protocol.dfos.com/signing#security-considerations)
for the detailed analysis.

### API request authentication — possession proves audience, not the credential

The credential-gated API surface (API-AUTH.md, an optional `0.x` capability) splits
authorization from authentication deliberately: a [DFOS credential](https://protocol.dfos.com/credentials)
names the grant, and a per-request **request proof** — a short-lived JWS signed by the
credential's audience key, binding `{method, host, path, bodyHash, credentialCID, iat}`
— proves the presenter _is_ that audience, making the credential useless as a bearer
token (API-AUTH.md "Motivation", `specs/API-AUTH.md`). The threat consequences the
surface is built around:

- **A stolen credential is a metadata leak, not an access leak.** Without the audience
  key, a captured credential authorizes nothing; the artifact that must never leak is
  the key, which never crosses a channel (API-AUTH.md "Security Considerations").
- **Public audience is refused at every level of the chain.** A single `aud: "*"`
  credential anywhere in the presented delegation chain would let a stranger self-issue
  a passing leaf audienced to their own key — a full proof-of-possession bypass — so the
  verifier scans the whole chain, not just the leaf (API-AUTH.md verification step 9).
- **Within-window identical-request replay is an explicitly-accepted bound**, which is
  why the v0 registry is read-only; write-bearing actions require a per-request
  uniqueness seam (API-AUTH.md "Within-window replay").
- **The host binding is only as strong as its source.** The verifier compares against
  its own configured hostname, never a request-supplied `Host`/`X-Forwarded-Host`; a
  verifier that derived the host from the request would have no cross-host binding at
  all (API-AUTH.md verification step 5).
- **The browser BFF is a signing surface, not a blind oracle** — a backend that signs
  the coordinates a browser hands it is a confused deputy (API-AUTH.md "The browser is
  not a keyholder").

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

| Adversary                   | Can                                                                                                                                                                      | Cannot                                                             | Pointer                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Malicious/Byzantine relay   | Withhold, reorder, equivocate, censor, serve stale state, read stored content-plane blobs                                                                                | Forge a chain or operation                                         | DID-METHOD.md §6.4 `specs/DID-METHOD.md`                                                                             |
| Malicious peer              | Push invalid/spam operations to peers                                                                                                                                    | Have invalid operations accepted (each peer re-verifies, no trust) | WEB-RELAY.md "Peering" `specs/WEB-RELAY.md`                                                                          |
| Unauthenticated submitter   | POST arbitrary JWS to `/proof/v1/operations`; publish a carried chain and let encounter-triggered fetch ingest it (a write path with no POST); impose CPU + storage cost | Have malformed/unsigned ops accepted                               | WEB-RELAY.md "Operation Ingestion" `specs/WEB-RELAY.md`; SIWD.md "`identity_chain` — chain carriage" `specs/SIWD.md` |
| Compromised custody/KMS key | Full, indistinguishable impersonation of the user                                                                                                                        | Be detected on-chain (signature is valid Ed25519)                  | SIWD.md "The custodial signer agent" `specs/SIWD.md`                                                                 |
| Lost key                    | —                                                                                                                                                                        | — (1-of-N availability vs. total loss)                             | DID-METHOD.md §6.2 `specs/DID-METHOD.md`                                                                             |

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
buffering, `specs/WEB-RELAY.md`) cost. One aggregate 64 KiB operation-size cap plus
a small set of cardinality caps bound per-operation abuse — there is deliberately no
per-field string-length table (PROTOCOL.md "Operation Size and Cardinality Limits",
`specs/PROTOCOL.md`) — but **protocol-layer rate limiting is explicitly deferred** to
the deployment layer (WEB-RELAY.md "What's Deferred", `specs/WEB-RELAY.md`).

The same class reaches ingestion **without POSTing anything**: SIWD chain carriage is
encounter-triggered — a consumer that meets an app description MAY fetch and ingest its
carried chain on the consumer's own initiative, so the write path is the consumer's
outbound fetch, not an inbound submission (SIWD.md "`identity_chain` — chain carriage",
`specs/SIWD.md`). The submitter's cost-imposition surface is the same — every carried
operation is verified like any other — and it is bounded by the 100-operation carriage
cap (a consumer MAY refuse a longer chain unexamined) with ingestion and retention
entirely at the consumer's discretion, including abuse removal (SIWD.md "Carried
identity chains", `specs/SIWD.md`).

### Compromised custody / KMS key

Where a hosting platform holds the user's key material and signs on their behalf — the
custodial posture profile A works against today, and the custodial signer agent that
polls a mailbox for a keyless subject under profile B (SIWD.md "Profile A — Web
Redirect" / "The custodial signer agent", `specs/SIWD.md`) — a compromise of that
custody is **full impersonation** and is **indistinguishable on-chain**: the signature
is a valid Ed25519 signature by a key declared in the identity chain, so it verifies
identically to a self-custodied one (SIWD.md "Overview", `specs/SIWD.md`). Self-custody
avoids this by never letting the platform touch the key: the subject holds the key and
polls the mailbox, so the signature is produced where the key lives (SIWD.md "Profile B
— Sign-Request Mailbox", `specs/SIWD.md`).

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

This parameter (alphabet size × length) is settled for v1, not an open one: at this
width the targeted second-preimage cost (≈ 2^131.6) sits above the 128-bit floor, and
the birthday-collision cost of ≈ 2^65.8 is the accepted consequence. See PROTOCOL.md
"ID Alphabet" (`specs/PROTOCOL.md`) and DID-METHOD.md §3.1 (`specs/DID-METHOD.md`).

---

## Head Selection Is Convergent, Not Canonical — and Content-Only

Deterministic head selection — highest `createdAt`, lexicographic-highest-CID tiebreak —
applies to **content chains** and guarantees that any implementation with the same set of
operations computes the same head, regardless of ingestion order (PROTOCOL.md "Chain
Validity", `specs/PROTOCOL.md`; WEB-RELAY.md "Fork Acceptance", `specs/WEB-RELAY.md`).
That is its entire job: **convergence across implementations.**

It is **not** a canonical-truth or causal-ordering mechanism. `createdAt` is signer-asserted
and bounded only by the relay-enforced +24h future bound (PROTOCOL.md "Future timestamp
bound", `specs/PROTOCOL.md`; WEB-RELAY.md "Future timestamp guard", `specs/WEB-RELAY.md`).
Head selection answers "which tip do all honest verifiers agree on?" — not "which tip is
true?" or "which happened first?". Semantic interpretation of content-chain forks
(concurrency glitch, intentional recovery) is application-defined (PROTOCOL.md "Chain
Validity", `specs/PROTOCOL.md`).

**Identity chains are outside this mechanism entirely.** Identity chains are strictly
linear (PROTOCOL.md "Chain Validity", `specs/PROTOCOL.md`): a conflicting extension is
invalid, the head is the last operation of the single timeline, and there is no timestamp
competition to win — no once-current key can bid the head from an ancestor, whatever its
`createdAt` claims. Forks are permitted exactly where a merge function exists, and key
state has none. Undeletion is the explicit
`restore` operation, signed by a controller key of the deleted head state (WEB-RELAY.md
"Deletion Semantics", `specs/WEB-RELAY.md`; DID-METHOD.md §5.5, `specs/DID-METHOD.md`).
Ordering authority for an identity chain is its services-listed home relay — single-writer
ordering with multi-relay read replication, arbitration rather than merge (WEB-RELAY.md
"Identity Linearity and Order Authority", `specs/WEB-RELAY.md`); equivocation by the
holder is detectable and invalid rather than head-selected (DID-METHOD.md §6.3,
`specs/DID-METHOD.md`).

---

## Explicitly-Accepted Residual Risks (v1)

These are known and deliberately accepted for v1.

- **Rotation is not revocation.** Rotating a key ends its authoring window for freshly
  admitted operations, but committed facts it signed re-verify forever — their invalidation
  mechanism is revocation or deletion, never rotation (WEB-RELAY.md "Key Resolution",
  `specs/WEB-RELAY.md`). The chain itself is not at risk: identity chains are strictly
  linear (PROTOCOL.md "Chain Validity", `specs/PROTOCOL.md`), so a rotated-out key has no
  path back into the chain — there is no ancestor to fork from and no timestamp to bid.
- **Delete is not a substitute for rotation.** `restore` requires only a controller key of
  the **deleted head state** (PROTOCOL.md "Identity Operations", `specs/PROTOCOL.md`). A
  thief holding a still-current controller key can therefore restore a deleted identity —
  and then rotate the legitimate holder out. The remedy for key compromise is **rotate
  first, then delete** if desired: deleting while a compromised key is still current
  leaves the chain reopenable by exactly that key. (A key rotated out _before_ the delete
  is not in the deleted state and cannot restore.)
- **Home-relay write availability (single-writer identity ordering).** The subject's
  services-listed relay is the order authority for its identity chain; peers replicate
  its committed order and refuse conflicting extensions (WEB-RELAY.md "Identity Linearity
  and Order Authority", `specs/WEB-RELAY.md`). An identity write attempted during a
  home-relay outage is at-risk-until-retry — never arbitrated in later by timestamp. This
  is the deliberate trade for a non-auctionable authority record: identity writes are rare,
  reads replicate everywhere, and arbitration beats auction for key state.

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
- **SIWD security controls live in the relying party.** Replay prevention (nonce),
  redirect-URI validation, challenge-DID binding, and timestamp windows are obligations
  on the verifying third party — no relay and no signer can enforce them on its behalf.
  The client library ships a conforming path (`createSiwdLoginRequest`,
  `readSiwdCallback`, `verifySiwd` in
  [`@metalabel/dfos-client/siwd`](https://www.npmjs.com/package/@metalabel/dfos-client)); a
  relying party that hand-rolls verification instead forfeits these controls silently,
  and nothing on the wire reveals that it did (SIWD.md "Security Considerations",
  `specs/SIWD.md`).
- **Cursor validation is a cheap membership signal over already-public sets.** The
  list routes' 400-on-unknown-cursor answers "does this relay hold X at this position"
  with one status code — information already derivable by paging the same public
  enumeration, so no new disclosure, but a lower-cost probe than the enumeration it
  shortcuts (WEB-RELAY.md "Error Responses", `specs/WEB-RELAY.md`).
- **The signing-mailbox courier reads pending payloads, and bundle deposits admit on
  depositor-attested state** (SIGNING `0.x` — optional capability, default-off; listed
  here because it adds adversary surface wherever enabled). A relay serving
  `capabilities.signing` can read every pending sign-request payload in the clear
  (encrypt-to-device is the named future seam), and a deposit `chain` bundle for a
  foreign requester can hide a rotation, deletion, or revocation from the **relay** — a
  chain prefix verifies, and head-ness is unprovable from the chain alone. The exposure
  is bounded to **relay spam-admission** by the subject-rooted, expiring deposit
  credential; integrity holds at the signer, which independently re-resolves the
  requester to current state (SIGNING.md "Courier, Not Ledger"; the bundle
  trust-boundary paragraphs under "POST /signing/v0/requests", `specs/SIGNING.md`).

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

# DFOS Signing Requests

A generic, transport-agnostic way for one party to ask another to produce a DFOS signature. A **sign request** is a signed envelope that says: _I, this requester, ask this subject to sign exactly these bytes, as this kind of artifact, before this deadline._ The optional relay **signing mailbox** is a courier that carries the envelope to the subject and the resulting signature back — nothing more.

> **Status — SIGNING 0.1, an optional capability on its own `0.x` clock, independent of the Protocol v1 freeze.** The sign-request envelope (`did:dfos:sign-request`), the signer obligations, and the mailbox courier semantics below are published for review and early implementation — they are **not part of the frozen protocol surface**, and the frozen protocol never depends on them. SIGNING builds on frozen primitives (the identity chain, the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile), [DFOS Credentials](https://protocol.dfos.com/credentials)) and sits **outside** the frozen v1 vector set on purpose: nothing here touches identity or content chains. Reference vectors ship in the TypeScript and Go packages; the five-language sweep is a freeze requirement, not a `0.x` one. Discuss in the [DFOS](https://nce.dfos.com) space.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/chain/sign-request.ts) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Motivation

Every interesting DFOS artifact is a signature: a [credit claim](https://protocol.dfos.com/credits) is the claimant's signature, a countersign is the witness's, a [SIWD](https://protocol.dfos.com/siwd) proof is the user's, a delegated operation rides on a credential someone signed. The protocol says precisely what each signature means — and says nothing about how the party who _wants_ one asks the party who _holds the key_. Today that gap is filled ad hoc: a platform signs custodially on the user's behalf, or a bespoke flow (SIWD's redirect dance) is built per artifact type.

The sign request closes the gap once, generically. Any **composer** — a platform, a site, a CLI, an agent — builds the exact bytes it wants signed, wraps them in a sign-request envelope naming the **subject** it wants them signed by, and gets back the finished JWS. Any **signer** — a phone holding a device key, a CLI holding a sovereign key, an agent holding a delegated key — receives the request, shows the human what it actually says, and signs or ignores it.

This is the interface that makes device-held keys real. A custodial platform can keep signing on its users' behalf, and the moment a user enrolls a device key, the same flows route a sign request to the device instead — push-to-approve, claim-your-credit, release ceremonies, sign-in — without any of those features knowing which custody tier the user is on. The envelope is the seam the custody ladder climbs.

### What this deliberately is not

- **Not a new signature semantic.** The response to a sign request is an ordinary artifact of the requested type — a credit claim, a SIWD proof, a countersign — meaning exactly what its own spec says it means. The envelope adds no meaning to the artifact and leaves no residue inside it.
- **Not proof plane.** Requests and responses are never gossiped, never indexed, never part of any chain. The mailbox is a courier, not a ledger (see [Courier, Not Ledger](#courier-not-ledger)).
- **Not a display format.** The envelope carries no human-readable `statement`. What the user sees is rendered by the signer from the parsed payload itself — see [Signer Obligations](#signer-obligations-wysiwys), which exist precisely so that display text and signed bytes cannot diverge.

---

## The Sign-Request Envelope

A sign request is a JWS in the same envelope family as [credentials](https://protocol.dfos.com/credentials), [credit claims](https://protocol.dfos.com/credits), and revocations, with its own `typ`.

### JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:sign-request",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

| Field | Value                     | Description                                          |
| ----- | ------------------------- | ---------------------------------------------------- |
| `alg` | `"EdDSA"`                 | Ed25519 signature algorithm                          |
| `typ` | `"did:dfos:sign-request"` | Protocol-specific type discriminator                 |
| `kid` | DID URL                   | `did:dfos:<id>#<keyId>` — identifies the signing key |
| `cid` | CID string                | Content address of the payload                       |

**kid format.** The `kid` MUST be a DID URL containing `#`. The DID portion MUST equal the payload's `did` — the requester signs its own ask, always.

**Key resolution is current-state.** The requester's signing key is resolved against the **current** state of its identity chain — rotated-out keys are rejected, and a **deleted requester's requests are rejected**. This is the live-authentication rule, not the credential rule, and the asymmetry with the rest of the envelope family is deliberate: a credential or a credit claim is a durable artifact whose validity must survive rotation (invalidated by revocation or nothing), while a sign request is an ephemeral standing _ask_ with a hard expiry and **no revocation primitive**. Rotation is how a requester whose key is compromised stops the compromised key from minting asks in its name; a historical rule would leave no way to do that. Any current key role (auth, assert, controller) may sign.

### Payload

```json
{
  "version": 1,
  "type": "sign-request",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "subject": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae",
  "payloadTyp": "did:dfos:credit-claim",
  "payload": "eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlZGl0LWNsYWltIiw...",
  "createdAt": "2026-08-10T00:00:00.000Z",
  "expiresAt": "2026-08-13T00:00:00.000Z"
}
```

| Field        | Type             | Required | Description                                                                                                            |
| ------------ | ---------------- | -------- | ---------------------------------------------------------------------------------------------------------------------- |
| `version`    | `1`              | yes      | Schema version (literal `1`)                                                                                           |
| `type`       | `"sign-request"` | yes      | Literal discriminator                                                                                                  |
| `did`        | string           | yes      | The requester DID — MUST equal the `kid`'s DID                                                                         |
| `subject`    | string           | yes      | The target signer DID — the only identity being asked                                                                  |
| `payloadTyp` | string           | yes      | The JWS `typ` the produced artifact MUST carry (e.g. `did:dfos:credit-claim`)                                          |
| `payload`    | string           | yes      | **Unpadded base64url of the exact bytes to be signed** — see below                                                     |
| `createdAt`  | string           | yes      | The [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) (millisecond precision, UTC)                 |
| `expiresAt`  | string           | yes      | The [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) (millisecond precision, UTC) — hard deadline |

Unknown top-level fields on the **envelope** are preserved-and-ignored, per the protocol's MUST-ignore-unknown rule — the CID commits to the exact bytes, so a verifier that stripped unknown keys would fail its own CID check. (The **target payload** inside `payload` is held to the opposite, stricter standard at signing time — see [Signer Obligations](#signer-obligations-wysiwys).)

**`payload` carries bytes, not JSON.** The field is the unpadded base64url encoding (RFC 4648 §5, no `=` padding) of the exact octets the composer wants signed — the octets that will become the produced JWS's payload segment, byte for byte. It is **never** a re-serialized parse: a composer that decodes, transforms, or "normalizes" the bytes en route has composed a different request. Padded input, or any encoding of the same bytes other than the canonical unpadded form, is invalid. The decoded bytes MUST be non-empty.

**One subject.** A sign request is monadic — one requester asks one subject to sign one payload. Fan-out (N witnesses on a ceremony, co-signers on a release) is N requests composed by the requester, not a multi-subject envelope. This keeps the signer's question binary — _do I sign these bytes?_ — and keeps every downstream rule (mailbox authorization, response verification, replay analysis) one-to-one.

**`payloadTyp` names the artifact, and the artifact's own spec governs it.** The envelope does not say which of the subject's keys should sign, what the payload schema is, or what the artifact will mean — the spec behind `payloadTyp` already says all three, and restating any of it here would create a second authority that could disagree with the first. In particular there is no `keyRole` field: if `did:dfos:credit-claim` accepts any key role, so does a requested credit claim.

**Timestamps are whole-second.** Signers of the envelope MUST normalize `createdAt` and `expiresAt` to whole seconds (`.000Z` millisecond component) — the canonical form this envelope family uses, applied to caller-supplied overrides exactly as to "now" (floor, never round). The grammar remains the millisecond-precision [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar); the normalization binds producers so that re-deriving a request from the same inputs lands on the same CID on every implementation.

### Expiry

`expiresAt` is the request's one terminator, and it is bounded:

- `expiresAt` MUST be strictly after `createdAt`.
- **`expiresAt − createdAt` MUST NOT exceed 7 days** (604800 seconds). This bound is validity-determining and identical across implementations: a verifier MUST reject an envelope whose window exceeds it, however far in the future or past the window sits.
- A verifier evaluates expiry against the **current time**: a request is live only while `now < expiresAt`. This is the read-path time basis from the [credential spec](https://protocol.dfos.com/credentials) — requests are local, ephemeral decisions that never enter a replicated log, so the wall clock is the correct basis and there is no convergence concern.

The 7-day ceiling is a phishing control, not a convenience default. A long-lived pending request is an attack pattern: it sits in a mailbox waiting for a moment of inattention, and its context ("you were minting a credit last Tuesday") has evaporated by the time it is approved. Days cover every legitimate human-latency flow — a phone that is off for a weekend, a co-signer in another timezone — and nothing legitimate needs months. There is no revocation or cancellation primitive **on purpose**: the composer that wants a request gone stops honoring its CID, and expiry collects it. A cancellation artifact would add a signed message type, a gossip question, and a race, to save at most seven days of a slot in a mailbox.

### CID Derivation

Identical to every other protocol object:

```
dagCborCanonicalEncode(payload) -> SHA-256 -> CIDv1 (dag-cbor + SHA-256)
```

The derived CID is embedded in the protected header as `cid`, and verification re-derives it from the parsed payload and compares — mismatch is a verification failure. The request CID is also the request's **correlation handle** everywhere: the mailbox slot key, the requester's poll handle, and the hook any future confirmation scheme would commit to. As everywhere else in the protocol, dag-cbor is used **only** for CID derivation; the JWS body carries JSON.

### Size Bounds

| Bound                  | Value          | Applies to                      |
| ---------------------- | -------------- | ------------------------------- |
| sign-request JWS token | **8192 bytes** | the serialized envelope token   |
| decoded target payload | **4096 bytes** | the octets `payload` decodes to |

Verifiers MUST reject a token exceeding 8192 bytes **before any decode** (a DoS guard), and MUST reject a decoded target payload exceeding 4096 bytes. These are the envelope's only byte arbiters — no per-field length caps, matching the protocol's practice everywhere else. The target-payload ceiling is generous for every stateless envelope this spec expects to carry (a credit-claim payload is under 300 bytes; a SIWD challenge under 1 KB) and deliberately tight in absolute terms: a payload a human is expected to review and approve should not be forty screens long. Payloads that legitimately exceed it are outside what SIGNING 0.1 couriers.

Both bounds are **validity-determining** and MUST be identical across implementations.

### Verification Algorithm

To verify a sign-request envelope, given the token, a way to resolve identities, and the current time:

1. **Size.** If the token exceeds **8192 bytes**, reject. Check this before any decode.
2. **Decode** the JWS and apply the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile) header gates: `typ` MUST be exactly `did:dfos:sign-request`, `alg` exactly `EdDSA`, a `crit` member rejects, an embedded key member (`jwk`, `x5c`, …) rejects. A header whose `typ` or `kid` is missing or not a string rejects.
3. **Payload schema.** `version` MUST be `1`, `type` MUST be `"sign-request"`, `did` and `subject` MUST be non-empty and carry the `did:` prefix, `payloadTyp` MUST be a non-empty string, `payload` MUST be a non-empty string, `createdAt` and `expiresAt` MUST parse per the [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar). (The `did:` checks are prefix checks, not full `did:dfos` validation.)
4. **Target bytes.** `payload` MUST decode as unpadded base64url; the decoded bytes MUST be non-empty and MUST NOT exceed **4096 bytes**.
5. **`kid` ↔ `did`.** The `kid`'s DID portion MUST equal `payload.did`.
6. **Resolve the requester** named by `did` to its **current** identity state. Unresolvable → **unverifiable**. Deleted → reject. Resolvable with no key matching the `kid` fragment in current state → reject.
7. **Signature.** Verify the JWS under that key.
8. **CID integrity.** Re-derive the payload CID and compare against the header `cid`.
9. **Temporal.** `expiresAt` MUST be strictly after `createdAt`; the window MUST NOT exceed 7 days; `now` MUST be strictly before `expiresAt`.

As with credit claims, the two failure verdicts MUST be machine-distinguishable: **invalid** ("checked and failed") versus **unverifiable** ("could not check" — an unresolvable requester or a resolver transport failure). The reference implementations expose the verdict structurally (TypeScript: a typed error's `reason` field; Go: `errors.Is`-able sentinels), never as prose to string-match.

A verified envelope is a well-formed _ask_. What the signer must do before honoring it is the next section — and it is the load-bearing one.

---

## Signer Obligations (WYSIWYS)

The central risk of any remote-signing protocol is **display/sign divergence**: the human approves what the screen says, the key signs what the bytes say, and an attacker arranges for the two to differ. Every obligation in this section exists to make that divergence structurally impossible — what you see is what you sign.

Given a verified envelope, a signer MUST, in order:

1. **Verify the subject is itself.** `subject` MUST equal the signer's own DID. A request addressed to anyone else MUST NOT be signed, whatever else is true of it. (This is also what kills cross-identity replay: `subject` sits inside the requester-signed bytes, so a request minted for Alice cannot be re-aimed at Bob without breaking the requester's own signature.)
2. **Refuse unknown types.** If the signer does not implement `payloadTyp` — its schema, its canonical serialization, and its signer-side rules — it MUST NOT sign. There is no generic path: signing bytes you cannot fully interpret is the exact failure this protocol exists to prevent.
3. **Decode and parse.** Base64url-decode `payload` and parse the octets as UTF-8 JSON. Any parse failure → refuse.
4. **Validate against the `payloadTyp` schema — strictly.** The parse MUST satisfy the target spec's payload schema, **and MUST contain no unknown fields**. The MUST-ignore-unknown rule is a _verifier's_ forward-compatibility posture; a _signer_ is being asked to take responsibility for bytes, and it cannot render a field it does not understand. Never sign what you cannot display. The target typ's signer-side obligations apply in full — for `did:dfos:credit-claim`, that means a whole-second `createdAt`, a non-empty `asOfDocumentCID` if the key is present, and `payload.did` equal to this signer's DID (the artifact's own kid ↔ did rule, checked before rather than after signing).
5. **Re-canonicalize and byte-compare.** Re-serialize the validated parse using the target typ's **canonical serialization** and compare the result to the decoded input, byte for byte. **Any mismatch → refuse.** This is the load-bearing check. After it passes, the input bytes are provably the unique canonical encoding of the parse — there is no duplicate key the parser silently collapsed, no non-shortest number form, no whitespace or escape-sequence trick, no key-order game: nothing in the bytes that is not in the parse, and nothing in the parse that is not in the bytes.
6. **Render from the parse.** Whatever the signer displays for approval MUST be derived from the validated parse — never from requester-supplied display text (the envelope carries none, on purpose) and never from a second decode.
7. **Sign the original bytes.** The produced JWS's payload segment MUST be the decoded input octets exactly — not a re-serialization, however canonical. The signer constructs its own protected header (`alg: "EdDSA"`, `typ` equal to the request's `payloadTyp`, its own `kid`, and whatever header fields the target spec requires, e.g. a `cid` over the payload).

Steps 5 and 7 together are the WYSIWYS contract: the byte-compare proves that rendering from the parse is rendering the bytes, and signing the original bytes proves the signature covers what was rendered. An implementation that skips the byte-compare and "just signs the re-serialization" has the same bytes in the honest case and **different bytes exactly in the adversarial one** — it converts the attack from "signature refused" into "signature silently covers something other than the request." The reference implementations ship adversarial vectors for this check (duplicate keys, non-shortest numbers, permuted key order, whitespace injection, unicode escapes of ASCII, unknown fields, sub-second timestamps), and any independent implementation should copy them wholesale.

**Canonical serialization** is defined per `payloadTyp`, and for every DFOS envelope family it is the same rule [SIWD already states for its challenge](https://protocol.dfos.com/siwd): the payload object serialized as minimal UTF-8 JSON (no insignificant whitespace), members in the exact order of the target spec's payload table, absent optional members omitted, timestamps in `.000Z` whole-second form — the bytes the target's own reference builder emits. A composer that builds payloads with the target spec's reference implementation produces canonical bytes by construction; the signer-side check exists for composers that do not.

**Approving twice is harmless.** Ed25519 is deterministic: the same key over the same bytes yields the identical artifact, so a double-approved request produces a byte-identical response, not a conflicting one. Two _different_ enrolled keys, however, produce two different valid artifacts — which is why the mailbox's response slot is first-write-wins (see below).

### Staleness: what a request can safely carry

Byte-exactness is never violated — a stale request is _refused and re-composed_, never patched. What varies by payload type is whether staleness can happen at all:

- **Stateless envelopes are the natural cargo.** A credit claim, a countersign payload, a SIWD challenge — these carry no reference to a chain head and **cannot go stale**. A request for one is exactly as signable on day 6 as at minute 1. Human-latency approval flows should be built from these.
- **Chain operations are supported, and the composer owns the race.** An identity or content operation embeds a `previousOperationCID`; if the chain advances while the request sits in a mailbox, the produced operation is simply invalid at ingest — rejected by every relay, harmless everywhere. The remedy is composer-side: observe the rejection, re-compose against the new head, re-deposit. Nothing in the courier retries, rebases, or mutates bytes.

---

## The Response

**There is no response envelope.** The response to a sign request _is_ the produced JWS — a complete, self-authenticating artifact of the requested `payloadTyp`, verifiable by anyone under its own spec's rules with no reference to the request that solicited it. Wrapping it would add a signature that attests nothing the artifact does not already prove.

Correlation is by **request CID**: the composer that deposited a request identified by CID `Q` asks the courier for the response to `Q`. The binding between the two is byte-equality — the response's payload segment decodes to exactly the requested bytes — which is checkable by anyone holding both, with no courier trust involved.

**Declines are courier-level and advisory.** A subject that wants to say "no" tells the courier, unsigned. A composer MAY surface a decline as UX ("your collaborator declined"), and MUST NOT treat it as authoritative: the courier is untrusted and could fabricate or suppress declines freely, and a signed decline would buy nothing (the relay could suppress that too). **Expiry is the only real terminator.** In particular, a composer MUST NOT irreversibly cancel real-world state on the strength of a decline — a response may still arrive from another of the subject's devices until `expiresAt`.

---

## The Signing Mailbox (relay capability `signing`)

Everything above is transport-independent — a sign request can travel over a QR code, a deep link, a local socket, or a pasted string, and SIGNING 0.1 defines exactly one transport: a relay-hosted **mailbox**, poll-based, one per subject DID.

### Courier, Not Ledger

The mailbox is a courier. The doctrine, normatively:

- Mailbox state is **not proof plane**. It is never gossiped, never indexed, never referenced by any chain, and confers no meaning on its contents. A relay holds it the way a post office holds a letter.
- **Retention MUST NOT exceed the envelope's `expiresAt`.** This is two obligations, not one: an expired request MUST NOT be **served** on any route (to the subject, the requester, or anyone), **and** its bytes MUST NOT be **retained at rest** past expiry — a relay MUST delete expired courier state, not merely filter it from reads. The payload is plaintext (see below), so retaining an expired request is retaining cleartext a composer already asked the courier to forget; read-time filtering satisfies the serving half and not the retention half. A relay MAY delete opportunistically (e.g. dropping any expired row it encounters) or on a sweep; the reference relays prune expired rows as they touch them, **and** sweep once at construction — so expired rows stranded by a capability toggle are collected at the next restart, and an active mailbox never accumulates them. The honest residual: a relay that runs uninterrupted while a store's signing routes go untouched retains its expired rows until the next touch or restart — a deployment that cannot accept that window schedules its own sweep (the store surface exposes the prune). A relay MAY drop courier state earlier still under its own policy; durability is explicitly not promised, and a composer that needs delivery guarantees re-deposits.
- A relay stores **only** the request token, the response artifact, the decline flag, and its own bookkeeping timestamps. The deposit credential and any identity bundle are verified and **discarded** — they authorize the deposit, they are not courier cargo.
- **No cross-subject enumeration, ever.** There is no route that lists mailboxes, counts them, or reveals whether a subject's mailbox exists to anyone who cannot read it. Pending requests reveal who is asking whom to sign what — precisely the shape of unreleased work — and an enumerable courier would leak it exactly as an indexed attribution surface would (the same argument, and the same refusal, as [CREDITS' attribution privacy](https://protocol.dfos.com/credits)).
- **The courier sees payloads in the clear.** This is v0.1 being honest rather than a design position: a relay operator can read every pending request it carries. Deployments for which that matters should run their own relay. The named future seam is an encrypt-to-device-key payload variant — same envelope, opaque `payload`, a signer-side decrypt step before the WYSIWYS checks — which nothing in v0.1 forecloses.

### Capability

A relay advertises the mailbox via `capabilities.signing` in its well-known response ([WEB-RELAY.md](https://protocol.dfos.com/web-relay)). The flag defaults to **false** and an absent flag reads as false — this is an opt-in surface, and the reference relays ship it disabled. When `false` or absent, every `/signing/v0/*` route returns **501 Not Implemented** — not 404 — with the gate firing before authentication, body parsing, or any store lookup, per the relay's uniform capability discipline.

**Interaction with `capabilities.write: false`.** The `write` flag governs the two replicated planes — proof-plane operation ingest and content-plane blob upload — and courier state is on neither. A relay MAY therefore serve `signing: true` alongside `write: false`, and this combination is expected in practice: a public read-only relay that couriers signing traffic without ingesting a single operation. Its no-ingest invariant is stated precisely as _"this relay never ingests proof-plane operations"_ — and the deposit gate below is what keeps the signing surface from becoming an ingest path in disguise (bundles are verified ephemerally, never stored, never folded). On such a relay the deposit surface is its only authenticated write of any kind, which is why the byte caps and the credential gate in this section are load-bearing DoS controls, not hygiene: a relay MUST enforce them, and SHOULD apply per-requester rate limits on deposit as well.

The mailbox requires the relay to resolve the **subject's** identity chain locally — a mailbox lives where its subject's identity lives. A deposit for a subject the relay cannot resolve is refused (404), and so is a deposit for a subject whose local state is **deleted**: a tombstoned identity cannot be asked to sign, and its mailbox does not exist — the same "no such mailbox" class, not a new one. (The deposit credential reaches the same conclusion independently — a deleted subject's root issuance dies with it, per [CREDENTIALS.md](https://protocol.dfos.com/credentials) — but the gate states it directly rather than leaving it to inference.) A composer picks the subject's relay, not an arbitrary one — and finding it is already protocol vocabulary: the subject's resolved identity state carries its `services` entries of `type: "DfosRelay"` ([PROTOCOL.md → Services](https://protocol.dfos.com/spec#services)), resolvable from any relay. When the subject lists more than one relay, a composer SHOULD deposit at every listed relay that advertises `signing` — Ed25519 is deterministic, so a request signed twice yields byte-identical responses and the first-write-wins gate absorbs the duplicate harmlessly — and a signer SHOULD poll every relay its own state lists: one-sided selection is how a correct composer and a correct signer silently miss each other. A future `SigningMailbox` service type — the closed-dispatch extension path for a mailbox hosted somewhere other than the subject's identity relay — is a named seam, not part of 0.1.

### Routes

All routes live under `/signing/v0` at the relay root — an own-clock family beside `/index/v0` and `/revocations/v1`, not part of the frozen `/proof/v1` plane. The `v0` is this spec's `0.x` clock made legible in the path, exactly as `/index/v0`'s: when SIGNING exits `0.x`, the family re-mounts at `/signing/v1` and `v0` is retired. Errors use the relay's uniform error body ([WEB-RELAY.md → Error Responses](https://protocol.dfos.com/web-relay)); callers branch on status codes, never on message text.

#### `POST /signing/v0/requests` — deposit (credentialed)

```json
{
  "request": "<sign-request JWS>",
  "credential": "<DFOS credential JWS>",
  "chain": ["<identity operation JWS>", "..."]
}
```

| Field        | Required | Description                                                                  |
| ------------ | -------- | ---------------------------------------------------------------------------- |
| `request`    | yes      | The sign-request envelope                                                    |
| `credential` | yes      | The deposit credential — see [Deposit Authorization](#deposit-authorization) |
| `chain`      | no       | Identity-chain operations for identities the relay cannot resolve locally    |

The relay verifies the envelope (full [algorithm](#verification-algorithm) above, wall-clock `now`), verifies the deposit credential (next section), and stores the request keyed by its CID. Responses: **201** with `{ "cid": "...", "expiresAt": "..." }`; **200** with the same body for an idempotent re-deposit of the identical token; **409** when the CID already holds a _different_ request token (a hash collision on distinct bytes is not expected; this is a defensive guard, not a routine outcome); **400** for an invalid or expired envelope; **404** when the subject is not resolvable on this relay; **403** when the credential fails the deposit rule; **413** over the caps; **429** when the subject's pending set is at the relay's cap (see [the poll route](#get-signingv0requests--poll-subject-only) — relay policy, reference cap 1024). The aggregate deposit body MUST NOT exceed **524288 bytes** (512 KiB — a maximal credential chain plus envelope plus bundle headroom).

**The deposit is self-contained.** Verifying it requires resolving the _requester's_ identity chain (envelope signature) and every _issuer_ in the credential chain — identities the subject's relay may not host. The relay resolves locally first; `chain` fills the gaps for foreign identities. Bundled operations are verified exactly as chain verification always verifies them — genesis derivation, hash-linking, signatures — then used ephemerally for key resolution and **discarded**. They are never ingested, stored, gossiped, or folded, whatever the relay's write posture. A deposit MUST NOT become a cross-relay resolution dependency: if the bundle plus local state does not suffice, the deposit is refused, not deferred.

**What the bundle proves, and what it cannot (normative trust boundary).** A supplied `chain` bundle is a set of validly-signed, hash-linked operations — but a **prefix** of an append-only chain is itself a valid chain, and a relay that does not host the identity has no way to know it holds the chain's _head_. For an identity resolved **from the bundle** (never for one resolved **locally** — local state is always the chain's true head and always wins), three guarantees the **relay** checks at deposit time therefore degrade to **as attested by the depositor**:

- **Current-state key resolution** (the envelope's requester key): a bundle truncated just before a key rotation presents a rotated-out key as current. The relay cannot detect this.
- **Deletion** (a credential issuer): a bundle omitting the deletion operation presents a tombstoned issuer as live.
- **Revocation** (a sub-delegation in the credential chain): the relay holds revocations only for credentials it has seen; a foreign issuer's revocation of a mid-chain delegation is invisible to it.

None of these degradations reaches **what the subject signs**. The relay verifies a deposit and then **discards** the bundle, and a signer runs the full [verification algorithm](#verification-algorithm) on every polled request — resolving the requester to current state through its own resolution path, never through the depositor's bytes, which no longer exist to consult. A bundle truncated to hide a rotation is therefore caught at the signer: its resolver sees the true head, the dead-key signature fails step 7, and the request is rejected. What a truncated bundle buys is **relay spam-admission** — a request the relay admitted but the signer will refuse occupies a mailbox slot until it is polled and rejected, or expires.

Even that admission is not a hole to be patched at the courier — it is inherent to accepting a self-contained bundle for an identity the relay does not track, and the honest bound is a **credentialed, expiring one**: every admission is confined by the deposit credential, which MUST root at the locally-resolved `subject` (rule 2 below, checked against true head state) and carries its own `exp`. The exposure is therefore "a party the subject already authorized to deposit, whose key was compromised _and_ rotated, can keep occupying mailbox slots in its own name until its deposit credential expires" — a bounded amplification of an already-granted trust; never a path to a mailbox the subject did not open, and never a path to a signature. A deployment that will not accept even that bound MUST require the requester and every credential issuer to be **locally resolvable** and reject bundle-only deposits; the reference relays accept the bundle and inherit the bound. (The response side is likewise unaffected end to end: a response is verified against the subject's key and its bytes by the composer regardless of any relay's identity knowledge. The one residual that does reach a signer is ordinary resolver staleness — the signer's own source can be behind, as any single source can be for any current-state question in the protocol — and the bundle neither causes nor worsens it.)

#### `GET /signing/v0/requests` — poll (subject only)

Authenticated with an **identity proof** ([API-AUTH](https://protocol.dfos.com/api-auth#the-identity-proof), consumed per [WEB-RELAY.md → Authentication](https://protocol.dfos.com/web-relay#authentication)): a request-bound possession proof self-signed by a **current** key on the subject's identity chain, host-bound to this relay. The mailbox read is exactly a "prove you are currently this DID" question, and the identity proof is exactly that proof; being yourself requires no credential, and no `collect` grant exists (see [Deposit Authorization](#deposit-authorization) for why). Revoking a device's mailbox access is key rotation, which the protocol already has.

The subject is the proof's `kid` DID. The response lists **pending** requests — deposited, unexpired, unresponded — oldest first:

```json
{
  "requests": [
    {
      "cid": "bafyrei...",
      "request": "<sign-request JWS>",
      "depositedAt": "...",
      "declined": false
    }
  ],
  "next": "..."
}
```

Pagination is the relay's one shared list envelope ([WEB-RELAY.md](https://protocol.dfos.com/web-relay)): `after` (cursor), `limit` (default 100, max 1000, values above the max clamped), and `next` — the cursor to pass as `after` on the next call, or `null` when the page was not full (caught up). The pending set is ordered by deposit time ascending (tiebreak: request CID), and because that is a composite key, `after`/`next` are **opaque cursor tokens** exactly as in the index's ordered mode — a caller passes `next` back verbatim and MUST NOT parse or construct one; resumption is strictly past the composite key, so a decodable cursor whose request has since expired or been responded resumes at the next key rather than truncating, while an **undecodable** token — or one minted for a different subject's mailbox — is a **400** (`invalid cursor`): the cursor is bound to the mailbox it came from, and reusing it across subjects would otherwise silently skip the new subject's older pending requests. Reference relays additionally cap a mailbox's **pending set** (relay policy; the reference cap is 1024) — the deposit that would exceed it is refused (**429**), which is the per-mailbox flood fence the caps-and-rate-limits posture promises for open (`aud: "*"`) mailboxes. Polling is the v0.1 transport in full — no server push, no SSE, no delivery callbacks. Native push (APNs/FCM) is a signer-app concern layered outside this spec: a push notification may _prompt_ a poll, but delivery is always the poll.

A signer MUST run the full [verification algorithm](#verification-algorithm) and every [signer obligation](#signer-obligations-wysiwys) on each polled envelope. The mailbox's own checks are anti-abuse, not delegated trust — a signer treats a polled request exactly as one that arrived by QR code from a stranger.

#### `POST /signing/v0/requests/{cid}/response` — respond (validity is the auth)

```json
{ "response": "<produced artifact JWS>" }
```

**Unauthenticated, deliberately.** A valid response is unforgeable — only a holder of the subject's key can produce it — so proving who _couriers_ it adds nothing: anyone may deliver a sealed letter. This also frees the signing device from needing any relationship with the relay beyond reachability, and lets a composer relay a response it obtained out-of-band.

The aggregate request body MUST NOT exceed **8704 bytes** — the 8192-byte token cap plus JSON-wrapper headroom — checked before any decode (**413** over it). The relay accepts the response iff **all** of the following hold; otherwise **400** (or **404** for an unknown or expired `cid`):

1. A pending request with this CID exists and is unexpired.
2. The token does not exceed **8192 bytes** (checked before any decode).
3. The JWS decodes, passes the profile header gates, and its `typ` equals the request's `payloadTyp` exactly.
4. The `kid`'s DID portion equals the request's `subject`.
5. The `kid` names a key that has appeared in the subject's identity chain (**historical** resolution — the artifact will be judged by its own spec's rules downstream, and every artifact family resolves historically; the courier gate must not be stricter than the artifact's own verifier).
6. The payload segment decodes to **exactly the request's target bytes** — byte equality, the whole point. Its base64url spelling MUST be **canonical** (unpadded, no non-zero trailing bits): the stored artifact is served back verbatim and must round-trip identically across implementations, so a non-canonical encoding of the right bytes is refused, not normalized.
7. The signature verifies under the resolved key.

The slot is **first-write-wins**: at most one response per request, the first valid one stored. A re-put of the byte-identical token is idempotent (**200**); a _different_ valid artifact — possible when the subject holds multiple enrolled keys — is refused (**409**), and the composer reads the one that won. **201** on first acceptance. Responding to a declined request is legal (decline is advisory); the response simply wins. A response arriving for a `cid` that has expired or was never deposited is **404**, not 400 — the same not-found semantics the requester-poll route uses, so the two failure classes stay machine-distinguishable across all four routes.

#### `GET /signing/v0/requests/{cid}/response` — requester poll

**Unauthenticated.** Knowledge of the request CID is the capability: it is held by the composer that deposited the request and the subject that polled it, and is not enumerable (there is no route that lists CIDs). Note the precise strength of this: the CID is a hash of the requester-signed payload, and those inputs are not secret — a party who can guess or reconstruct the exact envelope bytes can compute the CID. This route therefore protects against **enumeration**, not against a determined guesser who already knows what was asked; and what it guards is only the response artifact, which is itself self-authenticating and independently verifiable, not a secret. A deployment wanting response-fetch to be a true secret must carry entropy the requester does not derive from public inputs (a random correlation token established out of band) — a future seam this route's shape does not foreclose. Responses:

```json
{ "status": "pending" }
{ "status": "declined" }
{ "status": "responded", "response": "<artifact JWS>" }
```

**404** for an unknown or expired CID — after expiry, a request and its response cease to be served at all (retention MUST NOT exceed expiry; a composer that wants the artifact keeps it).

A composer MUST verify a fetched response itself, under the artifact's own spec — the courier's checks are not a verification the composer inherits.

#### `POST /signing/v0/requests/{cid}/decline` — decline (advisory)

Unauthenticated, no body — a non-empty body under the cap is a **400**, and a body over **512 bytes** is a **413**. Sets the advisory decline flag on a pending request: **204** (idempotent on repeat); **409** if a response already exists; **404** unknown or expired. Unauthenticated is coherent because the flag carries no authority — see [The Response](#the-response) — and requiring subject auth would only lend it a credibility the spec explicitly denies it. No reason text is carried: a decline reason is exactly the kind of requester-facing display string this envelope refuses to courier.

### Deposit Authorization

Depositing into a mailbox requires a [DFOS credential](https://protocol.dfos.com/credentials) — standard verification, plus one rule that makes the mailbox the subject's own.

**The resource form** is `mailbox:<id>`, where `<id>` is the subject DID's 31-character identifier (the `did:dfos:` prefix stripped — resource ids do not repeat their scheme, exactly as `chain:<contentId>` does not). The action is **`deposit`**. This form is registered additively in [CREDENTIALS.md](https://protocol.dfos.com/credentials); its semantics live here.

A relay MUST verify, at deposit time:

1. **The credential chain verifies** under the credential spec in full — signatures, schema, CID integrity, linear delegation, depth, monotonic attenuation, audience linkage at every hop — with expiry evaluated against the **wall clock** (a deposit is a read-path, live decision) and **revocation checked at every level** against the relay's **current** knowledge (acceptance is a freshness decision; there is no as-of question here because deposits never enter a replicated log).
2. **The chain roots at the subject.** The root credential's `iss` MUST equal the request's `subject` DID. Only the subject is original authority over its own mailbox — no relay policy, no platform grant, no third-party root can substitute. This single rule is what makes a mailbox _belong_ to its subject on an untrusted relay.
3. **The leaf reaches the requester.** The leaf credential's `aud` MUST equal the request's `did` (the requester), or be `"*"`. A public (`aud: "*"`) deposit credential is the subject **opting into an open mailbox** — legitimate for a public figure soliciting requests, and carrying the same bearer-grant caution as every public credential: anyone may deposit, and the caps and rate limits are what stand between an open mailbox and a flooded one. Default posture is a named audience — deny-by-default.
4. **Attenuation covers the deposit.** Some `att` entry on the leaf MUST cover resource `mailbox:<subject id>` with action `deposit`, under the credential spec's action-canonicalization rules. The resource match is **exact only**: no wildcard form is defined for `mailbox`, and a relay MUST NOT honor `mailbox:*` (or any non-exact form) as covering a deposit. (Root-pinning would make a subject-rooted wildcard equivalent to the exact form anyway; refusing it keeps the deposit gate byte-comparable across implementations and keeps default-deny legible.)

**Why there is no `collect` action.** The principle is clean: **credentials delegate authority to others; being yourself is not a delegation.** A signer is, by definition, a holder of a key on the subject's own chain — key possession (the poll route's identity proof) is necessary and sufficient to read the subject's own mailbox, and a `collect` credential would be a second, revocable-in-a-second-way statement of a fact the identity chain already states. Device de-enrollment is key rotation. The resource form therefore carries exactly one action, and a credential attenuated to `collect` on a mailbox grants nothing.

**Issuance moments.** The deposit credential is designed to fall out of consent moments that already exist, not to require new ones: a SIWD authorization can return a deposit credential alongside its proof (the third-party app can now ask for signatures); joining a space can carry a deposit grant to the space (the space can now route ceremony requests to its members); a custodial platform holding a user's controller key issues deposit credentials on the user's behalf, and a sovereign user issues the identical shape from their own key — the credential grammar does not know the difference, which is the point. And a subject-rooted grant to a platform, sub-delegated onward through linear chains, lets the platform authorize its own services without ever re-touching the subject's key.

Every one of these moments presupposes a standing relationship, and that is the honest bound of 0.1: **a stranger with no prior grant cannot deposit at all, by any route.** The open-mailbox posture exists (`aud: "*"`, rule 3 above), but how a stranger _obtains_ a subject's public deposit credential — publication, directory, QR — is deliberately unspecified here. Distribution of standing authorizations is its own seam, and this family defines no new surface for it — but it does name the convention: a subject MAY publish its `aud: "*"` deposit credential as a public credential artifact on its own chain, where any composer can discover it through a relay's credential index (`GET /index/v0/credentials?issuer=<subject id>`). An existing artifact in an existing index — the open-mailbox posture becomes discoverable without a directory, and the deposit gate treats a discovered grant exactly as a directly-delivered one.

---

## Security Considerations

**Phishing is the threat model, and omission is most of the defense.** The envelope carries no `statement`, no display name, no app icon, no localized prose — nothing the requester controls that a signer might render. Requester-controlled display text is a phishing surface with a cryptographic costume: the user reads the friendly string, the key signs the hostile bytes. Here the _only_ thing a signer can render is the parse of the actual bytes (SIWD's `statement` survives inside its own challenge payload, where it is part of the signed bytes and governed by SIWD's own rules — the envelope adds no second one). The short expiry ceiling, the subject binding, and the WYSIWYS byte contract are the rest of the posture.

**Replay is dead on arrival, twice over.** Cross-identity: `subject` is inside the requester-signed bytes, so a request cannot be re-aimed. Cross-request: the response is bound to its request by byte equality of the payload, so a response to one request _is_ the response to any byte-identical request — which is not a replay but the same statement, idempotently (Ed25519 determinism makes even the artifact identical). A composer that needs two distinguishable approvals composes two requests with distinguishable bytes (e.g. distinct nonces or timestamps inside the target payload, where the target spec allows).

**The courier is untrusted and the design assumes it.** A malicious relay can drop requests (denial, indistinguishable from network failure), serve expired ones (refused by any conforming signer — the envelope's expiry is in the requester-signed bytes), fabricate declines (advisory only), or read payloads (named honestly above; encrypt-to-device is the future seam). It cannot forge a request (requester-signed), redirect one (subject-signed-in), forge a response (subject-keyed), or substitute response bytes (byte-equality checked by relay and — mandatorily — re-checked by the composer). Every trust-bearing check appears twice: once at the courier as anti-abuse, once at an endpoint as the real thing.

**DoS controls are load-bearing on public relays.** The 8 KiB envelope cap, the 4 KiB payload cap, the 512 KiB deposit body cap, and the deposit credential gate are the difference between "public courier" and "unauthenticated durable storage of arbitrary bytes." Relays SHOULD add per-requester rate limits on deposit; per-CID response and decline routes are bounded by the pending-request set those controls already gate.

**No confirmation sigils, deliberately.** Short-hash confirmation schemes ("compare these four emoji on both screens") built on a bare hash of public bytes are theater — an attacker who controls one screen computes the same emoji. SIGNING 0.1 ships none. The request CID is the stable hook a real scheme would use — a MAC over the CID with a pairing secret established out-of-band — and nothing in this spec forecloses that; it declines only to ship the theater version.

---

## Relationship to SIWD

SIWD is this protocol's ancestor and is now its client: **`did:dfos:siwd` is a registered `payloadTyp`** ([SIWD.md](https://protocol.dfos.com/siwd)). The SIWD challenge schema, its canonical signing input, and its verification rules survived the absorption unchanged as the target spec; the web-redirect dance remains as SIWD's profile A (a good transport for a browser already standing at the platform's door); the mailbox is its profile B, the courier self-custodied signing rides — the same job without a port, a health probe, or a same-machine constraint. Scope-to-credential issuance is untouched, and SIWD's `deposit` scope is the canonical issuance moment for the mailbox deposit credential this document requires.

---

## Conformance

The mailbox is covered by the relay conformance suite ([CONFORMANCE.md](https://protocol.dfos.com/conformance)) under the standard capability discipline: enabled-behavior tests self-skip unless the relay advertises `capabilities.signing`, and a paired disabled suite asserts that every `/signing/v0/*` route returns **501** — never 404 — on a relay with the capability off, with adjacent surfaces unaffected. The envelope itself is covered by cross-implementation vectors in the TypeScript and Go reference packages, including the adversarial canonicalization set (the WYSIWYS byte contract is only as strong as the vectors that attack it).

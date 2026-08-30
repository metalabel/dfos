# DFOS Key Proof

A challenge-bound proof that a specific key is held and consents to one named introduction — `{nonce, audience, did, roleSet, prevCID, candidate key, timestamp}`, signed by the candidate key itself, scoped by a registered JWS `typ` per ceremony purpose. A key proof proves a key, and binds that key's consent to exactly one position in exactly one identity chain. It never conveys intent, content, or authority.

> **Status — the envelope is protocol surface; the ceremony around it is operator behavior.** The envelope grammar, its canonical bytes, and the [chain-walk verification](#chain-walk-verification) obligations are load-bearing for identity-chain verification — [PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession) requires an embedded key proof for every non-genesis key introduction, and this document is where that envelope's bytes are defined. Those surfaces share the protocol's clock. The carriage, the presentation flow, and the resolution shape are reference ceremony-operator behavior on their own `0.x` clock, like [WEB-RELAY.md](https://protocol.dfos.com/web-relay)'s relation to the frozen core. `typ` values register in the [extension registry](https://protocol.dfos.com/extensions). Discuss in the [DFOS](https://nce.dfos.com) space.

---

## Motivation

Two problems share one artifact.

**The ceremony problem.** Ceremonies that attach a key to something need evidence of two facts at once: that the key's holder actually holds it, and that the holder consents to **this** introduction at **this** operator — deliverable across a device gap (a code typed from one screen into another tool, a QR scanned by a phone) without the carriage becoming an attack surface. The first such ceremony is **key-add**: a holder of a self-custodied key presents it for addition to an identity whose chain another party custodies, so that the holder signs as that identity from their own device from then on.

**The listing problem.** Nothing structural stops a chain from *declaring* a public key its author does not hold — the hole PGP closed in 2003 after subkey hijacking (mandatory cross-certification back-signatures), the same evidence X.509 demands in a CSR's proof-of-possession, ACME in its key authorizations, and WebAuthn in attestation. W3C DID-core does not require it of verification methods, and carries the hole; `did:plc` likewise. DFOS closes it at the chain layer: a key's appearance in an identity chain is accompanied by that key's own signature over the appearance — see [PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession). (KERI's threshold inception is the named counterpoint — possession distributed across an inception quorum — and is not this protocol's shape: a custodial operator holding a user's chain is a reality this design states rather than hides, and a single self-signing genesis key keeps genesis verifiable in isolation.)

One envelope serves both: the proof a holder signs during a ceremony is, byte for byte, the proof the chain carries forever. The ceremony wire artifact **is** the on-chain artifact, verified by the same algorithm at presentation, at adoption, and on every future chain walk.

The shape is not new to this corpus. [SIWD](https://protocol.dfos.com/siwd)'s ask proof — a JWS over the requester's own request bytes under `typ: "did:dfos:siwd-ask"` — is structurally a key proof avant la lettre: key control demonstrated by signing a challenge-bearing payload, scoped by `typ` to exactly one use. This document generalizes that shape once: one envelope grammar, one verification algorithm, and a registry of ceremony purposes, so the next ceremony registers a `typ` instead of minting a bespoke envelope. SIWD's shipped envelopes are **not** retrofitted — the family resemblance is acknowledged here in prose, and their bytes stay their own.

Two properties are pinned normatively before any member is described, because they are the design:

1. **The payload is CLOSED.** The member set below is exhaustive — no free-form payload member, no content-bearing extension, ever. A key proof proves a key; anything that wants to say more is a different artifact. New members land only by amending this document's table, and no amendment may introduce a member that carries intent or content.
2. **Ceremonies are single-shot.** One envelope completes at most one ceremony, and nothing about the exchange establishes a session, a pairing, or a standing channel. Anything ongoing is a separate, deliberate grant under its own machinery. The envelope's afterlife on the chain is not a session either — it is a fact about one introduction at one position, inert everywhere else.

---

## The Envelope

The payload is a JSON object of exactly seven members:

| Member               | Description                                                                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nonce`              | The verifier-minted, single-use challenge string, exactly as the carriage delivered it. Opaque to the holder. A verifier SHOULD mint at least 128 bits of entropy.                                                                                               |
| `audience`           | The completing authority. In a hosted ceremony: the presentation endpoint's **lowercase authority** — bare hostname on the default HTTPS port, `host:port` on any other; never a scheme, never a path (the [API-AUTH authority grammar](https://protocol.dfos.com/api-auth#the-apihost-resource-and-its-actions)). In the [controller-verified leg](#the-two-legs), where no host mediates: the target chain's DID, byte-equal to this payload's own `did` member.  |
| `did`                | The identity chain this key is being introduced to — the DID the holder's human saw and consented to.                                                                                                                                                            |
| `roleSet`            | The [canonical role-set string](#the-roleset-grammar) naming the roles the key gains.                                                                                                                                                                            |
| `prevCID`            | The chain head the introduction builds on — the CID that the introducing operation carries as its `previousOperationCID`.                                                                                                                                        |
| `publicKeyMultibase` | The candidate key — the [Multikey](https://protocol.dfos.com/spec#multikey-encoding-w3c-multikey-for-ed25519) multibase string of the key this proof is about, which is also the key that signs it.                                                              |
| `timestamp`          | ISO 8601 creation time, floor-normalized to whole seconds (`.000Z` millisecond component), as [SIWD](https://protocol.dfos.com/siwd#challenge-schema) normalizes its challenges.                                                                                 |

**Canonical signing input.** The payload is serialized as minimal UTF-8 JSON (no insignificant whitespace) with members in exactly the order above — `nonce`, `audience`, `did`, `roleSet`, `prevCID`, `publicKeyMultibase`, `timestamp` — the family's standard canonical-serialization rule ([SIGNING → canonical serialization](https://protocol.dfos.com/signing)). These bytes are the JWS payload segment. The rule binds both halves: a signer emits these bytes, and a verifier recomputes them from the members it parsed and refuses a payload segment that decodes to anything else ([Presentation Verification](#presentation-verification) step 3). One set of members has one payload serialization, on both sides.

### The roleSet grammar

`roleSet` names the subset of the chain's three key roles the introduction covers, as one canonical string: members drawn from exactly `auth`, `assert`, `controller`; serialized as the subset in the fixed order `auth,assert,controller`; comma-joined; no whitespace; no duplicates; never empty. `auth,assert` and `controller` are canonical spellings; `assert,auth`, `auth, assert`, and `auth,auth` are not role sets, they are schema violations — a verifier rejects them at the same step it rejects a reordered payload. The grammar is closed the way the payload is closed: three role names, one order, nothing else.

### Position binding

The `did`, `roleSet`, and `prevCID` members bind the proof to one introduction at one position:

- `did` binds the proof to one chain. An envelope signed for one identity is dead bytes presented for any other.
- `roleSet` binds the proof to the roles gained. A key's membership in a role is proved only by an envelope whose `roleSet` includes that role — promotion into a role the key's envelopes never covered is a new introduction demanding a fresh proof.
- `prevCID` binds the proof to one chain position. The envelope proves consent to *this* introduction, built on *this* head — not to the key's presence in the chain at large. A removed key cannot be re-added on the strength of an old envelope: the re-adding operation has a different `previousOperationCID`, so the old proof does not cover it, and only the holder can mint the new one. Consent does not stand; it is spent at the position it named.

**Self-proving.** The signature verifies against the payload's own `publicKeyMultibase`. That circularity is the point: a valid envelope is possession demonstrated over challenge bytes — nothing about it depends on who relayed it, and nothing in it is worth stealing after its nonce is consumed and its position is spent.

**The JWS.** The payload is signed as a compact JWS by the candidate key itself:

- `typ` — exactly one registered purpose value from the [purpose registry](#purpose-registry) below. Verifiers reject any other `typ`; the gate is what keeps a proof signed for one ceremony from ever being presented for another.
- `alg` — the signature algorithm of the candidate key's Multikey type. The identity chain's key registry admits `ed25519-pub`, signed as `EdDSA`; the envelope grammar itself is key-type-agnostic and carries whatever Multikey the chain's key registry admits, so a key type admitted to chains is admitted here by the same act, with no change to this document.
- `kid` — **absent.** The candidate key is not in any chain, so there is no DID URL to name; the verification key rides in the signed payload itself. A `crit` member rejects, and an embedded key member (`jwk`, `jku`, `x5c`, …) rejects, exactly as the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile) requires everywhere.

**What stays outside the signed bytes.** The ceremony identifier travels beside the envelope in the presentation request, never inside it. The nonce is the binding: the verifier minted it for exactly one ceremony, so envelope→ceremony linkage is the verifier's own bookkeeping. The optional human-readable key label an operator accepts alongside a presentation is likewise unsigned operator metadata, never a payload member.

---

## The Two Legs

An introduction is verified by whoever appends it, and the envelope's `audience` names that party in the value domain the flow actually has:

- **The hosted ceremony leg.** A ceremony operator (a host custodying the chain) mints the nonce, and `audience` is that host's authority. This is the key-add ceremony: the holder's tool resolves a carriage, its human confirms, it signs and presents, and the operator's authenticated side commits the introduction.
- **The controller-verified leg.** A chain's own controller introduces a key held on another of its human's devices — no host mediates. The controller's tool mints the nonce and delivers `{did, roleSet, prevCID, nonce}` to the device; the device signs and returns the envelope; the controller's tool verifies and appends. Here `audience` is the target chain's DID, and the verifier REQUIRES `audience` to byte-equal the payload's `did`.

The two value domains never overlap — a host authority is not a DID — so an envelope signed for one leg can never verify in the other, with no discriminator member and no registry. On the chain the distinction evaporates: [chain-walk verification](#chain-walk-verification) treats `audience` as byte-fixed transport in both legs.

---

## Audience Binding

`audience` is the load-bearing security member of the hosted leg. The signer writes the authority of the endpoint it intends to present at — the authority its human confirmed — and the verifier byte-compares that member against **its own configured authority**, never against anything request-derived, rejecting on mismatch ([API-AUTH's host-binding discipline](https://protocol.dfos.com/api-auth#verification-algorithm), same reasoning).

This is what defeats the challenge-relay attack that code and QR carriage invites: a phishing page that obtains a victim's ceremony code and re-displays it on its own surface still cannot harvest a usable proof, because the proof the victim's tool produces names the authority the victim confirmed — and a proof audienced to one host is dead bytes at every other.

---

## Purpose Registry

Each ceremony purpose is one registered `typ`. The envelope grammar and the verification algorithms are identical for every row; what a completed proof _effects_ is the ceremony operator's own machinery, outside this document. A new purpose lands by adding its row here **and** its row in the [extension registry](https://protocol.dfos.com/extensions), in the same PR that specifies the ceremony — never by minting locally.

| `typ` value        | Purpose                                                                                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `did:dfos:key-add` | The candidate key consents to introduction into the named identity chain's key sets, for the named roles, at the named position. Both [legs](#the-two-legs) use this value; it is the `typ` that [chain-walk verification](#chain-walk-verification) requires of every embedded proof. |

---

## Carriage

The carriage conveys exactly two values — **an authority and a code** — and the code is the ceremony's identifier: it selects the ceremony at resolution and travels beside the envelope at presentation. What the carriage does not carry is the signing context: everything the payload binds and everything the holder's human must see lives in the *resolution* of a live code, so every carriage form funnels through one resolution step, and a tool MUST resolve before signing — there is no self-contained carriage that skips it. The code itself names no identity; resolving it names everything — this is deliberate, and its trust posture is examined under [Security Considerations](#security-considerations).

**Short code.** The human-typeable display form, `<authority>/<code>`, where `<code>` is an operator-chosen compact token.

**URI carriage.** One HTTPS URL naming the same resolution — the [resolution endpoint](#carriage) with its `code` member. A QR code and a deep link are this URI verbatim: a phone arrives later as a carriage of the same flow, never as a second flow, and lands at the same mandatory resolution as a typed code.

**Resolution.** A tool resolves with `GET https://<authority>/.well-known/dfos-key-proof?code=<code>`. A live code answers the full signing context:

```jsonc
{
  "present": "…",          // absolute URL of the presentation endpoint
  "nonce": "…",            // the verifier-minted challenge the payload carries
  "audience": "…",         // the authority the envelope names — byte-equal to the resolving authority
  "purpose": "did:dfos:key-add",
  "adopts": { "did": "…", "handle": "…", "displayName": "…" },
  "roleSet": "…",          // canonical role-set string the ceremony introduces
  "prevCID": "…",          // the chain's current head
  "expiresAt": "…",
  "relay": "…"             // OPTIONAL — the advisory oracle, below
}
```

The resolved `audience` MUST byte-equal the resolving authority, and the `present` URL's authority MUST byte-equal it too — a code's resolution can never redirect a ceremony off the host the human typed.

`adopts` names the identity the introduction targets: its DID, and the operator's public handle and display name for it. The holder's tool renders these to its human verbatim; a tool MUST NOT sign on a resolution that omits them. `prevCID` is the head the envelope binds — a holder that signs a stale head produces an envelope the operator refuses at adoption, and re-resolves for the current head to re-sign; re-resolution of a live ceremony is how the holder recovers, never a second ceremony.

The `relay` member, when present, is an absolute `https` URL of a relay serving the [`key=` reverse index](https://protocol.dfos.com/web-relay#identities-get-indexv0identitiesdidkeyhaspublicprofilenamecontainsorderafterdidlimitn). It is the operator naming an oracle for the [one-key-one-DID pre-flight](#holder-obligations): a holder with no oracle of its own SHOULD check against it, **for that ceremony only**, and MUST NOT adopt it as a standing peer — the member configures nothing beyond the single pre-flight it names, and a holder's own configured relay always takes precedence. A tool ignores resolution members it does not recognize.

Single-shot applies to the carriage too: a code is consumed with its ceremony, and neither the code, the nonce, nor any resolution member is a session, a pairing, or a credential.

---

## Presentation Verification

A verifier receiving an envelope at presentation — a ceremony operator on the hosted leg, the controller's tool on the controller-verified leg:

1. **Size cap.** Reject an envelope over 4 KiB before parsing.
2. **Header gates.** `typ` MUST be exactly the registered value the ceremony requires; `alg` MUST be the algorithm of the payload key's Multikey type; a `crit` member rejects; an embedded key member rejects; a present `kid` rejects.
3. **Payload schema, over canonical bytes.** Exactly the seven members above, each a string, `roleSet` in the [canonical grammar](#the-roleset-grammar); any absent, any extra, any non-string, or any non-canonical `roleSet` member rejects. The verifier then recomputes the [canonical signing input](#the-envelope) from the parsed members and byte-compares it against the payload octets presented; a mismatch rejects. The recomputation is not redundant with the signature check: a signature covers whatever octets arrived, so without it a payload whose members are reordered — or re-spelled with insignificant whitespace — and signed over that serialization verifies exactly like the canonical one. What the comparison pins is the payload's octets, and nothing past them; a conformant signer emits those bytes already, so it refuses nothing that could be signed correctly.
4. **Audience.** On the hosted leg, `audience` MUST byte-equal the verifier's own configured authority. On the controller-verified leg, `audience` MUST byte-equal the payload's `did`.
5. **Position.** `did` MUST name the chain this ceremony introduces to; `roleSet` MUST equal the role set the ceremony grants; `prevCID` MUST equal the chain's current head. A `prevCID` mismatch is a stale envelope — refused without prejudice; the holder re-signs against the current head.
6. **Freshness.** `timestamp` MUST fall within the verifier's acceptance window (RECOMMENDED: 300 seconds, either side, matching the ceremony's own lifetime).
7. **Nonce.** The nonce MUST be one this verifier minted, for this ceremony, not yet consumed — checked and consumed **atomically** (check-and-delete, [SIWD's consumed discipline](https://protocol.dfos.com/siwd)), so two racing presentations cannot both pass.
8. **Signature.** The JWS MUST verify against the payload's `publicKeyMultibase`.

A proof that passes all eight is exactly one fact: _the named key was held, and consented to joining the named chain in the named roles at the named position, at this verifier, inside this window._ Everything after — the adoption decision, custody policy, notification — is the ceremony operator's, per the purpose's owner. What the operator that adopts it MUST do with the bytes is one thing only: embed them verbatim in the introducing operation's `keyProofs` member ([PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession)) — the artifact verified at presentation is the artifact the chain carries.

---

## Chain-Walk Verification

The envelope's second life is on the chain, embedded in the operation that introduced its key. A verifier walking an identity chain checks, for each embedded envelope:

1. **Header gates**, as at presentation: `typ` MUST be `did:dfos:key-add`; `alg` per the key's Multikey type; `crit`, embedded key members, and `kid` reject.
2. **Payload schema, over canonical bytes** — the same closed seven-member schema, canonical `roleSet` grammar, and byte-compare as presentation step 3.
3. **Key.** `publicKeyMultibase` MUST equal the introduced key's multikey.
4. **Chain.** `did` MUST equal the chain's own DID.
5. **Position.** `prevCID` MUST equal the carrying operation's `previousOperationCID`.
6. **Coverage.** `roleSet` MUST include every role the operation introduces the key to (a key's proved-ness is computed per role — see [PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession)).
7. **Signature.** The JWS MUST verify against the payload's `publicKeyMultibase`.

`nonce`, `audience`, and `timestamp` are presentation-time transport, byte-fixed under the signature and inert at walk time: a walker re-checks neither freshness nor audience nor nonce state. Their job was done when the introduction was adopted; on the chain they are simply part of the bytes the holder signed.

What a failed walk-time check means is defined by [PROTOCOL.md](https://protocol.dfos.com/spec#key-possession), not here: an unproved introduction is **void** — excluded from the chain's effective key state — and never invalidates the operation or the chain.

---

## Holder Obligations

- **Render before signing.** A holder MUST show its human, before signing: the `audience`, the ceremony purpose, the adopting identity — DID, and the operator-published handle and display name from the [resolution](#carriage) — and the `roleSet`. It MUST refuse to sign when any of these is absent from the resolution, and MUST refuse an audience its human did not initiate. A proof is consent, and consent that was never displayed was never given.
- **One key, one DID — ever.** A holder SHOULD refuse to sign a key proof for a key that any identity's chain has ever declared *and proved* (its own DID included, for a key-add naming a different identity). The [`key=` reverse index](https://protocol.dfos.com/web-relay#identities-get-indexv0identitiesdidkeyhaspublicprofilenamecontainsorderafterdidlimitn) is has-ever-proved across all three key sets, and its rows survive rotation and deletion — proving one key into two chains publishes an irreversible public link between them. An *unproved* declaration of the key in some other chain is not a link and not a burn: it is void, it never indexes, and it never obligates the true holder ([PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession)). Reference tooling checks against a named oracle relay and refuses by default. A holder with no oracle of its own takes the one the [carriage resolution names](#carriage), for that ceremony only.
- **Fresh bytes only.** A holder signs a payload it constructed itself from a carriage it resolved — never payload bytes supplied ready-made by anyone else.

---

## Security Considerations

- **Challenge relay / phishing** — defeated by [audience binding](#audience-binding): a relayed challenge yields a proof audienced to the host the victim confirmed, unusable elsewhere.
- **Replay** — bounded three ways: nonce consumption (atomic, single-use) and the freshness window close the presentation; [position binding](#position-binding) closes the chain — an envelope names one head of one chain for one role set, and is dead bytes at every other position, forever.
- **Standing consent** — foreclosed by `prevCID`: no party, the chain's own controller included, can re-introduce a removed key on the strength of its old envelope. The old proof named a head that is no longer the head. Every introduction costs a fresh signature from the key itself.
- **Hostile listing / preemptive claim** — a chain that declares a key it does not hold produces a void membership: never effective, never indexed, never a burn against the true holder. The listing problem this document exists to close cannot be reopened by the listing itself. See [PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession).
- **Carriage interception** — possession of a code or QR yields the ability to *resolve* the ceremony's context and to *attempt* a presentation, which still requires signing with a key the interceptor does not hold; the operator's own ceremony authorization is the gate on everything after. The resolution names the adopting identity — that disclosure is deliberate: the named facts (DID, handle, display name) are public identity facts, the code is a short-lived single-ceremony capability, and a holder who cannot see whom they are joining cannot meaningfully consent. The trade is stated, not hidden: a code-holder learns *which* public identity is mid-ceremony, and nothing else.
- **Wrong-ceremony signing** — the render-before-sign obligation plus position binding: the human sees the DID and roles their terminal is about to consent to, and the operator's dialog independently displays the presented key's fingerprint for the human to compare, so a proof harvested into the wrong ceremony fails at `did`/`roleSet`/`prevCID` before any human error is needed. The `did` line defends against a wrong or relayed code — not against a malicious chain custodian, who custodies the chain being joined and needs no forged proof to harm it.
- **Intent smuggling** — foreclosed by the closed payload: there is no member in which to embed a transaction, a message, or an instruction, so a key proof can never be socially engineered into "signing something".
- **Payload malleability** — foreclosed by the canonical-bytes recomputation in [Presentation Verification](#presentation-verification) step 3 and [Chain-Walk Verification](#chain-walk-verification) step 2: a signature covers presented octets rather than member semantics, so a verifier that checked only the parsed shape admits a reordered or re-spaced payload signed over its own serialization, and the payload stops being a function of its members. The recomputation binds the payload octets to the members, and that is its extent. The envelope around them is not canonicalized — the family's base64url decoding is padding-tolerant, and no rule pins the protected header's serialization — so one proof still has more than one envelope spelling. Nothing rests on envelope uniqueness at presentation (what a presentation spends is the nonce, consumed atomically and once); on the chain the carrying operation's CID pins one spelling of the whole operation, envelope included.
- **Session capture** — foreclosed by single-shot: no pairing or channel exists to hijack after adoption.
- **Cross-DID linkage** — the one-key-one-DID holder rule above; the linkage risk is public and permanent by construction of the has-ever-proved index, which is why the refusal belongs in the holder's tooling, before any signature exists.
- **Operator-named oracle** — the resolution's `relay` member hands the pre-flight's data source to the same party that runs the ceremony, which is trust the ceremony already extends: the operator decides what its adoption effects, and a holder's own configured relay always takes precedence over the member. It reaches only the holder that brought no oracle at all — for whom the alternative was no check running — and it is ceremony-scoped by rule: a holder that registered it as a standing peer would be extending trust the ceremony never asked for.
- **Key-type agility** — the grammar carries any chain-admissible Multikey; admitting a new key type to identity chains is a deliberate protocol-level act with its own review, and this envelope inherits the result without amendment.

---

## What This Is Not

- **Not a [SIGNING](https://protocol.dfos.com/signing) family.** A sign-request couriers someone else's payload to a signer whose human approves the _content_; a key proof is self-signed over self-constructed bytes with nothing to approve but the introduction itself. Nothing here rides the mailbox.
- **Not [SIWD](https://protocol.dfos.com/siwd).** SIWD establishes a relationship by exercising a key an identity chain **already declares**; a key proof presents a candidate key for an introduction the chain has not yet made. The resemblance is the family's shared canonical-bytes discipline, not shared purpose.
- **Not a credential.** A key proof conveys no authority and delegates nothing; what its adoption effects is the ceremony operator's machinery, what its embedding proves is defined by [PROTOCOL.md](https://protocol.dfos.com/spec#key-possession), and revoking a key (removing it) is chain machinery, not proof machinery. There is no proof revocation: a proof is spent at the position it names, and removal is an ordinary chain operation.

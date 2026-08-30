# DFOS Key Proof

A challenge-bound, single-shot proof that a specific key is held and consents to one named ceremony — `{nonce, audience, candidate key, timestamp}`, signed by the candidate key itself, scoped by a registered JWS `typ` per ceremony purpose. A key proof proves a key. It never conveys intent, content, or authority.

> **Status — KEY-PROOF 0.1, an optional capability on its own `0.x` clock, independent of the Protocol v1 freeze.** The key-proof envelope, its verification obligations, and the purpose registry below are published for review and early implementation — they are **not part of the frozen protocol surface**, and the frozen protocol never depends on them. KEY-PROOF builds on frozen primitives (the [Multikey encoding](https://protocol.dfos.com/spec#multikey-encoding-w3c-multikey-for-ed25519) and the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile)'s header discipline) and registers its `typ` values in the [extension registry](https://protocol.dfos.com/extensions). The envelope is never relay-ingested and sits outside the frozen v1 vector set on purpose. Discuss in the [DFOS](https://nce.dfos.com) space.

---

## Motivation

Ceremonies that attach a key to something need evidence of two facts at once: that the key's holder actually holds it, and that the holder consents to **this** ceremony at **this** operator — deliverable across a device gap (a code typed from one screen into another tool, a QR scanned by a phone) without the carriage becoming an attack surface. The first such ceremony is **key-add**: a holder of a self-custodied key presents it for addition to an identity whose chain another party custodies, so that the holder signs as that identity from their own device from then on.

The shape is not new to this corpus. [SIWD](https://protocol.dfos.com/siwd)'s ask proof — a JWS over the requester's own request bytes under `typ: "did:dfos:siwd-ask"` — is structurally a key proof avant la lettre: key control demonstrated by signing a challenge-bearing payload, scoped by `typ` to exactly one use. This document generalizes that shape once: one envelope grammar, one verification algorithm, and a registry of ceremony purposes, so the next ceremony registers a `typ` instead of minting a bespoke envelope. SIWD's shipped envelopes are **not** retrofitted — the family resemblance is acknowledged here in prose, and their bytes stay their own.

Two properties are pinned normatively before any member is described, because they are the design:

1. **The payload is CLOSED.** The member set below is exhaustive — no free-form payload member, no content-bearing extension, ever. A key proof proves a key; anything that wants to say more is a different artifact. New members land only by amending this document's table, and no amendment may introduce a member that carries intent or content.
2. **Ceremonies are single-shot.** One envelope completes at most one ceremony, and nothing about the exchange establishes a session, a pairing, or a standing channel. Anything ongoing is a separate, deliberate grant under its own machinery.

---

## The Envelope

The payload is a JSON object of exactly four members:

| Member               | Description                                                                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nonce`              | The verifier-minted, single-use challenge string, exactly as the carriage delivered it. Opaque to the holder. A verifier SHOULD mint at least 128 bits of entropy.                                                                                               |
| `audience`           | The completion endpoint's **lowercase authority** — bare hostname on the default HTTPS port, `host:port` on any other; never a scheme, never a path (the [API-AUTH authority grammar](https://protocol.dfos.com/api-auth#the-apihost-resource-and-its-actions)). |
| `publicKeyMultibase` | The candidate key — the [Multikey](https://protocol.dfos.com/spec#multikey-encoding-w3c-multikey-for-ed25519) multibase string of the key this proof is about, which is also the key that signs it.                                                              |
| `timestamp`          | ISO 8601 creation time, floor-normalized to whole seconds (`.000Z` millisecond component), as [SIWD](https://protocol.dfos.com/siwd#challenge-schema) normalizes its challenges.                                                                                 |

**Canonical signing input.** The payload is serialized as minimal UTF-8 JSON (no insignificant whitespace) with members in exactly the order above — the family's standard canonical-serialization rule ([SIGNING → canonical serialization](https://protocol.dfos.com/signing)). These bytes are the JWS payload segment. The rule binds both halves: a signer emits these bytes, and a verifier recomputes them and refuses a payload segment that is not them ([Verification](#verification) step 3), so an envelope's bytes are a function of its members and a proof has exactly one spelling.

**The JWS.** The payload is signed as a compact JWS by the candidate key itself:

- `typ` — exactly one registered purpose value from the [purpose registry](#purpose-registry) below. Verifiers reject any other `typ`; the gate is what keeps a proof signed for one ceremony from ever being presented for another.
- `alg` — the signature algorithm of the candidate key's Multikey type. The identity chain's key registry admits `ed25519-pub`, signed as `EdDSA`; the envelope grammar itself is key-type-agnostic and carries whatever Multikey the chain's key registry admits, so a key type admitted to chains is admitted here by the same act, with no change to this document.
- `kid` — **absent.** The candidate key is not in any chain, so there is no DID URL to name; the verification key rides in the signed payload itself. A `crit` member rejects, and an embedded key member (`jwk`, `jku`, `x5c`, …) rejects, exactly as the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile) requires everywhere.

**Self-proving.** The signature verifies against the payload's own `publicKeyMultibase`. That circularity is the point: a valid envelope is possession demonstrated over fresh verifier-minted bytes — nothing about it depends on who relayed it, and nothing in it is worth stealing after its nonce is consumed.

**What stays outside the signed bytes.** The ceremony identifier travels beside the envelope in the completion request, never inside it. The nonce is the binding: the verifier minted it for exactly one ceremony, so envelope→ceremony linkage is the verifier's own bookkeeping, and the payload stays four members forever.

---

## Audience Binding

`audience` is the load-bearing security member. The signer writes the authority of the endpoint it intends to complete at — the authority its human confirmed — and the verifier byte-compares that member against **its own configured authority**, never against anything request-derived, rejecting on mismatch ([API-AUTH's host-binding discipline](https://protocol.dfos.com/api-auth#verification-algorithm), same reasoning).

This is what defeats the challenge-relay attack that code and QR carriage invites: a phishing page that obtains a victim's ceremony code and re-displays it on its own surface still cannot harvest a usable proof, because the proof the victim's tool produces names the authority the victim confirmed — and a proof audienced to one host is dead bytes at every other.

---

## Purpose Registry

Each ceremony purpose is one registered `typ`. The envelope grammar and the [verification algorithm](#verification) are identical for every row; what a completed proof _effects_ is the ceremony operator's own machinery, outside this document. A new purpose lands by adding its row here **and** its row in the [extension registry](https://protocol.dfos.com/extensions), in the same PR that specifies the ceremony — never by minting locally.

| `typ` value        | Purpose                                                                                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `did:dfos:key-add` | The candidate key presents for addition to a ceremony-named identity's `authKeys`/`assertKeys` sets. Which identity, and every custody rule around the append, is the ceremony operator's. |

---

## Carriage

The carriage conveys exactly three values — **completion endpoint, ceremony identifier, nonce** — and names no identity: a shoulder-surfed code or an intercepted QR learns where a ceremony completes and nothing about whom it is for.

**URI carriage.** One HTTPS URL carrying the triple: the completion endpoint with `ceremony` and `nonce` query members; the completion endpoint is the URL with those two members removed. A QR code and a deep link are this URI verbatim — a phone arrives later as a carriage of the same flow, never as a second flow.

**Short code.** A human-typeable display form, `<authority>/<code>`, where `<code>` is an operator-chosen compact token. A tool resolves it with `GET https://<authority>/.well-known/dfos-key-proof?code=<code>`, which answers `{"uri": "<carriage URI>"}` — and the resolved URI's authority MUST byte-equal the resolving authority, so a code's resolution can never redirect a ceremony off the host the human typed.

The resolution answer MAY carry one more member: `relay`, an absolute `https` URL of a relay serving the has-ever-declared [`key=` reverse index](https://protocol.dfos.com/web-relay#identities-get-indexv0identitiesdidkeyhaspublicprofilenamecontainsorderafterdidlimitn). It is the operator naming an oracle for the [one-key-one-DID pre-flight](#holder-obligations): a holder with no oracle of its own SHOULD check against it, **for that ceremony only**, and MUST NOT adopt it as a standing peer — the member configures nothing beyond the single pre-flight it names, and a holder's own configured relay always takes precedence. The trust posture is examined under [Security Considerations](#security-considerations). A tool ignores resolution members it does not recognize.

Single-shot applies to the carriage too: a carriage token is consumed with its ceremony, and no member of the triple is a session, a pairing, or a credential.

---

## Verification

A verifier completing a ceremony, on receiving an envelope:

1. **Size cap.** Reject an envelope over 4 KiB before parsing.
2. **Header gates.** `typ` MUST be exactly the registered value the ceremony requires; `alg` MUST be the algorithm of the payload key's Multikey type; a `crit` member rejects; an embedded key member rejects; a present `kid` rejects.
3. **Payload schema, over canonical bytes.** Exactly the four members above, each a string; any absent, any extra, or any non-string member rejects. The verifier then recomputes the [canonical signing input](#the-envelope) from the parsed members and byte-compares it against the payload segment presented; a mismatch rejects. The recomputation is not redundant with the signature check: a signature covers whatever octets arrived, so without it a payload whose members are reordered — or re-spelled with insignificant whitespace — and signed over that serialization verifies exactly like the canonical one, and one proof has many spellings. A conformant signer emits the canonical bytes already, so this refuses nothing that could be signed correctly.
4. **Audience.** `audience` MUST byte-equal the verifier's own configured authority.
5. **Freshness.** `timestamp` MUST fall within the verifier's acceptance window (RECOMMENDED: 300 seconds, either side, matching the ceremony's own lifetime).
6. **Nonce.** The nonce MUST be one this verifier minted, for this ceremony, not yet consumed — checked and consumed **atomically** (check-and-delete, [SIWD's consumed discipline](https://protocol.dfos.com/siwd)), so two racing completions cannot both pass.
7. **Signature.** The JWS MUST verify against the payload's `publicKeyMultibase`.

A proof that passes all seven is exactly one fact: _the named key was held, and consented to this ceremony at this verifier, inside this window._ Everything after — appending the key to a chain, custody policy, notification — is the ceremony operator's, per the purpose's owner.

---

## Holder Obligations

- **Display before signing.** A holder MUST show its human the audience and the ceremony purpose before signing, and MUST refuse an audience its human did not initiate — the audience member only defends people who saw it.
- **One key, one DID — ever.** A holder SHOULD refuse to sign a key proof for a key that any identity's chain has ever declared (its own DID included, for a key-add naming a different identity). The [`key=` reverse index](https://protocol.dfos.com/web-relay#identities-get-indexv0identitiesdidkeyhaspublicprofilenamecontainsorderafterdidlimitn) is has-ever-declared across all three key sets, and its rows survive rotation and deletion — declaring one key in two chains publishes an irreversible public link between them. Reference tooling checks against a named oracle relay and refuses by default. A holder with no oracle of its own takes the one the [carriage resolution names](#carriage), for that ceremony only.
- **Fresh bytes only.** A holder signs a payload it constructed itself from a carriage it resolved — never payload bytes supplied ready-made by anyone else.

---

## Security Considerations

- **Challenge relay / phishing** — defeated by [audience binding](#audience-binding): a relayed challenge yields a proof audienced to the host the victim confirmed, unusable elsewhere.
- **Replay** — bounded by nonce consumption (atomic, single-use) plus the freshness window; a captured envelope is dead bytes after either bound closes.
- **Carriage interception** — the carriage names no identity; possession of a code or QR yields the ability to _attempt_ a completion, which still requires signing with a key the interceptor does not hold, at which point the operator's own ceremony authorization (who may complete this ceremony) is the gate.
- **Intent smuggling** — foreclosed by the closed payload: there is no member in which to embed a transaction, a message, or an instruction, so a key proof can never be socially engineered into "signing something".
- **Payload malleability** — foreclosed by the canonical-bytes recomputation in [Verification](#verification) step 3. A signature covers presented octets, not member semantics, so a verifier that checked only the parsed shape would admit a reordered or re-spaced payload signed over its own serialization: the same proof under many byte strings, each with its own hash, for a caller to key, log, cache, or deduplicate against. Byte-comparing against the recomputed canonical input makes the envelope a function of its members again.
- **Session capture** — foreclosed by single-shot: no pairing or channel exists to hijack after completion.
- **Cross-DID linkage** — the one-key-one-DID holder rule above; the linkage risk is public and permanent by construction of the has-ever-declared index, which is why the refusal belongs in the holder's tooling, before any signature exists.
- **Operator-named oracle** — the resolution's `relay` member hands the pre-flight's data source to the same party that runs the ceremony, which is trust the ceremony already extends: the operator decides what its completion effects, and a holder's own configured relay always takes precedence over the member. It reaches only the holder that brought no oracle at all — for whom the alternative was no check running — and it is ceremony-scoped by rule: a holder that registered it as a standing peer would be extending trust the ceremony never asked for.
- **Key-type agility** — the grammar carries any chain-admissible Multikey; admitting a new key type to identity chains is a deliberate protocol-level act with its own review, and this envelope inherits the result without amendment.

---

## What This Is Not

- **Not a [SIGNING](https://protocol.dfos.com/signing) family.** A sign-request couriers someone else's payload to a signer whose human approves the _content_; a key proof is self-signed over self-constructed bytes with nothing to approve but the ceremony itself. Nothing here rides the mailbox.
- **Not [SIWD](https://protocol.dfos.com/siwd).** SIWD establishes a relationship by exercising a key an identity chain **already declares**; a key proof presents a candidate key that no chain declares yet. The resemblance is the family's shared canonical-bytes discipline, not shared purpose.
- **Not a credential.** A key proof conveys no authority and delegates nothing; what its completion effects is entirely the ceremony operator's machinery, and revoking that effect (removing a key) is chain machinery, not proof machinery.

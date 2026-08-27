# DFOS Credits

Verifiable attribution for DFOS content. A **credit claim** is a claimant's own signed statement that it holds a named role on a content chain — the mechanism that turns a liner-note credit into a fact the credited party asserted for itself.

> **Status — new capability, additively landed on Protocol v1.** The credit-claim envelope (`did:dfos:credit-claim`), the `credits[]` embedding, and the two-way bind defined here are **settled**: build on them as specified. Per the [core protocol status](https://protocol.dfos.com/spec), v1 is frozen but not yet final — new capability like this lands additively, clarifications are corrected in place, and a genuine break to a settled field becomes v1.1 or v2, never a silent edit. Credits sit **outside** the frozen v1 vector set on purpose: this is a document-layer envelope, not a change to identity or content chains. The reference packages stay on their own `0.x` semver line. Discuss in the [DFOS](https://nce.dfos.com) space.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/chain/credit-claim.ts) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Motivation

Who signed a thing and who **made** a thing are different claims, and the protocol only ever knew the first one. Every operation's `kid` DID is cryptographic fact, but a great deal of real content is signed by a custodial host or a space on behalf of the people who made it — so the signer is honest and still tells you almost nothing about authorship. The [content model](https://protocol.dfos.com/content-model) closed half of that gap with `credits[]`: the signer says who made it, and a consumer reads that as an assertion **of the signer**. What was missing was the other half — a way for the credited party to say it too.

A credit claim is that half. It is small, standalone, and boring on purpose: the claimant signs `(contentId, did, role)` and nothing else.

### Attribution is content, not proof-plane

The tempting design is to put attribution on the proof plane — gossip claims between relays, index them, serve "who claimed what" as a queryable surface. DFOS deliberately does not, and the reason is the boundary the whole system is built on: **chain metadata is public; document bytes are gated.**

Anything on the proof plane is world-readable by construction. Operations gossip, and a relay that holds an operation holds it in the clear. So a claim on the proof plane would announce `did:dfos:alice — photographer — chain X` to every peer, for **every** chain — including chains whose document bytes are gated and whose contents Alice can see but the public cannot. Attribution would leak the one thing the gate exists to protect: the shape of private work. A creator's unreleased catalog would become enumerable through its credits.

Putting the claim **inside the document bytes** puts attribution on the same side of the boundary as the thing it attributes. A claim on gated content is exactly as visible as the content: readers who can fetch the document can verify the credit; readers who cannot, cannot. Nothing about the claim needs its own access-control story, because it inherits the document's. This is not a limitation worked around — it is the coherent position, and it is why credits are a document-layer envelope rather than a fourth kind of gossiped operation.

The cost is real and worth naming: there is no global "show me everything Alice claims" query. That index would be precisely the enumeration leak above. A consumer verifies the credits on content it can already read.

---

## The Credit Claim Envelope

A credit claim is a JWS in the same envelope family as [credentials](https://protocol.dfos.com/credentials) and revocations, with its own `typ`.

### JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:credit-claim",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

| Field | Value                     | Description                                          |
| ----- | ------------------------- | ---------------------------------------------------- |
| `alg` | `"EdDSA"`                 | Ed25519 signature algorithm                          |
| `typ` | `"did:dfos:credit-claim"` | Protocol-specific type discriminator                 |
| `kid` | DID URL                   | `did:dfos:<id>#<keyId>` — identifies the signing key |
| `cid` | CID string                | Content address of the payload                       |

**kid format.** The `kid` MUST be a DID URL containing `#`. The DID portion MUST equal the payload's `did`. This is the rule that makes a claim self-asserted: **only the claimant can claim its own credit.** A third party signing "Alice is the photographer" produces an invalid claim, not a weaker one — that statement already has a home in `credits[]`, where it is correctly read as the signer's assertion.

**Key resolution** follows the credential rule: **historical** resolution, any key role. Every key that has ever appeared in the claimant's identity chain is an acceptable signing key, so a claim survives key rotation. This is the right default for a permanent historical attribution — a credit signed in 2026 should not evaporate because the claimant rotated keys in 2028.

Historical resolution is a **requirement on the resolver a verifier is given**, not something the verifier can supply for itself. A verified identity's `authKeys`/`assertKeys`/`controllerKeys` are a projection of the chain's CURRENT head — an `update` operation replaces each role array wholesale — so a resolver built from head state alone has already discarded the rotated-out key a two-year-old claim was signed with. An implementation MUST resolve claimant keys from chain history (merging every key the chain has ever carried, exactly as credential verification already requires) before handing the identity to a claim verifier. A verifier fed current-state-only keys reports **invalid** for every claim predating the claimant's most recent rotation — silently un-crediting real work, and reporting a positive failure where the honest answer was "this key rotated."

### Payload

```json
{
  "version": 1,
  "type": "credit-claim",
  "contentId": "cv7n8vkvr64cctf3294h9k4eanhff8z",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "role": "photography",
  "createdAt": "2026-03-07T00:00:00.000Z"
}
```

| Field             | Type             | Required | Description                                                       |
| ----------------- | ---------------- | -------- | ----------------------------------------------------------------- |
| `version`         | `1`              | yes      | Schema version (literal `1`)                                      |
| `type`            | `"credit-claim"` | yes      | Literal discriminator                                             |
| `contentId`       | string           | yes      | The 31-char content chain id this claim binds to — **the binder** |
| `did`             | string           | yes      | The claimant DID — MUST equal the `kid`'s DID                     |
| `role`            | string           | yes      | The claimed role — open vocabulary, compared byte-exact           |
| `createdAt`       | string           | yes      | ISO 8601, millisecond precision, UTC                              |
| `asOfDocumentCID` | CID              | no       | Optional pinned document state (see **Content-strength claims**)  |

Unknown top-level fields are preserved-and-ignored, per the protocol's MUST-ignore-unknown rule. The CID commits to the exact bytes, so a verifier that stripped unknown keys would fail its own CID check.

**`role` is an open vocabulary** compared by **exact, case-sensitive byte equality**. `"photography"`, `"editor"`, `"mixed by"`, and `"翻訳"` are all legal, and `"Author"` is a different role from `"author"`. No normalization of any kind is applied — not case folding, not Unicode normalization, not whitespace trimming. `role` is one of the three components of the bind, so any normalization would be a place where two implementations could disagree about whether an entry is claimed. Applications that want a controlled vocabulary enforce it at their own layer.

**`createdAt` is not load-bearing.** Unlike an operation's `createdAt` (which orders chain history), a claim's timestamp orders nothing and gates nothing. It is provenance metadata — when the claimant signed. Verification never compares it against a clock, and a claim has **no expiry**.

**Signers MUST normalize `createdAt` to whole seconds** — the millisecond component of a signed claim is always `000`, the canonical form this envelope family uses. This binds signers, not verifiers: a verifier accepts any conforming millisecond-precision timestamp (the grammar is what is normative), but a signer that emitted real milliseconds would produce different claim bytes, and therefore a different claim CID, for a statement another implementation encodes as `.000Z`. The rule applies to a caller-supplied timestamp exactly as it does to "now": an override is normalized, not passed through, so re-deriving a claim from the same inputs lands on the same CID on every implementation.

### CID Derivation

Identical to every other protocol object:

```
dagCborCanonicalEncode(payload) -> SHA-256 -> CIDv1 (dag-cbor + SHA-256)
```

The derived CID is embedded in the protected header as `cid`, and verification re-derives it from the parsed payload and compares. Mismatch is a verification failure. As everywhere else in the protocol, dag-cbor is used **only** for CID derivation; the JWS body carries JSON.

### Size Bound

| Bound                  | Value          | Applies to                 |
| ---------------------- | -------------- | -------------------------- |
| credit claim JWS token | **4096 bytes** | the serialized claim token |

Verifiers MUST reject a claim whose serialized JWS token exceeds 4096 bytes, checked **before any decode** (a DoS guard). This is the claim's single aggregate byte arbiter: `role` and `contentId` carry no separate per-field length caps, matching the protocol's practice everywhere else of preferring one aggregate bound over a per-field length table that would fork validity across implementations.

The cap is deliberately **tight** — two orders of magnitude below the credential cap — because claims travel inside document bytes. A document crediting twelve collaborators carries twelve tokens in its blob, so a generous per-claim ceiling multiplies into the document. A claim has no nested structure and nothing that legitimately grows: 4096 bytes is far more than a real claim needs.

This bound is **validity-determining** and MUST be identical across implementations.

### Content-strength claims (`asOfDocumentCID`)

By default a claim binds to the chain and says nothing about which revision the claimant saw. `asOfDocumentCID` is an optional stronger statement: _I credit myself on the chain, and this is the document state I was looking at._ It is useful when a role attaches to a specific version of the work rather than to the work's whole future.

It is **not** part of the bind, and consumers that ignore it are fully conformant. Omitting it is the default and is CID-neutral — an absent `asOfDocumentCID` encodes identically to a claim that never had the field, so adding the flavor is never retroactively implied.

---

## Embedding: the `credits[]` Entry

A claim is not published on its own. It rides in the `claim` field of a `credits[]` entry inside the document that credits the claimant — `post/v1`, and the canonical shape for any schema that carries credits.

```json
"credits": [
  {
    "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
    "role": "photography",
    "name": "Alice",
    "claim": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRpdC1jbGFpbSIsImtpZCI6..."
  },
  { "did": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae", "role": "author" }
]
```

| Field   | Type   | Required | Description                                                                       |
| ------- | ------ | -------- | --------------------------------------------------------------------------------- |
| `did`   | string | yes      | The credited identity                                                             |
| `role`  | string | no       | The credited role — open vocabulary, byte-exact; REQUIRED when `claim` is present |
| `name`  | string | no       | Display name at time of publication — a convenience, never authoritative          |
| `claim` | string | no       | A `did:dfos:credit-claim` JWS binding this entry                                  |

- Array **order is display order**, and the **first entry is the primary author**. Both are unchanged from the credits shape they extend.
- **`name` is a cached display string, not a source of truth.** The claimant's [profile](https://protocol.dfos.com/content-model) is authoritative for its current name; `name` records what the document said when it was signed, so a document renders sensibly without resolving every credited DID. A consumer that resolves profiles SHOULD prefer the profile name. `name` is never compared during verification.
- **`role` is REQUIRED whenever `claim` is present**, because `role` is a component of the bind. An entry carrying a `claim` with no `role` has nothing for the claim's (always-present) `role` to match, so it is a bind mismatch and resolves **invalid** — never unclaimed, and never a wildcard match. See [Two-Way Binding](#two-way-binding). Publishers get this checked for free: the published schema encodes it as `dependentRequired: { claim: ["role"] }`.
- Omit `credits` entirely for unattributed content. An empty entry list and an absent list mean the same thing.

Both the claim payload and this entry shape are published as [`credit-claim/v1`](https://schemas.dfos.com/credit-claim/v1).

> **Note on `post/v1`.** The credit entry's role field is named `role` — unambiguously, because `role` is a component of the claim's byte-exact bind. `role` is OPTIONAL: an unroled credit is still a legal credit, and only claim-bearing entries need one.

---

## Two-Way Binding

Attribution has two sides, and DFOS keeps both. They are separate assertions by separate parties, and the interesting object is the **agreement** between them.

- **Assertion by commitment** — the `credits[]` entry. Whoever signed the document committed to it. If a space signs a post crediting Alice as photographer, the space has staked its signature on that statement. This side always exists (an entry is what makes a credit a credit) and is exactly as trustworthy as the document's signer.
- **Assertion by signature** — the `claim` JWS. Alice signed `(contentId, alice, photography)` herself. This side is optional, and its trust anchor is Alice's own key.

**The bind is the exact match of `(contentId, did, role)`** between the entry plaintext and the signed claim payload:

| Component   | Entry side                     | Claim side          | Comparison                          |
| ----------- | ------------------------------ | ------------------- | ----------------------------------- |
| `contentId` | the chain hosting the document | `payload.contentId` | exact string equality               |
| `did`       | `entry.did`                    | `payload.did`       | exact string equality               |
| `role`      | `entry.role`                   | `payload.role`      | exact, case-sensitive byte equality |

All three MUST match. Nothing is normalized, folded, or coerced on either side. A claim that verifies cryptographically but names a different role than the entry it sits in is **not** a weaker claim about that entry — it is a failed bind, and the entry is invalid.

**A claim-bearing entry MUST carry a `role`.** `role` is OPTIONAL on the entry in general — an unroled credit is a perfectly ordinary credit — but the payload's `role` is REQUIRED and non-empty, so an entry that carries a `claim` and omits `role` can never satisfy the third row of the table above. Verifiers MUST treat that as an ordinary **bind mismatch** and resolve the entry **invalid**. There is no lenient reading in which a missing entry role is a wildcard that matches whatever the claim asserts: that reading would let a claim signed for one role bind to an entry displayed under any other, which is precisely the agreement the bind exists to establish. Nor is it **unclaimed** — a `claim` is present, so the entry is making a verifiable assertion and failing it.

What the bind establishes, when it holds, is narrow and worth stating exactly: **the document's signer and the claimant independently assert the same credit.** It does not establish that the credit is true. Two parties can agree and both be wrong, or collude. What it rules out is the interesting adversarial case — a signer attributing work to someone who never agreed to be attributed, and a claimant attaching itself to work no one credited it for. Neither party can produce a claimed entry alone.

---

## Verification States

Every `credits[]` entry resolves to exactly one of four states. A consumer SHOULD surface the distinction; collapsing all four into "credited" throws away the entire point of the mechanism.

| State            | Condition                                                                             | How to read it                                                              |
| ---------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **claimed**      | `claim` present, verifies, and all three bind components match                        | Signer and claimant both assert this credit                                 |
| **unclaimed**    | No `claim` field                                                                      | The signer asserts this credit; the claimant has not (yet) countersigned it |
| **invalid**      | `claim` present but verification or the bind fails                                    | Something is wrong — do not present this as either claimed or unclaimed     |
| **unverifiable** | `claim` present and well-formed, but the claimant's identity chain cannot be resolved | Verdict unknown — insufficient information, not a failure                   |

**unclaimed is legal and ordinary, not an error.** It is the default for most content and always will be: the credited party may not hold keys, may not have gotten around to it, or may simply be a person who was credited by a host that signs on their behalf. A consumer MUST NOT render unclaimed as suspicious. The only thing an unclaimed entry lacks is the second signature.

**invalid is different in kind** and SHOULD be surfaced as such. A `claim` that fails to verify is a positive signal that something is off — a corrupted blob, a claim replayed from another chain, a role edited after the claim was signed, or a forgery attempt. Rendering it as "unclaimed" would silently launder a failure into the ordinary case.

**unverifiable is honest ignorance.** The claimant's DID may live on a relay this consumer cannot reach, or the identity may simply not be resolvable here. The claim may be perfectly valid. Consumers SHOULD distinguish "I checked and it failed" from "I could not check," and SHOULD NOT cache an unverifiable verdict as invalid.

**The two failure verdicts MUST be machine-distinguishable.** A verifier that signals every failure as one undifferentiated error forces consumers to string-match its prose to tell "checked and failed" from "could not check" — and prose gets reworded, so those consumers break silently and land on the wrong verdict. Implementations MUST expose the verdict structurally: the reference implementations carry it as a field on a typed error (TypeScript: `CreditClaimVerifyError.reason`) and as `errors.Is`-able sentinels (Go: `ErrCreditClaimInvalid` / `ErrCreditClaimUnverifiable`). A failure whose cause cannot be attributed — an unexpected fault inside the verifier itself — MUST resolve to **unverifiable**, never **invalid**: absent evidence against the claim, the honest verdict is that it was not checked.

A **transport failure is unverifiable, not invalid.** If identity resolution fails because a relay is unreachable, times out, or errors, the correct verdict is unverifiable — an outage is not evidence about a signature. A verifier that reports a network error as invalid tells its users the credit was checked and found bad, which is false, and which the spec's own "checked and failed" language would then license a consumer to display as a warning about the claimant.

---

## Verification Algorithm

To verify one `credits[]` entry, given the entry, the `contentId` of the chain whose document contains it, and a way to resolve identities:

1. **No `claim` field?** The entry is **unclaimed**. Stop.
2. **Size.** If the `claim` token exceeds **4096 bytes**, the entry is **invalid**. Check this before any decode.
3. **Decode** the JWS. Failure to decode → **invalid**.
4. **`typ`.** MUST be `did:dfos:credit-claim`. Anything else → **invalid**. (In particular, another envelope type from this family — a credential, a revocation, a countersign — is not a credit claim, no matter how well it verifies.)
5. **Payload schema.** `version` MUST be `1`, `type` MUST be `credit-claim`, `contentId` MUST be a 31-char content chain id, `did` MUST be non-empty and carry the `did:` prefix, `role` MUST be non-empty, `createdAt` MUST parse as ISO 8601 millisecond-precision UTC, and `asOfDocumentCID` — if the key is PRESENT — MUST be a non-empty string. Otherwise → **invalid**. (The `did:` check is a prefix check, not full `did:dfos` validation: a claimant is not required to be a `did:dfos` identifier.)
6. **`kid` ↔ `did`.** The `kid`'s DID portion MUST equal `payload.did`. Otherwise → **invalid**.
7. **Resolve the claimant identity** named by `payload.did` and find the key named by the `kid` fragment. Unresolvable identity → **unverifiable**. Resolvable identity with no such key → **invalid**.
8. **Signature.** Verify the JWS under that key. Failure → **invalid**.
9. **CID integrity.** Re-derive the payload CID and compare against the header `cid`. A missing or mismatched `cid` → **invalid**.
10. **The bind.** `payload.contentId` MUST equal the hosting chain's `contentId`; `payload.did` MUST equal `entry.did`; `payload.role` MUST equal `entry.role` byte-for-byte. Any mismatch → **invalid**. An **absent** `entry.role` is a mismatch, not a wildcard: `payload.role` is always present and non-empty, so a claim-bearing entry without a `role` fails here → **invalid**.
11. Otherwise the entry is **claimed**.

Step 10 is the step implementations skip. A claim that passes steps 1–9 is a valid signed statement **by** someone **about** something — verifying it without binding it to the entry that hosts it verifies the wrong proposition.

**Deliberately absent from this algorithm:** any expiry or freshness check (claims never expire), any revocation lookup (there is no credit revocation — see the reservation below), any relay query (a claim is self-contained given identity resolution), and any identity-deletion gate (see the next section).

### A deleted claimant still verifies

Verification MUST NOT consult the claimant's `isDeleted` state. A claim signed by an identity that has since been tombstoned **still verifies**, and its entry is still **claimed**.

This is the opposite of the [credential](https://protocol.dfos.com/credentials) rule, where a deleted issuer's credentials are dead, and the asymmetry is deliberate:

- A **credential** is a live grant of authority. Authority must die with the identity that holds it — otherwise a deleted identity keeps authorizing writes, which is an obvious hole.
- A **credit claim** is a statement of historical fact. The fact does not stop having happened because the claimant later deleted its identity. Someone photographed that record in 2026; that remains true in 2030 regardless of what happened to their DID.

**Attribution is history; authorization is standing.** Verifiers that treat identity deletion as a blanket "reject everything signed by this DID" rule get this wrong, and the failure mode is ugly: a person deleting their identity would retroactively strip their own name off everything they ever made, replacing verified credits with `invalid` across the corpus. Deletion should end an identity's ability to act. It should not rewrite what it did.

Note the practical consequence, which is intentional: a claim's verifiability depends on the claimant's identity chain remaining **resolvable**, which is not the same as the identity remaining **live**. A resolver that returns tombstoned identities with their historical keys lets old credits keep verifying. One that returns nothing for a deleted DID yields **unverifiable** — honest, but weaker.

---

## Why `contentId` Is the Binder

The claim binds to the chain's stable 31-char `contentId`. The two alternatives are both worse, and for different reasons.

**Not the document CID.** A claim lives inside the document. If it committed to that document's CID, the CID would have to be known before the document containing the claim existed — the circularity is unresolvable. Binding to the chain sidesteps it entirely: the `contentId` is derived at genesis and is already known when any later revision is composed. (`asOfDocumentCID` is the escape hatch for callers who genuinely want a document-pinned statement, and it is optional precisely because it cannot be the binder.)

**Not the chain head CID.** The head moves on every write. A head-bound claim would be invalidated by the next edit — including edits that have nothing to do with authorship, like fixing a typo. Attribution would need re-signing on every revision, which is both absurd and expensive: re-signing mints a fresh `createdAt`, changing the claim bytes, changing the embedding document's CID, triggering another revision. A chain-bound claim survives every edit verbatim.

**And `contentId` is what makes the claim anti-replay.** Without a chain component in the signed payload, a claim would be a free-floating "Alice is a photographer" token — valid anywhere, liftable from one document and pasted into any other. Anyone who could read one of Alice's claims could credit her, verifiably, on content she never touched. Naming the chain in the signed bytes is what confines a claim to the one chain it was made about.

This is why step 10 of the algorithm is not optional and why implementations SHOULD always pass the expected `contentId` to their verifier: a consumer reading a credits entry **always** knows which chain the document came from, so there is never a legitimate reason to skip the check. The reference implementations expose the unbound form (TS: omitting `expectedContentId`; Go: `VerifyCreditClaim` rather than `VerifyCreditClaimBound`) only for tooling that inspects a claim in isolation.

**An empty expected `contentId` MUST be an error, never a skip.** A verifier that treats the empty string as "no binder wanted" hands unbound semantics to a caller who asked for bound ones — and the empty string is exactly what an unhydrated database column, a zero-valued struct field, or a failed parse produces. The skip must be requested by a distinct, deliberate act (omitting an optional argument, or calling a differently-named function), so that an accidental empty value fails loudly instead of quietly reopening the cross-chain replay this section exists to close.

**Ship the entry-level check, not just the claim-level one.** Because the bind has three components and a claim verifier can only enforce one of them, an implementation whose only public entry point is "verify this claim token" has made the unsafe call the easy one, and step 10 the caller's homework. Implementations SHOULD expose a single call that takes the whole `credits[]` entry plus the hosting `contentId` and returns one of the four states, performing the full comparison internally — the reference implementations do (`verifyCreditEntry` / `VerifyCreditEntry`), and it is the call consumers should reach for.

### Claim stability

A given `(contentId, did, role)` triple SHOULD be signed **once** and the resulting token reused verbatim wherever that credit appears. Re-signing produces a byte-different claim (a fresh `createdAt`), which changes the embedding document's CID, which appends a chain operation. A system that re-signs claims on every document projection converges on nothing — it emits an endless series of revisions that differ only in claim timestamps. Store the token; do not re-mint it.

---

## Relays Are Not Credit-Claim Aware

**Relays are not credit-claim aware; claims travel inside document bytes.**

A relay never sees a credit claim as a claim. It sees document blobs, which it stores and serves as opaque bytes, and it applies exactly the access control it already applies to those bytes. There is no credit-claim ingest path and no gossip; as a **verifier** of claims the relay does not exist, and the verifier is always the consumer that reads the document.

This follows directly from the doctrine above: a gossiped or relay-indexed claim is a public claim, and attribution must be no more public than the content it attributes.

**Adding relay awareness requires a spec change, not an implementation.** A relay operator who indexes claims out of the blobs it stores has not added a feature — they have built the enumeration surface this design exists to avoid, and they have done it unilaterally, for content whose access rules they were supposed to be enforcing. Any credit-claim relay surface needs a design pass in this spec first, covering at minimum: what it reveals about gated content, how it interacts with the document gateway's authorization, and whether the index is per-relay policy or protocol-normative.

### Design pass: the public-snapshot credits index

Exactly one such surface has passed that review: [WEB-RELAY.md](https://protocol.dfos.com/web-relay)'s **credit projection** and its `/index/v0/credits` family — a `(contentId, did, role)` index derived **exclusively from the current head documents of publicly readable content**. Its answers to the three questions above, recorded here as the conditions of the sanction:

- **What it reveals about gated content: nothing.** Rows derive solely from head-document bytes any anonymous reader can already fetch. A non-public chain has **zero** rows — no redacted variant, no probe surface. The events that take content dark (revocation, deletion, a de-crediting revision) are themselves operations, and each recompute **replaces the chain's full row set from the current head**, so rows for darkened or re-credited content are stripped rather than stranded. The enumeration this section exists to avoid — attribution more public than its content — cannot occur, because row lifetime is a strict subset of public lifetime.
- **How it interacts with the document gateway's authorization: it doesn't.** Index rows are discovery hints, never authorization inputs; the gateway re-derives read access live on every fetch. The projection reads the same standing public-read predicate the relay already maintains and grants nothing.
- **Per-relay policy or protocol-normative: per-relay index surface, on the index's own `0.x` clock.** The claim primitive, its verification algorithm, and this section's doctrine are untouched by the index; a relay without the index family serves credits the only way credits ever travel — inside document bytes. The projection is assertion-tier and claim-unaware: rows restate what a public document's `credits[]` says (`hasClaim` records byte-presence of a claim token, never validity), and verification of the four states remains the consumer's fold over the fetched document.

Any surface beyond this one — gated-content awareness in any form, claim validity in a row, protocol-normative claim indexing — reopens the design pass.

---

## Relationship to Other Primitives

### Versus countersignatures

A [countersignature](https://protocol.dfos.com/spec) is the protocol's other "one subject signs about another subject's thing" primitive, and it is close enough to credits to be worth separating carefully. The difference is not what they mean — both are attestations — but **which plane they live on**.

A countersign is a **public attestation**: a first-class operation, CID-addressed, gossiped across the proof plane, addressing its target by CID with an open-namespace `relation` tag. It is the right tool when the attestation should be publicly discoverable — a witness statement, an endorsement, a public co-sign — and when it should exist independently of whether the reader can access the target's bytes. Its visibility is a feature.

A credit claim is a **gated attestation**: not an operation, not gossiped, carried inside document bytes, and readable exactly by whoever can read the document. It is the right tool for attribution, where visibility must track the content's own gate.

The same social act therefore has two forms depending on plane, and the choice is a privacy decision, not a modeling one:

|                       | Countersignature             | Credit claim                      |
| --------------------- | ---------------------------- | --------------------------------- |
| Plane                 | Proof (public)               | Document (gated with the content) |
| Gossiped              | Yes                          | No                                |
| Binds to              | Target operation CID         | Chain `contentId`                 |
| Discoverable          | Yes, via the relay           | Only by reading the document      |
| Survives target edits | No — pinned to one operation | Yes — pinned to the chain         |
| Relay-aware           | Yes                          | No                                |

Publicly co-signing a public work is a countersign. Claiming a credit on a work whose bytes are gated is a credit claim. A deployment that wants both can carry both; they are not exclusive and they do not overlap.

### Versus delegated writes

A design worth rejecting explicitly: upgrading a credit from assertion to proof via a **claim operation** — the credited DID receiving a write credential and appending a no-op `update` that re-commits the head `documentCID`. The comparison is worth stating plainly, because the delegated-write machinery is load-bearing in its own right.

**Delegated writes are the general multi-writer mechanism.** A credential authorizing a non-creator DID to append to a chain is how DFOS supports more than one writer on one chain: collaborative documents, an editor with commit rights, a device writing on behalf of its owner, a service maintaining an index. That is a genuine capability, and credit claims do not touch it.

It is simply the wrong instrument for attribution. Using a write to say "I am the photographer" means: issuing the claimant a **write credential** (real authority over the chain, granted only so a signature could be produced), appending an **operation** to the chain (permanent proof-plane residue, publicly visible, for content that may be gated), and getting a signature that binds to the **chain and a document state** rather than to a role — a claim operation cannot say which credit it is claiming. Three costs, none of which attribution needs, and the crucial one is the middle one: the operation is public even when the content is not.

A credit claim grants no authority, appends no operation, and names the role. It is the smaller object, and the smaller object is the right one.

---

## Reserved: `did:dfos:credit-renounce`

The `did:dfos:credit-renounce` type is **reserved and undefined**. There is no renunciation mechanism in this version, and implementations MUST NOT emit or accept anything under that `typ`.

It is named here only to reserve the name, and to be honest that the underlying question is open. A credit claim is permanent in the same way every signed DFOS statement is permanent: the token exists inside document bytes that may already be copied, and re-signing nothing un-signs it. A future renunciation would have to answer questions this spec does not: whether a renunciation can be honored at all when the claim travels inside bytes the renouncer does not control, what a consumer should render for a renounced-but-still-present claim, and whether removing the credits entry (which the document signer can already do on the next revision, and which does not touch history) is the better answer than a new envelope. Reserving the name keeps the option open without pretending the design exists.

Note what a claimant can already do without any new primitive: stop claiming. A credit entry with its `claim` removed on the next revision is **unclaimed** — an ordinary, unremarkable state — while the operation log preserves the earlier revision, so nothing is falsified.

---

## Worked Example

A space publishes a post it signs itself, crediting two people. Alice claims her credit; Bob has not.

**Alice's claim** (signed by Alice, before the post document is composed):

```json
// JWS Header
{
  "alg": "EdDSA",
  "typ": "did:dfos:credit-claim",
  "kid": "did:dfos:alice...#key_abc",
  "cid": "bafyrei..."
}

// JWS Payload
{
  "version": 1,
  "type": "credit-claim",
  "contentId": "cv7n8vkvr64cctf3294h9k4eanhff8z",
  "did": "did:dfos:alice...",
  "role": "photography",
  "createdAt": "2026-03-07T00:00:00.000Z"
}
```

**The post document**, committed by the space to chain `cv7n8vkvr64cctf3294h9k4eanhff8z`:

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "long-post",
  "title": "Field Notes",
  "body": "...",
  "credits": [
    { "did": "did:dfos:bob...", "role": "author", "name": "Bob" },
    {
      "did": "did:dfos:alice...",
      "role": "photography",
      "name": "Alice",
      "claim": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRpdC1jbGFpbSIs..."
    }
  ]
}
```

A consumer reading this document from chain `cv7n8vkvr64cctf3294h9k4eanhff8z` resolves:

- **Bob — author — unclaimed.** The space asserts it. Ordinary; render it as a credit.
- **Alice — photography — claimed.** The claim verifies under Alice's key, and `(cv7n8vkvr64cctf3294h9k4eanhff8z, did:dfos:alice..., photography)` matches the entry exactly. Both parties assert it.

Now suppose someone lifts Alice's claim token and pastes it into a different chain's document, crediting her there. That document's reader checks step 10: the claim says `cv7n8vkvr64cctf3294h9k4eanhff8z`, the hosting chain is something else, and the entry resolves **invalid**. The claim is cryptographically perfect and still refused — which is the whole reason the binder is in the signed bytes.

If instead the space edits the post — new title, new `documentCID`, new operation — Alice's claim is untouched. It binds the chain, not the document, so it still verifies verbatim and Alice stays **claimed** across every future revision.

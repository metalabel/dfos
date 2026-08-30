# DFOS Protocol

Verifiable identity and content chains — Ed25519 signatures, content-addressed CIDs, W3C DIDs. Cross-language verification in TypeScript, Go, Python, Rust, and Swift.

> **Status — Protocol v1: feature-complete and frozen.** The v1 surface is **frozen**: the core primitives — chain mechanics, canonical DAG-CBOR encoding, identifier derivation, and the validity bounds — are settled and will not change in shape. Build on the wire as specified. v1 is frozen but not yet declared final, and changes from here are limited and disciplined:
>
> - **Clarifications** — where the prose was ambiguous but conformant implementations already agree — are corrected in place.
> - **Additive** capability — new optional fields, new service types, the [content plane / document gateway](https://protocol.dfos.com/web-relay#content-plane--document-gateway) — lands atop frozen v1, never as a break.
> - A genuine **breaking** change to a frozen field is never a silent v1 edit; it becomes v1.1 or v2.
>
> v1 is declared final once independent implementations confirm the spec verifies byte-for-byte from the prose alone. The protocol version is independent of the reference packages: the `@metalabel/dfos-protocol` and `dfos-protocol-go` releases stay on their own `0.x` semver line, so freezing v1 commits the **wire**, not yet a library API. Discuss in the [DFOS](https://nce.dfos.com) space.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Philosophy

DFOS is a dark forest operating system. Content lives in access-controlled spaces — undisclosed by default, governed by the communities that create it. The cryptographic proof layer is public: signed chains of commitments that anyone can independently verify with a public key and any standard EdDSA library. The proof is public; the content is access-controlled. The protocol commits to content hashes, not plaintext — it does not encrypt. Confidentiality of the underlying documents is enforced at the application layer by whoever serves them; a relay operator can read what it stores. This is undisclosed-by-default, not end-to-end encrypted.

Two chain types — identity and content — use the same mechanics: Ed25519 signatures, JWS compact tokens, content-addressed CIDs. The protocol operates on keys and document hashes. Application semantics — posts, profiles, feeds — are a separate concern, free to evolve without protocol changes.

Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. No platform dependency, no coordination required.

---

## Protocol Overview

The DFOS protocol has five components:

| Component             | Concern                                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Crypto core**       | Identity chains + content chains — Ed25519 signatures, JWS tokens, CID links                               |
| **Credentials**       | DFOS credentials for delegated authorization — see [CREDENTIALS.md](https://protocol.dfos.com/credentials) |
| **Services**          | Identity discovery vocabulary — controller-signed relay locators and stable content anchors                |
| **Artifacts**         | Standalone signed inline documents — immutable, CID-addressable structured data                            |
| **Countersignatures** | Standalone witness attestation — signed references to any CID-addressable op                               |

> **Note:** The credential format (read/write credentials, revocation) is specified in [CREDENTIALS.md](https://protocol.dfos.com/credentials); request authentication is [API-AUTH](https://protocol.dfos.com/api-auth). This document covers the crypto core, chain primitives, services, artifacts, and countersignatures.

The crypto core is the trust boundary — everything below it is cryptographically verified. Documents are flat content objects, content-addressed directly: `documentCID = CID(dagCborCanonicalEncode(contentObject))`. What goes inside the content object is application-defined — see the [DFOS Content Model](https://protocol.dfos.com/content-model) for the standard schema library.

### Crypto Core: Two Chain Types

|                | Identity Chain             | Content Chain                    |
| -------------- | -------------------------- | -------------------------------- |
| Commits to     | Key sets (embedded)        | Documents (by CID reference)     |
| Identifier     | `did:dfos:<hash>`          | `<hash>` (bare)                  |
| Operations     | create, update, delete     | create, update, delete           |
| JWS typ        | `did:dfos:identity-op`     | `did:dfos:content-op`            |
| Self-sovereign | Yes (signs own operations) | No (signed by external identity) |

Both chains are signed linked lists of state commitments. Identity chains embed their state (key sets). Content chains reference their state via `documentCID` — a content-addressed pointer to a flat content object.

### Addressing

Three addressing modes, self-describing by format:

| Thing                 | Form                     | Example                                    |
| --------------------- | ------------------------ | ------------------------------------------ |
| Operation or document | CID (dag-cbor + SHA-256) | `bafyrei...` (base32lower)                 |
| Content chain         | contentId (31-char hash) | `cv7n8vkvr64cctf3294h9k4eanhff8z`          |
| Identity chain        | DID                      | `did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr` |

CIDs are specific immutable artifacts — a pointer to an exact operation or document. Content IDs are living content chain entities — the 31-char bare hash derived from the genesis CID. DIDs are living identity chain entities.

Operations and documents are CIDs — standard IPLD content addresses. Content chains and identity chains use derived identifiers — `customAlpha(SHA-256(genesis CID bytes))`. Same derivation for both. Identity chains prepend `did:dfos:` (W3C DID spec). Content identifiers are bare — just the 31-char hash, no prefix.

Application code may add prefixes for routing (e.g., `post_xxxx`) — these are strippable semantic sugar, not part of the protocol identifier.

---

## Protocol Rules

### Commitment Scheme

Both operations and documents are content-addressed via **CID** (`dagCborCanonicalEncode(payload)` → SHA-256 → CIDv1). Operations are additionally signed via **JWS**.

| Representation | Encoding                                                                                                       | Purpose                                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| CID            | `dagCborCanonicalEncode(payload)` → SHA-256 → CIDv1                                                            | Deterministic content addressing for operations and documents |
| JWS            | `base64url(JSON.stringify(header))` + `.` + `base64url(JSON.stringify(payload))` → EdDSA signature covers both | Signature verification for operations                         |

CID uses [dag-cbor canonical encoding](https://ipld.io/specs/codecs/dag-cbor/spec/) for determinism — given the same logical payload, the CID MUST be identical regardless of implementation language or platform. JWS uses standard JSON for library interoperability. The dag-cbor hex test vectors in this document allow byte-level verification.

### Chain Validity

A valid chain is a sequence of operations rooted at a genesis. Each operation (after genesis) links to a predecessor via `previousOperationCID`. The chain provides structural ordering independent of timestamps. The two chain kinds differ in exactly one structural rule — whether that sequence may branch:

**Identity chains are strictly linear.** Each identity operation has at most one child. Two identity operations sharing the same `previousOperationCID` are a **conflicting extension**, and a verifier MUST reject any identity log that contains one. There is no identity-chain head selection — the head is the last operation of the single timeline, and identity state is the state that timeline folds to. The doctrine: forks are permitted exactly where a deterministic merge function exists. Content state has merge semantics (head selection for register schemas, the canonical fold for accumulating schemas — see [CONTENT-MODEL.md](https://protocol.dfos.com/content-model)); identity key state has no merge function, only arbitration — head selection could only arbitrate between competing key timelines, and an authority record whose current keys can be outbid by a signer-chosen timestamp is not an authority record. An identity chain therefore gets an order authority instead of a DAG:

**Order authority.** The subject's services-listed relay — its `DfosRelay` entry (see [Services](#services)) — is the **order authority** for its identity chain: identity writes go to the home relay, the home relay's committed log is the chain's canonical order, and peers replicate that order. A node MUST refuse an identity operation whose `previousOperationCID` references an operation that already has a committed child — a **permanent** rejection, never buffered, retried, or admitted later, on every path an operation arrives by (direct submission, gossip, sync, read-through), whatever the competing operation's `createdAt` claims. First-seen is each node's local admission mechanism; the home relay's committed log is the convergence rule between nodes — committed identity order is never auctioned or re-arbitrated by timestamp. What is single-writer is **ordering**, not availability: identity chains replicate everywhere via peering, and an identity write attempted while the home relay is unreachable is **at-risk-until-retry** — it either lands at the home relay on retry or it does not exist; identity writes are rare, and trading their write availability during a home-relay outage for a non-auctionable authority record is deliberate. An identity whose `services` list names no relay has no order authority at all: its chain, however obtained, is controller-attested end to end, and consumers apply the carried-chain divergence discipline ([SIWD.md → Carried identity chains](https://protocol.dfos.com/siwd#carried-identity-chains)). Relay-side ingest mechanics live in [WEB-RELAY.md → Identity Linearity and Order Authority](https://protocol.dfos.com/web-relay#identity-linearity-and-order-authority).

**Content-chain forks are valid.** A valid content chain is a **directed acyclic graph (DAG)** of operations. Two content operations referencing the same `previousOperationCID` constitute a fork — both branches are accepted. The chain log stores all branches. A **deterministic head selection** rule ensures convergence across implementations given the same set of operations:

1. Find all **tips** — operations with no children.
2. Select the tip with the **highest `createdAt`** string (descending order).
3. If two or more tips share an identical `createdAt`, break the tie by the **highest CID multibase string** (descending order). Two distinct operations cannot collide on both `createdAt` and CID: distinct payloads yield distinct CIDs (the CID is the SHA-256 of the dag-cbor payload), so this tiebreak is total.

**Comparison basis (normative).** Both ordering comparisons — `createdAt` for timestamp ordering and head selection, and the CID for the head-selection tiebreak — MUST be performed as a byte-wise (Unicode code-point) comparison of the raw strings, equivalent to comparing the UTF-8 byte sequences left to right. An implementation MUST NOT parse `createdAt` to an epoch, a floating-point value, or a broken-down time before comparing, and MUST NOT apply any locale-aware or collation-aware comparison (e.g. ICU collation, JavaScript `String.prototype.localeCompare`) to either field. This is sound, not merely convenient: `createdAt` is the fixed-width grammar `YYYY-MM-DDTHH:MM:SS.sssZ` (see Timestamp Grammar) — UTC, a literal `Z`, exactly three fraction digits, zero-padded throughout — so byte-wise order is identical to chronological order; and a CID is a base32-lower multibase string (`b`-prefixed, ASCII `[a-z2-7]`), so code-point order is identical to byte order. Locale collation has no determinism contract across engines or locales and would let two conforming relays select different heads from the same operation set; parsing-to-number discards sub-millisecond byte identity and admits format-dependent drift. The reference implementations use the relational string operators directly (TypeScript `a < b`/`a > b` on the UTF-16 code units, which for this ASCII grammar equals byte order; Go string comparison, which is byte-wise) and are byte-for-byte equivalent on this input domain.

This is deterministic: any implementation with the same operations computes the same head, regardless of ingestion order. Semantic interpretation of content-chain forks (concurrency glitch, intentional recovery, etc.) is application-defined — the protocol stores the DAG, clients interpret it.

**Timestamp ordering**: `createdAt` MUST be strictly greater than the `createdAt` of the parent operation (the operation referenced by `previousOperationCID`). On an identity chain this is plain successor ordering — each operation's `createdAt` exceeds its predecessor's along the single timeline. On a content chain it is enforced per-branch, not globally — a fork branch's timestamps are validated against its own parent, not the other branch's operations.

**Future timestamp bound**: Relays, and any component that performs deterministic head selection, MUST reject identity and content operations with a `createdAt` more than 24 hours in the future relative to the verifier's clock. Since deterministic head selection favors the highest `createdAt`, a far-future timestamp would otherwise permanently dominate head selection — this guard prevents temporal denial-of-service. Bare linear chain verification (`verifyIdentityChain` / `verifyContentChain`) does not select a head and does not enforce this bound; it validates only that each operation's `createdAt` is strictly greater than its parent's (below). The reference relays enforce the 24-hour bound at ingest.

### Identity Chain Signer Validity

An identity chain operation is valid only if the signing key was a **controller key in the immediately prior declared state** ([Key Possession](#key-possession) defines declared vs effective state; signer validity is deliberately checked against the declared set — see the three-door rule there for why). A genesis operation declares exactly **one key** — the same key in all three role arrays — and is signed by it: the genesis operation introduces and simultaneously authorizes its own key, and the signature is the key's own [possession proof](#key-possession). A genesis declaring more than one distinct key across its role arrays is invalid. Identities with several controllers bootstrap the ordinary way: genesis with one key, then `update` operations introducing the rest under the possession rule.

This is a self-sovereign invariant: the identity chain defines its own valid signers via `controllerKeys`, and the protocol enforces this. No external authority is consulted. The single-key genesis makes it verifiable in isolation, too: one key, declared and signing, with no prior state to consult and no key present that the signature does not vouch for — an identity is never born holding a key nobody demonstrated.

### Key Possession

Every key an identity chain lists is backed by a demonstration that its holder holds it and consented to listing it. The rule is bimodal, with no third case:

1. **The genesis key proves possession by signing genesis.** One key, declared across all three role arrays, signing the very operation that declares it — the signature is the proof, for all three roles at once.
2. **Every other key proves possession by an embedded [key proof](https://protocol.dfos.com/key-proof).** A key's introduction to a role is accompanied by an envelope the key itself signed, binding `{chain DID, role set, chain position}` — the back-signature discipline, carried on the chain.

**Introduction.** An operation **introduces** key K to role R when K appears in the operation's R array and K was not in the immediately prior *effective* R state. For each key it introduces, an `update` operation carries exactly one envelope in its `keyProofs` member ([Identity Operations](#identity-operations)) whose `publicKeyMultibase` is K, whose `did` is the chain's DID, whose `prevCID` equals the operation's own `previousOperationCID`, and whose `roleSet` includes every role the operation introduces K to — verified per [KEY-PROOF.md → Chain-Walk Verification](https://protocol.dfos.com/key-proof#chain-walk-verification). An operation that merely replays a key already effective in a role carries no proof for it: proofs live at introduction, full-state replay carries keys, and verification walks back to the introducing operation. Because the envelope names one `previousOperationCID`, a proof is spent at the position it names: re-adding a removed key is a new introduction demanding a fresh envelope, and promotion into a role the key's envelope never covered is likewise a new introduction for that role. There is no standing consent and no proof revocation — removal is an ordinary `update`, and nothing signed yesterday re-adds a key tomorrow.

**Declared vs effective state.** An identity chain yields two readings of its key arrays. The **declared** state is structural: the arrays as the operations wrote them. The **effective** state is the declared state minus every unproved membership. A key-role membership whose introduction carries no valid covering envelope is **void**: excluded from the effective state for that role, never resolved for signature verification by consumers, never indexed, never surfaced in recovery, and never a [one-key-one-DID](https://protocol.dfos.com/key-proof#holder-obligations) burn against the key's true holder. Void is not invalid — the operation and the chain stand — and tooling MUST surface void memberships loudly rather than silently dropping them: a void key is a claim somebody wrote and nobody proved, and a human looking at the chain gets to see that.

**The three doors.** Possession is enforced at three distinct surfaces, and the separation is load-bearing:

- **Writers hard-reject.** Software authoring an identity operation MUST refuse to produce an unproved introduction. The void path exists for reading hostile or defective chains, not as something conformant tooling emits.
- **Relays sequence regardless.** A relay MUST admit and sequence every structurally valid identity operation — linearity, CIDs, timestamps, declared-state signer validity — whatever its proof status. Log membership never depends on semantic key validation: identity chains are linear with no branch to fall back to, so two relays disagreeing about one operation's proofs would fork the log itself — a split-brain identity — and a rejecting relay would additionally stall forever on the chain under union-of-CIDs sync. The relay's log answers *what was written*; proofs answer *what counts*.
- **Verifiers compute void.** Every consumer of identity key state — signature resolution for content and API surfaces, key indexes, recovery oracles — reads the effective state.

Signer validity for the chain's own operations is checked against the **declared** controller set, per the same door discipline: it is a structural admission rule that every relay must evaluate identically, so it cannot depend on proof status. What a void controller key can do is therefore exactly what any holder of the declared chain could do — extend the declared timeline; what it can never do is act *as* the identity anywhere effective state is consulted, which is everywhere identity is consumed. A chain whose effective controller set becomes empty — every controller membership void — is extendable in declared form but dead in effect: no key it lists can authenticate, assert, or authorize as the identity. Conformant writers cannot produce this state; a chain that authored it against door one has done to itself what losing every key does.

### Content Chain Signer Model

Content chain verification requires a **valid EdDSA signature** and delegates key resolution to the caller. The `kid` in each operation's JWS header is a DID URL (`did:dfos:<id>#<keyId>`). The verifier calls `resolveKey(kid)` to obtain the raw Ed25519 public key bytes for that key on that identity. How the resolver obtains and validates the identity's key state is application-defined.

**Creator sovereignty**: The DID that signs the genesis (create) operation is the **chain creator** and permanently owns the chain. The creator can sign subsequent operations directly — no credential needed. Other DIDs require a **DFOS credential with write access** in the operation's `authorization` field, issued by the creator DID. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for the credential format.

**Signer-payload consistency**: The `kid` DID in the JWS header MUST match the `did` field in the content operation payload. This enables discrimination between author operations and countersignatures — if the kid DID differs from the payload `did`, it is a countersignature (witness attestation), not a chain operation.

**What the protocol enforces:**

- The EdDSA signature on each operation is valid against the key returned by `resolveKey(kid)`
- Chain integrity (CID links, timestamp ordering, terminal state)
- The `kid` DID matches the payload `did` for chain operations
- Creator-sovereignty authorization (when `enforceAuthorization` is enabled): non-creator signers must present a valid DFOS credential with `action: "write"` issued by the creator

**What the protocol does NOT enforce (application concerns):**

- Which key role (auth, assert, controller) the signing key must have
- Ownership or attribution semantics beyond creator sovereignty

### Terminal States and Special Operations

**Content chains: `delete` is the terminal state.** No valid content operations may follow a delete. This is enforced per-branch: a delete seals further linear extension of its own branch, but forks rooted at a pre-delete operation remain valid, and deterministic head selection may make a non-deleted branch the head. Delete prevents future operations but does NOT remove data — the complete chain remains intact for verification. Data removal is an application concern.

**Identity chains: `active ⇄ deleted`, every transition an explicit signed operation.** A `delete` moves the identity to the deleted state and seals the chain against every operation except one: a **`restore`** operation MAY follow the `delete` as its immediate linear successor, returning the identity to the active state (see [Identity Operations](#identity-operations) for the validity rules, and the `did:dfos` DID Method specification, Deactivation). An implementation MUST reject any other operation after a delete. Both transitions are ordinary operations in the one linear timeline: the `delete` and any `restore` are permanent, auditable facts of the log, never removed. As with content chains, deletion removes no data — the complete chain remains intact for verification.

**Controller key requirement:** `update` operations on identity chains MUST include at least one controller key. If decommissioning is intended, `delete` is the correct terminal operation.

**Content-null:** An `update` on a content chain with `documentCID: null` means the content exists but its document is cleared. The chain continues — a subsequent update can set content again.

### `typ` Header

The JWS `typ` header uses protocol-specific values (not IANA media types). Every `typ` value — this document's core operation families and every extension envelope — is registered in one place, the [extension registry](https://protocol.dfos.com/extensions), which names each value, the spec that owns it, and whether its envelope carries the [`cid` header](#cid-header). A new envelope family adds its row there, never a local name; registration is for `typ` routing and says nothing about ingestion (several registered families are document-plane artifacts no relay ever ingests — the registry's semantics column says which).

Protocol-specific `typ` values are non-standard per JOSE convention, documented intentionally. The `typ` header aids routing but is not security-critical. Implementations SHOULD validate it but MUST NOT rely on it for security decisions.

### Operation Versioning

Every proof-plane operation payload (identity, content, artifact, countersign, revocation) carries a top-level integer `version` field. This document specifies version `1`; verifiers MUST reject any operation whose `version` is not exactly `1`. Both reference implementations pin `version: 1` and reject all other values. A future wire-incompatible revision of the operation format would increment this field, and implementations declare which versions they accept. The operation `version` is distinct from content-document `$schema` versioning (see [CONTENT-MODEL.md](https://protocol.dfos.com/content-model)), which versions application payloads independently and does not affect operation-level verification.

### Operation Size and Cardinality Limits

The protocol bounds operations with **one aggregate size cap** plus a small set of **cardinality caps** — not a per-field string-length table. The single bound is measured over the exact CBOR bytes the CID commits to, so it is identical-by-construction across implementations; a per-field length table (`did ≤ 256`, `label ≤ 256`, …) would instead invite Unicode/length-counting divergence between implementations.

**Aggregate operation size (size cap):**

| Bound                              | Value                    | Applies to                              |
| ---------------------------------- | ------------------------ | --------------------------------------- |
| dag-cbor-encoded operation payload | **65536 bytes** (64 KiB) | identity operations, content operations |

Verifiers MUST reject an identity or content operation whose `dagCborCanonicalEncode(payload)` exceeds 65536 bytes, **measured with any embedded `authorization` credential excluded** (see below). The cap is measured over the canonical CBOR bytes the operation CID commits to, so every implementation computes it identically (no Unicode/length-counting ambiguity). It is generous by design — a legitimate proof-layer operation is far smaller — and bounds decode/verify cost as a DoS guard. Credentials are NOT subject to this cap; they carry their own larger 262144-byte (256 KiB) ceiling (a maximum-depth delegation chain embeds each parent token in `prf` and legitimately exceeds 64 KiB — see [CREDENTIALS.md](https://protocol.dfos.com/credentials)). Artifacts keep their own 16384-byte cap (below); the `services` array keeps its 32768-byte cap (above).

A delegated content `update`/`delete` carries its authorizing credential in the operation's `authorization` field, and that credential — itself bounded by the 262144-byte credential cap — can legitimately approach 256 KiB at maximum delegation depth. Counting it against the 64 KiB operation cap would conflate two independent limits and reject a valid deep-delegation write, so the operation-size cap is measured over the payload **with the `authorization` field removed**; the `authorization` credential is bounded separately by the credential cap. Total operation bytes are therefore bounded by the sum (≤ 64 KiB + 256 KiB). The operation CID still commits to the complete payload including `authorization`.

The `keyProofs` member of an identity `update` ([Key Possession](#key-possession)) gets no such exclusion: its envelopes are ordinary payload members, inside the bytes the CID commits to and inside the 64 KiB measurement. Each envelope is separately bounded by [KEY-PROOF.md](https://protocol.dfos.com/key-proof)'s own 4 KiB cap, and the aggregate operation cap is the real bound on how many keys one operation can introduce — the same posture as the key arrays themselves.

**Cardinality caps (structure, not byte length):**

| Field                                        | Max       | Rationale                                       |
| -------------------------------------------- | --------- | ----------------------------------------------- |
| `authKeys` / `assertKeys` / `controllerKeys` | 256 items | Generous ceiling; op-size cap is the real bound |
| `services` entries                           | 256 items | (see Services, above)                           |
| countersignature `relation`                  | 64 chars  | Open-namespace tag (min 1 when present)         |

The protocol does NOT limit individual field string lengths, **document content size** (the protocol commits to a CID, not the document — large binary media is referenced, not inlined), **chain length**, or **number of chains per identity**. These are application/transport concerns.

**Resource policy (non-validity, MAY differ per node).** Beyond the validity-determining bounds above, a node SHOULD apply a **decoder recursion-depth guard** when canonicalizing/encoding a payload, as a DoS protection against pathologically nested input. Both reference implementations cap nesting at 1024 levels — generous enough that it never binds a legitimate operation (real payloads are a handful of levels deep). This is a local resource guard, **not** a chain-validity rule: it bounds a node's own stack cost and never changes which operations are part of the canonical chain. Nodes MAY apply stricter local ingress limits (max bytes decoded off the wire, rate limits) provided they never accept an operation the validity rules reject, nor reject one they accept.

---

## Standards and Dependencies

| Component           | Standard / Library                                                                  |
| ------------------- | ----------------------------------------------------------------------------------- |
| Key generation      | Ed25519 (RFC 8032) via `@noble/curves/ed25519`                                      |
| Signature algorithm | EdDSA over Ed25519 (pure, no prehash — Ed25519 handles SHA-512 internally)          |
| Key encoding        | W3C Multikey (multicodec `0xed01` + base58btc multibase)                            |
| Signed envelopes    | JWS Compact Serialization (RFC 7515) with `alg: "EdDSA"`                            |
| Content addressing  | CIDv1 with dag-cbor codec (`0x71`) + SHA-256 multihash (`0x12`)                     |
| ID encoding         | SHA-256 → custom 19-char alphabet, 31 characters                                    |
| Timestamp encoding  | Strict ISO-8601 / RFC 3339 UTC, fixed millisecond precision (see Timestamp Grammar) |

### ID Alphabet

```
Alphabet: 2346789acdefhknrtvz  (19 characters)
Length:   31 characters
Entropy:  ~131.6 bits (19^31)
```

Process: `SHA-256(input) → for each of first 31 bytes: alphabet[byte % 19]`. The modulo introduces a ~0.3% bias (256 is not evenly divisible by 19) — not security-relevant for identifiers.

DIDs: `did:dfos:` + 31-char ID derived from `SHA-256(genesis CID raw bytes)`

There is a single canonical identifier width. Verifiers MUST reject any `did:dfos:` identifier that is not exactly 31 characters over this alphabet — whether it appears in an operation's signing-key `kid`, in an operation payload, or as the DID of a resolved identity state.

Key IDs: `key_` + 31-char ID. Convention: derive from public key hash (`key_` + `customAlpha(SHA-256(publicKey))`), making key IDs deterministic and verifiable. Not a protocol requirement — key IDs can be any string.

### Multikey Encoding (W3C Multikey for Ed25519)

```
Encode:
  1. Take 32-byte Ed25519 public key
  2. Prepend multicodec varint prefix [0xed, 0x01] (unsigned varint for 0xed = 237 = ed25519-pub)
  3. Base58btc encode the 34-byte result
  4. Prepend 'z' multibase prefix
  → "z6Mk..."

Decode:
  1. Strip 'z' multibase prefix
  2. Base58btc decode → 34 bytes
  3. First 2 bytes must be [0xed, 0x01] (ed25519-pub multicodec varint)
  4. Remaining 32 bytes = raw Ed25519 public key
```

**Worked example:**

```
Public key (hex):     ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32
Prefix + key (hex):   ed01 ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32
Base58btc + 'z':      z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb
```

Note: `[0xed, 0x01]` is the unsigned varint encoding of 237 (`0xed`). Since `0xed > 0x7f`, it requires two bytes in varint format: `0xed` (low 7 bits + continuation bit) then `0x01` (high bits). This is NOT big-endian `[0x00, 0xed]`.

### Timestamp Grammar

Every operation's `createdAt` field MUST match exactly the grammar:

```
YYYY-MM-DDTHH:MM:SS.sssZ
```

That is, in order, with no other characters and no surrounding or internal whitespace:

- a 4-digit zero-padded calendar **year** (`0000`–`9999`),
- a literal `-`, a 2-digit zero-padded **month** (`01`–`12`),
- a literal `-`, a 2-digit zero-padded **day** of month,
- a literal uppercase **`T`** date/time separator,
- a 2-digit zero-padded **hour** (`00`–`23`), `:`, a 2-digit **minute** (`00`–`59`), `:`, a 2-digit **second** (`00`–`59`),
- a literal `.` followed by **exactly three** decimal digits of fractional seconds (millisecond precision — no more, no fewer),
- a literal uppercase **`Z`** designating UTC.

The value MUST be a real calendar instant: the month/day combination MUST be valid (leap years are honored — e.g. `2024-02-29` is valid, `2023-02-29` is not). A **timezone offset** (e.g. `+00:00`, `-05:00`) MUST NOT appear; only the literal `Z` is permitted. **Leap seconds** (`:60`) MUST be rejected. A lowercase `z`, a missing or differently-sized fractional part, a space in place of `T`, non-zero-padded fields, or any leading/trailing/embedded whitespace MUST be rejected.

A verifier MUST reject any operation whose `createdAt` does not match this grammar. This applies on the read/verify path, not only at write time.

This grammar is load-bearing for ordering. Timestamp ordering (Chain Validity → **Timestamp ordering** — successor ordering on identity chains, per-branch on content chains) and deterministic head selection (Chain Validity, step 2 — "highest `createdAt`") are implemented as a **lexicographic string comparison** of the `createdAt` field. Because the grammar is fixed-width and zero-padded, lexicographic byte order is identical to chronological order, so the comparison is correct without parsing. An implementation that accepted a looser grammar — variable fractional-second width, an offset form, a space separator, etc. — would compare strings whose lexicographic order no longer tracks time, forking ordering and head selection from conforming implementations. The grammar is therefore a validity rule, not a formatting suggestion.

> The reference implementations gate this identically: the TypeScript library validates `createdAt` with `z.iso.datetime({ offset: false, precision: 3 })` and the Go library with `time.Parse("2006-01-02T15:04:05.000Z", …)` on the verify path. Both are exercised against a shared 22-case accept/reject vector set asserted verdict-for-verdict across the two implementations.

### CID Construction (dag-cbor + SHA-256)

```
1. JSON payload → dag-cbor canonical encoding → CBOR bytes
2. SHA-256(CBOR bytes) → 32-byte hash
3. Construct CIDv1:
   - Version: 1 (varint: 0x01)
   - Codec: dag-cbor (varint: 0x71)
   - Multihash: SHA-256 (function: 0x12, length: 0x20, digest: 32 bytes)
4. CID binary = [0x01, 0x71, 0x12, 0x20, ...32 hash bytes]
5. Base32lower multibase encode → "bafyrei..."
```

dag-cbor canonical ordering: map keys sorted by encoded byte length first, then lexicographic. Strings to CBOR text strings. Null to CBOR null. Arrays to CBOR arrays. Objects to CBOR maps with sorted keys.

#### Number Encoding (Critical for CID Determinism)

JSON has a single number type (IEEE 754 double). CBOR has distinct integer and floating-point types with different byte encodings. This difference is the most common source of CID divergence across implementations.

**Rule: JSON numbers that are mathematically integers (no fractional part) MUST be encoded as CBOR integers (major type 0/1), never as CBOR floats.** This is consistent with the [IPLD data model](https://ipld.io/docs/data-model/) integer/float distinction and required by the [dag-cbor codec spec](https://ipld.io/specs/codecs/dag-cbor/spec/).

Why this matters: CBOR integer `1` encodes as a single byte `0x01`. CBOR float `1.0` encodes as three bytes `0xf9 0x3c 0x00` (half-precision). Same logical value, different bytes, different SHA-256, different CID. An implementation that encodes `version: 1` as a float will produce a valid CBOR document but a wrong CID — silent, undetectable without cross-implementation testing.

**Common trap**: Languages that decode JSON into untyped maps (Go's `map[string]any`, Python's `dict`, etc.) typically represent all JSON numbers as floating-point. When this decoded value is then CBOR-encoded, it becomes a CBOR float instead of an integer. Implementations MUST normalize number types after JSON deserialization and before CBOR encoding.

**Number bounds (normative)**: a canonicalizable number MUST be an integer in the range `[-(2^53 - 1), 2^53 - 1]` (JSON's safe-integer range). Implementations MUST reject — at CID derivation, before CBOR encoding — any payload containing a non-integer number, `NaN`, `±Infinity`, or an integer outside that range. Applications that need fractional or larger-magnitude values MUST encode them as strings. Bounding numbers to this single form is what makes the encoding deterministic across implementations: it eliminates both the shortest-float divergence (`1.5` encoded as `0xf9…` half-float by one library vs `0xfb…` double by another) and the integer-vs-`float64` split for values above `2^53`. The reference implementations enforce this in `dagCborCanonicalEncode` (TypeScript) and `DagCborEncode` (Go); a non-conforming number is a verification failure, not a silently-divergent CID.

#### String Encoding (no Unicode normalization)

String values are committed as their exact UTF-8 byte sequence. Implementations MUST NOT apply Unicode normalization (NFC, NFD, NFKC, NFKD) or any other transformation to string values before dag-cbor encoding or signing — the CID and signature commit to the bytes as received. Two strings that are Unicode-equivalent but byte-distinct (for example a precomposed `é` versus an `e` followed by a combining accent) produce different CIDs and are different protocol values. The reference implementations pass strings through verbatim (no `.normalize()` step); any normalization inserted by an implementation is a CID divergence, not an interoperable transformation.

#### JSON Payload Canonicalization

The signed JWS payload is decoded as JSON, then re-encoded as dag-cbor for CID derivation. Producers MUST emit canonical JSON: object keys unique within each object, no insignificant whitespace dependence (dag-cbor re-encodes from the decoded value, so whitespace and key order in the source JSON do not affect the CID). Producers MUST NOT emit duplicate object keys. Where duplicate keys are nonetheless present, both reference implementations decode via standard JSON parsers that retain the final occurrence (last value wins) before dag-cbor encoding — but this is a recovery behavior, not a guarantee: the signature commits to the raw payload bytes while the CID derives from the decoded value, so a duplicate-key payload can desync signature-input from CID across non-conforming parsers. Treat any payload containing duplicate keys as malformed.

**Verification test vector** — encodes `{"version": 1, "type": "test"}`:

```
Integer encoding (CORRECT):
  CBOR: a2647479706564746573746776657273696f6e01
  CID:  bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa

Float encoding (WRONG — different bytes, different CID):
  CBOR: a2647479706564746573746776657273696f6ef93c00
  CID:  bafyreiawbms4476m5jlrmqtyvtwe5ta3eo2bh7mdprtomfgfype7j57o4q
```

If your implementation produces the float CID, your number encoding is incorrect. The byte at offset 19 in the CBOR output is the discriminator: `0x01` = correct (CBOR integer), `0xf9` = wrong (CBOR float16 header).

**Worked example (genesis identity operation):**

```
CBOR bytes (468 bytes, hex):
a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b
65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065
684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e
776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62
696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173
736572744b65797381a362696478236b65795f72396576333466766332337a3939397665616166
7438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74
696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c7467
4d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b
65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065
684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e
776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62

CID bytes (hex): 017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69
CID string:      bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne
```

### DID Derivation (worked example)

```
Input:  CID bytes (hex) = 017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69
Step 1: SHA-256(CID bytes) = c66d21f27dceea0b05534c225ad7018ac7d4dfded0609dcd18022a3739a5488c
Step 2: Take first 31 bytes: c6 6d 21 f2 7d ce ea 0b 05 53 4c 22 5a d7 01 8a c7 d4 df de d0 60 9d cd 18 02 2a 37 39 a5 48
Step 3: For each byte, alphabet[byte % 19]:
        c6=198 → 198%19=8  → 'c'
        6d=109 → 109%19=14 → 'n'
        21=33  → 33%19=14  → 'n'
        f2=242 → 242%19=14 → 'n'
        ...
Result: cnnnft9f8a2rn938d6nkz38r847v2kr
DID:    did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr
```

---

## Operation Schemas

### Identity Operations

```typescript
// Genesis — starts the identity chain
{ version: 1, type: "create",
  authKeys: MultikeyPublicKey[],         // exactly one entry —
  assertKeys: MultikeyPublicKey[],       //   the same single key in all three
  controllerKeys: MultikeyPublicKey[],   //   arrays, which also signs (see Key Possession)
  services?: ServiceEntry[],              // discovery vocabulary (optional)
  createdAt: string }                     // ISO 8601, ms precision, UTC

// Key rotation / modification
{ version: 1, type: "update",
  previousOperationCID: string,                    // CID of previous operation
  authKeys: MultikeyPublicKey[],
  assertKeys: MultikeyPublicKey[],
  controllerKeys: MultikeyPublicKey[],   // must have at least one
  keyProofs?: string[],                  // one KEY-PROOF envelope per key this
                                         //   op introduces (see Key Possession)
  services?: ServiceEntry[],              // full-state — REPLACES the prior set
  createdAt: string }

// Deactivation — moves the identity to the deleted state
{ version: 1, type: "delete",
  previousOperationCID: string,
  createdAt: string }

// Undeletion — only valid as the immediate successor of a delete
{ version: 1, type: "restore",
  previousOperationCID: string,          // MUST be the CID of a delete operation
  createdAt: string }
```

The optional `services` array is full-state discovery vocabulary projected into
verified identity state — see [Services](#services). Omitting it encodes
identically to a service-less operation (CID-neutral); an `update` carrying it
REPLACES the entire prior set; a `delete` carries the last set unchanged.

The optional `keyProofs` array carries the [key-proof envelopes](https://protocol.dfos.com/key-proof)
for the keys an `update` [introduces](#key-possession) — compact JWS strings,
embedded verbatim as presented, one per introduced key. It is defined on
`update` only: a `create`, `delete`, or `restore` carrying it is invalid
(genesis proves its one key by signing; `delete` and `restore` change no keys).
An operation that introduces no key carries none — full-state replay carries
keys, never proofs — so the member appears exactly where a key first enters a
role and nowhere else. Omitting it encodes identically to an empty
introduction (CID-neutral), the same rule as `services`.

**`restore` validity (normative).** `restore` is the one operation that may
follow a `delete`, and the successor-of-delete position is the only position in
which it is valid:

- Its `previousOperationCID` MUST reference a `delete` operation. A `restore`
  anywhere else in the chain — after a `create`, `update`, or another `restore` —
  is invalid.
- It MUST be signed by a **controller key of the deleted head state** — the key
  state produced by the `delete` it restores (a `delete` carries the last key
  sets unchanged). A key rotated out before the delete is not in that state and
  grants nothing.
- Its effect is exactly to clear the deleted state: the identity returns to
  active with the keys and services as of the delete, **verbatim**. `restore`
  carries no key sets or services of its own — state changes happen via
  subsequent ordinary `update` operations.
- Its `createdAt` follows the ordinary rule: strictly greater than its parent's.
  There is no rate limit or once-only rule — a subsequent `delete` may itself be
  followed by another `restore`; every transition requires a current controller
  key, which is total authority over the identity anyway.

A protocol-level **irreversible** deletion (a true seal no controller key can
reopen) is deliberately not part of this specification; if it ships, it ships
as a future additive operation.

### Content Operations

```typescript
// Genesis — starts the content chain, commits initial document
{ version: 1, type: "create",
  did: string,                           // author DID, committed to by CID
  documentCID: string,                   // CID of flat content object
  baseDocumentCID: string | null,        // committed-but-uninterpreted provenance
  createdAt: string }

// Content change (null documentCID = clear content)
{ version: 1, type: "update",
  did: string,                           // author DID
  previousOperationCID: string,
  documentCID: string | null,
  baseDocumentCID: string | null,        // committed-but-uninterpreted provenance
  createdAt: string,
  authorization?: string }               // DFOS credential for delegated operations

// Permanent destruction
{ version: 1, type: "delete",
  did: string,                           // author DID
  previousOperationCID: string,
  createdAt: string,
  authorization?: string }               // DFOS credential for delegated operations
```

`baseDocumentCID` is committed-but-uninterpreted provenance — validated as
CID-or-null, no verification meaning; lets the public proof plane express
content-version lineage without exposing the private document.

### MultikeyPublicKey

```typescript
{ id: string,                             // e.g. "key_r9ev34fvc23z999veaaft83nn29zvhe"
  type: "Multikey",                       // literal discriminator
  publicKeyMultibase: string }            // e.g. "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
```

---

## JWS Envelope Format

### Signing

```
signingInput = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload))
signature = ed25519.sign(UTF8_bytes(signingInput), privateKey)
token = signingInput + "." + base64url(signature)
```

### kid Rules

| Context                        | kid format  | Example                               |
| ------------------------------ | ----------- | ------------------------------------- |
| Identity create (genesis)      | Bare key ID | `key_r9ev34fvc23z999veaaft83nn29zvhe` |
| Identity update/delete/restore | DID URL     | See below                             |
| All content ops                | DID URL     | See below                             |

DID URL examples:

```
did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe
did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8
```

### `cid` Header

Every operation JWS (identity-op and content-op) includes a `cid` field in the protected header. This is the CIDv1 string of the operation payload, derived from `dagCborCanonicalEncode(payload) → SHA-256 → CIDv1 → base32lower`. The `cid` is computed before signing and embedded in the protected header, so it is covered by the EdDSA signature.

**Signing order:**

1. Construct the operation payload
2. Derive the operation CID: `dagCborCanonicalEncode(payload) → CIDv1`
3. Build the protected header including `cid`
4. Sign: `ed25519.sign(UTF8(base64url(header) + "." + base64url(payload)), privateKey)`

**Verification rule:** After verifying the JWS signature and deriving the operation CID from the parsed payload, implementations MUST reject operations where:

- `header.cid` is missing
- `header.cid` does not match the derived CID

A CID mismatch between header and derived value immediately surfaces dag-cbor encoding disagreements across implementations.

Note: [API-AUTH](https://protocol.dfos.com/api-auth)'s request and identity proofs do NOT include a `cid` header. DFOS credentials DO include a `cid` header (for revocation addressability). Which envelope families carry `cid` is inventoried per family in the [extension registry](https://protocol.dfos.com/extensions).

### CID Derivation

```
operation CID = dagCborCanonicalEncode(operation_payload) → SHA-256 → CIDv1 → base32lower string
```

The CID is derived from the JWS payload (the unsigned operation JSON), NOT from the JWS token itself.

### DID Derivation

```
DID = "did:dfos:" + idEncode(SHA-256(genesis_CID_raw_bytes))
```

Where `idEncode` is the 19-char alphabet encoding described above.

---

## Signature Verification Profile

DFOS pins a deliberately narrow profile of the JOSE/JWS surface so that **all conformant verifiers accept and reject the same signatures byte-for-byte**. The rules below are normative and apply to **every** verification path: identity-op JWS, content-op JWS, artifacts, countersignatures, DFOS credentials, credential revocations, and every API-AUTH proof. A verifier MUST apply §1–§3 to the protected header **before** performing any signature computation, and MUST apply §4 as part of (or before) the signature check. A token that violates any rule MUST be rejected regardless of whether its signature would otherwise verify.

There is no algorithm agility: the verifier never branches on `alg` to select a primitive. Ed25519 (`EdDSA`) is the only signature algorithm.

### 1. Algorithm pinning (`alg`)

The protected header `alg` member MUST equal the exact string `"EdDSA"`. Any other value MUST be rejected before any signature check, including (non-exhaustively) `"none"`, `"HS256"`, `"RS256"`, `"ES256"`, the lowercase `"eddsa"`, or an absent `alg`. Verifiers MUST NOT use `alg` to choose a verification primitive; it is checked only for exact equality.

### 2. `crit` rejection

The protected header MUST NOT contain a `crit` member. DFOS emits no critical header parameters, so any token whose protected header carries `crit` (with any value) MUST be rejected. Verifiers MUST observe the member's presence directly — decoding into a fixed header shape that silently discards unknown members is not sufficient.

### 3. No header-key-trust

The verifier MUST NOT read key material from the protected header. The signing key is resolved exclusively from `kid` against the signer's identity chain (current state). **Current state is the state at the chain's head** — the key state after the last operation of the strictly linear identity chain (see Chain Validity) — never a union across history: a key that appears only in superseded operations is not current. (Families that verify under historical rather than current-state resolution say so explicitly in their own specs.) A protected header that carries an embedded public key — specifically a `jwk` or `x5c` member — MUST be rejected. (DFOS emits neither; the resolved key from `kid` is the only trusted key material.) A header-supplied key is never trusted, even if it happens to match the resolved key.

### 4. Canonical signature scalar (`S < L`)

An Ed25519 signature is `R || S` (64 bytes). The scalar `S` (the trailing 32 bytes, little-endian) MUST be canonical: strictly less than the group order

```
L = 2^252 + 27742317777372353535851937790883648493
  = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
```

A signature whose `S >= L` MUST be rejected (classic Ed25519 malleability). A signature that does not decode to exactly 64 bytes MUST also be rejected. Most Ed25519 libraries enforce `S < L` already; implementations on libraries that do not (notably `ed25519-dalek`, where even `verify_strict` accepts non-canonical `S`) MUST add an explicit constant-time `S < L` gate.

### Hardening axes outside this profile

The following hardening axes are intentionally **not part of v1**. v1 verifiers inherit whatever behavior their Ed25519 library provides on these axes:

- **Cofactorless verification equation pinning** — requiring the specific `[S]B == R + [k]A` (cofactorless) equation rather than the batch/cofactored form.
- **Full-order public key check** — the out-of-band `[L]A == identity` torsion test confirming `A` is a full-order point.
- **Canonical point encoding (`y < p`)** — rejecting non-canonical `y`-coordinate encodings of `R` and `A`.
- **Small-order public key rejection** — beyond whatever the underlying library already rejects.
- **Strict base64url tightening** — rejecting non-canonical base64url padding/alphabet beyond what the decoder already enforces.

These axes only matter for adversarially-constructed keys. Honest DFOS keys are full-order and canonically encoded, and honest signers produce canonical `S`, so honest participants are unaffected. Any residual cross-implementation divergence on these axes is reachable only with adversarial keys and sits outside the v1 profile.

### Admission and Re-Verification

Two different questions are asked of the same signature at two different times, and they resolve keys against different state. This is the acceptance/re-verification split [CREDENTIALS.md](https://protocol.dfos.com/credentials#acceptance-vs-validity-normative) states for revocation — _ingest asks freshness; re-verification asks validity_ — generalized to signing keys:

- **First admission is current-state.** A node accepting a **new** operation, artifact, or countersignature submitted to it resolves the signer against the identity's **current** state: an operation freshly signed by a rotated-out key is refused at the door, whatever its `createdAt` claims — otherwise rotation would leave a compromised key an indefinite authoring window. Rotation ends a key's authoring window, including for operations composed before the rotation but never submitted; the honest remedy is re-signing with a current key. (Identity-chain extension admission itself is governed by the prior-state controller rule — see [Identity Chain Signer Validity](#identity-chain-signer-validity) — which this section does not change.)
- **Committed history re-verifies historically, forever.** Once an operation is committed — accepted by a node, or ingested from a peer's committed log — it is a historical fact: re-verification resolves the signing key against every key that ever appeared in the chain's head lineage, because the key may since have rotated out, and re-verifying honest history under current state would break it after any rotation. The admission verdict never enters the replicated log, so cross-node convergence is untouched. A node ingesting a peer's committed log deliberately inherits the **peer's** admission discipline — choosing peers is a trust decision.
- **Two standing poles bracket the split.** Credentials and credit claims verify under **historical** resolution by their own specs' MUST — revocation, not rotation, is their invalidation mechanism ([CREDENTIALS.md](https://protocol.dfos.com/credentials), [CREDITS.md](https://protocol.dfos.com/credits)). Live authentication artifacts ([API-AUTH](https://protocol.dfos.com/api-auth)'s identity and request proofs, [SIWD](https://protocol.dfos.com/siwd) challenge proofs) are always **current-state**, per their own specs — rotation is exactly how a compromised key is stopped from minting new ones.

---

## Credentials

Credentials handle authorization for relay access and content chain delegation — authorize actions on resources (read, write) via attenuations. The full credential format, verification rules, and revocation mechanism are specified in [CREDENTIALS.md](https://protocol.dfos.com/credentials); request authentication (proving a caller controls a DID, per exact request) is [API-AUTH](https://protocol.dfos.com/api-auth)'s surface.

### Content Chain Authorization

When `enforceAuthorization` is enabled on content chain verification:

1. **Genesis operation**: The signer is the chain creator, always authorized
2. **Creator signs subsequent ops**: Authorized directly — no credential needed
3. **Different DID signs**: Must include an `authorization` field containing a valid DFOS credential where:
   - The delegation chain roots at the chain creator DID
   - The credential's `att` includes an entry with `action: "write"` covering this chain's resource
   - The credential is temporally valid (`iat <= now_s < exp`, where `now_s = floor(op.createdAt_ms / 1000)` — the operation's own timestamp, not wall clock; see CREDENTIALS.md)

The `authorization` field is available on `update` and `delete` content operations. It is absent for creator-signed operations.

### Credential Revocation

Credentials can be revoked by publishing a **revocation artifact** — a signed proof plane primitive with `typ: did:dfos:revocation`. Revocation is immediate and permanent. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for the revocation payload format and verification rules.

---

## Services

`services` is an identity's **discovery vocabulary** — a controller-signed,
full-state array carried in identity-chain `create`/`update` operations and
projected into verified identity state. It answers "given a DID, where do I
reach this identity, and what stable content does it publish?" Services are not a
standalone primitive: they live inside identity operations, inherit the chain's
signer rules (only a current controller key may change them), and inherit the
chain's linearity (services are a pure projection of the head state — the last
operation of the strictly linear identity chain — so a log resolves to exactly
one services set, the same way it resolves to exactly one key state).

### Service Entry

```typescript
{ id: string,        // did-core fragment, unique within the set (deref did:dfos:xxx#<id>)
  type: string,      // open namespace — recognized types are structurally validated
  ...                // type-specific fields (see below)
}
```

Every entry carries the common envelope `{ id, type }`. The namespace is **open**:
two types are recognized and structurally validated; any other `type` is an
opaque extension that verifiers MUST preserve verbatim and otherwise ignore
(MUST-ignore-unknown). New service types therefore never require a protocol or
cross-language change. Every registered type — core and extension — is indexed
in the [extension registry](https://protocol.dfos.com/extensions); a spec that
registers one adds its row there.

**Recognized types:**

```typescript
// Transport locator — where to reach a relay serving this identity
{ id: string, type: "DfosRelay", endpoint: string }   // endpoint: bare URL string

// Stable content reference under a client-defined semantic label
{ id: string, type: "ContentAnchor", label: string, anchor: string }
```

A `ContentAnchor`'s `anchor` references a **stable** content identifier,
dispatched by structural form:

| Anchor shape                  | Resolves to                       |
| ----------------------------- | --------------------------------- |
| `^[2346789acdefhknrtvz]{31}$` | content chain (mutable, gateable) |
| `^bafyrei[a-z2-7]{52}$`       | artifact (immutable, public)      |

These two shapes are the ONLY valid anchors, and the structural dispatch above is
normative. The contentId anchor is the exact 31-char form `^[2346789acdefhknrtvz]{31}$`.
The artifact anchor is the exact 59-char CIDv1(dag-cbor + SHA-256) base32 form
`^bafyrei[a-z2-7]{52}$` — artifact payloads are always dag-cbor + SHA-256, so every
artifact CID has the fixed `bafyrei` prefix and this exact length. An anchor matching
NEITHER shape MUST be rejected (`AnchorInvalid`); verifiers do not accept other CID
codecs or lengths. New anchor KINDS arrive via a new service `type`, never a new
anchor shape — the dispatch surface stays closed.

The `label` is an opaque client-semantic key (e.g. `"profile"`, `"avatar"`) —
the protocol assigns it no meaning, leaving applications free to define their own
namespaces while still resolving anchors uniformly. A chain HEAD CID is also a
`bafyrei…` dag-cbor CID, so it dispatches to "artifact" and then fails the
resolution-time `type: "artifact"` check — "never anchor a head CID" holds without
a mode flag.

### Bounds

- ≤ 256 entries per identity; entry `id`s MUST be unique within the set
- `id`, `type`, and the recognized string fields (`endpoint`, `label`) MUST be
  non-empty (`anchor` MUST match the contentId/CID shape). Individual field
  lengths are NOT separately capped — the aggregate byte cap below, plus the
  operation-size cap, bound entry size (no per-field length zoo)
- The CBOR-encoded `services` array MUST NOT exceed **32768 bytes**. Verifiers
  enforce this over the same canonical encoding used on the wire, so the bound is
  identical across implementations
- An entry whose **recognized** type is structurally malformed (e.g. a
  `DfosRelay` without an `endpoint`) MUST be rejected at verification. A malformed
  **unrecognized** type is preserved and ignored (envelope + byte cap only)

### Full-state semantics

`services` is full-state, not a delta. A `create` sets the initial set; an
`update` REPLACES the entire set (omit the field to clear it); a `delete` carries
the last set unchanged into terminal state. Omitting `services` encodes
identically to a service-less operation (CID-neutral).

### Worked Example: Services

`examples/identity-services.json` is a genesis publishing a relay locator and two
content anchors (one content-chain, one artifact). Signed by reference key 1:

```
did:          did:dfos:krhcznk98f7r2r4a6ktafcv77f7k6e2
typ:          did:dfos:identity-op
cid:          bafyreiasjg3vqs4b3vepwy5qc4oy4f4vpkcahmwi64jtuei5cf7zqpdxjy
services:     [ { id: "relay",   type: "DfosRelay",     endpoint: "https://relay.dfos.com" },
                { id: "profile", type: "ContentAnchor", label: "profile", anchor: "8n8fnzhrrefkrde6h72kfvff43r8c63" },
                { id: "avatar",  type: "ContentAnchor", label: "avatar",  anchor: "bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu" } ]
```

The full JWS token is in [`examples/identity-services.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/identity-services.json).

---

## Artifacts

Artifacts are standalone signed inline documents — immutable, CID-addressable proof plane primitives. Unlike chain operations which extend a sequence, an artifact is a single signed statement with no predecessor or successor.

### Payload

```json
{
  "version": 1,
  "type": "artifact",
  "did": "did:dfos:...",
  "content": {
    "$schema": "https://schemas.dfos.com/profile/v1",
    "name": "Example"
  },
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

The `content` object MUST include a `$schema` string that identifies the artifact's schema. The schema acts as a discriminator — consumers use it to determine how to interpret the artifact's content. Schema names are free-form strings (no protocol-level registry).

### Constraints

- **JWS `typ` header**: `did:dfos:artifact`
- **Max payload size**: 16384 bytes CBOR-encoded. Protocol constant — not configurable
- **Immutability**: Once published, an artifact is never updated or replaced
- **CID-addressable**: Each artifact is addressed by the CID of its CBOR-encoded payload

### Verification

1. JWS signature verification against the signing DID's current key state
2. CID integrity — `header.cid` matches the CID computed from dag-cbor canonical encoding the raw payload
3. Payload schema validation — `version`, `type: "artifact"`, `did`, `content` with `$schema`, `createdAt`
4. Size limit — CBOR-encoded payload does not exceed 16384 bytes

---

## Countersignatures

A countersignature is a standalone witness attestation — a signed statement that references a target operation by CID. Each countersignature has its own `typ` header (`did:dfos:countersign`), its own payload, and its own CID distinct from the target.

It is the protocol's only **inter-subjective** primitive. Every other operation
is monadic — a self-sovereign identity acting on its own chain. A countersignature
is the signed trace of one subject witnessing another: an endorsement, a
co-authorship, a solemnization. Where an artifact is the work, countersignatures
are the collective attesting "we made this" — authorship rendered as a social act
rather than a private claim.

### Payload

```json
{
  "version": 1,
  "type": "countersign",
  "did": "did:dfos:witness...",
  "targetCID": "bafy...",
  "relation": "endorses",
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

The `did` field is the witness identity — the DID signing the attestation. The `targetCID` references the operation being attested to. The optional `relation` field names the nature of the attestation.

**`relation`** is an OPEN-namespace tag — an arbitrary 1–64 character string. A
handful of values carry conventional social meaning (`endorses`, `coauthors`,
`witnessed`, `holds`, `received`), but the namespace is unbounded: recognized
values inform clients, unrecognized values MUST be preserved and ignored
(MUST-ignore-unknown). The field is optional, so a bare witness attestation (no
relation) encodes identically to one that never carried the field
(CID-neutral). When
present, `relation` is part of the canonical payload and therefore changes the
countersignature's CID.

### Properties

- **JWS `typ` header**: `did:dfos:countersign`
- **Own CID**: Each countersignature has its own CID derived from its own payload, distinct from the target. This avoids the ambiguity of multiple JWS tokens sharing the same CID
- **Stateless verification**: Signature + CID integrity + payload schema. No chain state required to verify the cryptographic validity of a countersignature
- **Composable**: The `targetCID` can reference any CID-addressable operation — content ops, artifacts, identity ops, even other countersignatures
- **Immutable**: Once published, a countersignature is permanent. There is no withdrawal primitive; consumers weight recency and may honor a newer attestation that supersedes an older relation

### Verification

1. Decode JWS, verify `typ` is `did:dfos:countersign`
2. Parse and validate countersign payload (`version`, `type: "countersign"`, `did`, `targetCID`, optional `relation` (1–64 chars when present), `createdAt`)
3. Verify the `kid` DID matches the payload `did` (the witness must sign with their own key)
4. CID integrity — `header.cid` matches the CID computed from dag-cbor canonical encoding the raw payload
5. Verify EdDSA JWS signature against the witness's public key

Relay-level semantic checks (target exists, witness ≠ author, deduplication) are enforcement concerns, not protocol verification.

Countersignatures live on the **proof plane** (public, gossiped). A countersignature is therefore unsuitable for crossing a public/private boundary: witnessing a target permanently and publicly links the witness DID to it.

---

## Verification

Every signature check below is performed under the [Signature Verification Profile](#signature-verification-profile): `alg` is pinned to `"EdDSA"`, a `crit` member or any embedded header key (`jwk`/`x5c`) causes rejection before the signature is checked, and signatures with a non-canonical scalar (`S >= L`) or a non-64-byte length are rejected.

### Identity Chain

1. Decode each JWS, parse payload as IdentityOperation
2. First op MUST be `type: "create"` — this is the genesis bootstrap:
   - Verify the [single-key rule](#key-possession): each of the three role arrays holds exactly one entry, all three the same key with the same id. A genesis declaring more than one distinct key MUST be rejected. A genesis carrying `keyProofs` MUST be rejected.
   - The one key declared in the genesis payload is trusted because the identity does not exist before this operation. There is no prior state to verify against.
   - The signing key (resolved from `kid`) MUST be that declared key. The genesis simultaneously introduces, authorizes, and proves possession of its own key.
   - Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID. Derive the DID from the CID.
3. For each subsequent op: verify `previousOperationCID` matches previous op's derived CID — the log is strictly linear, so each operation extends exactly the one before it; a log containing a conflicting extension (two operations sharing a parent) MUST be rejected. Verify `createdAt` is strictly greater than the parent operation's `createdAt` (MUST — see Chain Validity).
4. If the state before this operation is deleted, the only valid operation is a `restore` whose `previousOperationCID` is the delete's CID; any other operation MUST be rejected. A `restore` whose parent is not a `delete` MUST be rejected wherever it appears. A `delete` or `restore` carrying `keyProofs`, and any `keyProofs` member that is not an array of strings, MUST be rejected.
5. Resolve `kid` — genesis uses bare key ID, non-genesis uses DID URL (extract DID, verify it matches the derived DID; extract key ID).
6. Find controller key matching key ID **in the current declared state** (i.e., the declared state after all preceding operations — for a `restore`, this is the deleted head state produced by the `delete`, which carries the last key sets unchanged; see [Key Possession](#key-possession) for why signer validity reads the declared set). Decode multikey → raw Ed25519 public key.
7. Verify EdDSA JWS signature over the signing input bytes.
8. For an `update`, compute possession per [Key Possession](#key-possession): for each key-role membership the operation [introduces](#key-possession) (the key was not in the prior effective state for that role), find an envelope in `keyProofs` passing [chain-walk verification](https://protocol.dfos.com/key-proof#chain-walk-verification) for this operation, this key, and that role. A covered introduction is effective; an uncovered one is **void** — recorded, surfaced, excluded from effective state, and not a rejection.
9. Apply state change: `create` initializes declared and effective key state to its one key in all three roles, `update` replaces declared state (must have at least one declared controller key) and folds effective state per step 8 (memberships already effective stay effective; introductions enter effective state only when covered), `delete` marks the state deleted (key sets and services carried unchanged), `restore` clears the deleted state (keys and services as of the delete, verbatim, effective state included).

The verification result carries both readings — the declared state, the effective state, and the list of void memberships (key, role, operation CID) for tooling to surface. Consumers act on the effective state; the declared state exists for structural admission and for showing a human exactly what a chain claims versus what it proved.

### Content Chain

1. Decode each JWS, parse payload as ContentOperation
2. First op must be `type: "create"` — the signer is the chain creator
3. For each subsequent op: verify `previousOperationCID` matches, verify `createdAt` is strictly greater than the parent operation's `createdAt` (MUST)
4. Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID.
5. Verify the `kid` DID matches the payload `did` field
6. Resolve `kid` via external key resolver (caller provides)
7. Verify EdDSA JWS signature
8. If `enforceAuthorization` is enabled and the signer DID differs from the chain creator: verify the `authorization` field contains a valid DFOS credential with `action: "write"` covering this chain, with a delegation chain rooting at the creator DID, and not expired at `op.createdAt`
9. Apply state change (set document, clear, or delete)

---

## Deterministic Reference Artifacts

All artifacts below are deterministic and reproducible from fixed seeds. An independent implementer can verify every value using standard Ed25519 + dag-cbor libraries. Private keys are derived from `SHA-256(UTF8("dfos-protocol-reference-key-N"))`.

### Key 1 (Genesis Controller)

```
Seed:        SHA-256("dfos-protocol-reference-key-1")
Private key: 132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac
Public key:  ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32
Multikey:    z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb
Key ID:      key_r9ev34fvc23z999veaaft83nn29zvhe
```

### Key 2 (Rotated Controller)

```
Seed:        SHA-256("dfos-protocol-reference-key-2")
Private key: 384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8
Public key:  0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c
Multikey:    z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK
Key ID:      key_ez9a874tckr3dv933d3ckdn7z6zrct8
```

### Identity Chain: Create (Genesis)

Operation:

```json
{
  "version": 1,
  "type": "create",
  "authKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft83nn29zvhe",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "assertKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft83nn29zvhe",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "controllerKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft83nn29zvhe",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "createdAt": "2026-03-07T00:00:00.000Z"
}
```

JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
}
```

JWS Signature (hex):

```
4dece71e7cebb4a3864ebd05ce40cbdb3fa5b8c5a701b297ae60db8be131830ff130f0a7630187391323c3e04cdbc7f44684e2ac801e0fb776d16e514ae1ae06
```

JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg
```

Operation CID:

```
bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne
```

**Derived DID: `did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr`**

### Identity Chain: Update (Key Rotation)

JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei"
}
```

Operation:

```json
{
  "version": 1,
  "type": "update",
  "previousOperationCID": "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne",
  "authKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckdn7z6zrct8",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "assertKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckdn7z6zrct8",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "controllerKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckdn7z6zrct8",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "createdAt": "2026-03-07T00:01:00.000Z"
}
```

JWS Signature (hex):

```
edfaaf586115616f5ab40d6eaa9a7b94850e5a9e1d0132e92e33a6156cc937ef204cbf909d70c27b219c06ee405e11f33b9d9f6aec146af8752ab07ac0162e0b
```

JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw
```

Operation CID:

```
bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei
```

Post-rotation: DID unchanged (`did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr`), controller rotated to `key_ez9a874tckr3dv933d3ckdn7z6zrct8`.

### Identity Chain: Delete + Restore

Delete Operation:

```json
{
  "version": 1,
  "type": "delete",
  "previousOperationCID": "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei",
  "createdAt": "2026-03-07T00:02:00.000Z"
}
```

Delete JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreicl3a2t6vhz5vgvs5ojdw5wcwgoz3taxqqwexpbpltm2gh3q42zyi"
}
```

Delete JWS Signature (hex):

```
d340f2eea78aec8d210b73f5caf1112c920d04b362115f4b846f015dd50c20618b4ecc6e31cba19f762abaaf7a4906bc9b397e073b730f92ccc41a21619c5002
```

Delete JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsImNpZCI6ImJhZnlyZWljbDNhMnQ2dmh6NXZndnM1b2pkdzV3Y3dnb3ozdGF4cXF3ZXhwYnBsdG0yZ2gzcTQyenlpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiZGVsZXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmZ1aDYzdXYzM2kyaTVlb29lM2JvaXQycnV5amVodWJzcnllbXV1ejZtcnRsZWoyNnJlaSIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.00Dy7qeK7I0hC3P1yvERLJINBLNiEV9LhG8BXdUMIGGLTsxuMcuhn3Yquq96SQa8mzl-BztzD5LMxBohYZxQAg
```

Delete Operation CID:

```
bafyreicl3a2t6vhz5vgvs5ojdw5wcwgoz3taxqqwexpbpltm2gh3q42zyi
```

Restore Operation:

```json
{
  "version": 1,
  "type": "restore",
  "previousOperationCID": "bafyreicl3a2t6vhz5vgvs5ojdw5wcwgoz3taxqqwexpbpltm2gh3q42zyi",
  "createdAt": "2026-03-07T00:03:00.000Z"
}
```

Restore JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreieyavue6vxzt63ulkqpwetfwqvfzdkeq6t3q3gwrjnqghmijrgyba"
}
```

Restore JWS Signature (hex):

```
9552998f7e081a6c9ffb4527ed310b48f3f78b9ee058c7bc8f9778774ea016787caf88697f9ff5547314af0c24b7b0859d671de148b809d7973ca4bc8e921e02
```

Restore JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsImNpZCI6ImJhZnlyZWlleWF2dWU2dnh6dDYzdWxrcXB3ZXRmd3F2Znpka2VxNnQzcTNnd3JqbnFnaG1panJneWJhIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoicmVzdG9yZSIsInByZXZpb3VzT3BlcmF0aW9uQ0lEIjoiYmFmeXJlaWNsM2EydDZ2aHo1dmd2czVvamR3NXdjd2dvejN0YXhxcXdleHBicGx0bTJnaDNxNDJ6eWkiLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAzOjAwLjAwMFoifQ.lVKZj34IGmyf-0Un7TELSPP3i57gWMe8j5d4d06gFnh8r4hpf5_1VHMUrwwkt7CFnWcd4Ui4CdeXPKS8jpIeAg
```

Restore Operation CID:

```
bafyreieyavue6vxzt63ulkqpwetfwqvfzdkeq6t3q3gwrjnqghmijrgyba
```

### Content Chain: Document + Create

Document (flat content object):

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "publishedAt": "2026-03-07T00:02:00.000Z",
  "title": "Hello World",
  "body": "First post on the protocol.",
  "credits": [
    {
      "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
      "label": "author"
    }
  ]
}
```

Document CID:

```
bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu
```

Content Create JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:content-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i"
}
```

Content Create Payload:

```json
{
  "version": 1,
  "type": "create",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "documentCID": "bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu",
  "baseDocumentCID": null,
  "createdAt": "2026-03-07T00:02:00.000Z"
}
```

Content Create JWS Signature (hex):

```
069523331dffceae6af9bc4e40dd29978b5f81ffee648b7deebedf33f76e909afefb307483bb311bd21c06ccb4451dcffc3b482b8181d7b8a4c035030c79ee03
```

Content Create JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWJzM3ZsdmFpbmZqZnVldDZ4NHVkczNwaXZibWJvaHk3ZjY0aWVnYnV3M2dwc3VxdG1hNmkifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWU2eGZrcnR3YXgyZHE1Z2R3M3Jwc3VyejJnbHNkdXh5Y2ZoazdqamxsZXdpd2l2a2thZnUiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.BpUjMx3_zq5q-bxOQN0pl4tfgf_uZIt97r7fM_dukJr--zB0g7sxG9IcBsy0RR3P_DtIK4GB17ikwDUDDHnuAw
```

Content Operation CID:

```
bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i
```

### Content Chain: Update

Content Update Payload:

```json
{
  "version": 1,
  "type": "update",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "previousOperationCID": "bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i",
  "documentCID": "bafyreiaoinzo2ai4hx56b7244zahnfqmgurcd3rppqbawhv32xzlvct5m4",
  "baseDocumentCID": "bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu",
  "createdAt": "2026-03-07T00:03:00.000Z"
}
```

Updated document (flat content object):

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "publishedAt": "2026-03-07T00:02:00.000Z",
  "title": "Hello World (edited)",
  "body": "Updated content.",
  "credits": [
    {
      "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
      "label": "author"
    }
  ]
}
```

Document CID (edited):

```
bafyreiaoinzo2ai4hx56b7244zahnfqmgurcd3rppqbawhv32xzlvct5m4
```

Content Update CID:

```
bafyreied5cjgjjt2pdz52k6pgipcjg3i4xl7txbrbdedscejvqhtgltxdi
```

### Content Chain Verified State

```
Content ID:   8n8fnzhrrefkrde6h72kfvff43r8c63
Genesis CID:  bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i
Head CID:     bafyreied5cjgjjt2pdz52k6pgipcjg3i4xl7txbrbdedscejvqhtgltxdi
```

---

## Verification Checklist (For Independent Implementers)

Given the artifacts above, verify:

1. **Multikey decode**: strip `z`, base58btc decode, strip `[0xed, 0x01]` prefix → raw public key:

   ```
   z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb
   → ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32
   ```

2. **Genesis JWS verify**: split token on `.`, take first two segments as signing input (UTF-8 bytes), base64url-decode third segment as 64-byte signature, `ed25519.verify(signature, signingInputBytes, publicKey)` → true. The header contains `cid` alongside `alg`, `typ`, and `kid`.

3. **Genesis CID**: base64url-decode JWS payload → parse JSON → dag-cbor canonical encode → SHA-256 → CIDv1 → should be:

   ```
   bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne
   ```

4. **CID header**: Verify each operation JWS header contains `cid` matching the derived operation CID

5. **DID derivation**: take raw CID bytes of genesis CID → SHA-256 → first 31 bytes → `byte % 19` → alphabet lookup → should be `cnnnft9f8a2rn938d6nkz38r847v2kr` → DID = `did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr`

6. **Rotation JWS**: signed by OLD controller key (key 1). Verify with key 1's public key. kid:

   ```
   did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe
   ```

7. **Content create JWS**: signed by NEW controller key (key 2, post-rotation). Verify with key 2's public key. kid:

   ```
   did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8
   ```

8. **Document CID**: dag-cbor canonical encode the flat content object → SHA-256 → CIDv1 → should be:

   ```
   bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu
   ```

9. **Content operation `did` field**: verify the `did` field in each content operation matches the `kid` DID in the JWS header

10. **Content chain integrity**: update's `previousOperationCID` matches create's operation CID

11. **Chain completeness**: all operation CIDs, DID derivation, key rotation, and content chain linkage verified end-to-end.

12. **Credential verify**: using the issuer's public key, verify a DFOS credential with write or read access: check EdDSA signature, expiration, `kid` DID URL format, `kid` DID matches `iss`, credential type matches expected DFOS type. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for format details. Test vectors in [`examples/credential-write.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/credential-write.json) and [`examples/credential-read.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/credential-read.json).

13. **Delegated content chain verify**: using [`examples/content-delegated.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/content-delegated.json), verify a content chain where the genesis is signed by the creator and a subsequent update is signed by a delegate with an embedded DFOS write credential in the `authorization` field. The credential must be issued by the creator DID, with `aud` matching the delegate DID.

14. **Number encoding determinism**: dag-cbor encode `{"version": 1, "type": "test"}` and verify:
    - CBOR hex is `a2647479706564746573746776657273696f6e01` (20 bytes)
    - CID is `bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa`
    - Byte at offset 19 is `0x01` (CBOR integer 1), NOT `0xf9` (CBOR float header)
    - If your implementation decodes this payload from JSON (e.g., from a JWS token) and then re-encodes to dag-cbor, the CID MUST still match. This catches the JSON `float64` → CBOR float trap.

---

## Source and Verification

All source lives in [`packages/dfos-protocol/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) — self-contained, zero monorepo dependencies. Cross-language test counts are listed in the [table below](#cross-language-verification).

- [`crypto/ed25519`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/ed25519.ts) — `createNewEd25519Keypair`, `importEd25519Keypair`, `signPayloadEd25519`, `isValidEd25519Signature`
- [`crypto/jws`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/jws.ts) — `createJws`, `verifyJws`, `decodeJwsUnsafe`
- [`crypto/jwt`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/jwt.ts) — `createJwt`, `verifyJwt`
- [`crypto/base64url`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/base64url.ts) — `base64urlEncode`, `base64urlDecode`
- [`crypto/multiformats`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/multiformats.ts) — `dagCborCanonicalEncode`, `dagCborCanonicalEqual`
- [`crypto/id`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/id.ts) — `generateId`, `generateIdNoPrefix`, `isValidId`
- [`chain/multikey`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/multikey.ts) — `encodeEd25519Multikey`, `decodeMultikey`
- [`chain/schemas`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/schemas.ts) — `IdentityOperation`, `ContentOperation`, `ArtifactPayload`, `CountersignPayload`, `MultikeyPublicKey`, `VerifiedIdentity`
- [`chain/identity-chain`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/identity-chain.ts) — `signIdentityOperation`, `verifyIdentityChain`, `verifyIdentityExtensionFromTrustedState`
- [`chain/content-chain`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/content-chain.ts) — `signContentOperation`, `verifyContentChain`, `verifyContentExtensionFromTrustedState`
- [`chain/derivation`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/derivation.ts) — `deriveChainIdentifier`, `deriveContentId`
- [`chain/services`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/services.ts) — `classifyAnchor`, `relayEndpoints`, `anchorsByLabel`
- [`chain/artifact`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/artifact.ts) — `signArtifact`, `verifyArtifact`
- [`chain/countersign`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/countersign.ts) — `signCountersignature`, `verifyCountersignature`
- [`chain/credit-claim`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/credit-claim.ts) — `signCreditClaim`, `verifyCreditClaim`, `verifyCreditEntry`
- [`chain/sign-request`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/sign-request.ts) — `buildSignRequest`, `verifySignRequest`, `assertCanonicalSignRequestPayload`
- [`chain/revocation`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/revocation.ts) — `signRevocation`, `verifyRevocation`
- [`credentials/dfos-credential`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/dfos-credential.ts) — `createDFOSCredential`, `verifyDFOSCredential`, `decodeDFOSCredentialUnsafe`
- [`credentials/schemas`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/schemas.ts) — `DFOSCredentialPayload`, `Attenuation`

### Related Specifications

- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method) — W3C DID method specification for identity chains
- [Content Model](https://protocol.dfos.com/content-model) — Standard content schemas (post, profile) for document content objects
- [Credentials](https://protocol.dfos.com/credentials) — UCAN-style authorization credentials for the DFOS protocol
- [Credits](https://protocol.dfos.com/credits) — Verifiable attribution for DFOS content
- [Sign In With DFOS](https://protocol.dfos.com/siwd) — Cryptographic identity verification for third-party applications
- [Signing](https://protocol.dfos.com/signing) — A transport-agnostic way for one party to ask another to produce a DFOS signature
- [Web Relay](https://protocol.dfos.com/web-relay) — HTTP relay specification for ingestion, state, and content plane
- [Content Plane / Document Gateway](https://protocol.dfos.com/web-relay#content-plane--document-gateway) — A stateless, content-addressed blob store with authorization derived from the proof plane
- [Threat Model](https://protocol.dfos.com/threat-model) — A consolidated map of the DFOS adversary model and trust boundaries
- [Conformance](https://protocol.dfos.com/conformance) — Conformance tiers and their proving corpora

### Cross-Language Verification

| Language   | Tests | Source                                                                                                   |
| ---------- | ----- | -------------------------------------------------------------------------------------------------------- |
| TypeScript | 402   | [`dfos-protocol/tests/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/tests)       |
| TypeScript | 81    | [`protocol-verify/ts/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/ts)         |
| Go         | 20    | [`protocol-verify/go/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/go)         |
| Rust       | 20    | [`protocol-verify/rust/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/rust)     |
| Python     | 82    | [`protocol-verify/python/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/python) |
| Swift      | 19    | [`protocol-verify/swift/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/swift)   |

# DFOS Protocol

DFOS is an identity you hold and content whose authorship anyone can check
without asking the host. A platform can host your identity. It cannot own it.

This document specifies the wire: the byte encodings, the identifier
derivations, the chain rules, the possession rules, and the verification
algorithms that make a DFOS operation the same object in every implementation.
It is a wire specification plus the ingest and integration conventions that
surround it. Authorship is verifiable without trusting any server. Which view of
an identity you follow is a choice of relay.

Scope: the protocol commits to content hashes, not plaintext. It does not
encrypt. Confidentiality of the underlying documents is the application layer's,
enforced by whoever serves them, and a relay operator can read what it stores.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Overview

| Component             | Concern                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------ |
| **Crypto core**       | Identity chains and content chains: Ed25519 signatures, JWS tokens, CID links              |
| **Credentials**       | Delegated authorization; format in [CREDENTIALS.md](https://protocol.dfos.com/credentials) |
| **Services**          | Identity discovery vocabulary: controller-signed relay locators and stable content anchors |
| **Artifacts**         | Standalone signed inline documents: immutable, CID-addressable structured data             |
| **Countersignatures** | Standalone witness attestation: signed references to any CID-addressable operation         |

Documents are flat content objects, content-addressed directly:
`documentCID = CID(dagCborCanonicalEncode(contentObject))`. What goes inside the
content object is application-defined; the standard schema library is the
[DFOS Content Model](https://protocol.dfos.com/content-model).

### Two chain types

|                | Identity Chain             | Content Chain                    |
| -------------- | -------------------------- | -------------------------------- |
| Commits to     | Key sets (embedded)        | Documents (by CID reference)     |
| Identifier     | `did:dfos:<hash>`          | `<hash>` (bare)                  |
| Operations     | create, update, delete     | create, update, delete           |
| JWS typ        | `did:dfos:identity-op`     | `did:dfos:content-op`            |
| Self-sovereign | Yes (signs own operations) | No (signed by external identity) |

Both chains are signed linked lists of state commitments. Identity chains embed
their state (key sets). Content chains reference their state via `documentCID`.

### Addressing

Three addressing modes, self-describing by format:

| Thing                 | Form                     | Example                                    |
| --------------------- | ------------------------ | ------------------------------------------ |
| Operation or document | CID (dag-cbor + SHA-256) | `bafyrei...` (base32lower)                 |
| Content chain         | contentId (31-char hash) | `cv7n8vkvr64cctf3294h9k4eanhff8z`          |
| Identity chain        | DID                      | `did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr` |

CIDs address specific immutable artifacts: an exact operation or document.
Content IDs and DIDs address living chains, derived as
`customAlpha(SHA-256(genesis CID bytes))`. Same derivation for both. Identity
chains prepend `did:dfos:` (W3C DID spec); content identifiers are bare.

Application code may add prefixes for routing (e.g. `post_xxxx`). These are
strippable semantic sugar, not part of the protocol identifier.

---

## Encoding

Both operations and documents are content-addressed via **CID**
(`dagCborCanonicalEncode(payload)` to SHA-256 to CIDv1). Operations are
additionally signed via **JWS**.

| Representation | Encoding                                                                                                       | Purpose                                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| CID            | `dagCborCanonicalEncode(payload)` → SHA-256 → CIDv1                                                            | Deterministic content addressing for operations and documents |
| JWS            | `base64url(JSON.stringify(header))` + `.` + `base64url(JSON.stringify(payload))` → EdDSA signature covers both | Signature verification for operations                         |

CID uses [dag-cbor canonical encoding](https://ipld.io/specs/codecs/dag-cbor/spec/):
given the same logical payload, the CID MUST be identical regardless of
implementation language or platform. JWS uses standard JSON for library
interoperability.

### Standards

| Component           | Standard                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Key generation      | Ed25519 (RFC 8032)                                                                                                                    |
| Signature algorithm | EdDSA over Ed25519 (pure, no prehash; Ed25519 handles SHA-512 internally)                                                             |
| Key encoding        | W3C Multikey (multicodec `0xed01` + base58btc multibase)                                                                              |
| Signed envelopes    | JWS Compact Serialization (RFC 7515) with `alg: "EdDSA"`                                                                              |
| Content addressing  | CIDv1 with dag-cbor codec (`0x71`) + SHA-256 multihash (`0x12`)                                                                       |
| ID encoding         | SHA-256 → custom 19-char alphabet, 31 characters                                                                                      |
| Timestamp encoding  | ECMA-262 Date Time String Format, UTC form: a strict ISO-8601 / RFC 3339 profile, fixed millisecond precision (see Timestamp Grammar) |

### CID construction (dag-cbor + SHA-256)

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

dag-cbor canonical ordering: map keys sorted by encoded byte length first, then
lexicographic. Strings to CBOR text strings. Null to CBOR null. Arrays to CBOR
arrays. Objects to CBOR maps with sorted keys.

The operation CID is derived from the JWS payload (the unsigned operation JSON),
never from the JWS token:

```
operation CID = dagCborCanonicalEncode(operation_payload) → SHA-256 → CIDv1 → base32lower string
```

#### Number encoding

**JSON numbers that are mathematically integers (no fractional part) MUST be
encoded as CBOR integers (major type 0/1), never as CBOR floats.** This follows
the [IPLD data model](https://ipld.io/docs/data-model/) integer/float distinction
and the [dag-cbor codec spec](https://ipld.io/specs/codecs/dag-cbor/spec/). CBOR
integer `1` encodes as `0x01` and CBOR float `1.0` encodes as `0xf9 0x3c 0x00`:
the same logical value, a different CID.

Languages that decode JSON into untyped maps (Go's `map[string]any`, Python's
`dict`) typically represent all JSON numbers as floating-point. Implementations
MUST normalize number types after JSON deserialization and before CBOR encoding.

**Number bounds (normative).** A canonicalizable number MUST be an integer in the
range `[-(2^53 - 1), 2^53 - 1]` (JSON's safe-integer range). Implementations MUST
reject, at CID derivation and before CBOR encoding, any payload containing a
non-integer number, `NaN`, `±Infinity`, or an integer outside that range.
Applications that need fractional or larger-magnitude values MUST encode them as
strings. This single form eliminates both the shortest-float divergence and the
integer-versus-`float64` split above `2^53`.

**Verification test vector**, encoding `{"version": 1, "type": "test"}`:

```
Integer encoding (CORRECT):
  CBOR: a2647479706564746573746776657273696f6e01
  CID:  bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa

Float encoding (WRONG — different bytes, different CID):
  CBOR: a2647479706564746573746776657273696f6ef93c00
  CID:  bafyreiawbms4476m5jlrmqtyvtwe5ta3eo2bh7mdprtomfgfype7j57o4q
```

The byte at offset 19 in the CBOR output is the discriminator: `0x01` is a CBOR
integer, `0xf9` is a CBOR float16 header.

#### String encoding

String values are committed as their exact UTF-8 byte sequence. Implementations
MUST NOT apply Unicode normalization (NFC, NFD, NFKC, NFKD) or any other
transformation to string values before dag-cbor encoding or signing. The CID and
the signature commit to the bytes as received, so two strings that are
Unicode-equivalent but byte-distinct are different protocol values.

#### JSON payload canonicalization

The signed JWS payload is decoded as JSON, then re-encoded as dag-cbor for CID
derivation. Producers MUST emit canonical JSON: object keys unique within each
object, no duplicate object keys. Whitespace and key order in the source JSON do
not affect the CID, because dag-cbor re-encodes from the decoded value. A payload
containing duplicate keys is malformed: the signature commits to the raw payload
bytes while the CID derives from the decoded value.

#### Decoder recursion depth

A node SHOULD apply a decoder recursion-depth guard when canonicalizing or
encoding a payload. Both reference implementations cap nesting at 1024 levels.
This is a local resource guard, not a chain-validity rule. Nodes MAY
apply stricter local ingress limits (max bytes decoded off the wire, rate limits)
provided they never accept an operation the validity rules reject, nor reject one
they accept.

### ID alphabet

```
Alphabet: 2346789acdefhknrtvz  (19 characters)
Length:   31 characters
Entropy:  ~131.6 bits (19^31)
```

Process: `SHA-256(input) → for each of first 31 bytes: alphabet[byte % 19]`. The
modulo introduces a ~0.3% bias (256 is not evenly divisible by 19), which is not
security-relevant for identifiers.

DIDs are `did:dfos:` + the 31-char ID derived from `SHA-256(genesis CID raw bytes)`:

```
DID = "did:dfos:" + idEncode(SHA-256(genesis_CID_raw_bytes))
```

There is a single canonical identifier width. Verifiers MUST reject any
`did:dfos:` identifier that is not exactly 31 characters over this alphabet,
whether it appears in an operation's signing-key `kid`, in an operation payload,
or as the DID of a resolved identity state.

Key IDs are `key_` + a 31-char ID. Convention: derive from the key,
`key_` + `customAlpha(SHA-256(publicKeyMultibase))`, where the input is the
multibase **string** a chain carries, not the raw key bytes. This is not a
protocol requirement; key IDs can be any string.

#### DID derivation (worked example)

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

### Multikey encoding (W3C Multikey for Ed25519)

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

`[0xed, 0x01]` is the unsigned varint encoding of 237 (`0xed`). Since
`0xed > 0x7f` it requires two bytes in varint format: `0xed` (low 7 bits plus
continuation bit) then `0x01` (high bits). This is NOT big-endian `[0x00, 0xed]`.

### Timestamp grammar

Every operation's `createdAt` field MUST match exactly the grammar:

```
YYYY-MM-DDTHH:MM:SS.sssZ
```

That is, in order, with no other characters and no surrounding or internal
whitespace:

- a 4-digit zero-padded calendar **year** (`0000`–`9999`),
- a literal `-`, a 2-digit zero-padded **month** (`01`–`12`),
- a literal `-`, a 2-digit zero-padded **day** of month,
- a literal uppercase **`T`** date/time separator,
- a 2-digit zero-padded **hour** (`00`–`23`), `:`, a 2-digit **minute** (`00`–`59`), `:`, a 2-digit **second** (`00`–`59`),
- a literal `.` followed by **exactly three** decimal digits of fractional seconds (millisecond precision, no more, no fewer),
- a literal uppercase **`Z`** designating UTC.

The value MUST be a real calendar instant: the month/day combination MUST be
valid (leap years are honored, so `2024-02-29` is valid and `2023-02-29` is not).
A **timezone offset** (e.g. `+00:00`, `-05:00`) MUST NOT appear; only the literal
`Z` is permitted. **Leap seconds** (`:60`) MUST be rejected. A lowercase `z`, a
missing or differently-sized fractional part, a space in place of `T`,
non-zero-padded fields, or any leading, trailing, or embedded whitespace MUST be
rejected.

A verifier MUST reject any operation whose `createdAt` does not match this
grammar. This applies on the read/verify path, not only at write time.

The grammar is [ECMA-262 §21.4.1.32](https://tc39.es/ecma262/#sec-date-time-string-format)'s
Date Time String Format in its UTC form, a strict profile of ISO 8601 /
[RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) that excludes the offset
forms, week dates, ordinal dates, and comma separators those admit.

The grammar is a validity rule, not a formatting suggestion: ordering and head
selection compare `createdAt` as raw strings, and only a fixed-width zero-padded
grammar makes byte order identical to chronological order.

---

## Chains

### Chain validity

A valid chain is a sequence of operations rooted at a genesis. Each operation
after genesis links to a predecessor via `previousOperationCID`. The chain
provides structural ordering independent of timestamps. The two chain kinds
differ in exactly one structural rule: whether that sequence may branch.

**Identity chains are linear.** Each identity operation has at most one child.
An identity chain, as verified, is one sequence: the head is its last operation,
and identity state is what that sequence folds to.

**Content chains are DAGs.** A valid content chain is a directed acyclic graph of
operations. Two content operations referencing the same `previousOperationCID`
constitute a fork, and both branches are accepted. The chain log stores all
branches. A **deterministic head selection** rule makes every implementation
holding the same set of operations compute the same head:

1. Find all **tips**: operations with no children.
2. Select the tip with the **highest `createdAt`** string (descending order).
3. If two or more tips share an identical `createdAt`, break the tie by the
   **highest CID multibase string** (descending order). Distinct payloads yield
   distinct CIDs, so this tiebreak is total.

Semantic interpretation of a content-chain fork is application-defined. The
protocol stores the DAG; clients interpret it.

### Views

An identity chain is linear per view. Two identity operations that share a parent
are two views of that identity, not an invalid log: a relay keeps its own log
linear by admitting the first successor it sees for a position and refusing
later ones, so what each relay serves is one linear chain. Choosing which view of
an identity you follow is choosing a relay. On a content chain divergence needs
no choice of view, because head selection resolves the same operation set to the
same head everywhere.

### Comparison basis

Both ordering comparisons, `createdAt` and the head-selection CID tiebreak, MUST
compare the raw strings byte-wise (Unicode code point, left to right). An
implementation MUST NOT parse `createdAt` to an epoch, a floating-point value, or
a broken-down time before comparing, and MUST NOT apply a locale-aware or
collation-aware comparison (for example ICU collation or
`String.prototype.localeCompare`) to either field. The `createdAt` grammar is
fixed-width and zero-padded and a CID is a base32-lower multibase string, so byte
order is chronological order for the first and byte order for the second.

### Timestamp ordering

`createdAt` MUST be strictly greater than the `createdAt` of the parent operation
(the operation referenced by `previousOperationCID`). On an identity chain this
is plain successor ordering. On a content chain it is enforced per-branch: a fork
branch's timestamps are validated against its own parent, not the other branch's
operations.

`createdAt` is asserted by the signer. What bounds it is per-branch monotonic
ordering plus the future bound below; there is no clock anyone else vouches for.

### Future timestamp bound

Relays, and any component that performs deterministic head selection, MUST reject
identity and content operations with a `createdAt` more than 24 hours in the
future relative to the verifier's clock. Head selection favors the highest `createdAt`, so an unbounded future timestamp
would otherwise dominate it permanently.

Bare linear chain verification (`verifyIdentityChain` / `verifyContentChain`)
does not select a head and does not enforce this bound; it validates only that
each operation's `createdAt` is strictly greater than its parent's. The reference
relays enforce the 24-hour bound at ingest.

### Identity chain signer validity

An identity chain operation is valid only if the signing key was a **controller
key in the immediately prior declared state** ([Key possession](#key-possession)
defines declared versus effective state). Signer validity reads the declared set
because it is a structural admission rule every relay must evaluate identically.

A genesis operation declares exactly **one key**, the same key in all three role
arrays, and is signed by it: the genesis introduces and simultaneously authorizes
its own key, and the signature is that key's possession proof. A genesis
declaring more than one distinct key across its role arrays is invalid.
Identities with several controllers bootstrap the ordinary way: genesis with one
key, then `update` operations introducing the rest under the possession rule.

The identity chain defines its own valid signers via `controllerKeys` and the
protocol enforces that. No external authority is consulted.

### Content chain signer model

Content chain verification requires a **valid EdDSA signature** and delegates key
resolution to the caller. The `kid` in each operation's JWS header is a DID URL
(`did:dfos:<id>#<keyId>`). The verifier calls `resolveKey(kid)` to obtain the raw
Ed25519 public key bytes for that key on that identity. How the resolver obtains
and validates the identity's key state is application-defined.

**Creator sovereignty.** The DID that signs the genesis (create) operation is the
**chain creator** and permanently owns the chain. The creator can sign subsequent
operations directly, with no credential. Other DIDs require a **DFOS credential
with write access** in the operation's `authorization` field, issued by the
creator DID.

**Signer-payload consistency.** The `kid` DID in the JWS header MUST match the
`did` field in the content operation payload. This discriminates author
operations from countersignatures: if the `kid` DID differs from the payload
`did`, it is a countersignature, not a chain operation.

Which key role (auth, assert, controller) a signing key must hold, and any
ownership or attribution semantics beyond creator sovereignty, are application
concerns. What the protocol itself checks is
[Content chain verification](#content-chain).

### Terminal states

**Content chains: `delete` is the terminal state.** No valid content operations
may follow a delete. This is enforced per-branch: a delete seals further linear
extension of its own branch, forks rooted at a pre-delete operation remain valid,
and head selection may make a non-deleted branch the head. Delete prevents future
operations but removes no data; the complete chain remains intact for
verification. Data removal is an application concern.

**Identity chains: `active ⇄ deleted`, every transition an explicit signed
operation.** A `delete` moves the identity to the deleted state and seals the
chain against every operation except one: a **`restore`** operation MAY follow
the `delete` as its immediate linear successor, returning the identity to the
active state. An implementation MUST reject any other operation after a delete.
Both transitions are ordinary operations in the one timeline, permanent and
auditable, never removed. As with content chains, deletion removes no data.

**Controller key requirement.** `update` operations on identity chains MUST
include at least one controller key. If decommissioning is intended, `delete` is
the correct terminal operation.

**Content-null.** An `update` on a content chain with `documentCID: null` means
the content exists but its document is cleared. The chain continues; a subsequent
update can set content again.

### Operation versioning

Every proof-plane operation payload (identity, content, artifact, countersign,
revocation) carries a top-level integer `version` field. This document specifies
version `1`; verifiers MUST reject any operation whose `version` is not exactly
`1`. The operation `version` is distinct from content-document `$schema`
versioning (see [CONTENT-MODEL.md](https://protocol.dfos.com/content-model)),
which versions application payloads independently.

### Size and cardinality limits

The protocol bounds operations with one aggregate size cap plus a small set of
cardinality caps, never a per-field string-length table. The aggregate bound is measured over the exact CBOR bytes the CID commits to, so
every implementation computes it identically.

| Bound                              | Value                    | Applies to                              |
| ---------------------------------- | ------------------------ | --------------------------------------- |
| dag-cbor-encoded operation payload | **65536 bytes** (64 KiB) | identity operations, content operations |

Verifiers MUST reject an identity or content operation whose
`dagCborCanonicalEncode(payload)` exceeds 65536 bytes, **measured with any
embedded `authorization` credential excluded**. Credentials are not subject to
this cap; they carry their own 262144-byte (256 KiB) ceiling, because a
maximum-depth delegation chain embeds each parent token in `prf` and exceeds
64 KiB. Total operation bytes are bounded by the sum (≤ 64 KiB + 256 KiB). The operation CID still commits to the complete payload
including `authorization`.

The `keyProofs` member of an identity `update` gets no such exclusion: its
envelopes are ordinary payload members, inside the bytes the CID commits to and
inside the 64 KiB measurement. Each envelope is separately bounded by the 4096-byte
[key-proof envelope cap](#the-envelope).

Artifacts keep their own 16384-byte cap; the `services` array keeps its
32768-byte cap.

**Cardinality caps (structure, not byte length):**

| Field                                        | Max       | Note                                            |
| -------------------------------------------- | --------- | ----------------------------------------------- |
| `authKeys` / `assertKeys` / `controllerKeys` | 256 items | Generous ceiling; op-size cap is the real bound |
| `keyProofs` entries                          | 256 items | Bounds signature checks per operation           |
| `services` entries                           | 256 items | (see Services)                                  |
| countersignature `relation`                  | 64 chars  | Open-namespace tag (min 1 when present)         |

The protocol does not limit individual field string lengths, document content
size (the protocol commits to a CID, not the document, so large binary media is
referenced rather than inlined), chain length, or number of chains per identity.
These are application and transport concerns.

---

## Time basis

Every verification has a **basis time**, and every temporal check in this corpus
resolves against it.

- For a **committed artifact**, an operation in a chain and anything carried
  inline in it, the basis is the operation's own `createdAt`.
- For an **ephemeral presentation**, a request proof, a sign-in challenge, or a
  read-time credential check, the basis is now.

At the basis:

- the signing key MUST be effective in the identity's state as of the basis;
- an `exp` MUST be strictly greater than the basis;
- no revocation effective as of the basis may cover the artifact.

An identity's **state as of a basis time** is the state produced by the last
operation in the chain whose `createdAt` is less than or equal to the basis, with
key memberships read from the effective (proved) state. For an ephemeral
presentation the basis is now, so this is the chain head.

Credentials have no validity window of their own beyond `exp`; `iat` is
informational and is not a rejection gate.

Rotation therefore revokes going forward and leaves history valid: an operation
committed while a key was effective still verifies after that key is rotated out,
and the same key cannot sign a new ephemeral proof once it is gone.

A **credit claim** runs no temporal check at all, so it has no basis time. The
claimant's key is resolved against every key that claimant's identity chain has
ever held. A claim binds a chain rather than a moment, so it survives the
claimant's later rotations and the hosting document's later revisions
([CONTENT-MODEL, Credits](https://protocol.dfos.com/content-model#credits)).

The ingest basis is derived from `createdAt` by converting to integer Unix
seconds:

```
now_s = floor(createdAt_epoch_ms / 1000)
```

The conversion MUST truncate (floor) the millisecond remainder and MUST NOT
round. A credential's `exp` is integer Unix seconds (JWT `NumericDate`), and the
`exp` boundary is exclusive: a credential MUST be rejected as expired when
`exp <= now_s`, including the exact instant `exp == now_s`.

Two relays processing the same committed operation reach the same temporal
verdict regardless of when each one ingests it. A relay MUST NOT add an
ingest-time wall-clock `exp` check.

---

## Key possession

Every key an identity chain lists is backed by a demonstration that its holder
holds it and consented to listing it. The rule is bimodal, with no third case:

1. **The genesis key proves possession by signing genesis.** One key, declared
   across all three role arrays, signing the very operation that declares it. The
   signature is the proof, for all three roles at once.
2. **Every other key proves possession by an embedded key proof.** A key's
   introduction to a role is accompanied by an envelope the key itself signed,
   binding `{chain DID, role set, chain position}`.

**Introduction.** An operation **introduces** key K to role R when K appears in
the operation's R array and K was not in the immediately prior _effective_ R
state. For each key it introduces, an `update` operation carries exactly one
envelope in its `keyProofs` member whose `publicKeyMultibase` is K, whose `did`
is the chain's DID, whose `prevCID` equals the operation's own
`previousOperationCID`, and whose `roleSet` includes every role the operation
introduces K to, verified per [Chain-walk verification](#chain-walk-verification).
An operation that merely replays a key already effective in a role carries no
proof for it: proofs live at introduction, and verification walks back to the
introducing operation. A proof is spent at the position it names, so re-adding a
removed key is a new introduction demanding a fresh envelope, and promotion into
a role the key's envelope never covered is likewise a new introduction. There is
no standing consent and no proof revocation; removal is an ordinary `update`.

**Declared versus effective state.** An identity chain yields two readings of its
key arrays. The **declared** state is structural: the arrays as the operations
wrote them. The **effective** state is the declared state minus every unproved
membership. A key-role membership whose introduction carries no valid covering
envelope is **void**: excluded from the effective state for that role, never
resolved for signature verification by consumers, never indexed, never surfaced
in recovery. Void is not invalid, the operation and the chain stand, and tooling
MUST surface void memberships rather than silently dropping them.

**The three doors.** Possession is enforced at three surfaces:

- **Writers hard-reject.** Software authoring an identity operation MUST refuse
  to produce an unproved introduction. The void path exists for reading hostile
  or defective chains, not as something conformant tooling emits.
- **Relays sequence regardless.** A relay MUST admit and sequence every
  structurally valid identity operation (linearity, CIDs, timestamps,
  declared-state signer validity) whatever its proof status. Log membership never
  depends on semantic key validation. The relay's log answers _what was written_;
  proofs answer _what counts_.
- **Verifiers compute void.** Every consumer of identity key state (signature
  resolution for content and API surfaces, key indexes, recovery oracles) reads
  the effective state.

A chain whose effective controller set becomes empty is extendable in declared
form but dead in effect: no key it lists can authenticate, assert, or authorize
as the identity. Conformant writers cannot produce this state.

### The envelope

A key proof is a compact JWS signed by the candidate key itself. Its payload is a
JSON object of exactly seven members. The member set is **closed**: no free-form
member, no content-bearing extension. A key proof proves a key and conveys no
intent, content, or authority.

| Member               | Description                                                                                                                                                                                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `nonce`              | The verifier-minted, single-use challenge string, taken verbatim from the ceremony that issued it. Opaque to the holder. A verifier SHOULD mint at least 128 bits of entropy.                                                                                                                                      |
| `audience`           | The completing authority. In a hosted ceremony: the presentation endpoint's **lowercase authority**, bare hostname on the default HTTPS port and `host:port` on any other, never a scheme and never a path. In the controller-verified leg: the target chain's DID, byte-equal to this payload's own `did` member. |
| `did`                | The identity chain this key is being introduced to.                                                                                                                                                                                                                                                                |
| `roleSet`            | The [canonical role-set string](#the-roleset-grammar) naming the roles the key gains.                                                                                                                                                                                                                              |
| `prevCID`            | The chain head the introduction builds on: the CID the introducing operation carries as its `previousOperationCID`.                                                                                                                                                                                                |
| `publicKeyMultibase` | The candidate key: the Multikey multibase string of the key this proof is about, which is also the key that signs it.                                                                                                                                                                                              |
| `timestamp`          | Creation time in the [timestamp grammar](#timestamp-grammar), floor-normalized to whole seconds (`.000Z` millisecond component).                                                                                                                                                                                   |

**Canonical signing input.** The payload is serialized as minimal UTF-8 JSON (no
insignificant whitespace) with members in exactly the order above: `nonce`,
`audience`, `did`, `roleSet`, `prevCID`, `publicKeyMultibase`, `timestamp`. These
bytes are the JWS payload segment. The rule binds both halves: a signer emits
these bytes, and a verifier recomputes them from the members it parsed and
refuses a payload segment that decodes to anything else.

**Envelope size.** An envelope over **4096 bytes** is rejected before parsing.

**The JWS header.**

- `typ` is exactly `did:dfos:key-add`, the one registered key-proof purpose.
- `alg` is the signature algorithm of the candidate key's Multikey type
  (`ed25519-pub`, signed as `EdDSA`).
- `kid` is **absent.** The candidate key is in no chain, so there is no DID URL to
  name; the verification key rides in the signed payload. A present `kid`
  rejects. `crit` and embedded key members reject per the
  [Signature verification profile](#signature-verification-profile).

**Self-proving.** The signature verifies against the payload's own
`publicKeyMultibase`. A valid envelope is possession demonstrated over challenge
bytes.

#### The roleSet grammar

`roleSet` names the subset of the chain's three key roles the introduction
covers, as one canonical string: members drawn from exactly `auth`, `assert`,
`controller`; serialized as the subset in the fixed order
`auth,assert,controller`; comma-joined; no whitespace; no duplicates; never
empty. `auth,assert` and `controller` are canonical spellings; `assert,auth`,
`auth, assert`, and `auth,auth` are schema violations.

#### Position binding

The `did`, `roleSet`, and `prevCID` members bind the proof to one introduction at
one position:

- `did` binds the proof to one chain. An envelope signed for one identity does
  not verify for any other.
- `roleSet` binds the proof to the roles gained. A key's membership in a role is
  proved only by an envelope whose `roleSet` includes that role.
- `prevCID` binds the proof to one chain position. A removed key cannot be
  re-added on the strength of an old envelope: the re-adding operation has a
  different `previousOperationCID`, so the old proof does not cover it.

#### The two legs

An introduction is verified by whoever appends it, and `audience` names that
party in the value domain the flow has. On the **hosted ceremony leg** a ceremony
operator custodying the chain mints the nonce and `audience` is that host's
authority, which the verifier byte-compares against its own configured authority,
never against anything request-derived. On the **controller-verified leg** the
chain's own controller mints the nonce and delivers `{did, roleSet, prevCID,
nonce}` to wherever the candidate key lives, and `audience` MUST byte-equal the
payload's `did`. A host authority is never a DID, so the two value domains never
overlap and an envelope signed for one leg cannot verify in the other.

Everything between minting a nonce and adopting the returned envelope is an
integration convention rather than a chain rule, and it is specified in
[INTEGRATIONS, Key ceremonies](https://protocol.dfos.com/integrations#key-ceremonies):
the short-code and URI carriage, the `/.well-known/dfos-key-proof` resolution
endpoint and its JSON, the holder's obligations, and the presentation check a
verifier runs before embedding the bytes. A chain walker re-runs none of it; what
a walker checks is below.

### Chain-walk verification

A verifier walking an identity chain checks, for each embedded envelope:

1. **Header gates.** `typ` MUST be `did:dfos:key-add`; `alg` MUST be the
   algorithm of the payload key's Multikey type; `crit`, embedded key members,
   and a present `kid` reject.
2. **Payload schema, over canonical bytes.** Exactly the closed seven-member
   schema, each member a string, `roleSet` in the canonical grammar; the walker
   recomputes the canonical signing input from the parsed members and
   byte-compares it against the payload octets, and a mismatch rejects.
3. **Key.** `publicKeyMultibase` MUST equal the introduced key's multikey.
4. **Chain.** `did` MUST equal the chain's own DID.
5. **Position.** `prevCID` MUST equal the carrying operation's
   `previousOperationCID`.
6. **Coverage.** `roleSet` MUST include every role the operation introduces the
   key to.
7. **Signature.** The JWS MUST verify against the payload's `publicKeyMultibase`.

`nonce`, `audience`, and `timestamp` are presentation-time transport, byte-fixed
under the signature and inert at walk time: a walker re-checks neither freshness
nor audience nor nonce state.

A failed walk-time check makes the introduction **void**, excluded from the
chain's effective key state. It never invalidates the operation or the chain.

---

## Operation schemas

### Identity operations

```typescript
// Genesis — starts the identity chain
{ version: 1, type: "create",
  authKeys: MultikeyPublicKey[],         // exactly one entry —
  assertKeys: MultikeyPublicKey[],       //   the same single key in all three
  controllerKeys: MultikeyPublicKey[],   //   arrays, which also signs (see Key Possession)
  services?: ServiceEntry[],              // discovery vocabulary (optional)
  createdAt: string }                     // timestamp grammar — ms precision, UTC

// Key rotation / modification
{ version: 1, type: "update",
  previousOperationCID: string,                    // CID of previous operation
  authKeys: MultikeyPublicKey[],
  assertKeys: MultikeyPublicKey[],
  controllerKeys: MultikeyPublicKey[],   // must have at least one
  keyProofs?: string[],                  // one key-proof envelope per key this
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
verified identity state (see [Services](#services)). Omitting it encodes
identically to a service-less operation (CID-neutral); an `update` carrying it
REPLACES the entire prior set; a `delete` carries the last set unchanged.

The optional `keyProofs` array carries the key-proof envelopes for the keys an
`update` [introduces](#key-possession): compact JWS strings, embedded verbatim as
presented, one per introduced key. It is defined on `update` only; a `create`,
`delete`, or `restore` carrying it is invalid. An operation that introduces no
key carries none. Omitting it encodes identically to an empty introduction
(CID-neutral), the same rule as `services`.

**`restore` validity (normative).** `restore` is the one operation that may
follow a `delete`, and the successor-of-delete position is the only position in
which it is valid:

- Its `previousOperationCID` MUST reference a `delete` operation. A `restore`
  anywhere else in the chain is invalid.
- It MUST be signed by a **controller key of the deleted head state**, the key
  state produced by the `delete` it restores. A key rotated out before the delete
  is not in that state and grants nothing.
- Its effect is exactly to clear the deleted state: the identity returns to
  active with the keys and services as of the delete, **verbatim**. `restore`
  carries no key sets or services of its own; state changes happen via subsequent
  ordinary `update` operations.
- Its `createdAt` follows the ordinary rule: strictly greater than its parent's.
  There is no rate limit and no once-only rule; every transition requires a
  current controller key, which is total authority over the identity anyway.

A protocol-level irreversible deletion that no controller key can reopen is not
part of this specification.

### Content operations

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

`baseDocumentCID` is committed-but-uninterpreted provenance, validated as
CID-or-null with no verification meaning. It lets the public proof plane express
content-version lineage without exposing the private document.

### MultikeyPublicKey

```typescript
{ id: string,                             // e.g. "key_r9ev34fvc23z999veaaft83nn29zvhe"
  type: "Multikey",                       // literal discriminator
  publicKeyMultibase: string }            // e.g. "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
```

---

## JWS envelope format

### Signing

```
signingInput = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload))
signature = ed25519.sign(UTF8_bytes(signingInput), privateKey)
token = signingInput + "." + base64url(signature)
```

### kid rules

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

### `cid` header

Every operation JWS (identity-op and content-op) includes a `cid` field in the
protected header: the CIDv1 string of the operation payload, derived from
`dagCborCanonicalEncode(payload) → SHA-256 → CIDv1 → base32lower`. The `cid` is
computed before signing and embedded in the protected header, so the EdDSA
signature covers it.

**Signing order:**

1. Construct the operation payload
2. Derive the operation CID: `dagCborCanonicalEncode(payload) → CIDv1`
3. Build the protected header including `cid`
4. Sign: `ed25519.sign(UTF8(base64url(header) + "." + base64url(payload)), privateKey)`

**Verification rule.** After verifying the JWS signature and deriving the
operation CID from the parsed payload, implementations MUST reject operations
where `header.cid` is missing, or `header.cid` does not match the derived CID.

Which envelope families carry `cid` is inventoried per family in the
[extension registry](#extension-registry).

### `typ` header

The JWS `typ` header uses protocol-specific values, not IANA media types. Every
`typ` value is registered in the [extension registry](#extension-registry), which
names each value, the spec that owns it, and whether its envelope carries the
`cid` header. A new envelope family adds a row there, never a local name.
Registration is for `typ` routing and says nothing about ingestion; several
registered families are document-plane artifacts no relay ingests.

Where a family's verification requires an exact `typ`, that check is normative
and is stated with that family's rules: key proofs, credentials and revocations,
SIWD challenge and ask proofs, API-AUTH request and identity proofs, and
sign-requests all gate on it, and it is what keeps a JWS signed for one purpose
from being presented as another. Elsewhere `typ` is routing: implementations
SHOULD validate it and MUST NOT treat it as a substitute for the checks a
family's own rules require.

---

## Signature verification profile

DFOS pins one narrow profile of the JOSE/JWS surface so that all conformant
verifiers accept and reject the same signatures byte-for-byte. The rules below
are normative and apply to **every** verification path: identity-op JWS,
content-op JWS, key proofs, artifacts, countersignatures, DFOS credentials,
credential revocations, and every API-AUTH and SIWD proof. A verifier MUST apply
§1 to §3 to the protected header **before** performing any signature
computation, and MUST apply §4 as part of or before the signature check. A token
that violates any rule MUST be rejected regardless of whether its signature would
otherwise verify.

There is no algorithm agility: the verifier never branches on `alg` to select a
primitive. Ed25519 (`EdDSA`) is the only signature algorithm.

### 1. Algorithm pinning (`alg`)

The protected header `alg` member MUST equal the exact string `"EdDSA"`. Any
other value MUST be rejected before any signature check, including `"none"`,
`"HS256"`, `"RS256"`, `"ES256"`, the lowercase `"eddsa"`, or an absent `alg`.
Verifiers MUST NOT use `alg` to choose a verification primitive; it is checked
only for exact equality.

### 2. `crit` rejection

The protected header MUST NOT contain a `crit` member. DFOS emits no critical
header parameters, so any token whose protected header carries `crit`, with any
value, MUST be rejected. Verifiers MUST observe the member's presence directly:
decoding into a fixed header shape that silently discards unknown members is not
sufficient.

### 3. No header key trust

The verifier MUST NOT read key material from the protected header, and MUST NOT
follow a reference that fetches it. A protected header carrying any of `jwk`,
`jku`, `x5c`, or `x5u` MUST be rejected. A URL that fetches a key is header key
trust with an extra hop.

The signing key is resolved exclusively from `kid` against the signer's identity
chain, in that identity's effective state as of the verification's
[basis time](#time-basis). A key proof is the one family that carries no `kid`:
its key rides in the signed payload, per [The envelope](#the-envelope). A
header-supplied key is never trusted, even if it happens to match the resolved
key.

### 4. Canonical signature scalar (`S < L`)

An Ed25519 signature is `R || S` (64 bytes). The scalar `S`, the trailing 32
bytes little-endian, MUST be canonical: strictly less than the group order

```
L = 2^252 + 27742317777372353535851937790883648493
  = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
```

A signature whose `S >= L` MUST be rejected. A signature that does not decode to
exactly 64 bytes MUST also be rejected. An implementation on an Ed25519 library
that accepts a non-canonical `S` MUST add an explicit constant-time `S < L`
gate.

### Axes outside this profile

Verifiers inherit whatever their Ed25519 library does on these axes: cofactorless
verification equation pinning (the specific `[S]B == R + [k]A` equation rather
than the batch or cofactored form), the full-order public key check
(`[L]A == identity`), canonical point encoding (`y < p`) for `R` and `A`,
small-order public key rejection, and strict base64url tightening.

---

## Credentials

Credentials authorize actions on resources (read, write) via attenuations, for
relay access and content chain delegation. The credential format, verification
rules, and revocation payloads are specified in
[CREDENTIALS.md](https://protocol.dfos.com/credentials).

### Content chain authorization

When `enforceAuthorization` is enabled on content chain verification:

1. **Genesis operation.** The signer is the chain creator, always authorized.
2. **Creator signs subsequent ops.** Authorized directly, no credential needed.
3. **A different DID signs.** The operation MUST include an `authorization` field
   containing a valid DFOS credential where:
   - The delegation chain roots at the chain creator DID
   - The credential's `att` includes an entry with `action: "write"` covering this
     chain's resource
   - The credential is valid at the operation's [basis time](#time-basis): the
     issuer's signing key effective as of the basis, `exp` strictly greater than
     the basis, and no revocation effective as of the basis covering it or any
     parent in its delegation chain

The `authorization` field is available on `update` and `delete` content
operations. It is absent for creator-signed operations.

### Revocation

Credentials are revoked by publishing a **revocation artifact**, a signed
proof-plane primitive with `typ: did:dfos:revocation`. Only the credential's
issuer DID can revoke it, and there is no un-revoke operation. Revocation is
checked at **every level** of a presented credential, the leaf and each parent in
its delegation chain, on both the read path and the write path.

Revocation is forward-looking against the basis: it prevents future use of a
credential and does not retroactively invalidate operations already committed to
a content chain.

---

## Services

`services` is an identity's **discovery vocabulary**: a controller-signed,
full-state array carried in identity-chain `create` and `update` operations and
projected into verified identity state. It answers "given a DID, where do I reach
this identity, and what stable content does it publish?" Services live inside
identity operations, inherit the chain's signer rules, and inherit the chain's
linearity, so one log resolves to exactly one services set.

### Service entry

```typescript
{ id: string,        // did-core fragment, unique within the set (deref did:dfos:xxx#<id>)
  type: string,      // open namespace — recognized types are structurally validated
  ...                // type-specific fields (see below)
}
```

Every entry carries the common envelope `{ id, type }`. The namespace is **open**:
two types are recognized and structurally validated, and any other `type` is an
opaque extension that verifiers MUST preserve verbatim and otherwise ignore. New
service types therefore never require a protocol or cross-language change. Every
registered type is indexed in the [extension registry](#extension-registry).

**Recognized types:**

```typescript
// Transport locator — where to reach a relay serving this identity
{ id: string, type: "DfosRelay", endpoint: string }   // endpoint: bare URL string

// Stable content reference under a client-defined semantic label
{ id: string, type: "ContentAnchor", label: string, anchor: string }
```

A `ContentAnchor`'s `anchor` references a stable content identifier, dispatched
by structural form:

| Anchor shape                  | Resolves to                       |
| ----------------------------- | --------------------------------- |
| `^[2346789acdefhknrtvz]{31}$` | content chain (mutable, gateable) |
| `^bafyrei[a-z2-7]{52}$`       | artifact (immutable, public)      |

These two shapes are the ONLY valid anchors and the structural dispatch above is
normative. An anchor matching neither shape MUST be rejected (`AnchorInvalid`);
verifiers do not accept other CID codecs or lengths. New anchor kinds arrive via
a new service `type`, never a new anchor shape.

The `label` is an opaque client-semantic key (for example `"profile"`,
`"avatar"`). The protocol assigns it no meaning.

### Bounds

- ≤ 256 entries per identity; entry `id`s MUST be unique within the set
- `id`, `type`, and the recognized string fields (`endpoint`, `label`) MUST be
  non-empty, and `anchor` MUST match the contentId or CID shape. Individual field
  lengths are not separately capped
- The CBOR-encoded `services` array MUST NOT exceed **32768 bytes**
- An entry whose **recognized** type is structurally malformed (for example a
  `DfosRelay` without an `endpoint`) MUST be rejected at verification. A malformed
  **unrecognized** type is preserved and ignored

### Full-state semantics

`services` is full-state, not a delta. A `create` sets the initial set; an
`update` REPLACES the entire set (omit the field to clear it); a `delete` carries
the last set unchanged into terminal state. Omitting `services` encodes
identically to a service-less operation (CID-neutral).

### Worked example

`examples/identity-services.json` is a genesis publishing a relay locator and two
content anchors, one content-chain and one artifact. Signed by reference key 1:

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

## Standalone signed statements

An artifact and a countersignature are each one signed statement with no
predecessor and no successor: a JWS envelope over a dag-cbor payload, addressed
by the payload's CID, verified against the signing identity's state as of the
statement's own `createdAt` ([Time basis](#time-basis)). Neither is a chain
operation: nothing links to one by `previousOperationCID`, and neither changes
chain state.

### Payload shape

| Field       | Artifact                                     | Countersignature                                         |
| ----------- | -------------------------------------------- | -------------------------------------------------------- |
| `version`   | `1`                                          | `1`                                                      |
| `type`      | `"artifact"`                                 | `"countersign"`                                          |
| `did`       | The signing identity                         | The witness identity                                     |
| body        | `content`: an object with a `$schema` string | `targetCID`: the CID witnessed; `relation`: optional tag |
| `createdAt` | [Timestamp grammar](#timestamp-grammar)      | Same                                                     |

The JWS `typ` is `did:dfos:artifact` or `did:dfos:countersign`, and the
envelope carries the [`cid` header](#cid-header).

**Artifact.** `content` is an inline document. Its `$schema` is a free-form
discriminator with no protocol-level registry; consumers dispatch on it. The
CBOR-encoded payload MUST NOT exceed 16384 bytes. An artifact is immutable and
is addressed by its CID.

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

**Countersignature.** `targetCID` names any CID-addressed statement: a content
or identity operation, an artifact, or another countersignature. `relation` is
an optional open-namespace tag of 1 to 64 characters. Recognized values
(`endorses`, `coauthors`, `witnessed`, `holds`, `received`) inform clients;
unrecognized values MUST be preserved and ignored. When present, `relation` is
part of the canonical payload and so of the CID; absent, the payload encodes
identically to one that never carried it. A countersignature is permanent.
There is no withdrawal; a consumer may weight a newer statement by the same
witness over an older one. Witnessing publicly and permanently links the
witness DID to the target.

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

### Verification

1. Decode the JWS. `typ` MUST be the value registered for the payload `type`.
2. Validate the payload: `version`, `type`, `did`, `createdAt`, and the body
   for that type (`content` carrying a `$schema` string, or `targetCID` with a
   well-formed `relation` when present).
3. The `kid` DID MUST equal the payload `did`.
4. Verify the EdDSA signature against the key `kid` names, effective in the
   signer's state as of `createdAt`.
5. `header.cid` MUST equal the CID of the dag-cbor canonical encoding of the
   payload.
6. Artifact only: the CBOR-encoded payload MUST NOT exceed 16384 bytes.

A relay's checks on a countersignature (the target exists, the witness is not
the target's author, one countersignature per witness per target) are ingest
rules, specified in
[RELAY](https://protocol.dfos.com/relay#artifacts-and-countersignatures-on-the-wire).

---

## Verification

Every signature check below is performed under the
[Signature verification profile](#signature-verification-profile).

### Identity chain

1. Decode each JWS, parse payload as IdentityOperation
2. First op MUST be `type: "create"`, the genesis bootstrap:
   - Verify the [single-key rule](#key-possession): each of the three role arrays holds exactly one entry, all three the same key with the same id. A genesis declaring more than one distinct key MUST be rejected. A genesis carrying `keyProofs` MUST be rejected.
   - The one key declared in the genesis payload is trusted because the identity does not exist before this operation.
   - The signing key (resolved from `kid`) MUST be that declared key.
   - Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID. Derive the DID from the CID.
3. For each subsequent op: verify `previousOperationCID` matches the previous op's derived CID, so the chain as verified is one linear sequence. Verify `createdAt` is strictly greater than the parent operation's `createdAt` (MUST).
4. If the state before this operation is deleted, the only valid operation is a `restore` whose `previousOperationCID` is the delete's CID; any other operation MUST be rejected. A `restore` whose parent is not a `delete` MUST be rejected wherever it appears. A `delete` or `restore` carrying `keyProofs`, and any `keyProofs` member that is not an array of strings, MUST be rejected.
5. Resolve `kid`: genesis uses a bare key ID, non-genesis uses a DID URL (extract the DID, verify it matches the derived DID; extract the key ID).
6. Find the controller key matching that key ID **in the current declared state**, the declared state after all preceding operations. For a `restore` this is the deleted head state produced by the `delete`, which carries the last key sets unchanged. Decode multikey to a raw Ed25519 public key.
7. Verify the EdDSA JWS signature over the signing input bytes.
8. For an `update`, compute possession per [Key possession](#key-possession): for each key-role membership the operation introduces, find an envelope in `keyProofs` passing [chain-walk verification](#chain-walk-verification) for this operation, this key, and that role. A covered introduction is effective; an uncovered one is **void**, recorded and surfaced, excluded from effective state, and not a rejection.
9. Apply the state change: `create` initializes declared and effective key state to its one key in all three roles; `update` replaces declared state (which must have at least one declared controller key) and folds effective state per step 8; `delete` marks the state deleted (key sets and services carried unchanged); `restore` clears the deleted state (keys and services as of the delete, verbatim, effective state included).

The verification result carries both readings: the declared state, the effective
state, and the list of void memberships (key, role, operation CID). Consumers act
on the effective state; the declared state exists for structural admission and
for showing a human what a chain claims versus what it proved.

### Content chain

1. Decode each JWS, parse payload as ContentOperation
2. First op must be `type: "create"`; the signer is the chain creator
3. For each subsequent op: verify `previousOperationCID` matches, verify `createdAt` is strictly greater than the parent operation's `createdAt` (MUST)
4. Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID.
5. Verify the `kid` DID matches the payload `did` field
6. Resolve `kid` via the external key resolver the caller provides
7. Verify the EdDSA JWS signature
8. If `enforceAuthorization` is enabled and the signer DID differs from the chain creator: verify the `authorization` field contains a valid DFOS credential with `action: "write"` covering this chain, with a delegation chain rooting at the creator DID, valid at the operation's [basis time](#time-basis)
9. Apply the state change (set document, clear, or delete)

---

## Extension registry

Every name the corpus registers under the core's open namespaces is indexed here:
service types under [Services](#services), and JWS `typ` values under the
[`typ` header](#typ-header) convention. Each name's semantics live in its owner
spec, which is normative wherever the two could be read to disagree. A new name
lands by adding its row here in the same PR that specifies it.

### Service types

| Service `type`            | Owner spec                                                                            | Validation | Semantics                                                                                        |
| ------------------------- | ------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------ |
| `DfosRelay`               | [PROTOCOL](#services)                                                                 | core       | Transport locator: where to reach a relay serving this identity.                                 |
| `ContentAnchor`           | [PROTOCOL](#services)                                                                 | core       | Stable content reference: a contentId or artifact CID under a client-defined semantic label.     |
| `DfosAuthorizationServer` | [INTEGRATIONS](https://protocol.dfos.com/integrations#finding-the-authorize-endpoint) | consumer   | The canonical authorize origin able to produce this subject's signature under sign-in profile A. |
| `DfosOrigin`              | [INTEGRATIONS](https://protocol.dfos.com/integrations#the-dfosorigin-service-entry)   | consumer   | The identity's claimed web domain: the chain half of the bidirectional origin binding.           |

**Validation.** `core`: structurally validated by every conformant verifier, and
a malformed entry rejects at verification. `consumer`: opaque to the core
(preserved verbatim, ignored); structural validation is an obligation of the
owner spec's consumers. Ambiguity rules, field grammar, and display discipline
are the owner spec's.

### JWS `typ` values

Every DFOS JWS envelope is typ-scoped. The `cid` column marks whether the
envelope carries the protocol's [`cid` header](#cid-header).

| `typ` value               | Owner spec                                                                | `cid` | Semantics                                                                                                                                                                                        |
| ------------------------- | ------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `did:dfos:identity-op`    | [PROTOCOL](#typ-header)                                                   | yes   | Identity chain operations.                                                                                                                                                                       |
| `did:dfos:content-op`     | [PROTOCOL](#typ-header)                                                   | yes   | Content chain operations.                                                                                                                                                                        |
| `did:dfos:artifact`       | [PROTOCOL](#standalone-signed-statements)                                 | yes   | Standalone signed statements: inline documents.                                                                                                                                                  |
| `did:dfos:countersign`    | [PROTOCOL](#standalone-signed-statements)                                 | yes   | Standalone signed statements: witness attestations.                                                                                                                                              |
| `did:dfos:key-add`        | [PROTOCOL](#key-possession)                                               | no    | Key introduction proofs: the candidate key's position-bound possession-and-consent proof, self-signed, presented to ceremonies and embedded in the introducing identity operation's `keyProofs`. |
| `did:dfos:credential`     | [CREDENTIALS](https://protocol.dfos.com/credentials)                      | yes   | Authorization credentials; the `cid` is their revocation address.                                                                                                                                |
| `did:dfos:revocation`     | [CREDENTIALS](https://protocol.dfos.com/credentials)                      | yes   | Credential revocation artifacts.                                                                                                                                                                 |
| `did:dfos:credit-claim`   | [CONTENT-MODEL](https://protocol.dfos.com/content-model)                  | yes   | Document-plane credit claims: registered for `typ` routing, never relay-ingested.                                                                                                                |
| `did:dfos:sign-request`   | [RELAY](https://protocol.dfos.com/relay#the-sign-request-envelope)        | yes   | Sign-request envelopes: travel the signing-mailbox courier, never `POST /proof/v1/operations`.                                                                                                   |
| `did:dfos:siwd`           | [INTEGRATIONS](https://protocol.dfos.com/integrations#sign-in)            | no    | Sign In With DFOS challenge proofs: delivered by web redirect or the signing mailbox, never relay-ingested.                                                                                      |
| `did:dfos:siwd-ask`       | [INTEGRATIONS](https://protocol.dfos.com/integrations#the-ask-proof)      | no    | Loopback client ask proofs: the client's key-control proof over its own authorize request.                                                                                                       |
| `did:dfos:request-proof`  | [INTEGRATIONS](https://protocol.dfos.com/integrations#the-request-proof)  | no    | API request proofs: ride the `Authorization` header of a credential-gated API request and die with the freshness window.                                                                         |
| `did:dfos:identity-proof` | [INTEGRATIONS](https://protocol.dfos.com/integrations#the-identity-proof) | no    | API identity proofs: bind one exact request to a bare DID, authentication only.                                                                                                                  |

Names whose grammar is inseparable from their owner's machinery register there:
credential resource forms in
[CREDENTIALS](https://protocol.dfos.com/credentials); API action tokens, sign-in
scope tokens, and app description members in
[INTEGRATIONS](https://protocol.dfos.com/integrations); sign-request
`payloadTyp` families in [RELAY](https://protocol.dfos.com/relay); and content
schemas in [CONTENT-MODEL](https://protocol.dfos.com/content-model), hosted at
[schemas.dfos.com](https://schemas.dfos.com).

### External registrations

The corpus also mints names in two global namespaces DFOS does not own, and
[RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615#section-3) and
[RFC 8552 §4.1.5](https://www.rfc-editor.org/rfc/rfc8552#section-4.1.5) require
each to be entered in its IANA registry. A spec that mints a well-known path or
an underscored name adds its row here in the same PR that specifies it;
registration itself is an act of the project's stewards.

| Name                          | Registry                                                                             | Owner spec                                                                          | Registered |
| ----------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- | ---------- |
| `/.well-known/dfos-relay`     | IANA Well-Known URIs ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615))            | [RELAY](https://protocol.dfos.com/relay#the-well-known-document)                    | not listed |
| `/.well-known/dfos-app.json`  | IANA Well-Known URIs ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615))            | [INTEGRATIONS](https://protocol.dfos.com/integrations#the-app-description-document) | not listed |
| `/.well-known/dfos-did`       | IANA Well-Known URIs ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615))            | [INTEGRATIONS](https://protocol.dfos.com/integrations#https-well-knowndfos-did)     | not listed |
| `/.well-known/dfos-key-proof` | IANA Well-Known URIs ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615))            | [INTEGRATIONS](https://protocol.dfos.com/integrations#key-ceremonies)               | not listed |
| `_dfos` (TXT)                 | IANA Underscored DNS Node Names ([RFC 8552](https://www.rfc-editor.org/rfc/rfc8552)) | [INTEGRATIONS](https://protocol.dfos.com/integrations#dns-txt-at-_dfosdomain)       | not listed |

---

## Reference vectors

The vectors in this section are published as
[`packages/protocol-verify/vectors.json`](https://github.com/metalabel/dfos/blob/main/packages/protocol-verify/vectors.json),
the artifact every verification suite loads. The prose here renders that
artifact byte for byte; the TypeScript reference suite regenerates it from the
fixed seeds and fails if the two diverge.

All artifacts below are deterministic and reproducible from fixed seeds. An independent implementer can verify every value using standard Ed25519 + dag-cbor libraries. Private keys are derived from `SHA-256(UTF8("dfos-protocol-reference-key-N"))`.

The same values are re-derived from scratch, in five languages using only native cryptography libraries, by the suites in [`packages/protocol-verify/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify). Each suite hardcodes these constants and imports no DFOS library, so a disagreement between any two suites is an ambiguity in this document.

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

### Identity chain: Create (Genesis)

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

### Reference key proof (key 2's introduction)

The rotation below introduces key 2 to all three roles, so it carries key 2's [key-proof envelope](#the-envelope) in `keyProofs` ([Key possession](#key-possession)). The envelope is signed by **key 2**, the key being introduced, while the operation carrying it is signed by **key 1**. Its deterministic inputs: `nonce` is the literal `dfos-protocol-reference-nonce-1`, `audience` is `keys.dfos.com`, `timestamp` is `2026-03-07T00:00:30.000Z`. The rest is derived: `did` is the reference DID, `roleSet` is `auth,assert,controller`, `prevCID` is the genesis CID, `publicKeyMultibase` is key 2's multikey.

Decoded payload:

```json
{
  "nonce": "dfos-protocol-reference-nonce-1",
  "audience": "keys.dfos.com",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "roleSet": "auth,assert,controller",
  "prevCID": "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne",
  "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK",
  "timestamp": "2026-03-07T00:00:30.000Z"
}
```

Canonical signing input (the exact payload octets):

```
{"nonce":"dfos-protocol-reference-nonce-1","audience":"keys.dfos.com","did":"did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr","roleSet":"auth,assert,controller","prevCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","publicKeyMultibase":"z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK","timestamp":"2026-03-07T00:00:30.000Z"}
```

JWS protected header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:key-add"
}
```

JWS Signature (hex):

```
f27835d076dbb360450ac6284983474b54f4d36d3e1d79b8683d7442b1e5a72b0ed6caa6cb553f763f72133d0225230260dc214d931b4e26a7849f021f52ed03
```

Compact JWS token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6ImRmb3MtcHJvdG9jb2wtcmVmZXJlbmNlLW5vbmNlLTEiLCJhdWRpZW5jZSI6ImtleXMuZGZvcy5jb20iLCJkaWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwicm9sZVNldCI6ImF1dGgsYXNzZXJ0LGNvbnRyb2xsZXIiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rZlVkNjVKckFoZmRnRnVNQ2NjVTlUaFF2akIyZkpBTVVIa3V1YWpGOTkyZ0siLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjMwLjAwMFoifQ.8ng10Hbbs2BFCsYoSYNHS1T0020-HXm4aD10QrHlpysO1sqmy1U_dj9yEz0CJSMCYNwhTZMbTianhJ8CH1LtAw
```

### Identity chain: Update (Key Rotation)

JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyreiarc7mv6fvhaoe2mmk4ujpskgqpesv66pzd5juqlg5bzmridikkqy"
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
  "createdAt": "2026-03-07T00:01:00.000Z",
  "keyProofs": [
    "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6ImRmb3MtcHJvdG9jb2wtcmVmZXJlbmNlLW5vbmNlLTEiLCJhdWRpZW5jZSI6ImtleXMuZGZvcy5jb20iLCJkaWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwicm9sZVNldCI6ImF1dGgsYXNzZXJ0LGNvbnRyb2xsZXIiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rZlVkNjVKckFoZmRnRnVNQ2NjVTlUaFF2akIyZkpBTVVIa3V1YWpGOTkyZ0siLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjMwLjAwMFoifQ.8ng10Hbbs2BFCsYoSYNHS1T0020-HXm4aD10QrHlpysO1sqmy1U_dj9yEz0CJSMCYNwhTZMbTianhJ8CH1LtAw"
  ]
}
```

JWS Signature (hex):

```
d77a2bfd7ef30ce7b391214775604bc0f70dc88686dd794701bf661e9806f3354395dcf4c063f45fc5a25481cf2d0fb6d19b023afb21f18e816e0c5d6c8bcc04
```

JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWlhcmM3bXY2ZnZoYW9lMm1tazR1anBza2dxcGVzdjY2cHpkNWp1cWxnNWJ6bXJpZGlra3F5In0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIiwia2V5UHJvb2ZzIjpbImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJwWkRwa1ptOXpPbXRsZVMxaFpHUWlmUS5leUp1YjI1alpTSTZJbVJtYjNNdGNISnZkRzlqYjJ3dGNtVm1aWEpsYm1ObExXNXZibU5sTFRFaUxDSmhkV1JwWlc1alpTSTZJbXRsZVhNdVpHWnZjeTVqYjIwaUxDSmthV1FpT2lKa2FXUTZaR1p2Y3pwamJtNXVablE1WmpoaE1uSnVPVE00WkRadWEzb3pPSEk0TkRkMk1tdHlJaXdpY205c1pWTmxkQ0k2SW1GMWRHZ3NZWE56WlhKMExHTnZiblJ5YjJ4c1pYSWlMQ0p3Y21WMlEwbEVJam9pWW1GbWVYSmxhV052WjJoMmFucHVkbXhwZFd4dmVIaHRZbVkxTkhSd2VuRjNZV2h1Y1hCcGJHczNibU40WlhCcWFXNWxaSEJyWjJFemJtVWlMQ0p3ZFdKc2FXTkxaWGxOZFd4MGFXSmhjMlVpT2lKNk5rMXJabFZrTmpWS2NrRm9abVJuUm5WTlEyTmpWVGxVYUZGMmFrSXlaa3BCVFZWSWEzVjFZV3BHT1RreVowc2lMQ0owYVcxbGMzUmhiWEFpT2lJeU1ESTJMVEF6TFRBM1ZEQXdPakF3T2pNd0xqQXdNRm9pZlEuOG5nMTBIYmJzMkJGQ3NZb1NZTkhTMVQwMDIwLUhYbTRhRDEwUXJIbHB5c08xc3FteTFVX2RqOXlFejBDSlNNQ1lOd2hUWk1iVGlhbmhKOENIMUx0QXciXX0.13or_X7zDOezkSFHdWBLwPcNyIaG3XlHAb9mHpgG8zVDldz0wGP0X8WiVIHPLQ-20ZsCOvsh8Y6BbgxdbIvMBA
```

Operation CID:

```
bafyreiarc7mv6fvhaoe2mmk4ujpskgqpesv66pzd5juqlg5bzmridikkqy
```

Post-rotation: DID unchanged (`did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr`), controller rotated to `key_ez9a874tckr3dv933d3ckdn7z6zrct8`, key 2 proved for all three roles by the embedded envelope.

### Identity chain: Delete + Restore

Delete Operation:

```json
{
  "version": 1,
  "type": "delete",
  "previousOperationCID": "bafyreiarc7mv6fvhaoe2mmk4ujpskgqpesv66pzd5juqlg5bzmridikkqy",
  "createdAt": "2026-03-07T00:02:00.000Z"
}
```

Delete JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreiaiy5m4fiyntdryikzfwzynojwiglkqrwiefulb4dl36eqeefbpwm"
}
```

Delete JWS Signature (hex):

```
40887e1d10fe60457ce328355f72f0cfeb5724418f08baee4ecb160ba2206f98ff406d1a18f8c9eac02a144d5533c29445896616468b818655e8edbcdf560108
```

Delete JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsImNpZCI6ImJhZnlyZWlhaXk1bTRmaXludGRyeWlremZ3enlub2p3aWdsa3Fyd2llZnVsYjRkbDM2ZXFlZWZicHdtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiZGVsZXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYXJjN212NmZ2aGFvZTJtbWs0dWpwc2tncXBlc3Y2NnB6ZDVqdXFsZzViem1yaWRpa2txeSIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.QIh-HRD-YEV84yg1X3Lwz-tXJEGPCLruTssWC6Igb5j_QG0aGPjJ6sAqFE1VM8KURYlmFkaLgYZV6O2831YBCA
```

Delete Operation CID:

```
bafyreiaiy5m4fiyntdryikzfwzynojwiglkqrwiefulb4dl36eqeefbpwm
```

Restore Operation:

```json
{
  "version": 1,
  "type": "restore",
  "previousOperationCID": "bafyreiaiy5m4fiyntdryikzfwzynojwiglkqrwiefulb4dl36eqeefbpwm",
  "createdAt": "2026-03-07T00:03:00.000Z"
}
```

Restore JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreicfxp65m3js4tellb3optwn54ginqv7pp4ldifcnuvry7glunh7aq"
}
```

Restore JWS Signature (hex):

```
2622005ca66a2199c3a5952b6dde12ec5eed1280448c478829c1a0dd645e6170052628bdeb4c2964b15fcab737c8028e36c330f614f9685462be8b3892d86e04
```

Restore JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsImNpZCI6ImJhZnlyZWljZnhwNjVtM2pzNHRlbGxiM29wdHduNTRnaW5xdjdwcDRsZGlmY251dnJ5N2dsdW5oN2FxIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoicmVzdG9yZSIsInByZXZpb3VzT3BlcmF0aW9uQ0lEIjoiYmFmeXJlaWFpeTVtNGZpeW50ZHJ5aWt6Znd6eW5vandpZ2xrcXJ3aWVmdWxiNGRsMzZlcWVlZmJwd20iLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAzOjAwLjAwMFoifQ.JiIAXKZqIZnDpZUrbd4S7F7tEoBEjEeIKcGg3WReYXAFJii960wpZLFfyrc3yAKONsMw9hT5aFRivos4kthuBA
```

Restore Operation CID:

```
bafyreicfxp65m3js4tellb3optwn54ginqv7pp4ldifcnuvry7glunh7aq
```

### Content chain: Document + Create

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

### Content chain: Update

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

### Content chain verified state

```
Content ID:   8n8fnzhrrefkrde6h72kfvff43r8c63
Genesis CID:  bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i
Head CID:     bafyreied5cjgjjt2pdz52k6pgipcjg3i4xl7txbrbdedscejvqhtgltxdi
```

---

## Independent verification

The checklist is executable. The suites in
[`packages/protocol-verify/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify)
load [`vectors.json`](https://github.com/metalabel/dfos/blob/main/packages/protocol-verify/vectors.json)
and re-derive every value above in five languages: multikey decoding, JWS
verification, CID and DID derivation, the rotation's key proof, dag-cbor number
encoding, and the credential and delegated-chain examples in
[`packages/dfos-protocol/examples/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/examples).

---

## Source

The reference TypeScript implementation is
[`packages/dfos-protocol/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol),
self-contained with zero monorepo dependencies, published as
[`@metalabel/dfos-protocol`](https://www.npmjs.com/package/@metalabel/dfos-protocol).
Its Go twin is
[`packages/dfos-protocol-go/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol-go).
The five-language cross-verification suites are
[`packages/protocol-verify/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify).

### Related specifications

- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method): the W3C DID method registration for identity chains
- [Content Model](https://protocol.dfos.com/content-model): document schemas and the credit vocabulary
- [Credentials](https://protocol.dfos.com/credentials): authorization credentials and revocation
- [Relay](https://protocol.dfos.com/relay): the HTTP relay: read and write contracts, ingestion, profiles, and the content plane
- [Integrations](https://protocol.dfos.com/integrations): sign-in, API authentication, origin binding, and key ceremonies
- [Guarantees](https://protocol.dfos.com/guarantees): what holds without trusting a server, what is a chosen view, and what the operator can read

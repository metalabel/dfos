# DFOS Protocol

Verifiable identity and content chains — Ed25519 signatures, content-addressed CIDs, W3C DIDs. Cross-language verification in TypeScript, Go, Python, Rust, and Swift.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol) · [Gist](https://gist.github.com/bvalosek/ed4c96fd4b841302de544ffaee871648)

---

## Philosophy

DFOS is a dark forest operating system. Content lives in access-controlled spaces — undisclosed by default, governed by the communities that create it. The cryptographic proof layer is public: signed chains of commitments that anyone can independently verify with a public key and any standard EdDSA library. The proof is public; the content is access-controlled. The protocol commits to content hashes, not plaintext — it does not encrypt. Confidentiality of the underlying documents is enforced at the application layer by whoever serves them; a relay operator can read what it stores. This is undisclosed-by-default, not end-to-end encrypted.

Two chain types — identity and content — use the same mechanics: Ed25519 signatures, JWS compact tokens, content-addressed CIDs. The protocol operates on keys and document hashes. Application semantics — posts, profiles, feeds — are a separate concern, free to evolve without protocol changes.

Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. No platform dependency, no coordination required.

---

## Protocol Overview

The DFOS protocol has five components:

| Component             | Concern                                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Crypto core**       | Identity chains + content chains — Ed25519 signatures, JWS tokens, CID links                                     |
| **Credentials**       | Auth tokens and DFOS credentials for authorization — see [CREDENTIALS.md](https://protocol.dfos.com/credentials) |
| **Services**          | Identity discovery vocabulary — controller-signed relay locators and stable content anchors                      |
| **Artifacts**         | Standalone signed inline documents — immutable, CID-addressable structured data                                  |
| **Countersignatures** | Standalone witness attestation — signed references to any CID-addressable op                                     |

> **Note:** The credential format (auth tokens, read/write credentials, revocation) is specified in [CREDENTIALS.md](https://protocol.dfos.com/credentials). This document covers the crypto core, chain primitives, services, artifacts, and countersignatures.

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

A valid chain is a **directed acyclic graph (DAG)** of operations rooted at a genesis. Each operation (after genesis) links to a predecessor via `previousOperationCID`. The chain provides structural ordering independent of timestamps.

**Forks are valid.** Two operations referencing the same `previousOperationCID` constitute a fork — both branches are accepted. The chain log stores all branches. A **deterministic head selection** rule ensures convergence across implementations given the same set of operations:

1. Find all **tips** — operations with no children
2. Select the tip with the **highest `createdAt`** timestamp
3. **Lexicographic highest CID** as tiebreaker

This is deterministic: any implementation with the same operations computes the same head, regardless of ingestion order. Semantic interpretation of forks (concurrency glitch, intentional recovery, etc.) is application-defined — the protocol stores the DAG, clients interpret it.

**Timestamp ordering**: `createdAt` MUST be strictly greater than the `createdAt` of the parent operation (the operation referenced by `previousOperationCID`). This is enforced per-branch, not globally — a fork branch's timestamps are validated against its own parent, not the other branch's operations.

**Future timestamp bound**: Relays, and any component that performs deterministic head selection, MUST reject identity and content operations with a `createdAt` more than 24 hours in the future relative to the verifier's clock. Since deterministic head selection favors the highest `createdAt`, a far-future timestamp would otherwise permanently dominate head selection — this guard prevents temporal denial-of-service. Bare linear chain verification (`verifyIdentityChain` / `verifyContentChain`) does not select a head and does not enforce this bound; it validates only that each operation's `createdAt` is strictly greater than its parent's (below). The reference relays enforce the 24-hour bound at ingest.

### Identity Chain Signer Validity

An identity chain operation is valid only if the signing key was a **controller key in the immediately prior state**. For genesis operations, the signing key MUST be one of the controller keys declared in that same operation — this is the bootstrap: the genesis operation introduces and simultaneously authorizes its own keys.

This is a self-sovereign invariant: the identity chain defines its own valid signers via `controllerKeys`, and the protocol enforces this. No external authority is consulted.

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

**`delete` is the only terminal state.** No valid operations may follow a delete. An implementation MUST reject any operation after a delete. This is enforced per-branch: a delete seals further linear extension of its own branch, but forks rooted at a pre-delete operation remain valid, and deterministic head selection may make a non-deleted branch the head — see the `did:dfos` DID Method specification, Deactivation. Delete prevents future operations but does NOT remove data — the complete chain remains intact for verification. Data removal is an application concern.

**Controller key requirement:** `update` operations on identity chains MUST include at least one controller key. If decommissioning is intended, `delete` is the correct terminal operation.

**Content-null:** An `update` on a content chain with `documentCID: null` means the content exists but its document is cleared. The chain continues — a subsequent update can set content again.

### `typ` Header

The JWS `typ` header uses protocol-specific values (not IANA media types):

| `typ` value            | Usage                                         |
| ---------------------- | --------------------------------------------- |
| `did:dfos:identity-op` | Identity chain operations                     |
| `did:dfos:content-op`  | Content chain operations                      |
| `did:dfos:artifact`    | Standalone signed inline documents            |
| `did:dfos:countersign` | Standalone witness attestations               |
| `did:dfos:revocation`  | Credential revocation artifacts               |
| `did:dfos:credential`  | DFOS authorization credentials                |
| `JWT`                  | Auth tokens (DID-signed relay authentication) |

Protocol-specific `typ` values are non-standard per JOSE convention, documented intentionally. `JWT` follows IANA conventions. The `typ` header aids routing but is not security-critical. Implementations SHOULD validate it but MUST NOT rely on it for security decisions. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for credential `typ` values and format.

### Operation Versioning

Every proof-plane operation payload (identity, content, artifact, countersign, revocation) carries a top-level integer `version` field. This document specifies version `1`; verifiers MUST reject any operation whose `version` is not exactly `1`. Both reference implementations pin `version: 1` and reject all other values. A future wire-incompatible revision of the operation format would increment this field, and implementations declare which versions they accept. The operation `version` is distinct from content-document `$schema` versioning (see [CONTENT-MODEL.md](https://protocol.dfos.com/content-model)), which versions application payloads independently and does not affect operation-level verification.

### Operation Size and Cardinality Limits

The protocol bounds operations with **one aggregate size cap** plus a small set of **cardinality caps** — not a per-field string-length table. A per-field length zoo (`did ≤ 256`, `note ≤ 256`, …) was a defensive measure with no cross-implementation backing; it is replaced by a single bound measured over the exact bytes the CID commits to, which is identical-by-construction across implementations.

**Aggregate operation size (size cap):**

| Bound                              | Value                    | Applies to                              |
| ---------------------------------- | ------------------------ | --------------------------------------- |
| dag-cbor-encoded operation payload | **65536 bytes** (64 KiB) | identity operations, content operations |

Verifiers MUST reject an identity or content operation whose `dagCborCanonicalEncode(payload)` exceeds 65536 bytes, **measured with any embedded `authorization` credential excluded** (see below). The cap is measured over the canonical CBOR bytes the operation CID commits to, so every implementation computes it identically (no Unicode/length-counting ambiguity). It is generous by design — a legitimate proof-layer operation is far smaller — and bounds decode/verify cost as a DoS guard. Credentials are NOT subject to this cap; they carry their own larger 262144-byte (256 KiB) ceiling (a maximum-depth delegation chain embeds each parent token in `prf` and legitimately exceeds 64 KiB — see [CREDENTIALS.md](https://protocol.dfos.com/credentials)). Artifacts keep their own 16384-byte cap (below); the `services` array keeps its 8192-byte cap (above).

A delegated content `update`/`delete` carries its authorizing credential in the operation's `authorization` field, and that credential — itself bounded by the 262144-byte credential cap — can legitimately approach 256 KiB at maximum delegation depth. Counting it against the 64 KiB operation cap would conflate two independent limits and reject a valid deep-delegation write, so the operation-size cap is measured over the payload **with the `authorization` field removed**; the `authorization` credential is bounded separately by the credential cap. Total operation bytes are therefore bounded by the sum (≤ 64 KiB + 256 KiB). The operation CID still commits to the complete payload including `authorization`.

**Cardinality caps (structure, not byte length):**

| Field                                        | Max      | Rationale                               |
| -------------------------------------------- | -------- | --------------------------------------- |
| `authKeys` / `assertKeys` / `controllerKeys` | 16 items | Generous for key rotation               |
| `services` entries                           | 16 items | (see Services, above)                   |
| countersignature `relation`                  | 64 chars | Open-namespace tag (min 1 when present) |

The protocol does NOT limit individual field string lengths, **document content size** (the protocol commits to a CID, not the document — large binary media is referenced, not inlined), **chain length**, or **number of chains per identity**. These are application/transport concerns.

**Resource policy (non-validity, MAY differ per node).** Beyond the validity-determining bounds above, a node SHOULD apply a **decoder recursion-depth guard** when canonicalizing/encoding a payload, as a DoS protection against pathologically nested input. Both reference implementations cap nesting at 1024 levels — generous enough that it never binds a legitimate operation (real payloads are a handful of levels deep). This is a local resource guard, **not** a chain-validity rule: it bounds a node's own stack cost and never changes which operations are part of the canonical chain. Nodes MAY apply stricter local ingress limits (max bytes decoded off the wire, rate limits) provided they never accept an operation the validity rules reject, nor reject one they accept.

---

## Standards and Dependencies

| Component           | Standard / Library                                                         |
| ------------------- | -------------------------------------------------------------------------- |
| Key generation      | Ed25519 (RFC 8032) via `@noble/curves/ed25519`                             |
| Signature algorithm | EdDSA over Ed25519 (pure, no prehash — Ed25519 handles SHA-512 internally) |
| Key encoding        | W3C Multikey (multicodec `0xed01` + base58btc multibase)                   |
| Signed envelopes    | JWS Compact Serialization (RFC 7515) with `alg: "EdDSA"`                   |
| Content addressing  | CIDv1 with dag-cbor codec (`0x71`) + SHA-256 multihash (`0x12`)            |
| ID encoding         | SHA-256 → custom 19-char alphabet, 31 characters                           |

### ID Alphabet

```
Alphabet: 2346789acdefhknrtvz  (19 characters)
Length:   31 characters
Entropy:  ~131.6 bits (19^31)
```

Process: `SHA-256(input) → for each of first 31 bytes: alphabet[byte % 19]`. The modulo introduces a ~0.3% bias (256 is not evenly divisible by 19) — not security-relevant for identifiers.

DIDs: `did:dfos:` + 31-char ID derived from `SHA-256(genesis CID raw bytes)`
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
  authKeys: MultikeyPublicKey[],
  assertKeys: MultikeyPublicKey[],
  controllerKeys: MultikeyPublicKey[],   // must have at least one
  services?: ServiceEntry[],              // discovery vocabulary (optional)
  createdAt: string }                     // ISO 8601, ms precision, UTC

// Key rotation / modification
{ version: 1, type: "update",
  previousOperationCID: string,                    // CID of previous operation
  authKeys: MultikeyPublicKey[],
  assertKeys: MultikeyPublicKey[],
  controllerKeys: MultikeyPublicKey[],   // must have at least one
  services?: ServiceEntry[],              // full-state — REPLACES the prior set
  createdAt: string }

// Permanent destruction
{ version: 1, type: "delete",
  previousOperationCID: string,
  createdAt: string }
```

The optional `services` array is full-state discovery vocabulary projected into
verified identity state — see [Services](#services). Omitting it encodes
identically to a service-less operation (CID-neutral); an `update` carrying it
REPLACES the entire prior set; a `delete` carries the last set unchanged.

### Content Operations

```typescript
// Genesis — starts the content chain, commits initial document
{ version: 1, type: "create",
  did: string,                           // author DID, committed to by CID
  documentCID: string,                   // CID of flat content object
  baseDocumentCID: string | null,        // edit lineage — CID of prior document version
  createdAt: string,
  note: string | null }

// Content change (null documentCID = clear content)
{ version: 1, type: "update",
  did: string,                           // author DID
  previousOperationCID: string,
  documentCID: string | null,
  baseDocumentCID: string | null,
  createdAt: string,
  note: string | null,
  authorization?: string }               // DFOS credential for delegated operations

// Permanent destruction
{ version: 1, type: "delete",
  did: string,                           // author DID
  previousOperationCID: string,
  createdAt: string,
  note: string | null,
  authorization?: string }               // DFOS credential for delegated operations
```

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

| Context                   | kid format  | Example                               |
| ------------------------- | ----------- | ------------------------------------- |
| Identity create (genesis) | Bare key ID | `key_r9ev34fvc23z999veaaft83nn29zvhe` |
| Identity update/delete    | DID URL     | See below                             |
| All content ops           | DID URL     | See below                             |

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

Note: JWT auth tokens do NOT include a `cid` header. DFOS credentials DO include a `cid` header (for revocation addressability). This field is present on operation JWS tokens, artifacts, countersignatures, credentials, and revocations.

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

DFOS pins a deliberately narrow profile of the JOSE/JWS surface so that **all conformant verifiers accept and reject the same signatures byte-for-byte**. The rules below are normative and apply to **every** verification path: identity-op JWS, content-op JWS, artifacts, countersignatures, DFOS credentials, credential revocations, and auth-token JWTs. A verifier MUST apply §1–§3 to the protected header **before** performing any signature computation, and MUST apply §4 as part of (or before) the signature check. A token that violates any rule MUST be rejected regardless of whether its signature would otherwise verify.

There is no algorithm agility: the verifier never branches on `alg` to select a primitive. Ed25519 (`EdDSA`) is the only signature algorithm.

### 1. Algorithm pinning (`alg`)

The protected header `alg` member MUST equal the exact string `"EdDSA"`. Any other value MUST be rejected before any signature check, including (non-exhaustively) `"none"`, `"HS256"`, `"RS256"`, `"ES256"`, the lowercase `"eddsa"`, or an absent `alg`. Verifiers MUST NOT use `alg` to choose a verification primitive; it is checked only for exact equality.

### 2. `crit` rejection

The protected header MUST NOT contain a `crit` member. DFOS emits no critical header parameters, so any token whose protected header carries `crit` (with any value) MUST be rejected. Verifiers MUST observe the member's presence directly — decoding into a fixed header shape that silently discards unknown members is not sufficient.

### 3. No header-key-trust

The verifier MUST NOT read key material from the protected header. The signing key is resolved exclusively from `kid` against the signer's identity chain (current state). A protected header that carries an embedded public key — specifically a `jwk` or `x5c` member — MUST be rejected. (DFOS emits neither; the resolved key from `kid` is the only trusted key material.) A header-supplied key is never trusted, even if it happens to match the resolved key.

### 4. Canonical signature scalar (`S < L`)

An Ed25519 signature is `R || S` (64 bytes). The scalar `S` (the trailing 32 bytes, little-endian) MUST be canonical: strictly less than the group order

```
L = 2^252 + 27742317777372353535851937790883648493
  = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
```

A signature whose `S >= L` MUST be rejected (classic Ed25519 malleability). A signature that does not decode to exactly 64 bytes MUST also be rejected. Most Ed25519 libraries enforce `S < L` already; implementations on libraries that do not (notably `ed25519-dalek`, where even `verify_strict` accepts non-canonical `S`) MUST add an explicit constant-time `S < L` gate.

### Reserved for a future revision

The following hardening axes are intentionally **deferred** to a later profile revision and are NOT part of v1. v1 verifiers inherit whatever behavior their Ed25519 library provides on these axes:

- **Cofactorless verification equation pinning** — requiring the specific `[S]B == R + [k]A` (cofactorless) equation rather than the batch/cofactored form.
- **Full-order public key check** — the out-of-band `[L]A == identity` torsion test confirming `A` is a full-order point.
- **Canonical point encoding (`y < p`)** — rejecting non-canonical `y`-coordinate encodings of `R` and `A`.
- **Small-order public key rejection** — beyond whatever the underlying library already rejects.
- **Strict base64url tightening** — rejecting non-canonical base64url padding/alphabet beyond what the decoder already enforces.

These axes only matter for adversarially-constructed keys. Honest DFOS keys are full-order and canonically encoded, and honest signers produce canonical `S`, so honest participants are unaffected by the deferral. Any residual cross-implementation divergence on these axes is reachable only with adversarial keys and is addressed when this profile is next revised.

---

## Credentials

Credentials handle authentication and authorization for relay access and content chain delegation. The full credential format, verification rules, and revocation mechanism are specified in [CREDENTIALS.md](https://protocol.dfos.com/credentials).

Summary of credential types:

| Credential Type | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| Auth token      | DID-signed JWT proving identity (relay AuthN)                 |
| DFOS credential | Authorize actions on resources (read, write) via attenuations |

### Content Chain Authorization

When `enforceAuthorization` is enabled on content chain verification:

1. **Genesis operation**: The signer is the chain creator, always authorized
2. **Creator signs subsequent ops**: Authorized directly — no credential needed
3. **Different DID signs**: Must include an `authorization` field containing a valid DFOS credential where:
   - The delegation chain roots at the chain creator DID
   - The credential's `att` includes an entry with `action: "write"` covering this chain's resource
   - The credential is temporally valid (`iat <= op.createdAt < exp`, not wall clock)

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
chain's equivocation resolution (services are a pure projection of the winning
head, so a forked log resolves to exactly one services set via the same
deterministic head selection used for keys).

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
cross-language change.

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
| `^baf[a-z2-7]{20,}$`          | artifact (immutable, public)      |

The `label` is an opaque client-semantic key (e.g. `"profile"`, `"avatar"`) —
the protocol assigns it no meaning, leaving applications free to define their own
namespaces while still resolving anchors uniformly. A chain HEAD CID is also
`baf…`-shaped, so it dispatches to "artifact" and then fails the resolution-time
`type: "artifact"` check — "never anchor a head CID" holds without a mode flag.

### Bounds

- ≤ 16 entries per identity; entry `id`s MUST be unique within the set
- `id` and `type`: 1–64 characters; recognized string fields (`endpoint`,
  `label`, `anchor`): 1–512 characters
- The CBOR-encoded `services` array MUST NOT exceed **8192 bytes**. Verifiers
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
did:          did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar
typ:          did:dfos:identity-op
cid:          bafyreidi3qps3qttqp22m3y33bdbf2iykbq5r45jjhwa37mgesov7sdgze
services:     [ { id: "relay",   type: "DfosRelay",     endpoint: "https://relay.dfos.com" },
                { id: "profile", type: "ContentAnchor", label: "profile", anchor: "cv7n8vkvr64cctf3294h9k4eanhff8z" },
                { id: "avatar",  type: "ContentAnchor", label: "avatar",  anchor: "bafyreievcqrmvtz2pis5tdizt7sjotoqqogl6vrrqga64w2tnwkq2rnudy" } ]
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
relation) encodes identically to one before this revision (CID-neutral). When
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
   - The controller keys declared in the genesis payload are trusted because the identity does not exist before this operation. There is no prior state to verify against.
   - The signing key (resolved from `kid`) MUST be one of the controller keys declared in this same operation. The genesis simultaneously introduces and authorizes its own keys.
   - Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID. Derive the DID from the CID.
3. For each subsequent op: verify `previousOperationCID` matches previous op's derived CID. Verify `createdAt` is strictly greater than the parent operation's `createdAt` (MUST — see Chain Validity).
4. Verify the chain is not in a terminal state (deleted) before applying any operation.
5. Resolve `kid` — genesis uses bare key ID, non-genesis uses DID URL (extract DID, verify it matches the derived DID; extract key ID).
6. Find controller key matching key ID **in the current state** (i.e., the state after all preceding operations). Decode multikey → raw Ed25519 public key.
7. Verify EdDSA JWS signature over the signing input bytes.
8. Apply state change: `create` initializes key state, `update` replaces key state (must have at least one controller key), `delete` marks terminal.

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

### Content Chain: Document + Create

Document (flat content object):

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "title": "Hello World",
  "body": "First post on the protocol.",
  "createdByDID": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
}
```

Document CID:

```
bafyreievcqrmvtz2pis5tdizt7sjotoqqogl6vrrqga64w2tnwkq2rnudy
```

Content Create JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:content-op",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_ez9a874tckr3dv933d3ckdn7z6zrct8",
  "cid": "bafyreiaqatgdgwggufgy4tsz6eurwudtdxyguztt7nq5wgd7qi445nv56y"
}
```

Content Create Payload:

```json
{
  "version": 1,
  "type": "create",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "documentCID": "bafyreievcqrmvtz2pis5tdizt7sjotoqqogl6vrrqga64w2tnwkq2rnudy",
  "baseDocumentCID": null,
  "createdAt": "2026-03-07T00:02:00.000Z",
  "note": null
}
```

Content Create JWS Signature (hex):

```
3ce4dcbd16d86f9aff3fa669251340b9f0a410799f79b5327358dbfd44a0ef1746f1bc2ae76d0732c83ac168dfae153c63eefff3a21c2f0a65743d37fcbd3e02
```

Content Create JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWFxYXRnZGd3Z2d1Zmd5NHRzejZldXJ3dWR0ZHh5Z3V6dHQ3bnE1d2dkN3FpNDQ1bnY1NnkifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.POTcvRbYb5r_P6ZpJRNAufCkEHmfebUyc1jb_USg7xdG8bwq520HMsg6wWjfrhU8Y-7_86IcLwpldD03_L0-Ag
```

Content Operation CID:

```
bafyreiaqatgdgwggufgy4tsz6eurwudtdxyguztt7nq5wgd7qi445nv56y
```

### Content Chain: Update

Content Update Payload:

```json
{
  "version": 1,
  "type": "update",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "previousOperationCID": "bafyreiaqatgdgwggufgy4tsz6eurwudtdxyguztt7nq5wgd7qi445nv56y",
  "documentCID": "bafyreifetputky4fnzv7srg7l7ynih6j4ytzeqibrcp5uiepvolxqhcbcy",
  "baseDocumentCID": "bafyreievcqrmvtz2pis5tdizt7sjotoqqogl6vrrqga64w2tnwkq2rnudy",
  "createdAt": "2026-03-07T00:03:00.000Z",
  "note": "edited title and body"
}
```

Updated document (flat content object):

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "title": "Hello World (edited)",
  "body": "Updated content.",
  "createdByDID": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
}
```

Document CID (edited):

```
bafyreifetputky4fnzv7srg7l7ynih6j4ytzeqibrcp5uiepvolxqhcbcy
```

Content Update CID:

```
bafyreibpx4cgb4j6n3mz764pylrdg6q7a46njnhx6p4cq2rlgeue3s3evq
```

### Content Chain Verified State

```
Content ID:   cv7n8vkvr64cctf3294h9k4eanhff8z
Genesis CID:  bafyreiaqatgdgwggufgy4tsz6eurwudtdxyguztt7nq5wgd7qi445nv56y
Head CID:     bafyreibpx4cgb4j6n3mz764pylrdg6q7a46njnhx6p4cq2rlgeue3s3evq
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
   bafyreievcqrmvtz2pis5tdizt7sjotoqqogl6vrrqga64w2tnwkq2rnudy
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

All source lives in [`packages/dfos-protocol/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) — self-contained, zero monorepo dependencies. 266 checks across 5 languages.

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
- [`credentials/auth-token`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/auth-token.ts) — `createAuthToken`, `verifyAuthToken`
- [`chain/revocation`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/revocation.ts) — `signRevocation`, `verifyRevocation`
- [`credentials/dfos-credential`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/dfos-credential.ts) — `createDFOSCredential`, `verifyDFOSCredential`, `decodeDFOSCredentialUnsafe`
- [`credentials/schemas`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/schemas.ts) — `AuthTokenClaims`, `DFOSCredentialPayload`, `Attenuation`

### Related Specifications

- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method) — W3C DID method specification for identity chains
- [Credentials](https://protocol.dfos.com/credentials) — Auth tokens, DFOS credentials, and revocation
- [Content Model](https://protocol.dfos.com/content-model) — Standard content schemas (post, profile) for document content objects
- [Web Relay](https://protocol.dfos.com/web-relay) — HTTP relay specification for ingestion, state, and content plane

### Cross-Language Verification

| Language   | Tests | Source                                                                                                   |
| ---------- | ----- | -------------------------------------------------------------------------------------------------------- |
| TypeScript | 224   | [`dfos-protocol/tests/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/tests)       |
| TypeScript | 63    | [`protocol-verify/ts/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/ts)         |
| Go         | 18    | [`protocol-verify/go/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/go)         |
| Rust       | 18    | [`protocol-verify/rust/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/rust)     |
| Python     | 3     | [`protocol-verify/python/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/python) |
| Swift      | 3     | [`protocol-verify/swift/`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify/swift)   |

---

## Special Thanks

- **Vinny Bellavia** — [stcisgood.com](https://stcisgood.com)
- **Allison Clift-Jennings** — [Jura Labs](https://juralabs.com)

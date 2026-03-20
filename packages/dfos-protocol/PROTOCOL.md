# DFOS Protocol

Verifiable identity and content chains — Ed25519 signatures, content-addressed CIDs, W3C DIDs. Cross-language verification in TypeScript, Go, Python, Rust, and Swift.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol) · [Gist](https://gist.github.com/bvalosek/ed4c96fd4b841302de544ffaee871648)

---

## Philosophy

DFOS is a dark forest operating system. Content lives in private spaces — visible only to members, governed by the communities that create it. The cryptographic proof layer is public: signed chains of commitments that anyone can independently verify with a public key and any standard EdDSA library.

Two chain types — identity and content — use the same mechanics: Ed25519 signatures, JWS compact tokens, content-addressed CIDs. The protocol knows about keys and document hashes. It doesn't know about posts, profiles, or any application concept. Document semantics are application layer — free to evolve without protocol changes.

The protocol is not coupled to the DFOS platform. Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another.

---

## Protocol Overview

The DFOS protocol has four components:

| Component             | Concern                                                                      |
| --------------------- | ---------------------------------------------------------------------------- |
| **Crypto core**       | Identity chains + content chains — Ed25519 signatures, JWS tokens, CID links |
| **Beacons**           | Signed merkle root announcements — periodic commitment over content sets     |
| **Countersignatures** | Witness attestation — third-party signatures over existing chain operations  |
| **Merkle trees**      | SHA-256 binary trees over content IDs — inclusion proofs for beacon roots    |

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

| Thing                 | Form                     | Example                           |
| --------------------- | ------------------------ | --------------------------------- |
| Operation or document | CID (dag-cbor + SHA-256) | `bafyrei...` (base32lower)        |
| Content chain         | contentId (22-char hash) | `a82z92a3hndk6c97thcrn8`          |
| Identity chain        | DID                      | `did:dfos:e3vvtck42d4eacdnzvtrn6` |

CIDs are specific immutable artifacts — a pointer to an exact operation or document. Content IDs are living content chain entities — the 22-char bare hash derived from the genesis CID. DIDs are living identity chain entities.

Operations and documents are CIDs — standard IPLD content addresses. Content chains and identity chains use derived identifiers — `customAlpha(SHA-256(genesis CID bytes))`. Same derivation for both. Identity chains prepend `did:dfos:` (W3C DID spec). Content identifiers are bare — just the 22-char hash, no prefix.

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

A valid chain is a **linear sequence** of operations. Each operation (after genesis) links to its predecessor via `previousOperationCID`. The chain provides structural ordering independent of timestamps.

**Forks are invalid at the protocol level.** Two operations referencing the same `previousOperationCID` constitute a fork. The protocol does not define fork resolution — this is application-defined (e.g., longest chain, first-seen, advisory locks).

**Timestamp ordering**: `createdAt` SHOULD be strictly increasing within a chain. Implementations SHOULD reject operations with non-increasing timestamps as a sanity check against replayed or mis-ordered operations. However, the chain link (CID reference) is the authoritative ordering mechanism, not the timestamp. Implementations MAY relax timestamp ordering in constrained environments where clock synchronization is impractical.

### Identity Chain Signer Validity

An identity chain operation is valid only if the signing key was a **controller key in the immediately prior state**. For genesis operations, the signing key MUST be one of the controller keys declared in that same operation — this is the bootstrap: the genesis operation introduces and simultaneously authorizes its own keys.

This is a self-sovereign invariant: the identity chain defines its own valid signers via `controllerKeys`, and the protocol enforces this. No external authority is consulted.

### Content Chain Signer Model

Content chain verification requires a **valid EdDSA signature** and delegates key resolution to the caller. The `kid` in each operation's JWS header is a DID URL (`did:dfos:<id>#<keyId>`). The verifier calls `resolveKey(kid)` to obtain the raw Ed25519 public key bytes for that key on that identity. How the resolver obtains and validates the identity's key state is application-defined.

Identity chains are self-sovereign — they define their own valid signers via `controllerKeys`. Content chains are externally signed — a content chain with operations signed by multiple different identities is valid at the protocol level, as long as each signature verifies against the resolved key.

**Signer-payload consistency**: The `kid` DID in the JWS header MUST match the `did` field in the content operation payload. This enables discrimination between author operations and countersignatures — if the kid DID differs from the payload `did`, it is a countersignature (witness attestation), not a chain operation.

**What the protocol enforces:**

- The EdDSA signature on each operation is valid against the key returned by `resolveKey(kid)`
- Chain integrity (CID links, timestamp ordering, terminal state)
- The `kid` DID matches the payload `did` for chain operations

**What the protocol does NOT enforce (application concerns):**

- Which identities are authorized to sign operations on a given chain
- Which key role (auth, assert, controller) the signing key must have
- Whether a chain must have a single signer or may have multiple signers
- Ownership or attribution semantics between signers and content chains

### Terminal States and Special Operations

**`delete` is the only terminal state.** No valid operations may follow a delete. An implementation MUST reject any operation after a delete. Delete prevents future operations but does NOT remove data — the complete chain remains intact for verification. Data removal is an application concern.

**Controller key requirement:** `update` operations on identity chains MUST include at least one controller key. If decommissioning is intended, `delete` is the correct terminal operation.

**Content-null:** An `update` on a content chain with `documentCID: null` means the content exists but its document is cleared. The chain continues — a subsequent update can set content again.

### `typ` Header

The JWS `typ` header uses protocol-specific values (not IANA media types):

| `typ` value            | Usage                     |
| ---------------------- | ------------------------- |
| `did:dfos:identity-op` | Identity chain operations |
| `did:dfos:content-op`  | Content chain operations  |
| `did:dfos:beacon`      | Beacon announcements      |
| `JWT`                  | Device auth tokens        |

These are non-standard per JOSE convention, documented intentionally. The `typ` header aids routing but is not security-critical. Implementations SHOULD validate it but MUST NOT rely on it for security decisions.

### Operation Field Limits

The protocol defines maximum sizes for all operation fields as abuse-prevention ceilings. Implementations MUST reject operations that exceed these bounds. Implementations MAY impose stricter limits.

| Field                                        | Max       | Rationale                              |
| -------------------------------------------- | --------- | -------------------------------------- |
| `did`                                        | 256 chars | ~8× typical `did:dfos:` (~31 chars)    |
| `key.id`                                     | 64 chars  | ~3× typical key ID (`key_` + 22 chars) |
| `key.publicKeyMultibase`                     | 128 chars | ~2× Ed25519 multikey (~50 chars)       |
| `authKeys` / `assertKeys` / `controllerKeys` | 16 items  | Generous for key rotation              |
| `previousOperationCID`                       | 256 chars | ~4× typical CIDv1 (~60 chars)          |
| `documentCID`                                | 256 chars | Same as above                          |
| `note`                                       | 256 chars | Short annotation, not prose            |

These limits are enforced by the Zod schemas in `src/chain/schemas.ts`. Any implementation parsing operations MUST reject values exceeding these bounds.

The protocol does NOT limit:

- **Document content size** — the protocol commits to a CID, not the document. Document size limits are application/registry concerns.
- **Chain length** — no maximum operations per chain.
- **Number of chains per identity** — application scaling concern.

---

## Standards and Dependencies

| Component           | Standard / Library                                                         |
| ------------------- | -------------------------------------------------------------------------- |
| Key generation      | Ed25519 (RFC 8032) via `@noble/curves/ed25519`                             |
| Signature algorithm | EdDSA over Ed25519 (pure, no prehash — Ed25519 handles SHA-512 internally) |
| Key encoding        | W3C Multikey (multicodec `0xed01` + base58btc multibase)                   |
| Signed envelopes    | JWS Compact Serialization (RFC 7515) with `alg: "EdDSA"`                   |
| Content addressing  | CIDv1 with dag-cbor codec (`0x71`) + SHA-256 multihash (`0x12`)            |
| ID encoding         | SHA-256 → custom 19-char alphabet, 22 characters                           |

### ID Alphabet

```
Alphabet: 2346789acdefhknrtvz  (19 characters)
Length:   22 characters
Entropy:  ~93.4 bits (19^22)
```

Process: `SHA-256(input) → for each of first 22 bytes: alphabet[byte % 19]`. The modulo introduces a ~0.3% bias (256 is not evenly divisible by 19) — not security-relevant for identifiers.

DIDs: `did:dfos:` + 22-char ID derived from `SHA-256(genesis CID raw bytes)`
Key IDs: `key_` + 22-char ID. Convention: derive from public key hash (`key_` + `customAlpha(SHA-256(publicKey))`), making key IDs deterministic and verifiable. Not a protocol requirement — key IDs can be any string.

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

dag-cbor canonical ordering: map keys sorted by encoded byte length first, then lexicographic. JSON numbers map to CBOR integers. Strings to CBOR text strings. Null to CBOR null. Arrays to CBOR arrays. Objects to CBOR maps with sorted keys.

**Worked example (genesis identity operation):**

```
CBOR bytes (441 bytes, hex):
a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b
65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579
727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a535634503359
6363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441
747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381
a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d
756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f
4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e63
6f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939
766561616674386474797065684d756c74696b6579727075626c69634b65794d756c7469626173
6578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c
6561444c55714c7541536a62

CID bytes (hex): 01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486
CID string:      bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy
```

### DID Derivation (worked example)

```
Input:  CID bytes (hex) = 01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486
Step 1: SHA-256(CID bytes) = 4360cfbcbbb3f1614c8e02dbfe8d55935e1195cd2129820ab8aef94bde12ea8a
Step 2: Take first 22 bytes: 43 60 cf bc bb b3 f1 61 4c 8e 02 db fe 8d 55 93 5e 11 95 cd 21 29
Step 3: For each byte, alphabet[byte % 19]:
        43=67  → 67%19=10  → 'e'
        60=96  → 96%19=1   → '3'
        cf=207 → 207%19=17 → 'v'
        bc=188 → 188%19=17 → 'v'
        ...
Result: e3vvtck42d4eacdnzvtrn6
DID:    did:dfos:e3vvtck42d4eacdnzvtrn6
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
  createdAt: string }                     // ISO 8601, ms precision, UTC

// Key rotation / modification
{ version: 1, type: "update",
  previousOperationCID: string,                    // CID of previous operation
  authKeys: MultikeyPublicKey[],
  assertKeys: MultikeyPublicKey[],
  controllerKeys: MultikeyPublicKey[],   // must have at least one
  createdAt: string }

// Permanent destruction
{ version: 1, type: "delete",
  previousOperationCID: string,
  createdAt: string }
```

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
  note: string | null }

// Permanent destruction
{ version: 1, type: "delete",
  did: string,                           // author DID
  previousOperationCID: string,
  createdAt: string,
  note: string | null }
```

### MultikeyPublicKey

```typescript
{ id: string,                             // e.g. "key_r9ev34fvc23z999veaaft8"
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

| Context                   | kid format  | Example                      |
| ------------------------- | ----------- | ---------------------------- |
| Identity create (genesis) | Bare key ID | `key_r9ev34fvc23z999veaaft8` |
| Identity update/delete    | DID URL     | See below                    |
| All content ops           | DID URL     | See below                    |

DID URL examples:

```
did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8
did:dfos:e3vvtck42d4eacdnzvtrn6#key_ez9a874tckr3dv933d3ckd
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

Note: JWT tokens (device auth) do NOT include a `cid` header — this field is specific to operation JWS tokens.

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

## Beacons

A beacon is a signed announcement of a merkle root — a periodic commitment over a set of content IDs. Beacons are floating signed artifacts, not chained. They provide a compact, verifiable snapshot of an identity's content set at a point in time.

### Beacon Payload

```json
{
  "version": 1,
  "type": "beacon",
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "merkleRoot": "a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8",
  "createdAt": "2026-03-07T00:04:00.000Z"
}
```

| Field        | Type   | Description                                             |
| ------------ | ------ | ------------------------------------------------------- |
| `version`    | 1      | Protocol version                                        |
| `type`       | string | Literal `"beacon"`                                      |
| `did`        | string | DID of the identity publishing the beacon               |
| `merkleRoot` | string | Hex-encoded SHA-256 root (64 chars, `/^[0-9a-f]{64}$/`) |
| `createdAt`  | string | ISO 8601 timestamp                                      |

### Beacon JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:beacon",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_ez9a874tckr3dv933d3ckd",
  "cid": "bafyrei..."
}
```

### Beacon Semantics

Beacons are not chained — there is no `previousOperationCID`. For a given DID, the latest beacon with a strictly-greater `createdAt` timestamp wins. Beacons replace, not accumulate.

**Clock skew tolerance**: Implementations MUST reject beacons with a `createdAt` more than 5 minutes in the future relative to the verifier's clock. This prevents pre-dating attacks while accommodating reasonable clock drift.

**merkleRoot**: A hex-encoded SHA-256 hash (64 characters). This is a commitment, not a CID — it uses raw SHA-256, not dag-cbor encoding. See the Merkle Tree section below for construction. An empty content set produces a `null` merkle root (no beacon needed).

---

## Merkle Trees

Beacons commit to a set of content IDs via a pure SHA-256 binary Merkle tree. The tree has no dag-cbor dependency — it uses only SHA-256 over raw bytes.

### Construction

1. **Collect** all content IDs (22-char bare hashes) in the set
2. **Sort** content IDs lexicographically (UTF-8 byte order)
3. **Hash leaves**: for each content ID, `SHA-256(UTF-8(contentId))` → 32-byte leaf hash
4. **Build tree**: recursively pair adjacent hashes. For each pair, `SHA-256(left || right)` → 32 bytes. If a level has an odd number of nodes, the last node is promoted to the next level unpaired.
5. **Root**: the final 32-byte hash, hex-encoded to a 64-character string

An empty set of content IDs produces a `null` root. A single content ID produces a root equal to `hex(SHA-256(UTF-8(contentId)))`.

### Inclusion Proofs

A Merkle inclusion proof demonstrates that a specific content ID is part of the committed set without revealing the full set. The proof consists of sibling hashes along the path from leaf to root, plus a direction (left/right) for each step.

---

## Countersignatures

A countersignature is a witness attestation — a third-party identity signing the same CID-committed bytes as an existing chain operation. Countersignatures use the same JWS format and `typ` (`did:dfos:content-op`) as the original operation.

### Discrimination Rule

The protocol distinguishes author operations from countersignatures by comparing the `kid` DID in the JWS header to the `did` field in the operation payload:

- **`kid` DID === payload `did`** → author operation (chain operation)
- **`kid` DID !== payload `did`** → witness countersignature

### Semantics

A countersignature proves that a witness identity has seen and attested to a specific operation. The witness signs the exact same payload (same CID), but with their own key. The countersignature's JWS header will contain the witness's `kid` (their DID URL), while the payload's `did` field remains the original author's DID.

Countersignatures are not part of the chain — they do not have `previousOperationCID` links and do not affect chain state. They are auxiliary attestations stored alongside chain operations.

---

## Verification

### Identity Chain

1. Decode each JWS, parse payload as IdentityOperation
2. First op MUST be `type: "create"` — this is the genesis bootstrap:
   - The controller keys declared in the genesis payload are trusted because the identity does not exist before this operation. There is no prior state to verify against.
   - The signing key (resolved from `kid`) MUST be one of the controller keys declared in this same operation. The genesis simultaneously introduces and authorizes its own keys.
   - Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID. Derive the DID from the CID.
3. For each subsequent op: verify `previousOperationCID` matches previous op's derived CID. Verify `createdAt` is strictly increasing (SHOULD — see Protocol Rules).
4. Verify the chain is not in a terminal state (deleted) before applying any operation.
5. Resolve `kid` — genesis uses bare key ID, non-genesis uses DID URL (extract DID, verify it matches the derived DID; extract key ID).
6. Find controller key matching key ID **in the current state** (i.e., the state after all preceding operations). Decode multikey → raw Ed25519 public key.
7. Verify EdDSA JWS signature over the signing input bytes.
8. Apply state change: `create` initializes key state, `update` replaces key state (must have at least one controller key), `delete` marks terminal.

### Content Chain

1. Decode each JWS, parse payload as ContentOperation
2. First op must be `type: "create"`
3. For each subsequent op: verify `previousOperationCID` matches, verify `createdAt` increasing
4. Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID.
5. Verify the `kid` DID matches the payload `did` field (mismatches indicate a countersignature, not a chain operation)
6. Resolve `kid` via external key resolver (caller provides)
7. Verify EdDSA JWS signature
8. Apply state change (set document, clear, or delete)

---

## Deterministic Reference Artifacts

All artifacts below are deterministic and reproducible from fixed seeds. An independent implementer can verify every value using standard Ed25519 + dag-cbor libraries. Private keys are derived from `SHA-256(UTF8("dfos-protocol-reference-key-N"))`.

### Key 1 (Genesis Controller)

```
Seed:        SHA-256("dfos-protocol-reference-key-1")
Private key: 132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac
Public key:  ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32
Multikey:    z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb
Key ID:      key_r9ev34fvc23z999veaaft8
```

### Key 2 (Rotated Controller)

```
Seed:        SHA-256("dfos-protocol-reference-key-2")
Private key: 384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8
Public key:  0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c
Multikey:    z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK
Key ID:      key_ez9a874tckr3dv933d3ckd
```

### Identity Chain: Create (Genesis)

Operation:

```json
{
  "version": 1,
  "type": "create",
  "authKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft8",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "assertKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft8",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "controllerKeys": [
    {
      "id": "key_r9ev34fvc23z999veaaft8",
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
  "kid": "key_r9ev34fvc23z999veaaft8",
  "cid": "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy"
}
```

JWS Signature (hex):

```
103af20cad6ebed8b1fb5edc1ee9fdb7a31a705231dab326305d502f37c3e531654ac3af31cb9ef7ba428069f709778b545b55c60a42a21d241925e2a0a2b303
```

JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTF2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw
```

Operation CID:

```
bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy
```

**Derived DID: `did:dfos:e3vvtck42d4eacdnzvtrn6`**

### Identity Chain: Update (Key Rotation)

JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:identity-op",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8",
  "cid": "bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm"
}
```

Operation:

```json
{
  "version": 1,
  "type": "update",
  "previousOperationCID": "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy",
  "authKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckd",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "assertKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckd",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "controllerKeys": [
    {
      "id": "key_ez9a874tckr3dv933d3ckd",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
    }
  ],
  "createdAt": "2026-03-07T00:01:00.000Z"
}
```

JWS Signature (hex):

```
31272ea0196038ade3e505fdb45730d68bb4a382e0273886244b19e69bea881af549a800c80bf987ec1a8d086d83c20fedd2e533453895e5b6891adaf78e5c0e
```

JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg
```

Operation CID:

```
bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm
```

Post-rotation: DID unchanged (`did:dfos:e3vvtck42d4eacdnzvtrn6`), controller rotated to `key_ez9a874tckr3dv933d3ckd`.

### Content Chain: Document + Create

Document (flat content object):

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "title": "Hello World",
  "body": "First post on the protocol.",
  "createdByDID": "did:dfos:e3vvtck42d4eacdnzvtrn6"
}
```

Document CID:

```
bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4
```

Content Create JWS Header:

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:content-op",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_ez9a874tckr3dv933d3ckd",
  "cid": "bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu"
}
```

Content Create Payload:

```json
{
  "version": 1,
  "type": "create",
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "documentCID": "bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4",
  "baseDocumentCID": null,
  "createdAt": "2026-03-07T00:02:00.000Z",
  "note": null
}
```

Content Create JWS Signature (hex):

```
46feaf973e4c7ebc2a0d4ad25481ace197de05b91051205c5e1c7067a85fb9d4abe4cc61625d3c853a8b0ce0345b534c8cdd07b34216f635d3c0bc0fd5d30306
```

Content Create JWS Token:

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWFlZGhqcTY0YWFqcHdvY2lhaGw1dzM3ajZ1b3hyNW1vam9xNWRuYWg2ZnB2eHI1ZDRseHUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWh6d3VvdXBmZzNkeGlwNnhtZ3pteHN5d3lpaTJqZW94eHpiZ3gzenhtMmluN2tub2kzZzQiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.Rv6vlz5MfrwqDUrSVIGs4ZfeBbkQUSBcXhxwZ6hfudSr5MxhYl08hTqLDOA0W1NMjN0Hs0IW9jXTwLwP1dMDBg
```

Content Operation CID:

```
bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu
```

### Content Chain: Update

Content Update Payload:

```json
{
  "version": 1,
  "type": "update",
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "previousOperationCID": "bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu",
  "documentCID": "bafyreidh7e36cvwy3uw5ypitcqk7uoktbkkkj7e6hxhky4o75rxn7kxilu",
  "baseDocumentCID": "bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4",
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
  "createdByDID": "did:dfos:e3vvtck42d4eacdnzvtrn6"
}
```

Document CID (edited):

```
bafyreidh7e36cvwy3uw5ypitcqk7uoktbkkkj7e6hxhky4o75rxn7kxilu
```

Content Update CID:

```
bafyreih6e5cbjitpozhzhgmfktmiohmxyn3ucwhqd3mjixizvwmlhv7hm4
```

### Content Chain Verified State

```
Content ID:   a82z92a3hndk6c97thcrn8
Genesis CID:  bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu
Head CID:     bafyreih6e5cbjitpozhzhgmfktmiohmxyn3ucwhqd3mjixizvwmlhv7hm4
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
   bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy
   ```

4. **CID header**: Verify each operation JWS header contains `cid` matching the derived operation CID

5. **DID derivation**: take raw CID bytes of genesis CID → SHA-256 → first 22 bytes → `byte % 19` → alphabet lookup → should be `e3vvtck42d4eacdnzvtrn6` → DID = `did:dfos:e3vvtck42d4eacdnzvtrn6`

6. **Rotation JWS**: signed by OLD controller key (key 1). Verify with key 1's public key. kid:

   ```
   did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8
   ```

7. **Content create JWS**: signed by NEW controller key (key 2, post-rotation). Verify with key 2's public key. kid:

   ```
   did:dfos:e3vvtck42d4eacdnzvtrn6#key_ez9a874tckr3dv933d3ckd
   ```

8. **Document CID**: dag-cbor canonical encode the flat content object → SHA-256 → CIDv1 → should be:

   ```
   bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4
   ```

9. **Content operation `did` field**: verify the `did` field in each content operation matches the `kid` DID in the JWS header

10. **Content chain integrity**: update's `previousOperationCID` matches create's operation CID

11. **Chain completeness**: all operation CIDs, DID derivation, key rotation, and content chain linkage verified end-to-end.

---

## Source and Verification

All source lives in [`packages/dfos-protocol/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) — self-contained, zero monorepo dependencies. 235 checks across 5 languages.

- [`crypto/ed25519`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/ed25519.ts) — `createNewEd25519Keypair`, `importEd25519Keypair`, `signPayloadEd25519`, `isValidEd25519Signature`
- [`crypto/jws`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/jws.ts) — `createJws`, `verifyJws`, `decodeJwsUnsafe`
- [`crypto/base64url`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/base64url.ts) — `base64urlEncode`, `base64urlDecode`
- [`crypto/multiformats`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/multiformats.ts) — `dagCborCanonicalEncode`, `dagCborCanonicalEqual`
- [`crypto/id`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/crypto/id.ts) — `generateId`, `generateIdNoPrefix`, `isValidId`
- [`chain/multikey`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/multikey.ts) — `encodeEd25519Multikey`, `decodeMultikey`
- [`chain/schemas`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/schemas.ts) — `IdentityOperation`, `ContentOperation`, `MultikeyPublicKey`, `VerifiedIdentity`
- [`chain/identity-chain`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/identity-chain.ts) — `signIdentityOperation`, `verifyIdentityChain`
- [`chain/content-chain`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/content-chain.ts) — `signContentOperation`, `verifyContentChain`
- [`chain/derivation`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/derivation.ts) — `deriveChainIdentifier`, `deriveContentId`
- [`chain/beacon`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/beacon.ts) — `signBeacon`, `verifyBeacon`
- [`chain/countersign`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/countersign.ts) — `signCountersignature`, `verifyCountersignature`
- [`merkle/tree`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/merkle/tree.ts) — `buildMerkleTree`, `hashLeaf`
- [`merkle/proof`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/merkle/proof.ts) — `generateMerkleProof`, `verifyMerkleProof`

### Related Specifications

- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method) — W3C DID method specification for identity chains
- [Content Model](https://protocol.dfos.com/content-model) — Standard content schemas (post, profile) for document content objects

### Cross-Language Verification

| Language   | Tests | Source                                                                                               |
| ---------- | ----- | ---------------------------------------------------------------------------------------------------- |
| TypeScript | 149   | [`tests/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/tests)                 |
| Python     | 48    | [`verify/python/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/python) |
| Go         | 13    | [`verify/go/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/go)         |
| Rust       | 13    | [`verify/rust/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/rust)     |
| Swift      | 12    | [`verify/swift/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/swift)   |

---

## Special Thanks

- **Vinny Bellavia** — [stcisgood.com](https://stcisgood.com)
- **Allison Clift-Jennings** — [Jura Labs](https://juralabs.com)

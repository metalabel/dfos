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

The DFOS protocol has six components:

| Component             | Concern                                                                         |
| --------------------- | ------------------------------------------------------------------------------- |
| **Crypto core**       | Identity chains + content chains — Ed25519 signatures, JWS tokens, CID links    |
| **Credentials**       | Auth tokens (DID-signed JWT) and VC-JWT credentials for authorization           |
| **Beacons**           | Signed merkle root announcements — periodic commitment over content sets        |
| **Artifacts**         | Standalone signed inline documents — immutable, CID-addressable structured data |
| **Countersignatures** | Standalone witness attestation — signed references to any CID-addressable op    |
| **Merkle trees**      | SHA-256 binary trees over content IDs — inclusion proofs for beacon roots       |

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

**Creator sovereignty**: The DID that signs the genesis (create) operation is the **chain creator** and permanently owns the chain. The creator can sign subsequent operations directly — no credential needed. Other DIDs require a **DFOSContentWrite** VC-JWT credential in the operation's `authorization` field, issued by the creator DID. See [Credentials](#credentials) for the VC-JWT format.

**Signer-payload consistency**: The `kid` DID in the JWS header MUST match the `did` field in the content operation payload. This enables discrimination between author operations and countersignatures — if the kid DID differs from the payload `did`, it is a countersignature (witness attestation), not a chain operation.

**What the protocol enforces:**

- The EdDSA signature on each operation is valid against the key returned by `resolveKey(kid)`
- Chain integrity (CID links, timestamp ordering, terminal state)
- The `kid` DID matches the payload `did` for chain operations
- Creator-sovereignty authorization (when `enforceAuthorization` is enabled): non-creator signers must present a valid DFOSContentWrite VC-JWT issued by the creator

**What the protocol does NOT enforce (application concerns):**

- Which key role (auth, assert, controller) the signing key must have
- Ownership or attribution semantics beyond creator sovereignty

### Terminal States and Special Operations

**`delete` is the only terminal state.** No valid operations may follow a delete. An implementation MUST reject any operation after a delete. Delete prevents future operations but does NOT remove data — the complete chain remains intact for verification. Data removal is an application concern.

**Controller key requirement:** `update` operations on identity chains MUST include at least one controller key. If decommissioning is intended, `delete` is the correct terminal operation.

**Content-null:** An `update` on a content chain with `documentCID: null` means the content exists but its document is cleared. The chain continues — a subsequent update can set content again.

### `typ` Header

The JWS `typ` header uses protocol-specific values (not IANA media types):

| `typ` value            | Usage                                         |
| ---------------------- | --------------------------------------------- |
| `did:dfos:identity-op` | Identity chain operations                     |
| `did:dfos:content-op`  | Content chain operations                      |
| `did:dfos:beacon`      | Beacon announcements                          |
| `did:dfos:artifact`    | Standalone signed inline documents            |
| `did:dfos:countersign` | Standalone witness attestations               |
| `JWT`                  | Auth tokens (DID-signed relay authentication) |
| `vc+jwt`               | VC-JWT credentials (W3C VC Data Model v2)     |

Protocol-specific `typ` values are non-standard per JOSE convention, documented intentionally. `JWT` and `vc+jwt` follow IANA conventions. The `typ` header aids routing but is not security-critical. Implementations SHOULD validate it but MUST NOT rely on it for security decisions.

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

dag-cbor canonical ordering: map keys sorted by encoded byte length first, then lexicographic. Strings to CBOR text strings. Null to CBOR null. Arrays to CBOR arrays. Objects to CBOR maps with sorted keys.

#### Number Encoding (Critical for CID Determinism)

JSON has a single number type (IEEE 754 double). CBOR has distinct integer and floating-point types with different byte encodings. This difference is the most common source of CID divergence across implementations.

**Rule: JSON numbers that are mathematically integers (no fractional part) MUST be encoded as CBOR integers (major type 0/1), never as CBOR floats.** This is consistent with the [IPLD data model](https://ipld.io/docs/data-model/) integer/float distinction and required by the [dag-cbor codec spec](https://ipld.io/specs/codecs/dag-cbor/spec/).

Why this matters: CBOR integer `1` encodes as a single byte `0x01`. CBOR float `1.0` encodes as three bytes `0xf9 0x3c 0x00` (half-precision). Same logical value, different bytes, different SHA-256, different CID. An implementation that encodes `version: 1` as a float will produce a valid CBOR document but a wrong CID — silent, undetectable without cross-implementation testing.

**Common trap**: Languages that decode JSON into untyped maps (Go's `map[string]any`, Python's `dict`, etc.) typically represent all JSON numbers as floating-point. When this decoded value is then CBOR-encoded, it becomes a CBOR float instead of an integer. Implementations MUST normalize number types after JSON deserialization and before CBOR encoding.

**Integer bounds**: dag-cbor integers are limited to the range `[-(2^64), 2^64 - 1]`. All integer fields in the current protocol (`version: 1`) are small positive values. Future protocol extensions SHOULD NOT introduce integer fields that exceed JSON's safe integer range (`2^53 - 1`), as JSON serialization would lose precision.

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
  note: string | null,
  authorization?: string }               // VC-JWT for delegated operations

// Permanent destruction
{ version: 1, type: "delete",
  did: string,                           // author DID
  previousOperationCID: string,
  createdAt: string,
  note: string | null,
  authorization?: string }               // VC-JWT for delegated operations
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

Note: JWT auth tokens and VC-JWT credentials do NOT include a `cid` header — this field is specific to operation JWS tokens and beacons.

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

## Credentials

Two credential types handle authentication and authorization. Both are DID-signed JWTs using Ed25519 (`alg: "EdDSA"`).

### Auth Tokens (Relay Authentication)

A DID-signed JWT proving the caller controls a DID. Short-lived, scoped to a specific relay via the `aud` (audience) claim. Used for relay AuthN — establishing identity before making requests.

**JWT Header:**

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8"
}
```

**JWT Payload:**

```json
{
  "iss": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "sub": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "aud": "relay.example.com",
  "exp": 1772845200,
  "iat": 1772841600
}
```

| Field | Type   | Description                                                |
| ----- | ------ | ---------------------------------------------------------- |
| `iss` | string | DID proving identity (the signer)                          |
| `sub` | string | Same as `iss` for auth tokens                              |
| `aud` | string | Target relay hostname (prevents cross-relay replay)        |
| `exp` | number | Expiration — unix seconds (short-lived, typically minutes) |
| `iat` | number | Issued-at — unix seconds                                   |

**Verification:** Standard JWT verification — EdDSA signature check, temporal validity (`iat` must not be in the future, `exp` must be after current time), audience match. The `kid` MUST be a DID URL (`did:dfos:xxx#key_yyy`) and the `kid` DID MUST match `iss`.

Auth tokens do NOT include a `cid` header — they are ephemeral session tokens, not content-addressed artifacts.

### VC-JWT Credentials (Authorization)

W3C Verifiable Credential Data Model v2 credentials encoded as JWT (`typ: "vc+jwt"`). Two credential types:

| Credential Type    | Purpose                                                      |
| ------------------ | ------------------------------------------------------------ |
| `DFOSContentWrite` | Authorize extending a content chain (embedded in operations) |
| `DFOSContentRead`  | Authorize reading content plane data (presented to relay)    |

**VC-JWT Header:**

```json
{
  "alg": "EdDSA",
  "typ": "vc+jwt",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8"
}
```

**VC-JWT Payload:**

```json
{
  "iss": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "sub": "did:dfos:nzkf838efr424433rn2rzk",
  "exp": 1798761600,
  "iat": 1772841600,
  "vc": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential", "DFOSContentWrite"],
    "credentialSubject": {}
  }
}
```

| Field                  | Type     | Description                                              |
| ---------------------- | -------- | -------------------------------------------------------- |
| `iss`                  | string   | DID granting the credential (content creator/controller) |
| `sub`                  | string   | DID receiving the credential (collaborator/reader)       |
| `exp`                  | number   | Expiration — unix seconds                                |
| `iat`                  | number   | Issued-at — unix seconds                                 |
| `vc.@context`          | string[] | Must be `["https://www.w3.org/ns/credentials/v2"]`       |
| `vc.type`              | string[] | `["VerifiableCredential", "<DFOSCredentialType>"]`       |
| `vc.credentialSubject` | object   | Optional narrowing — see scope narrowing below           |

**Scope narrowing:** The `credentialSubject` object may contain a `contentId` field. If absent, the credential grants broad access to all content by the issuer. If present, the credential is narrowed to the specific content chain.

```json
// Broad — all content by this DID
{ "credentialSubject": {} }

// Narrow — specific content chain only
{ "credentialSubject": { "contentId": "a82z92a3hndk6c97thcrn8" } }
```

**Verification:** EdDSA signature check, temporal validity (`iat` must not be in the future, `exp` must be after current time — using operation `createdAt` for chain-embedded VCs, wall clock for relay-presented VCs), `kid` DID URL format, `kid` DID matches `iss`, payload structure via Zod schema. Optionally verify `sub` and credential type match expectations.

### Content Chain Authorization

When `enforceAuthorization` is enabled on content chain verification:

1. **Genesis operation**: The signer is the chain creator, always authorized
2. **Creator signs subsequent ops**: Authorized directly — no credential needed
3. **Different DID signs**: Must include an `authorization` field containing a valid `DFOSContentWrite` VC-JWT where:
   - `iss` matches the chain creator DID
   - `sub` matches the signing DID
   - The credential is temporally valid (`iat <= op.createdAt < exp`, not wall clock)
   - If `contentId` is present in `credentialSubject`, it must match this chain's contentId
   - The credential type is `DFOSContentWrite`

The `authorization` field is available on `update` and `delete` content operations. It is absent for creator-signed operations.

---

## Beacons

A beacon is a signed announcement of a merkle root — a periodic commitment over a set of content IDs. Beacons are floating signed artifacts, not chained. They provide a compact, verifiable snapshot of an identity's content set at a point in time.

### Beacon Payload

```json
{
  "version": 1,
  "type": "beacon",
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "merkleRoot": "7e80d4780f454e0fca0b090d8c646f572b49354f54154531606105aad2fda28e",
  "createdAt": "2026-03-07T00:05:00.000Z"
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
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8",
  "cid": "bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu"
}
```

### Worked Example: Beacon

Using the reference identity (`did:dfos:e3vvtck42d4eacdnzvtrn6`) and key 1 from the identity chain examples. The beacon commits to a merkle root over 5 content IDs (see Merkle Tree worked example below).

**Beacon CID** (dag-cbor canonical encode → CIDv1):

```
bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu
```

**Controller JWS** (key 1 signs):

```
kid:          did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8
typ:          did:dfos:beacon
cid:          bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu
```

**Witness countersignature** (a separate identity countersigns the beacon by CID):

A countersignature is a standalone operation with its own CID and `typ: did:dfos:countersign`. See the [Countersignatures](#countersignatures) section below.

Full JWS tokens are in [`examples/beacon.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/beacon.json).

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

### Worked Example: Merkle Tree

5 content IDs: `["alpha", "bravo", "charlie", "delta", "echo"]`

Already sorted lexicographically. Hash each leaf:

```
alpha   → SHA-256("alpha")   → 8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8
bravo   → SHA-256("bravo")   → 4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398
charlie → SHA-256("charlie") → 36ef585cd42d49706cd2827a77d86c91bfdaf87a3f22b8f0e0308bd2c16cf85f
delta   → SHA-256("delta")   → 18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4
echo    → SHA-256("echo")    → 092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d
```

Build tree bottom-up, pairing left-to-right. Odd nodes promote unpaired:

```
Level 0 (leaves):    [alpha]  [bravo]  [charlie]  [delta]  [echo]
Level 1:             [alpha‖bravo]     [charlie‖delta]     [echo]  ← promoted
Level 2:             [L1-left‖L1-mid]                      [echo]  ← promoted
Level 3 (root):      [L2-left‖echo]
```

Interior hashes:

```
SHA-256(alpha‖bravo)          → 90d39555bb3c223e12f5a375c3011d2462fe2e1e36b8416a0b623d5831a9b4f3
SHA-256(charlie‖delta)        → 6b55e77bef32937d9ccce2bd4b18127b0483f0be8e5b63c30bcc2b0d09f7dd44
SHA-256(alpha‖bravo ‖ charlie‖delta) → 23c83cb862e3b6a86eb2dfa0ea8ba0edcf1c3f3b8f14abc5eb9d72eab2edc2f7
```

**Root** (level 3):

```
SHA-256(23c83c...edc2f7 ‖ 092c79...f7431d) → 7e80d4780f454e0fca0b090d8c646f572b49354f54154531606105aad2fda28e
```

### Inclusion Proofs

A Merkle inclusion proof demonstrates that a specific content ID is part of the committed set without revealing the full set. The proof consists of sibling hashes along the path from leaf to root, plus a direction (left/right) for each step.

### Worked Example: Inclusion Proof for "charlie"

Starting from the leaf hash of "charlie" (`36ef58...`), walk to the root using sibling hashes:

```
Step 1: charlie (index 2) paired with delta (index 3)
        sibling: 4f4a9410...045398 (delta leaf)  position: right
        → SHA-256(charlie ‖ delta) → 6b55e77b...f7dd44

Step 2: charlie‖delta paired with alpha‖bravo
        sibling: 90d39555...a9b4f3 (alpha‖bravo) position: left
        → SHA-256(alpha‖bravo ‖ charlie‖delta) → 23c83cb8...edc2f7

Step 3: L2-left paired with echo (promoted)
        sibling: 092c79e8...f7431d (echo leaf)   position: right
        → SHA-256(L2-left ‖ echo) → 7e80d478...fda28e ✓ matches root
```

Proof path (from [`examples/merkle-tree.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/merkle-tree.json)):

```json
[
  {
    "hash": "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
    "position": "right"
  },
  {
    "hash": "90d39555bb3c223e12f5a375c3011d2462fe2e1e36b8416a0b623d5831a9b4f3",
    "position": "left"
  },
  {
    "hash": "092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d",
    "position": "right"
  }
]
```

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

### Payload

```json
{
  "version": 1,
  "type": "countersign",
  "did": "did:dfos:witness...",
  "targetCID": "bafy...",
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

The `did` field is the witness identity — the DID signing the attestation. The `targetCID` references the operation being attested to.

### Properties

- **JWS `typ` header**: `did:dfos:countersign`
- **Own CID**: Each countersignature has its own CID derived from its own payload, distinct from the target. This avoids the ambiguity of multiple JWS tokens sharing the same CID
- **Stateless verification**: Signature + CID integrity + payload schema. No chain state required to verify the cryptographic validity of a countersignature
- **Composable**: The `targetCID` can reference any CID-addressable operation — content ops, beacons, artifacts, identity ops, even other countersignatures
- **Immutable**: Once published, a countersignature is permanent

### Verification

1. Decode JWS, verify `typ` is `did:dfos:countersign`
2. Parse and validate countersign payload (`version`, `type: "countersign"`, `did`, `targetCID`, `createdAt`)
3. Verify the `kid` DID matches the payload `did` (the witness must sign with their own key)
4. CID integrity — `header.cid` matches the CID computed from dag-cbor canonical encoding the raw payload
5. Verify EdDSA JWS signature against the witness's public key

Relay-level semantic checks (target exists, witness ≠ author, deduplication) are enforcement concerns, not protocol verification.

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
2. First op must be `type: "create"` — the signer is the chain creator
3. For each subsequent op: verify `previousOperationCID` matches, verify `createdAt` increasing
4. Derive the operation CID via dag-cbor canonical encoding. Verify `header.cid` matches the derived CID.
5. Verify the `kid` DID matches the payload `did` field
6. Resolve `kid` via external key resolver (caller provides)
7. Verify EdDSA JWS signature
8. If `enforceAuthorization` is enabled and the signer DID differs from the chain creator: verify the `authorization` field contains a valid `DFOSContentWrite` VC-JWT issued by the creator DID, with `sub` matching the signer, not expired at `op.createdAt`, and `contentId` (if present) matching this chain
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

12. **VC-JWT credential verify**: using the issuer's public key, verify a `DFOSContentWrite` or `DFOSContentRead` credential: check EdDSA signature, `typ: "vc+jwt"`, expiration, `kid` DID URL format, `kid` DID matches `iss`, `vc` claim structure matches W3C VC Data Model v2, credential type matches expected DFOS type. Test vectors in [`examples/credential-write.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/credential-write.json) and [`examples/credential-read.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/credential-read.json).

13. **Delegated content chain verify**: using [`examples/content-delegated.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/examples/content-delegated.json), verify a content chain where the genesis is signed by the creator and a subsequent update is signed by a delegate with an embedded `DFOSContentWrite` VC-JWT in the `authorization` field. The VC must be issued by the creator DID, with `sub` matching the delegate DID.

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
- [`chain/beacon`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/beacon.ts) — `signBeacon`, `verifyBeacon`
- [`chain/artifact`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/artifact.ts) — `signArtifact`, `verifyArtifact`
- [`chain/countersign`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/chain/countersign.ts) — `signCountersignature`, `verifyCountersignature`
- [`credentials/auth-token`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/auth-token.ts) — `createAuthToken`, `verifyAuthToken`
- [`credentials/credential`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/credential.ts) — `createCredential`, `verifyCredential`, `decodeCredentialUnsafe`
- [`credentials/schemas`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/credentials/schemas.ts) — `AuthTokenClaims`, `CredentialClaims`, `VCClaim`, `DFOSCredentialType`
- [`merkle/tree`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/merkle/tree.ts) — `buildMerkleTree`, `hashLeaf`
- [`merkle/proof`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/merkle/proof.ts) — `generateMerkleProof`, `verifyMerkleProof`

### Related Specifications

- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method) — W3C DID method specification for identity chains
- [Content Model](https://protocol.dfos.com/content-model) — Standard content schemas (post, profile) for document content objects
- [Web Relay](https://protocol.dfos.com/web-relay) — HTTP relay specification for ingestion, state, and content plane

### Cross-Language Verification

| Language   | Tests | Source                                                                                               |
| ---------- | ----- | ---------------------------------------------------------------------------------------------------- |
| TypeScript | 224   | [`tests/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/tests)                 |
| Go         | 18    | [`verify/go/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/go)         |
| Rust       | 18    | [`verify/rust/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/rust)     |
| Python     | 3     | [`verify/python/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/python) |
| Swift      | 3     | [`verify/swift/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/verify/swift)   |

---

## Special Thanks

- **Vinny Bellavia** — [stcisgood.com](https://stcisgood.com)
- **Allison Clift-Jennings** — [Jura Labs](https://juralabs.com)

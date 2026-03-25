# DID Method: `did:dfos`

> **Version 0.4.0** · _2026-03-24_

W3C DID Method specification for DFOS identity chains. Self-certifying, transport-agnostic, Ed25519-based decentralized identifiers.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [Protocol Specification](./PROTOCOL.md) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Abstract

This document defines the `did:dfos` DID method in conformance with the [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) specification. A `did:dfos` identifier is derived deterministically from the genesis operation of a cryptographically signed identity chain. Resolution is verification-first and transport-agnostic — the identifier itself is the trust anchor, not any particular registry or consensus layer.

---

## Status

This specification is under active development. It has not been submitted to any formal standards body.

---

## Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Introduction

DFOS is a protocol for verifiable identity and content chains using Ed25519 signatures and content-addressed CIDs. Every identity in DFOS is an append-only chain of signed operations — a self-sovereign log of key management events. The DID for an identity is derived deterministically from the hash of the chain's genesis operation, making `did:dfos` identifiers **self-certifying**: given the chain, anyone can independently verify the DID without trusting the source.

This property makes `did:dfos` fundamentally transport-agnostic. There is no privileged registry, blockchain, or consensus layer. The chain can be obtained from any source — an HTTP API, a peer-to-peer exchange, a local file, a USB drive — and the verifier can independently confirm the chain belongs to the claimed DID.

For full protocol details including cryptographic primitives, chain mechanics, and test vectors, see the [DFOS Protocol Specification](./PROTOCOL.md).

### 1.1 Design Goals

- **Self-certifying** — The DID is a deterministic derivation of the genesis content. No external authority is needed to verify the binding between identifier and chain.
- **Transport-agnostic** — Resolution requires obtaining and verifying a chain, not querying a specific endpoint. Any system that stores and serves identity chains is a valid source.
- **Key rotation** — Identity chains support full key rotation via signed update operations. Keys can be added, removed, and replaced without changing the DID.
- **Deactivation** — Identities can be permanently deactivated via a signed delete operation.
- **Minimal** — The method defines identifiers and verification. It deliberately does not define discovery, gossip, or consensus mechanisms.

---

## 2. DID Method Name

The method name is `dfos`. A DID using this method MUST begin with the prefix `did:dfos:`.

---

## 3. Method-Specific Identifier

The method-specific identifier is a 22-character string derived from the genesis operation CID of an identity chain.

### 3.1 ABNF

```abnf
dfos-did       = "did:dfos:" dfos-id
dfos-id        = 22dfos-char
dfos-char      = "2" / "3" / "4" / "6" / "7" / "8" / "9" /
                 "a" / "c" / "d" / "e" / "f" / "h" / "k" /
                 "n" / "r" / "t" / "v" / "z"
```

The alphabet is 19 characters: `2346789acdefhknrtvz`. The identifier is exactly 22 characters, providing ~93.4 bits of entropy.

### 3.2 Derivation

The method-specific identifier is derived deterministically from the genesis identity operation:

```
1. Construct the genesis identity operation payload (type: "create")
2. Canonical-encode the payload as dag-cbor → CBOR bytes
3. Hash: SHA-256(CBOR bytes) → 32-byte digest
4. Construct CIDv1: [0x01, 0x71, 0x12, 0x20, ...32 digest bytes] → CID bytes
5. Hash the CID: SHA-256(CID bytes) → 32-byte digest
6. Encode: for each of the first 22 bytes → alphabet[byte % 19]
```

The resulting 22-character string is the method-specific identifier. The full DID is `did:dfos:` prepended to this string.

### 3.3 Example

```
Genesis CID bytes (hex): 01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486
SHA-256 of CID bytes:    4360cfbcbbb3f1614c8e02dbfe8d55935e1195cd2129820ab8aef94bde12ea8a
First 22 bytes encoded:  e3vvtck42d4eacdnzvtrn6
DID:                     did:dfos:e3vvtck42d4eacdnzvtrn6
```

See the [DFOS Protocol Specification](./PROTOCOL.md) for the complete worked example with key material, CBOR encoding, and CID construction.

---

## 4. DID Document

A resolved `did:dfos` DID Document is constructed from the current state of the identity chain — specifically, the key sets declared in the most recent non-terminal operation.

### 4.1 DID Document Structure

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "controller": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "verificationMethod": [
    {
      "id": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8",
      "type": "Multikey",
      "controller": "did:dfos:e3vvtck42d4eacdnzvtrn6",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "authentication": ["did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8"],
  "assertionMethod": ["did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8"],
  "capabilityInvocation": ["did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8"]
}
```

### 4.2 Verification Method Mapping

Identity chain operations declare three key sets. These map to W3C verification relationships as follows:

| Identity Chain Key Set | W3C Verification Relationship | Purpose                                                              |
| ---------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `authKeys`             | `authentication`              | Prove control of the DID (e.g., login, session establishment)        |
| `assertKeys`           | `assertionMethod`             | Issue verifiable assertions (e.g., sign content chain operations)    |
| `controllerKeys`       | `capabilityInvocation`        | Manage the DID itself (sign identity chain update/delete operations) |

Each key in the identity chain state becomes a `verificationMethod` entry. The `id` is constructed as a DID URL: `did:dfos:<id>#<keyId>`. The `type` is `Multikey`. The `publicKeyMultibase` is the W3C Multikey encoding (multicodec `0xed01` prefix + base58btc + `z` multibase prefix).

### 4.3 Controller

`did:dfos` identities are self-sovereign. The `controller` property of the DID Document is always the DID itself. Only keys within the identity chain's `controllerKeys` set can sign operations that modify the chain.

### 4.4 Key Rotation

When an identity chain includes `update` operations that change the key sets, the DID Document reflects the **current state** — the key sets from the most recent operation. Previous keys are not included in the resolved DID Document. Historical key states can be recovered by walking the chain.

### 4.5 Services

The core `did:dfos` method does not define any `service` entries in the DID Document. Applications MAY extend the DID Document with service endpoints through application-layer conventions.

---

## 5. Operations

### 5.1 Create

Creating a `did:dfos` identifier means constructing and signing a genesis identity chain operation.

1. Generate one or more Ed25519 key pairs.
2. Construct the genesis operation payload with `type: "create"`, populating `authKeys`, `assertKeys`, and `controllerKeys`. At least one `controllerKeys` entry is REQUIRED.
3. Canonical-encode the payload as dag-cbor, derive the CID, and include it in the JWS protected header as `cid`.
4. Sign the operation as a JWS Compact Serialization token using one of the controller keys. The `kid` in the protected header is the bare key ID (not a DID URL, since the DID does not yet exist).
5. The DID is derived from the genesis CID as described in [Section 3.2](#32-derivation).

The identity chain now exists as a single-operation chain. It can be stored in any system that serves identity chains.

### 5.2 Read (Resolve)

Resolving a `did:dfos` DID means obtaining the identity chain and constructing a DID Document from its current state.

#### 5.2.1 Resolution Algorithm

Given a DID `did:dfos:<id>`:

1. **Obtain** the identity chain from any available source. The method does not prescribe how chains are discovered or transported.
2. **Verify** the chain:
   a. Decode each JWS token and parse the operation payload.
   b. The first operation MUST be `type: "create"`.
   c. Derive the genesis operation CID via dag-cbor canonical encoding.
   d. Verify that `SHA-256(genesis CID bytes)` encoded with the ID alphabet produces `<id>`. If it does not match, the chain does not belong to this DID — reject it.
   e. For each operation, verify the JWS EdDSA signature against the appropriate key (controller key from current chain state).
   f. Verify `previousOperationCID` linkage, `createdAt` ordering, and `header.cid` consistency.
   g. See the [DFOS Protocol Specification](./PROTOCOL.md) for complete verification rules.
3. **Construct** the DID Document from the terminal chain state using the mapping in [Section 4.2](#42-verification-method-mapping).

#### 5.2.2 Resolution Metadata

| Property         | Value                                                        |
| ---------------- | ------------------------------------------------------------ |
| `contentType`    | `application/did+ld+json`                                    |
| `created`        | `createdAt` from the genesis operation                       |
| `updated`        | `createdAt` from the most recent operation                   |
| `deactivated`    | `true` if the chain's terminal operation is `type: "delete"` |
| `operationCount` | Number of operations in the chain                            |

#### 5.2.3 Self-Certification

The critical property of `did:dfos` resolution: **the DID is verified against the chain, not the source.** Step 2d above is the self-certification check — it proves the chain belongs to the claimed DID using only the chain content and a hash function. This means:

- A resolver does not need to trust the registry, server, or peer that provided the chain.
- The same chain can be served by multiple independent sources with identical results.
- Chains can be cached, replicated, and redistributed without loss of verifiability.
- Offline resolution is possible if the chain is available locally.

#### 5.2.4 Transport Bindings (Non-Normative)

The `did:dfos` method is transport-agnostic. Any system that can deliver an ordered sequence of JWS tokens (the identity chain) is a valid transport. Examples include:

- **HTTP API** — Any HTTP service that stores and retrieves ordered JWS logs can serve as a transport binding.
- **Peer-to-peer exchange** — Chains can be exchanged directly between parties.
- **Local storage** — Chains can be stored in local files, databases, or key-value stores.
- **Bundle export** — Applications can export chains as portable bundles (e.g., JSON arrays of JWS tokens).

### 5.3 Update

Updating a `did:dfos` DID means appending a signed `update` operation to the identity chain.

1. Construct an update operation payload with `type: "update"`, the new key sets, and `previousOperationCID` set to the CID of the current chain tip.
2. Sign the operation using a key from the **current** `controllerKeys` set. The `kid` is a DID URL: `did:dfos:<id>#<keyId>`.
3. Append the signed JWS token to the chain.

The DID does not change. The resolved DID Document now reflects the new key sets.

### 5.4 Deactivate (Delete)

Deactivating a `did:dfos` DID means appending a signed `delete` operation to the identity chain.

1. Construct a delete operation payload with `type: "delete"` and `previousOperationCID` set to the CID of the current chain tip.
2. Sign the operation using a key from the current `controllerKeys` set. The `kid` is a DID URL.
3. Append the signed JWS token to the chain.

After deactivation:

- The chain is in a **terminal state**. No further operations can be appended.
- Resolution MUST return a DID Document with `deactivated: true` in the resolution metadata.
- The DID Document SHOULD contain an empty set of verification methods, as the identity no longer has active keys.

Deactivation is **permanent and irreversible**. The DID cannot be reactivated.

---

## 6. Security Considerations

### 6.1 Self-Certifying Identifiers

`did:dfos` identifiers are derived from a cryptographic hash of the genesis operation content. This binding is verified during resolution (Section 5.2.1, step 2d). An attacker cannot present a forged chain for a given DID — the genesis content would hash to a different identifier.

### 6.2 Key Compromise

If a controller key is compromised, the legitimate holder should immediately sign a key rotation (`update`) operation removing the compromised key. The protocol does not support key pre-rotation — there is no mechanism to pre-commit to a future key. The window of vulnerability exists between compromise and rotation.

### 6.3 Equivocation

Because `did:dfos` has no global consensus layer, an identity holder could theoretically sign two different operations at the same chain position (same `previousOperationCID`, different payloads). This creates a **fork** — two valid chain branches.

Equivocation is **detectable**: a verifier who encounters two valid operations sharing a `previousOperationCID` can identify the conflict. Resolution policy for equivocation (reject both branches, prefer one, flag for human review) is an application-level concern and is deliberately outside the scope of this method specification.

In practice, equivocation requires the identity holder to act against themselves — no external party can extend an identity chain, since all operations must be signed by a current controller key.

### 6.4 Transport Security

The `did:dfos` method does not mandate any specific transport security. Because resolution is verification-first (the chain is validated against the DID, not the source), transport-layer attacks (MITM, DNS hijacking) cannot produce a valid chain for a targeted DID. An attacker who intercepts a chain request can:

- **Withhold** the chain (denial of service) — the resolver gets no result
- **Serve a stale chain** — the resolver gets a valid but outdated DID Document
- **Serve a completely different chain** — the self-certification check fails, the resolver rejects it

An attacker **cannot** serve a modified or forged chain that passes the self-certification check.

### 6.5 Denial of Service

A resolver that depends on a single source for chain retrieval is vulnerable to denial of service. Applications SHOULD support multiple chain sources and MAY cache verified chains locally to mitigate this.

### 6.6 Cryptographic Agility

The current specification uses Ed25519 exclusively. The protocol does not currently support multiple signature algorithms. Future versions MAY introduce additional algorithms via new multicodec identifiers and verification method types. Implementations MUST reject operations signed with unrecognized algorithms.

---

## 7. Privacy Considerations

### 7.1 Correlation

`did:dfos` identifiers are persistent and globally unique. Any content chain signed by a DID can be correlated to the same identity. Users who require unlinkability across contexts should use distinct identities (distinct identity chains and DIDs) for each context.

### 7.2 Key Material

Identity chains contain only public keys. Private key material is never included in the chain and MUST NOT be transmitted during resolution.

### 7.3 Chain History

The full identity chain is available to any resolver. This reveals the history of key rotations, including timestamps (`createdAt`). Applications that consider key rotation history sensitive should be aware that this metadata is inherently public as part of the chain.

### 7.4 Herd Privacy

Because `did:dfos` resolution can happen through any transport (including local storage), a resolver does not necessarily reveal which DIDs it is interested in. However, when using a shared registry API, the registry operator can observe resolution patterns. Applications with strong privacy requirements SHOULD resolve chains through privacy-preserving transports or maintain local chain caches.

---

## 8. Reference Implementation

A complete reference implementation is available as the `@metalabel/dfos-protocol` npm package:

- **npm**: [@metalabel/dfos-protocol](https://www.npmjs.com/package/@metalabel/dfos-protocol)
- **Source**: [github.com/metalabel/dfos](https://github.com/metalabel/dfos)
- **Cross-language verification**: Go, Python, Rust, and Swift implementations verify the same deterministic test vectors

---

## 9. References

### 9.1 Normative References

| Reference                   | URI                                                 |
| --------------------------- | --------------------------------------------------- |
| W3C DID Core 1.0            | https://www.w3.org/TR/did-core/                     |
| W3C Multikey                | https://www.w3.org/TR/controller-document/#multikey |
| RFC 2119 (Key Words)        | https://www.rfc-editor.org/rfc/rfc2119              |
| RFC 7515 (JWS)              | https://www.rfc-editor.org/rfc/rfc7515              |
| RFC 8032 (Ed25519)          | https://www.rfc-editor.org/rfc/rfc8032              |
| DFOS Protocol Specification | [PROTOCOL.md](./PROTOCOL.md)                        |

### 9.2 Informative References

| Reference               | URI                                         |
| ----------------------- | ------------------------------------------- |
| W3C DID Spec Registries | https://w3c.github.io/did-spec-registries/  |
| Multicodec Table        | https://github.com/multiformats/multicodec  |
| CIDv1 Specification     | https://github.com/multiformats/cid         |
| dag-cbor Codec          | https://ipld.io/specs/codecs/dag-cbor/spec/ |

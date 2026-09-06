# DID Method: `did:dfos`

W3C DID method registration for DFOS identity chains. Ed25519 keys, self-certifying identifiers, resolution from a signed chain rather than a registry.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol) · [Protocol Specification](https://protocol.dfos.com/spec) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## 1. Scope

This document registers `did:dfos`. It defines the identifier syntax, the DID Document built from an identity's verified state, and the mapping of DID operations onto identity chain operations.

The mechanics underneath are specified in [PROTOCOL.md](https://protocol.dfos.com/spec) and are not restated here: canonical encoding and CIDs, the JWS envelope, identity chain signer validity, key possession, services, and the verification algorithm.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Method Name

The method name is `dfos`. A DID using this method MUST begin with the prefix `did:dfos:`.

---

## 3. Method-Specific Identifier

The method-specific identifier is a 31-character string derived from the genesis operation CID of an identity chain.

### 3.1 ABNF

```abnf
dfos-did       = "did:dfos:" dfos-id
dfos-id        = 31dfos-char
dfos-char      = "2" / "3" / "4" / "6" / "7" / "8" / "9" /
                 "a" / "c" / "d" / "e" / "f" / "h" / "k" /
                 "n" / "r" / "t" / "v" / "z"
```

The alphabet is 19 characters: `2346789acdefhknrtvz`. The identifier is exactly 31 characters, an identifier space of `19^31 ≈ 2^131.6`.

An identifier that does not match `dfos-id`, the exact 31-character form over this alphabet, is not a valid `did:dfos` identifier. Resolvers and verifiers MUST reject any operation that references, and any resolved state that yields, a `did:dfos` identifier of any other length or character set.

### 3.2 Derivation

The method-specific identifier is derived deterministically from the genesis identity operation:

```
1. Construct the genesis identity operation payload (type: "create")
2. Canonical-encode the payload as dag-cbor → CBOR bytes
3. Hash: SHA-256(CBOR bytes) → 32-byte digest
4. Construct CIDv1: [0x01, 0x71, 0x12, 0x20, ...32 digest bytes] → CID bytes
5. Hash the CID: SHA-256(CID bytes) → 32-byte digest
6. Encode: for each of the first 31 bytes → alphabet[byte % 19]
```

The resulting 31-character string is the method-specific identifier. The full DID is `did:dfos:` prepended to this string.

### 3.3 Example

```
Genesis CID bytes (hex): 017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69
SHA-256 of CID bytes:    c66d21f27dceea0b05534c225ad7018ac7d4dfded0609dcd18022a3739a5488c
First 31 bytes encoded:  cnnnft9f8a2rn938d6nkz38r847v2kr
DID:                     did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr
```

The worked example with key material, CBOR bytes, and CID construction is in [PROTOCOL.md](https://protocol.dfos.com/spec).

---

## 4. DID Document

A resolved `did:dfos` DID Document is constructed from the identity's **effective** state: the key state and services after the chain's last operation, with every key membership no possession proof covers excluded ([PROTOCOL.md → Key Possession](https://protocol.dfos.com/spec#key-possession)). A void membership is never a verification method. The document states the keys the chain proved, not the keys it listed.

### 4.1 DID Document Structure

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "controller": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "verificationMethod": [
    {
      "id": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
      "type": "Multikey",
      "controller": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
      "publicKeyMultibase": "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
    }
  ],
  "authentication": [
    "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe"
  ],
  "assertionMethod": [
    "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe"
  ],
  "capabilityInvocation": [
    "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe"
  ]
}
```

### 4.2 Verification Method Mapping

Identity chain operations declare three key sets. They map to W3C verification relationships as follows:

| Identity Chain Key Set | W3C Verification Relationship | Purpose                                                              |
| ---------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `authKeys`             | `authentication`              | Prove control of the DID (e.g., login, session establishment)        |
| `assertKeys`           | `assertionMethod`             | Issue verifiable assertions (e.g., sign content chain operations)    |
| `controllerKeys`       | `capabilityInvocation`        | Manage the DID itself (sign identity chain update/delete operations) |

Each effective key becomes a `verificationMethod` entry. The `id` is the DID URL `did:dfos:<id>#<keyId>`. The `type` is `Multikey`. The `publicKeyMultibase` is the W3C Multikey encoding (multicodec `0xed01` prefix + base58btc + `z` multibase prefix).

Key ids MUST be unique within a single key set on any operation that declares key sets (`create` or `update`); a verifier rejects a repeated id in the same usage section. The same key id MAY appear across different sets, and that is the common case: one key serving authentication, assertion, and control at once, as in the document above. Verification methods are keyed by DID URL, so a key id in several roles yields one `verificationMethod` entry referenced from each relationship.

### 4.3 Controller

The `controller` property is always the DID itself. Only keys in the identity chain's `controllerKeys` set sign operations that modify the chain.

### 4.4 Key Rotation

The DID Document reflects the state after the last operation of the chain, never a union across history. Rotated-out keys are absent from the document. Historical key states are recovered by walking the chain.

### 4.5 Services

Identity chain `create` and `update` operations MAY carry a controller-signed `services` array, the identity's discovery vocabulary, defined in [PROTOCOL.md → Services](https://protocol.dfos.com/spec#services).

Each entry in the effective state projects into the DID Document `service` array. The entry `id` becomes the DID URL fragment (`did:dfos:<id>#<entry-id>`). The namespace is open: a type this table does not name is preserved verbatim with its `id` re-anchored, and otherwise ignored.

| Service `type`            | Fields            | DID Document mapping                                           |
| ------------------------- | ----------------- | -------------------------------------------------------------- |
| `DfosRelay`               | `endpoint` (URL)  | `serviceEndpoint` = the relay URL                              |
| `DfosAuthorizationServer` | `endpoint` (URL)  | `serviceEndpoint` = the authorize origin                       |
| `ContentAnchor`           | `label`, `anchor` | `serviceEndpoint` = the anchor; `label` retained as a property |

```json
"service": [
  {
    "id": "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar#relay",
    "type": "DfosRelay",
    "serviceEndpoint": "https://relay.dfos.com"
  },
  {
    "id": "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar#profile",
    "type": "ContentAnchor",
    "label": "profile",
    "serviceEndpoint": "cv7n8vkvr64cctf3294h9k4eanhff8z"
  }
]
```

---

## 5. Operations

Each DID operation is one identity chain operation. The payload schemas, signer rules, and validity checks are in [PROTOCOL.md → Identity Operations](https://protocol.dfos.com/spec#identity-operations).

### 5.1 Create

Creating a `did:dfos` identifier means constructing and signing a genesis identity chain operation.

1. Generate one Ed25519 key pair.
2. Construct the genesis payload with `type: "create"`, declaring that one key as the sole entry of `authKeys`, `assertKeys`, and `controllerKeys`. Genesis declares exactly one key and its signature is that key's possession proof. Further keys join via `update` operations under the possession rule.
3. Sign the operation per PROTOCOL's JWS envelope.
4. The DID is derived from the genesis CID as in [Section 3.2](#32-derivation).

### 5.2 Read (Resolve)

Resolving a `did:dfos` DID means obtaining the identity chain and constructing a DID Document from its effective state.

#### 5.2.1 Resolution Algorithm

Given a DID `did:dfos:<id>`:

1. **Obtain** the identity chain. This method does not prescribe how chains are transported.
2. **Verify** the chain per [PROTOCOL.md → Verification](https://protocol.dfos.com/spec#verification): the genesis bootstrap, JWS signatures against the declared controller state, `previousOperationCID` linkage, `createdAt` ordering, `header.cid` consistency, and key possession.
3. **Bind** the chain to the DID: derive the genesis operation CID, and verify that `SHA-256(genesis CID bytes)` encoded with the ID alphabet produces `<id>`. If it does not match, the chain does not belong to this DID and the resolver MUST reject it.
4. **Construct** the DID Document from the effective state using the mapping in [Section 4](#4-did-document).

#### 5.2.2 Resolution Result

A resolver returns the DID Document with two metadata objects:

| Object                  | Property         | Value                                                    |
| ----------------------- | ---------------- | -------------------------------------------------------- |
| `didResolutionMetadata` | `contentType`    | `application/did+ld+json`                                |
| `didDocumentMetadata`   | `created`        | `createdAt` from the genesis operation                   |
| `didDocumentMetadata`   | `updated`        | `createdAt` from the most recent operation               |
| `didDocumentMetadata`   | `deactivated`    | `true` if the chain's last operation is `type: "delete"` |
| `didDocumentMetadata`   | `operationCount` | Number of operations in the chain                        |

#### 5.2.3 Self-Certification

Step 3 above is the self-certification check: it proves the chain belongs to the claimed DID using only the chain content and a hash function. A resolver therefore does not trust the server or peer that supplied the chain, the same chain served by independent sources yields the same document, and a chain held locally resolves offline.

#### 5.2.4 Resolution Is Relay-Relative

Authorship is verifiable without trusting any server. Which view of an identity you follow is a choice of relay.

A relay keeps its own identity log linear by first-seen admission: it admits the first operation it sees at a chain position and does not admit a second at that position. Two relays that admitted different operations at the same position hold two views of the same identity. Both views are controller-signed, and neither is invalid. Which relay you resolve through is which view you get.

A resolver that needs one answer picks one relay; an identity's `DfosRelay` service entries name relays that serve it. A resolver reading several relays sees the divergence and can present both views.

The chain itself is transport-agnostic: any source that delivers the ordered JWS tokens is a valid one, including an HTTP relay, a peer exchange, a local file, or an exported bundle. A relay serving the DIF Universal Resolver binding answers at `GET /1.0/identifiers/:did`; the route contract is in [WEB-RELAY.md](https://protocol.dfos.com/web-relay).

### 5.3 Update

Updating a `did:dfos` DID means appending a signed `update` operation: `type: "update"`, the new key sets, a `keyProofs` envelope for each key the operation introduces, and `previousOperationCID` set to the CID of the current chain tip, signed with a key from the current `controllerKeys` set.

The DID does not change. The resolved document reflects the new key sets.

### 5.4 Deactivate (Delete)

Deactivating a `did:dfos` DID means appending a signed `delete` operation, `previousOperationCID` set to the CID of the current chain tip, signed with a key from the current `controllerKeys` set.

After deactivation:

- Resolution MUST return `deactivated: true` in the document metadata, and the DID Document SHOULD contain an empty set of verification methods. The reference relays return an empty `verificationMethod` array and omit the verification relationships and services.
- The `delete` operation is a permanent, auditable fact of the log. It is replicated and retained like any other operation.
- The chain is sealed against every operation except one: a `restore` in the immediate successor position ([Section 5.5](#55-restore-undelete)). Any other operation from the deleted head is rejected.

A `restore` needs only a controller key of the deleted state, so deleting an identity is not a substitute for rotating out a compromised key. Rotate first, then delete.

### 5.5 Restore (Undelete)

Restoring a deactivated DID means appending a signed `restore` operation immediately after the `delete`: `type: "restore"` and `previousOperationCID` set to the CID of the `delete`, carrying nothing else beyond `version` and `createdAt`.

It is signed with a controller key of the deleted head state, the key state the `delete` produced, which carries the last key sets unchanged. A key rotated out before the delete is not in that state and cannot restore.

A valid `restore` clears the deactivated state: resolution reports `deactivated: false` and the document reflects the keys and services as of the delete, verbatim. Later changes happen via ordinary `update` operations. `restore` is valid only in the successor-of-delete position.

Deactivation is reversible by a controller key and only by a controller key. Both the `delete` and the `restore` stay in the log, so the deactivation history is auditable. There is no seal that a controller key cannot reopen.

---

## 6. Security Considerations

### 6.1 Self-Certifying Identifiers

The identifier is a hash of the genesis operation content, and resolution verifies that binding ([Section 5.2.3](#523-self-certification)). A chain that does not derive the claimed identifier is rejected.

The identifier is 31 characters over a 19-symbol alphabet:

```
Identifier space:         19^31 ≈ 2^131.6
Birthday collision:       ≈ 2^65.8
Targeted second-preimage: ≈ 2^131.6
```

These bound the identifier only. Finding two genesis chains that encode to the same DID costs `≈ 2^65.8`; forging a chain that encodes to a specific victim DID costs `≈ 2^131.6`. The 32-byte genesis CID and the Ed25519 signatures are unaffected by the truncation.

### 6.2 Key Compromise

A holder whose controller key is compromised signs an `update` removing that key. There is no key pre-rotation: nothing pre-commits to a future key. The window between compromise and rotation is open.

Each role set holds up to 256 keys and any one current key in a set authorizes an operation, so an identity can hold keys on several devices and a lost device is not loss of the identity. This is availability, not recovery: the extra keys are registered in advance, while a controller key is still held, and each one is another key to keep safe.

### 6.3 Who Can Extend a Chain

Every operation is signed by a controller key in the chain's declared state. Whoever holds a controller key can update, delete, and restore the identity. Where custody is split, for example an identity whose controller keys include one held by a hosting platform, each holder has that full power independently.

What no holder has is silence. Every extension is a signed operation in the log, addressed by CID and replicated by relays that have it, so a key removal or a deletion is visible to anyone reading the chain.

An identity chain has no consensus layer. Two operations signed at the same chain position are a divergence between relay views, handled as in [Section 5.2.4](#524-resolution-is-relay-relative), not a proof of invalidity.

### 6.4 Transport Security

This method mandates no transport security. Resolution verifies the chain against the DID rather than the source, so an intercepting attacker can withhold the chain, serve a stale chain, or serve a different chain that fails the self-certification check. It cannot produce a modified or forged chain that passes.

A resolver that depends on a single source can be denied service by that source. Applications SHOULD support several chain sources and MAY cache verified chains locally.

### 6.5 Algorithms

Ed25519 is the only signature algorithm. Implementations MUST reject operations signed with any other algorithm.

---

## 7. Privacy Considerations

### 7.1 Correlation

`did:dfos` identifiers are persistent and globally unique, so every content chain a DID signs is correlatable to it. Unlinkability across contexts comes from using distinct identities, each its own chain and DID.

### 7.2 Key Material

Identity chains carry public keys only. Private key material is never in the chain and MUST NOT be transmitted during resolution.

### 7.3 Chain History

The full chain is available to any resolver, including the history of key rotations and their timestamps. That metadata is public by construction.

### 7.4 Resolution Privacy

A resolver reading a local chain reveals nothing. A resolver reading a relay reveals to that operator which DIDs it is interested in. Applications with strong privacy requirements SHOULD resolve from local caches or through a privacy-preserving transport.

---

## 8. References

### 8.1 Normative References

| Reference                   | URI                                                 |
| --------------------------- | --------------------------------------------------- |
| W3C DID Core 1.0            | https://www.w3.org/TR/did-core/                     |
| W3C Multikey                | https://www.w3.org/TR/controller-document/#multikey |
| RFC 2119 (Key Words)        | https://www.rfc-editor.org/rfc/rfc2119              |
| RFC 7515 (JWS)              | https://www.rfc-editor.org/rfc/rfc7515              |
| RFC 8032 (Ed25519)          | https://www.rfc-editor.org/rfc/rfc8032              |
| DFOS Protocol Specification | https://protocol.dfos.com/spec                      |

### 8.2 Informative References

| Reference                   | URI                                                                  |
| --------------------------- | -------------------------------------------------------------------- |
| W3C DID Spec Registries     | https://w3c.github.io/did-spec-registries/                           |
| Multicodec Table            | https://github.com/multiformats/multicodec                           |
| CIDv1 Specification         | https://github.com/multiformats/cid                                  |
| dag-cbor Codec              | https://ipld.io/specs/codecs/dag-cbor/spec/                          |
| Reference implementation    | https://www.npmjs.com/package/@metalabel/dfos-protocol               |
| Cross-language verification | https://github.com/metalabel/dfos/tree/main/packages/protocol-verify |

# DFOS Credentials

UCAN-style authorization credentials for the DFOS protocol. Replaces VC-JWTs with a simpler, more powerful model: CID-addressable JWS tokens with embedded delegation chains, monotonic attenuation enforcement, and first-class public credential semantics.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/credentials) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Overview

DFOS credentials are signed authorization tokens. They answer the question: "does this DID have permission to do this thing?" A credential is a JWS-encoded payload where the issuer grants the audience specific permissions over specific resources, with an expiry.

Two mechanisms from UCAN make credentials composable:

1. **Delegation chains** — a credential can embed its parent credential(s) in a `prf` (proof) field, forming a verifiable chain of authority from a root issuer down to the leaf holder.
2. **Monotonic attenuation** — each hop in a delegation chain can only narrow scope, never widen it. Fewer resources, fewer actions, shorter expiry.

Credentials are content-addressed via CID (same `dagCborCanonicalEncode` + SHA-256 scheme as all protocol objects). The CID appears in the JWS header, making each credential a stable, revocable artifact.

### Why Not VC-JWTs

The prior credential format (W3C VC-JWT, `typ: "vc+jwt"`) carried unnecessary complexity for the protocol's needs: the `vc` wrapper object, `@context` arrays, `credentialSubject` nesting. DFOS credentials flatten this into a direct payload with explicit resource/action pairs and native delegation support. The VC-JWT format has been fully replaced — no backward compatibility is maintained.

---

## Schema

### DFOSCredentialPayload

The credential payload is validated by a strict Zod schema. No extra fields are permitted.

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "aud": "did:dfos:nzkf838efr424433rn2rzk",
  "att": [{ "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "write" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

| Field     | Type               | Description                                        |
| --------- | ------------------ | -------------------------------------------------- |
| `version` | `1`                | Schema version (literal `1`)                       |
| `type`    | `"DFOSCredential"` | Literal discriminator                              |
| `iss`     | string             | Issuer DID — the authority granting permission     |
| `aud`     | string             | Audience DID, or `"*"` for public credentials      |
| `att`     | Attenuation[]      | Resource + action pairs (min 1, max 32)            |
| `prf`     | string[]           | Parent credential JWS tokens (max 8, default `[]`) |
| `exp`     | number             | Expiration — unix seconds (positive integer)       |
| `iat`     | number             | Issued-at — unix seconds (positive integer)        |

### Attenuation Entry

Each attenuation entry is a strict object with two fields:

```json
{ "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "write" }
```

| Field      | Type   | Max | Description                            |
| ---------- | ------ | --- | -------------------------------------- |
| `resource` | string | 512 | Resource identifier (`type:id` format) |
| `action`   | string | 64  | Comma-separated action list            |

### Field Limits

| Field      | Limit     | Rationale                          |
| ---------- | --------- | ---------------------------------- |
| `iss`      | 256 chars | ~8x typical `did:dfos:` length     |
| `aud`      | 512 chars | Relay hostnames or `"*"`           |
| `resource` | 512 chars | Resource type + content ID         |
| `action`   | 64 chars  | Comma-separated action names       |
| `att`      | 32 items  | Generous for multi-resource grants |
| `prf`      | 8 items   | Multi-parent delegation support    |

### CID Derivation

The credential payload is content-addressed using the same scheme as all protocol objects:

```
dagCborCanonicalEncode(payload) -> SHA-256 -> CIDv1 (dag-cbor + SHA-256)
```

The resulting CID is embedded in the JWS protected header as `cid`. This makes the credential a stable, addressable artifact — used for revocation references and audit trails.

**CID integrity check:** During verification, the payload is re-encoded and the derived CID is compared against the `cid` header value. Mismatch is a verification failure.

### JWS Encoding

The credential is signed as a JWS Compact Serialization token (`header.payload.signature`). The payload is JSON-encoded (not dag-cbor) in the JWS body, following standard JWS conventions. dag-cbor is used only for CID derivation.

---

## JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:credential",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8",
  "cid": "bafyrei..."
}
```

| Field | Value                   | Description                                          |
| ----- | ----------------------- | ---------------------------------------------------- |
| `alg` | `"EdDSA"`               | Ed25519 signature algorithm                          |
| `typ` | `"did:dfos:credential"` | Protocol-specific type discriminator                 |
| `kid` | DID URL                 | `did:dfos:<id>#<keyId>` — identifies the signing key |
| `cid` | CID string              | Content address of the payload (for revocation)      |

**kid format:** The `kid` MUST be a DID URL containing `#`. The DID portion (before `#`) MUST match the `iss` field in the payload. The key fragment (after `#`) identifies which key on the issuer's identity was used to sign.

**Key resolution:** The signing key is resolved from the issuer's identity chain using **historical key resolution** — all keys that have ever appeared in the identity chain's create and update operations are considered valid signing keys, not just the current state. This means credentials survive key rotation: a credential signed before a key rotation remains valid even after the signing key is no longer in the issuer's current state. Revocation (not key rotation) is the invalidation mechanism for credentials. Any key role (auth, assert, controller) is accepted — the protocol does not restrict which key role may sign credentials.

This is distinct from auth tokens, which use **current-state-only** key resolution (rotated-out keys are immediately rejected). The difference reflects the different lifetimes: auth tokens are ephemeral (minutes), while credentials are long-lived (hours to months) and their validity is managed through explicit revocation.

---

## Delegation Chains

Delegation chains enable transitive authorization. A root authority issues a credential to an intermediary, who can then issue a narrower credential to a downstream party, embedding the parent credential as proof.

### `prf` Semantics

The `prf` field contains an array of full JWS compact tokens — the complete parent credentials, not references or CIDs. This makes each credential self-contained: a verifier can walk the entire chain without external lookups (beyond identity resolution).

- `prf: []` — root credential. The issuer is the original authority.
- `prf: ["<parent JWS>"]` — delegated credential. The parent credential proves the issuer was authorized.
- `prf: ["<parent1>", "<parent2>"]` — multi-parent. The child's attenuations are checked against the union of all parents' attenuations.

### Verification Walk

Chain verification proceeds from the leaf credential upward:

1. **Verify the leaf credential** — signature, schema, expiry, CID integrity.
2. **Verify each parent in `prf`** — same checks, recursively.
3. **Audience linkage** — the child's `iss` MUST match at least one parent's `aud` (or the parent's `aud` MUST be `"*"`). This prevents a DID from using a credential not addressed to it.
4. **Expiry narrowing** — the child's `exp` MUST NOT exceed any parent's `exp`.
5. **Attenuation check** — the child's `att` MUST be a valid attenuation of the union of all parents' `att` (see [Attenuation Rules](#attenuation-rules)).
6. **Root check** — when a credential has `prf: []`, its `iss` MUST equal the expected root DID (e.g., the content chain creator).

**Depth limit:** Maximum 16 hops. Chains deeper than 16 are rejected.

**Linear walk:** For multi-parent credentials, all parents are verified, but the chain walk continues through the first parent. All parents contribute to the attenuation union.

**Revocation at every level:** Relays SHOULD check revocation at every level of the delegation chain, not just the leaf credential. A revoked intermediate credential invalidates all downstream delegations rooted through it.

---

## Attenuation Rules

Every delegation hop enforces monotonic attenuation. The child credential's scope MUST be a subset of the parent's scope. Two dimensions are attenuated independently: resources and actions.

### Scope Narrowing

Every entry in the child's `att` array must be covered by at least one entry in the parent's `att` array (or the union of all parents' `att` arrays for multi-parent chains).

Valid narrowing examples:

- Parent grants `chain:X` and `chain:Y` -- child requests only `chain:X` (subset of resources)
- Parent grants `read,write` -- child requests only `read` (subset of actions)
- Parent grants `manifest:M` -- child requests `chain:X` (type narrowing, see below)

Invalid widening:

- Parent grants `chain:X` -- child requests `chain:X` and `chain:Y` (new resource)
- Parent grants `read` -- child requests `read,write` (new action)
- Parent grants `chain:X` -- child requests `manifest:M` (type widening)

### Action Coverage

Actions are comma-separated strings. The child's action set must be a subset of the parent's action set for the matched resource entry.

### Expiry Narrowing

The child's `exp` MUST be less than or equal to every parent's `exp`. A delegated credential cannot outlive its authority.

---

## Resource Types

Two resource types are defined. Both use the `type:id` format.

### `chain:<contentId>` -- Exact Match

Grants access to a specific content chain identified by its 22-character content ID.

```json
{ "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "write" }
```

Matching: `chain:X` matches only `chain:X`. Exact content ID comparison.

### `chain:*` -- Wildcard Match

Grants access to all content chains owned by the credential's root authority. The wildcard covers all present and future content without enumerating specific chain IDs.

```json
{ "resource": "chain:*", "action": "read" }
```

Matching: `chain:*` matches any `chain:<contentId>` request for content where the delegation chain roots at the expected creator DID.

This is the broadest resource scope. Common use case: granting a collaborator access to all of a creator's content without maintaining an exhaustive manifest.

### `manifest:<contentId>` -- Transitive Match

Grants access to a manifest and all content chains it indexes. A manifest is itself a content chain whose document lists other content IDs.

```json
{ "resource": "manifest:k4f9t2r6v8n3h7d2c9a4e6", "action": "write" }
```

Matching at the relay:

- `manifest:M` matches a request for `manifest:M` (exact)
- `manifest:M` matches a request for `chain:X` IF a manifest lookup confirms that content ID `X` is indexed by manifest `M`
- Without a manifest lookup callback, `manifest:` resources can only match exact `manifest:` requests

### Attenuation Between Types

| Parent       | Child        | Valid? | Reason                                    |
| ------------ | ------------ | ------ | ----------------------------------------- |
| `chain:*`    | `chain:*`    | Yes    | Exact match                               |
| `chain:*`    | `chain:X`    | Yes    | Narrowing from wildcard to specific chain |
| `chain:*`    | `manifest:M` | Yes    | Narrowing from wildcard to manifest       |
| `chain:X`    | `chain:X`    | Yes    | Exact match                               |
| `manifest:M` | `manifest:M` | Yes    | Exact match                               |
| `manifest:M` | `chain:X`    | Yes    | Narrowing from manifest to specific chain |
| `chain:X`    | `chain:*`    | No     | Widening from specific to wildcard        |
| `chain:X`    | `manifest:M` | No     | Widening from chain to manifest           |
| `manifest:M` | `chain:*`    | No     | Widening from manifest to wildcard        |

The resource hierarchy from broadest to narrowest is: `chain:*` > `manifest:M` > `chain:X`. Each delegation hop can only move down this hierarchy, never up.

The `manifest -> chain` narrowing is valid structurally during delegation chain verification. The actual membership check (does manifest M contain chain X?) happens at the relay during resource matching, not during chain verification.

---

## Public Credentials

### `aud: "*"` Semantics

A credential with `aud` set to `"*"` is a **public credential**. It is not addressed to a specific DID -- it is a standing authorization that anyone can use.

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "aud": "*",
  "att": [{ "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "read" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

### Relay Ingestion

Public credentials are ingested into the relay and stored as standing authorizations. When a request arrives for a resource, the relay checks its stored public credentials for matching `att` entries. The caller does not need to present the credential per-request -- the relay already has it.

### Private Credentials

A credential with a specific DID as `aud` is a **private credential**. It is presented per-request by the holder. The relay does not store it -- the holder includes it with each request that requires authorization.

### Delegation Chain Interaction

A parent credential with `aud: "*"` satisfies the audience linkage check for any child issuer. This means a public credential can serve as a parent in a delegation chain -- any DID can issue a narrower child credential using the public credential as proof.

---

## Revocation

### Revocation Artifact

A revocation is a standalone signed artifact that permanently invalidates a credential. It uses the artifact type `did:dfos:revocation`.

**JWS Header:**

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:revocation",
  "kid": "did:dfos:e3vvtck42d4eacdnzvtrn6#key_r9ev34fvc23z999veaaft8",
  "cid": "bafyrei..."
}
```

**Payload:**

```json
{
  "version": 1,
  "type": "revocation",
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "credentialCID": "bafyrei...",
  "createdAt": "2026-03-07T00:00:00.000Z"
}
```

| Field           | Type           | Description                         |
| --------------- | -------------- | ----------------------------------- |
| `version`       | `1`            | Schema version (literal `1`)        |
| `type`          | `"revocation"` | Literal discriminator               |
| `did`           | string         | Issuer DID revoking the credential  |
| `credentialCID` | CID            | CID of the credential being revoked |
| `createdAt`     | string         | ISO 8601 timestamp                  |

### Rules

- **Issuer-only.** Only the credential's issuer DID can revoke it. The `kid` DID in the JWS header MUST match the `did` field in the payload.
- **Permanent.** There is no un-revoke operation. To restore access, issue a new credential.
- **CID-addressed.** The revocation artifact itself has a CID (derived from the payload, embedded in the header), making it a content-addressable artifact.
- **Gossiped.** Revocations are propagated across the relay network like beacons.

### Relay Enforcement

Relays maintain a revocation set keyed by `(issuerDID, credentialCID)`. During credential verification, the relay checks whether the credential's CID appears in the revocation set for that credential's issuer. This scoping prevents a rogue DID from revoking credentials it did not issue. A revoked credential fails verification regardless of its expiry or signature validity.

---

## Relationship to Auth Tokens

The credential system serves a different purpose than auth tokens. Both are DID-signed JWTs using Ed25519, but they answer different questions.

| Concern           | Auth Token                           | DFOS Credential                             |
| ----------------- | ------------------------------------ | ------------------------------------------- |
| Question answered | "Does this caller control this DID?" | "Does this DID have permission to do this?" |
| Role              | AuthN (authentication)               | AuthZ (authorization)                       |
| JWS `typ`         | `JWT`                                | `did:dfos:credential`                       |
| Lifetime          | Short (minutes)                      | Long (hours to months)                      |
| Audience          | Relay hostname (prevents replay)     | Specific DID or `"*"`                       |
| Content-addressed | No (`cid` not in header)             | Yes (`cid` in header)                       |
| Revocable         | No (short-lived, expires naturally)  | Yes (via revocation artifact)               |
| Delegation        | None                                 | Via `prf` chains                            |
| Key resolution    | Current-state only                   | Historical (survives key rotation)          |

A typical relay request flow:

1. **Auth token** proves the caller controls a DID (AuthN).
2. **Credential** proves the DID has access to the requested resource (AuthZ).

Auth tokens are ephemeral session tokens -- they establish identity. Credentials are durable authorization grants -- they establish access rights.

---

## Worked Examples

### Simple Credential

Alice (`did:dfos:alice...`) grants Bob (`did:dfos:bob...`) write access to a content chain:

```json
// JWS Header
{
  "alg": "EdDSA",
  "typ": "did:dfos:credential",
  "kid": "did:dfos:alice...#key_abc",
  "cid": "bafyrei..."
}

// JWS Payload
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:alice...",
  "aud": "did:dfos:bob...",
  "att": [
    { "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "write" }
  ],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

Alice is the root authority (`prf: []`). Bob presents this credential to a relay when writing to content chain `a82z92a3hndk6c97thcrn8`. The relay verifies Alice's signature, confirms the credential is not expired or revoked, and checks that the requested resource and action match an `att` entry.

### 2-Hop Delegation

A space DID grants a member write access, and the member delegates to their device:

```
Space (root) -> Member -> Device (leaf)
```

**Hop 1 -- Space issues root credential to Member:**

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:space...",
  "aud": "did:dfos:member...",
  "att": [{ "resource": "chain:content1", "action": "write" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

**Hop 2 -- Member delegates to Device (with narrower expiry):**

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:member...",
  "aud": "did:dfos:device...",
  "att": [{ "resource": "chain:content1", "action": "write" }],
  "prf": ["<full JWS from Hop 1>"],
  "exp": 1796169600,
  "iat": 1772841600
}
```

Verification walk for the Device's credential:

1. Verify Device credential signature (signed by Member).
2. Verify parent in `prf` (signed by Space).
3. Audience linkage: Device credential's `iss` (`member`) matches parent's `aud` (`member`).
4. Expiry: Device credential's `exp` does not exceed parent's `exp`.
5. Attenuation: `chain:content1/write` is covered by parent's `chain:content1/write`.
6. Parent has `prf: []` -- it is the root. Parent's `iss` (`space`) must match the expected root DID.

### Public Credential

A space DID issues a public read credential for a content chain. Any DID can read without presenting the credential per-request:

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:space...",
  "aud": "*",
  "att": [{ "resource": "chain:a82z92a3hndk6c97thcrn8", "action": "read" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

This credential is ingested by the relay as a standing authorization. When any authenticated caller requests read access to `chain:a82z92a3hndk6c97thcrn8`, the relay matches it against stored public credentials. No per-request credential presentation needed.

Because `aud` is `"*"`, any DID can also use this credential as a parent in a delegation chain -- e.g., to issue a narrower credential to a specific collaborator with a shorter expiry.

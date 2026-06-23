# DFOS Credentials

UCAN-style authorization credentials for the DFOS protocol. Replaces VC-JWTs with a simpler, more powerful model: CID-addressable JWS tokens with embedded delegation chains, monotonic attenuation enforcement, and first-class public credential semantics.

> **Status — Protocol v1: feature-complete and frozen.** The credential model — the JWS envelope, linear delegation, monotonic attenuation, revocation, and the validity bounds — is **frozen** as part of the v1 surface; build on it as specified. Per the [core protocol status](https://protocol.dfos.com/spec), v1 is frozen but not yet final: clarifications are corrected in place and new capability lands additively, while a genuine break to a frozen field becomes v1.1 or v2 — never a silent edit. The reference packages stay on their own `0.x` semver line. Discuss in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/credentials) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Overview

DFOS credentials are signed authorization tokens. They answer the question: "does this DID have permission to do this thing?" A credential is a JWS-encoded payload where the issuer grants the audience specific permissions over specific resources, with an expiry.

Two mechanisms from UCAN make credentials composable:

1. **Delegation chains** — a credential can embed its parent credential in a `prf` (proof) field, forming a verifiable linear chain of authority from a root issuer down to the leaf holder.
2. **Monotonic attenuation** — each hop in a delegation chain can only narrow scope, never widen it. Fewer resources, fewer actions, shorter expiry.

Credentials are content-addressed via CID (same `dagCborCanonicalEncode` + SHA-256 scheme as all protocol objects). The CID appears in the JWS header, making each credential a stable, revocable artifact.

---

## Schema

### DFOSCredentialPayload

The credential payload is validated against the schema below. Unknown top-level fields are preserved-and-ignored (forward-compat, per the protocol's MUST-ignore-unknown rule), not rejected; the CID still commits to the exact bytes.

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "aud": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae",
  "att": [{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

| Field     | Type               | Description                                                               |
| --------- | ------------------ | ------------------------------------------------------------------------- |
| `version` | `1`                | Schema version (literal `1`)                                              |
| `type`    | `"DFOSCredential"` | Literal discriminator                                                     |
| `iss`     | string             | Issuer DID — the authority granting permission                            |
| `aud`     | string             | Audience DID, or `"*"` for public credentials                             |
| `att`     | Attenuation[]      | Resource + action pairs (min 1, max 32)                                   |
| `prf`     | string[]           | Parent credential JWS token — at most 1 (linear delegation), default `[]` |
| `exp`     | number             | Expiration — unix seconds (positive integer)                              |
| `iat`     | number             | Issued-at — unix seconds (positive integer)                               |

### Attenuation Entry

Each attenuation entry is an object with two non-empty string fields:

```json
{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }
```

| Field      | Type   | Description                            |
| ---------- | ------ | -------------------------------------- |
| `resource` | string | Resource identifier (`type:id` format) |
| `action`   | string | Comma-separated action list            |

### Size and Cardinality Limits

A credential is bounded by **one aggregate size cap** plus a small set of **cardinality caps** — not a per-field string-length table. The validity rules that `iss`, `aud`, `resource`, and `action` participate in (issuer-key resolution, `aud → iss` delegation linkage, attenuation subset coverage) are enforced directly and identically in both implementations, so no per-field length cap is needed — and a per-field cap would only risk forking validity across implementations.

**Aggregate credential size:**

| Bound                | Value                      | Applies to                |
| -------------------- | -------------------------- | ------------------------- |
| credential JWS token | **262144 bytes** (256 KiB) | the serialized credential |

Verifiers MUST reject a credential whose serialized JWS token exceeds 262144 bytes, checked before any decode. The leaf token embeds the entire nested delegation chain (each parent is carried verbatim in `prf`), so this single cap bounds the whole chain. Credentials carry their own ceiling — larger than the 64 KiB operation cap ([PROTOCOL.md](https://protocol.dfos.com/spec)) — precisely because a maximum-depth delegation chain legitimately exceeds 64 KiB; the credential is exempt from the operation cap and bounded by this one instead.

**Cardinality caps:**

| Field | Max      | Rationale                                                                          |
| ----- | -------- | ---------------------------------------------------------------------------------- |
| `att` | 32 items | Generous for multi-resource grants; min 1 (a zero-`att` credential grants nothing) |
| `prf` | 1 item   | Single-parent (linear) delegation                                                  |

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
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
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
- `prf: ["<parent JWS>"]` — delegated credential. The single parent credential proves the issuer was authorized.

**Delegation is linear (single-parent).** A credential's `prf` MUST contain at most one entry. Verifiers MUST reject any credential whose `prf` has more than one element. (A prior union-of-authority model — attenuating the child against the _union_ of multiple parents while rooting the walk through only the first — allowed a self-issued secondary parent to contribute authority that was never rooted at the expected creator, an authority-escalation. Linear delegation removes the class entirely.)

### Verification Walk

Chain verification proceeds from the leaf credential upward:

1. **Verify the leaf credential** — signature, schema, expiry, CID integrity.
2. **Reject multi-parent** — if `prf` has more than one entry, reject.
3. **Verify the parent in `prf`** — same checks, recursively.
4. **Audience linkage** — the child's `iss` MUST match the parent's `aud` (or the parent's `aud` MUST be `"*"`). This prevents a DID from using a credential not addressed to it.
5. **Expiry narrowing** — the child's `exp` MUST NOT exceed the parent's `exp`.
6. **Attenuation check** — the child's `att` MUST be a valid attenuation of the parent's `att` (see [Attenuation Rules](#attenuation-rules)).
7. **Root check** — when a credential has `prf: []`, its `iss` MUST equal the expected root DID (e.g., the content chain creator).

**Depth limit:** A delegation chain MUST contain at most **16 credentials**, counting the leaf and the root inclusive (i.e. at most 15 delegation hops). A verifier walks from the leaf (counted as the first credential) toward the root; the **17th credential is rejected** ("delegation chain too deep"). This boundary is exact and normative — verifiers MUST agree on it (a verifier that accepts a 17-credential chain forks authorization validity). Conformance: a 16-credential chain verifies; a 17-credential chain is rejected.

**Revocation at every level:** Revocation is checked at every level of the delegation chain — the leaf credential AND each parent — not just the leaf (MUST — see Revocation / Relay Enforcement).

---

## Attenuation Rules

Every delegation hop enforces monotonic attenuation. The child credential's scope MUST be a subset of the parent's scope. Two dimensions are attenuated independently: resources and actions.

### Scope Narrowing

Every entry in the child's `att` array must be covered by at least one entry in the parent's `att` array.

Valid narrowing examples:

- Parent grants `chain:X` and `chain:Y` -- child requests only `chain:X` (subset of resources)
- Parent grants `read,write` -- child requests only `read` (subset of actions)
- Parent grants `chain:*` -- child requests `chain:X` (wildcard to specific)

Invalid widening:

- Parent grants `chain:X` -- child requests `chain:X` and `chain:Y` (new resource)
- Parent grants `read` -- child requests `read,write` (new action)
- Parent grants `chain:X` -- child requests `chain:*` (specific to wildcard)

### Action Coverage

An action is a **comma-separated list** of action tokens. To compare two action
strings, each is **canonicalized to a set** of tokens by the following rules,
applied identically by every verifier:

1. **Split on comma** (`,`).
2. **Trim** ASCII leading/trailing whitespace from each element.
3. **Drop empty elements.** An element that is empty after trimming contributes
   nothing to the set. Leading, trailing, and doubled commas are therefore
   insignificant — `read`, `read,`, `,read`, and `read,,read` all canonicalize
   to `{read}`.
4. **Collect into a set.** Order and duplication are insignificant; `write,read`
   and `read,write` both canonicalize to `{read, write}`.
5. **Compare tokens by exact, case-sensitive byte equality.** `read` and `Read`
   are distinct actions. There is **no action wildcard** — a `*` token is an
   ordinary, literal action token, not a match-all.

The child's canonical action set MUST be a **subset** of the parent's canonical
action set for the matched resource entry. Equivalently, every token in the
child's set MUST appear in the parent's set.

| Parent action | Child action  | Canonical child set | Covered? |
| ------------- | ------------- | ------------------- | -------- |
| `read,write`  | `read`        | `{read}`            | Yes      |
| `read,write`  | `write,read`  | `{read, write}`     | Yes      |
| `read,write`  | `read,,write` | `{read, write}`     | Yes      |
| `write`       | `write,`      | `{write}`           | Yes      |
| `read`        | `read,write`  | `{read, write}`     | No       |
| `read`        | `Read`        | `{Read}`            | No       |

**Empty action set (canonical bottom).** An action string that canonicalizes to
the empty set `{}` (e.g. `""` or `","`) is the bottom of the action lattice: it
is **vacuously a subset of any parent set**, so it never widens scope and passes
the attenuation check, but it **grants nothing** — a request always carries a
concrete action token, which is never a member of `{}`, so an `att` entry with
an empty action set authorizes no operation. Such an entry is inert, not
separately rejected.

### Expiry Narrowing

The child's `exp` MUST be less than or equal to every parent's `exp`. A delegated credential cannot outlive its authority.

### Expiry Basis (Normative)

`exp` is **signer-discretionary**: the issuer chooses how long a credential is valid, and there is no protocol-imposed maximum in v1. Verifiers compare `exp` against a **deterministic time basis**, NOT a free-running wall clock:

- **At ingest** (a delegated content operation carrying an inline `authorization`): `exp` is compared against the operation's own `createdAt`. A relay MUST NOT add an ingest-time wall-clock `exp` check. Each relay reads its own clock at a different instant, so a wall-clock check would make ingest verdicts diverge across relays and break convergence — the same content op would be accepted on one relay and rejected on another.
- **At read** (standing authorization / per-request credential checks): `exp` is compared against the current time, because reads are local, ephemeral decisions that never enter the replicated log.

#### Time Basis Conversion and Boundaries (Normative)

The ingest time basis is derived from the operation's `createdAt` (an ISO-8601, millisecond-precision, UTC string) by converting to **integer Unix seconds**:

```
now_s = floor(createdAt_epoch_ms / 1000)
```

where `createdAt_epoch_ms` is the number of milliseconds since the Unix epoch parsed from the `createdAt` string. The conversion MUST truncate (floor) the millisecond remainder; it MUST NOT round. For the `.000Z` millisecond form used by all conforming operations this is exact, but implementations MUST floor unconditionally so that any sub-second component is discarded rather than rounded up.

A credential's `iat` and `exp` are integer Unix seconds (JWT `NumericDate`). At ingest, a credential is temporally authorized **if and only if**:

```
iat <= now_s  AND  now_s < exp
```

This is the half-open interval `[iat, exp)`. The two boundaries are not symmetric and MUST be enforced exactly as stated:

- **`iat` boundary is inclusive (open-accepting).** A credential MUST be accepted when `iat == now_s`. A credential MUST be rejected as not-yet-valid only when `iat > now_s`.
- **`exp` boundary is exclusive (closed-rejecting).** A credential MUST be rejected as expired when `exp <= now_s`, including the exact instant `exp == now_s`. A credential is temporally valid only while `now_s < exp`.

Conversely, an `exp` strictly greater than `now_s` (i.e. in the future relative to the operation's `createdAt`) MUST be accepted on the temporal check — even if that `exp` is already in the past relative to the verifier's own wall clock.

This conversion and these boundaries are evaluated against the operation's `createdAt`, never against the verifier's wall clock (see the ingest bullet above). Two relays processing the same content operation therefore reach the same temporal verdict regardless of when each one ingests it.

Revocation — not expiry — is the **timely lever** for invalidating a credential ahead of its natural expiry (see Revocation, below). A relay MAY additionally enforce a local maximum-age policy as **relay policy** (rejecting credentials whose `exp` is implausibly far in the future), but this is post-v1 and out of scope for the wire protocol; v1 defines no maximum-`exp` cap.

---

## Resource Types

Two resource forms are defined. Both use the `chain:` prefix.

### `chain:<contentId>` -- Exact Match

Grants access to a specific content chain identified by its 31-character content ID.

```json
{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }
```

Matching: `chain:X` matches only `chain:X`. Exact content ID comparison.

### `chain:*` -- Wildcard Match

Grants access to all content chains owned by the credential's root authority. The wildcard covers all present and future content without enumerating specific chain IDs.

```json
{ "resource": "chain:*", "action": "read" }
```

Matching: `chain:*` matches any `chain:<contentId>` request for content where the delegation chain roots at the expected creator DID.

This is the broadest resource scope. Common use case: granting a collaborator access to all of a creator's content.

### Attenuation Between Forms

| Parent    | Child     | Valid? | Reason                                    |
| --------- | --------- | ------ | ----------------------------------------- |
| `chain:*` | `chain:*` | Yes    | Exact match                               |
| `chain:*` | `chain:X` | Yes    | Narrowing from wildcard to specific chain |
| `chain:X` | `chain:X` | Yes    | Exact match                               |
| `chain:X` | `chain:*` | No     | Widening from specific to wildcard        |

The resource hierarchy from broadest to narrowest is: `chain:*` > `chain:X`. Each delegation hop can only move down this hierarchy, never up.

---

## Public Credentials

### `aud: "*"` Semantics

A credential with `aud` set to `"*"` is a **public credential**. It is not addressed to a specific DID -- it is a standing authorization that anyone can use.

```json
{
  "version": 1,
  "type": "DFOSCredential",
  "iss": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "aud": "*",
  "att": [{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "read" }],
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

### Security: `aud: "*"` + write = a world-writable bearer grant

Because `aud: "*"` matches **any** operation signer, a public credential that grants a **write** action is a **bearer token anyone can present**. Any DID can attach the public credential inline as a content operation's `authorization` field and author writes to the covered chain(s) — the credential authorizes the bearer, not a named audience. A public `chain:*` write credential is effectively world-writable across every chain rooted at the issuer.

Public credentials SHOULD therefore be **read-scoped**. Reserve `write` (and `chain:*`) for **private** credentials with a specific `aud`, where the relay also verifies that the operation signer matches the audience. If a public write credential is issued and later regretted, revocation is the remedy — but the exposure window is every relay that ingested it.

---

## Revocation

### Revocation Artifact

A revocation is a standalone signed artifact that permanently invalidates a credential. It uses the artifact type `did:dfos:revocation`.

**JWS Header:**

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:revocation",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

**Payload:**

```json
{
  "version": 1,
  "type": "revocation",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
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
- **Gossiped.** Revocations are propagated across the relay network on the proof plane like any other signed operation.

### Relay Enforcement

Relays maintain a revocation set keyed by `(issuerDID, credentialCID)`. During credential verification, the relay checks whether the credential's CID appears in the revocation set for that credential's issuer. This scoping prevents a rogue DID from revoking credentials it did not issue. A revoked credential fails verification regardless of its expiry or signature validity.

Revocation MUST be checked at **every level** of a presented credential — the **leaf** credential AND each **parent** in its delegation chain. Checking only parents is insufficient: a revoked leaf credential, if its leaf-level revocation is not checked, would still authorize access. This applies to **both** authorization surfaces: the **read/route** path (standing authorization and per-request credential checks) and the **write** path (the inline `authorization` on a delegated content operation, verified at ingest). Without an explicit leaf check on the write path, revocation is not a timely lever for the leaf case.

### Revocation Scope

Revocation is **forward-looking**: it prevents future use of a credential but does not retroactively invalidate operations already committed to the content chain. Once a delegated content operation (create, update, delete) has been ingested and verified by a relay, revoking the authorizing credential does not undo that operation — the operation is permanently part of the content chain's log.

This is consistent with the content chain's append-only semantics: operations are immutable once committed. Revocation controls future access (standing authorization checks, per-request credential verification) but not the historical record.

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
    { "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }
  ],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

Alice is the root authority (`prf: []`). Bob presents this credential to a relay when writing to content chain `cv7n8vkvr64cctf3294h9k4eanhff8z`. The relay verifies Alice's signature, confirms the credential is not expired or revoked, and checks that the requested resource and action match an `att` entry.

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
  "att": [{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "read" }],
  "prf": [],
  "exp": 1798761600,
  "iat": 1772841600
}
```

This credential is ingested by the relay as a standing authorization. When any caller requests read access to `chain:cv7n8vkvr64cctf3294h9k4eanhff8z`, the relay matches it against stored public credentials — no auth token or per-request credential needed.

Because `aud` is `"*"`, any DID can also use this credential as a parent in a delegation chain -- e.g., to issue a narrower credential to a specific collaborator with a shorter expiry.

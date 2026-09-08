# DFOS Credentials

Authorization credentials for the DFOS protocol: CID-addressable JWS tokens that carry a resource grant, a linear delegation chain, and an expiry. They answer one question, "does this DID have permission to do this thing?", and they are the artifact a non-creator presents to write a content chain or to read a gated resource.

The shape is [UCAN](https://github.com/ucan-wg/spec) 0.10's: a compact-JWS token whose payload carries `att` attenuations and a `prf` proof chain. Three deltas from UCAN are deliberate. `prf` carries at most one parent, so delegation is linear. There is no `nnc`, `fct`, or `nbf` member: a credential is a standing grant, request binding is the API request proof's job, and `exp` against the basis time is the whole temporal window. Revocation is a first-class signed artifact on the proof plane.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/credentials) · [npm](https://www.npmjs.com/package/@metalabel/dfos-protocol)

---

## Overview

Two mechanisms make credentials composable:

1. **Delegation chains.** A credential embeds its parent credential in its `prf` field, forming a verifiable linear chain of authority from a root issuer down to the leaf holder.
2. **Monotonic attenuation.** Each hop in a delegation chain narrows scope and never widens it: fewer resources, fewer actions, shorter expiry.

Credentials are content-addressed via CID, using the same `dagCborCanonicalEncode` plus SHA-256 scheme as all protocol objects. The CID is carried in the JWS header, which makes each credential a stable artifact and gives revocation an address.

Every credential is verified against a **basis time**, defined once in [PROTOCOL, Time basis](https://protocol.dfos.com/spec#time-basis): the operation's own `createdAt` for a credential carried inline in a committed operation, and now for a credential presented at read time. Every temporal and key-resolution rule in this document resolves at that basis. Signature checking follows [PROTOCOL, Signature verification profile](https://protocol.dfos.com/spec#signature-verification-profile), which is normative for credentials and revocations and is not restated here.

---

## Schema

### DFOSCredentialPayload

The credential payload is validated against the schema below. Unknown top-level fields are preserved and ignored rather than rejected; the CID still commits to the exact bytes.

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

| Field     | Type               | Description                                                              |
| --------- | ------------------ | ------------------------------------------------------------------------ |
| `version` | `1`                | Schema version (literal `1`)                                             |
| `type`    | `"DFOSCredential"` | Literal discriminator                                                    |
| `iss`     | string             | Issuer DID, the authority granting permission                            |
| `aud`     | string             | Audience DID, or `"*"` for public credentials                            |
| `att`     | Attenuation[]      | Resource + action pairs (min 1, max 32)                                  |
| `prf`     | string[]           | Parent credential JWS token, at most 1 (linear delegation), default `[]` |
| `exp`     | number             | Expiration, unix seconds (positive integer)                              |
| `iat`     | number             | Issued-at, unix seconds (positive integer). Informational                |

`iat` records when the issuer minted the credential. It is not a verification gate: a credential is temporally authorized by `exp` against the basis time and by nothing else.

### Attenuation entry

Each attenuation entry is an object with two non-empty string fields:

```json
{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }
```

| Field      | Type   | Description                            |
| ---------- | ------ | -------------------------------------- |
| `resource` | string | Resource identifier (`type:id` format) |
| `action`   | string | Comma-separated action list            |

### Size and cardinality limits

A credential is bounded by one aggregate size cap plus a small set of cardinality caps, never a per-field string-length table. A per-field cap would only risk forking validity across implementations.

**Aggregate credential size:**

| Bound                | Value                      | Applies to                |
| -------------------- | -------------------------- | ------------------------- |
| credential JWS token | **262144 bytes** (256 KiB) | the serialized credential |

Verifiers MUST reject a credential whose serialized JWS token exceeds 262144 bytes, checked before any decode. The leaf token embeds the entire nested delegation chain, each parent carried verbatim in `prf`, so this single cap bounds the whole chain. The ceiling is larger than the 64 KiB operation cap ([PROTOCOL](https://protocol.dfos.com/spec#size-and-cardinality-limits)) because a maximum-depth delegation chain legitimately exceeds 64 KiB; a credential is excluded from the operation cap and bounded by this one instead.

**Cardinality caps:**

| Field | Max      | Note                                                                               |
| ----- | -------- | ---------------------------------------------------------------------------------- |
| `att` | 32 items | Generous for multi-resource grants; min 1 (a zero-`att` credential grants nothing) |
| `prf` | 1 item   | Single-parent (linear) delegation                                                  |

### Addressing and encoding

A credential is addressed and encoded like every other protocol artifact: dag-cbor canonical encoding to a CIDv1 carried in the `cid` protected header and re-derived at verification, a JSON payload in the JWS body, and the compact serialization on the wire ([PROTOCOL, CID construction](https://protocol.dfos.com/spec#cid-construction-dag-cbor--sha-256), [JWS envelope format](https://protocol.dfos.com/spec#jws-envelope-format)). The CID is what a revocation names.

---

## JWS header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:credential",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

| Field | Value                   | Description                                         |
| ----- | ----------------------- | --------------------------------------------------- |
| `alg` | `"EdDSA"`               | Ed25519 signature algorithm                         |
| `typ` | `"did:dfos:credential"` | Protocol-specific type discriminator                |
| `kid` | DID URL                 | `did:dfos:<id>#<keyId>`, identifies the signing key |
| `cid` | CID string              | Content address of the payload (for revocation)     |

**typ.** The protected header `typ` MUST equal the exact string `did:dfos:credential`. A JWS carrying any other `typ` is not a credential and is rejected before any credential rule runs, which is what keeps a JWS signed for one purpose from being presented as another.

**kid format.** The `kid` MUST be a DID URL containing `#`. The DID portion (before `#`) MUST match the `iss` field in the payload. The key fragment (after `#`) identifies which key on the issuer's identity signed.

**Key resolution.** The signing key is resolved from `kid` against the issuer's identity chain, in that identity's effective state as of the [basis time](https://protocol.dfos.com/spec#time-basis). A credential carried inline in a committed operation therefore still verifies after the issuer rotates that key out, and the same key signs nothing new once it is gone. Any key role (auth, assert, controller) may sign a credential; the protocol does not restrict which role.

The two withdrawals differ in reach. Rotating the signing key out ends every fresh presentation signed under it at once, because an ephemeral presentation resolves the key at the chain head, and it takes every other credential that key signed with it. Revocation is how an issuer withdraws one specific credential ahead of its expiry while the key keeps signing everything else.

---

## Delegation chains

Delegation chains enable transitive authorization. A root authority issues a credential to an intermediary, who issues a narrower credential to a downstream party, embedding the parent credential as proof.

### `prf` semantics

The `prf` field carries full JWS compact tokens, the complete parent credentials, not references or CIDs. Each credential is therefore self-contained: a verifier walks the entire chain with no external lookups beyond identity resolution.

- `prf: []` is a root credential. The issuer is the original authority.
- `prf: ["<parent JWS>"]` is a delegated credential. The single parent proves the issuer was authorized.

**Delegation is linear (single-parent).** A credential's `prf` MUST contain at most one entry, and verifiers MUST reject any credential whose `prf` has more than one element. Attenuating a child against the union of several parents while rooting the walk through one of them is an authority escalation, removed here by construction.

### Verification walk

Chain verification proceeds from the leaf credential upward:

1. **Verify the leaf credential:** signature, schema, `exp` against the basis, CID integrity.
2. **Reject multi-parent:** if `prf` has more than one entry, reject.
3. **Verify the parent in `prf`:** same checks, at the same basis, recursively.
4. **Audience linkage:** the child's `iss` MUST match the parent's `aud` (or the parent's `aud` MUST be `"*"`). This prevents a DID from using a credential not addressed to it.
5. **Expiry narrowing:** the child's `exp` MUST NOT exceed the parent's `exp`.
6. **Attenuation check:** the child's `att` MUST be a valid attenuation of the parent's `att` (see [Attenuation rules](#attenuation-rules)).
7. **Root check:** when a credential has `prf: []`, its `iss` MUST equal the expected root DID (for example the content chain creator).

Every level of the walk uses the one basis time of the verification, the leaf's and each parent's alike.

**Depth limit.** A delegation chain MUST contain at most **16 credentials**, counting the leaf and the root inclusive, so at most 15 delegation hops. A verifier walks from the leaf, counted as the first credential, toward the root; the **17th credential is rejected** ("delegation chain too deep"). This boundary is exact and normative: a verifier that accepts a 17-credential chain forks authorization validity. Conformance: a 16-credential chain verifies, a 17-credential chain is rejected.

**Revocation at every level.** Revocation is checked at every level of the delegation chain, the leaf credential AND each parent, not just the leaf (MUST, see [Relay enforcement](#relay-enforcement)).

---

## Attenuation rules

Every delegation hop enforces monotonic attenuation. The child credential's scope MUST be a subset of the parent's scope. Two dimensions are attenuated independently: resources and actions.

### Scope narrowing

Every entry in the child's `att` array must be covered by at least one entry in the parent's `att` array.

Valid narrowing:

- Parent grants `chain:X` and `chain:Y`, child requests only `chain:X` (subset of resources)
- Parent grants `read,write`, child requests only `read` (subset of actions)
- Parent grants `chain:*`, child requests `chain:X` (wildcard to specific)

Invalid widening:

- Parent grants `chain:X`, child requests `chain:X` and `chain:Y` (new resource)
- Parent grants `read`, child requests `read,write` (new action)
- Parent grants `chain:X`, child requests `chain:*` (specific to wildcard)

### Action coverage

An action is a **comma-separated list** of action tokens. To compare two action strings, each is **canonicalized to a set** of tokens by the following rules, applied identically by every verifier:

1. **Split on comma** (`,`).
2. **Trim** ASCII leading/trailing whitespace from each element.
3. **Drop empty elements.** An element that is empty after trimming contributes nothing to the set. Leading, trailing, and doubled commas are therefore insignificant: `read`, `read,`, `,read`, and `read,,read` all canonicalize to `{read}`.
4. **Collect into a set.** Order and duplication are insignificant; `write,read` and `read,write` both canonicalize to `{read, write}`.
5. **Compare tokens by exact, case-sensitive byte equality.** `read` and `Read` are distinct actions. There is **no action wildcard**: a `*` token is an ordinary, literal action token, not a match-all.

The child's canonical action set MUST be a **subset** of the parent's canonical action set for the matched resource entry. Equivalently, every token in the child's set MUST appear in the parent's set.

| Parent action | Child action  | Canonical child set | Covered? |
| ------------- | ------------- | ------------------- | -------- |
| `read,write`  | `read`        | `{read}`            | Yes      |
| `read,write`  | `write,read`  | `{read, write}`     | Yes      |
| `read,write`  | `read,,write` | `{read, write}`     | Yes      |
| `write`       | `write,`      | `{write}`           | Yes      |
| `read`        | `read,write`  | `{read, write}`     | No       |
| `read`        | `Read`        | `{Read}`            | No       |

**Empty action set (canonical bottom).** An action string that canonicalizes to the empty set `{}`, for example `""` or `","`, is the bottom of the action lattice: it is vacuously a subset of any parent set, so it never widens scope and passes the attenuation check, but it grants nothing, because a request always carries a concrete action token and no token is a member of `{}`. Such an entry is inert, not separately rejected.

### Expiry narrowing

The child's `exp` MUST be less than or equal to every parent's `exp`. A delegated credential cannot outlive its authority.

### Expiry against the basis

`exp` is signer-discretionary: the issuer chooses how long a credential is valid, and the protocol imposes no maximum. A credential is temporally authorized when its `exp` is strictly greater than the [basis time](https://protocol.dfos.com/spec#time-basis), which is where the conversion of a committed operation's `createdAt` to integer Unix seconds and the exclusive `exp` boundary are specified. A relay MAY additionally refuse credentials whose `exp` is implausibly far in the future; that is deployment policy, not the wire protocol.

---

## Resource types

Two resource forms are defined under the `chain:` prefix, and two more forms are registered by the specs that consume them: [`mailbox:<id>`](#mailboxid-signing-mailbox-deposit) and [`api:<host>`](#apihost-credential-gated-api-access), below. The resource grammar (`type:id`) is open by construction, and an unrecognized resource type never matches a request. It may still be carried down a delegation chain under the exact-equality rule in [Attenuation between forms](#attenuation-between-forms): matching a request and surviving the attenuation walk are different questions, and only registered forms are ever matched.

### `chain:<contentId>`, exact match

Grants access to a specific content chain identified by its 31-character content ID.

```json
{ "resource": "chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "action": "write" }
```

Matching: `chain:X` matches only `chain:X`. Exact content ID comparison.

### `chain:*`, wildcard match

Grants access to all content chains owned by the credential's root authority. The wildcard covers all of the issuer's content without enumerating specific chain IDs.

```json
{ "resource": "chain:*", "action": "read" }
```

Matching: `chain:*` matches any `chain:<contentId>` request for content where the delegation chain roots at the expected creator DID.

This is the broadest resource scope. Common use: granting a collaborator access to all of a creator's content.

### Attenuation between forms

| Parent           | Child            | Valid? | Reason                                    |
| ---------------- | ---------------- | ------ | ----------------------------------------- |
| `chain:*`        | `chain:*`        | Yes    | Exact match                               |
| `chain:*`        | `chain:X`        | Yes    | Narrowing from wildcard to specific chain |
| `chain:X`        | `chain:X`        | Yes    | Exact match                               |
| `chain:X`        | `chain:*`        | No     | Widening from specific to wildcard        |
| `api:H`          | `api:H`          | Yes    | Exact match                               |
| `api:H`          | `api:H/spaces/X` | Yes    | Narrowing from the host to one space      |
| `api:H/spaces/X` | `api:H/spaces/X` | Yes    | Exact match                               |
| `api:H/spaces/X` | `api:H`          | No     | Widening from one space to the host       |
| `api:H/spaces/X` | `api:H/spaces/Y` | No     | A sibling space is not narrower           |

The resource hierarchies from broadest to narrowest are `chain:*` > `chain:X` and `api:H` > `api:H/spaces/X`. Each delegation hop moves down a hierarchy, never up, and never across hosts.

Two of these rules are general, normative for **every** resource form, not just `chain:`:

- **Coverage never crosses resource types.** A `chain:` entry never covers a `mailbox:` request, nor any other pairing, in the delegation walk and in request matching alike.
- **A non-`chain:` form narrows by exact byte equality of the full resource string unless its registration defines a hierarchy.** [`api:`](#apihost-credential-gated-api-access) does, one level deep and enumerated; `mailbox:` and every unregistered id do not. The wildcard is a `chain:`-only concept: a literal `*` id in any other type is an ordinary id covering only itself.

### `mailbox:<id>`, signing mailbox deposit

Grants the audience the right to **deposit** sign requests into the subject's relay mailbox. `<id>` is the subject DID's 31-character identifier, the `did:dfos:` prefix stripped, exactly as `chain:<contentId>` does not repeat its scheme.

```json
{ "resource": "mailbox:cnnnft9f8a2rn938d6nkz38r847v2kr", "action": "deposit" }
```

- **`deposit` is the only action.** There is no `collect`: reading one's own mailbox is proven by key possession, not delegated by credential. A credential attenuated to any other action on a `mailbox:` resource grants nothing.
- **Exact match only, in the deposit gate AND the attenuation walk.** No wildcard form is defined for `mailbox`, and a relay MUST NOT honor `mailbox:*`, or any non-exact form, as covering a deposit. Delegation follows the general non-`chain:` rule in [Attenuation between forms](#attenuation-between-forms).
- **The consuming rules live with the signing mailbox** ([RELAY, Deposit authorization](https://protocol.dfos.com/relay#deposit-authorization)), including the one that gives the form its teeth: a deposit credential's delegation chain MUST **root at the subject DID**, because only the subject is original authority over its own mailbox.

### `api:<host>`, credential-gated API access

Grants the audience access to the credential-gated HTTP API served at `<host>`. `<host>` is the API's lowercase authority: the bare hostname on the default HTTPS port, `host:port` otherwise, never a scheme or path. Host-as-id means any deployment gets the same form: a fork's credential for `api:api.example.org` gates that host exactly as `api:api.dfos.com` gates the canonical one, with no registry of deployments anywhere.

Two forms are registered, one level deep:

| Form                     | Covers                                                |
| ------------------------ | ----------------------------------------------------- |
| `api:<host>`             | The whole API at that authority, every space included |
| `api:<host>/spaces/<id>` | One space at that authority                           |

`<id>` is the space's protocol DID with the `did:dfos:` prefix stripped, exactly 31 characters of the [identifier alphabet](https://protocol.dfos.com/did-method#31-abnf), as `mailbox:<id>` names a DID; never a subdomain and never a platform entity id. The form is a resource id, not an HTTP path: unversioned, and the hierarchy is enumerated, so a further child is one more row here, never a path grammar. An `api:` string that is neither form is an unregistered id: it never covers a request, and a delegation carries it only byte-identically.

```json
{ "resource": "api:api.dfos.com", "action": "read:profile" }
```

```json
{
  "resource": "api:api.dfos.com/spaces/9ctvrdn9vedda7efetrhcdakfh4cr2k",
  "action": "read:posts,write:comments"
}
```

- **Coverage is equal-or-ancestor.** `api:<host>` covers itself and every `api:<host>/spaces/<id>` at that host; a space form covers only itself. Coverage never crosses hosts (a non-default port is part of the host) and never crosses resource types. `api:*` is an ordinary id covering only itself and is never a served host. One rule decides request matching and the [attenuation walk](#attenuation-between-forms) alike, so a host grant narrows to one space and a space grant never widens.
- **Registration invariant.** A child form registered here MUST NOT let an existing host grant reach anything its action tokens did not already describe: the host form means every space at the host, and a space is what every space-level token already names.
- **Actions are enumerated registry tokens**, defined in [INTEGRATIONS](https://protocol.dfos.com/integrations#the-apihost-resource-and-its-actions), which registers `read:profile`, `read:email`, and `read:memberships` at the account level and `read:posts`, `write:upvotes`, `write:comments`, and `write:posts` at the space level. Growth is enumeration: a grant carrying several tokens is an ordinary comma-separated list, narrowed by dropping tokens. Per the [action lattice](#action-coverage) there is no action wildcard, so `read:*` is a literal token no route requires and an entry carrying it grants nothing. It does not widen in attenuation either: `{read:*}` narrows only from a parent that also carries `read:*`.
- **The consuming rules live in [INTEGRATIONS](https://protocol.dfos.com/integrations#verification-algorithm)**, including the ones that give the form its teeth: a credential is exercised only alongside a **request proof** signed by the leaf audience's key, so a bare credential authorizes nothing on that surface; **no credential in the presented chain may carry `aud: "*"`**, refused at every level and not just the leaf, because a public parent would let a stranger self-issue a passing leaf; and the chain's **root `iss` is the subject whose data is served**, so the credential selects the subject.

---

## Public credentials

### `aud: "*"` semantics

A credential with `aud` set to `"*"` is a **public credential**. It is not addressed to a specific DID: it is a standing authorization anyone can use.

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

### Relay ingestion

Public credentials are ingested by a relay and stored as standing authorizations. When a request arrives for a resource, the relay checks its stored public credentials for matching `att` entries. The caller does not present the credential per request; the relay already holds it.

### Private credentials

A credential with a specific DID as `aud` is a **private credential**. The holder presents it per request. The relay does not store it.

### Delegation chain interaction

A parent credential with `aud: "*"` satisfies the audience linkage check for any child issuer, so a public credential can serve as a parent in a delegation chain: any DID can issue a narrower child credential using it as proof.

### `aud: "*"` plus write is a bearer grant

Because `aud: "*"` matches any operation signer, a public credential granting a **write** action is a bearer token anyone can present: any DID can attach it as a content operation's inline `authorization` and author writes to the covered chains. A public `chain:*` write credential is world-writable across every chain rooted at the issuer.

Public credentials SHOULD therefore be read-scoped. Reserve `write` and `chain:*` for private credentials with a specific `aud`, where the relay also checks that the operation signer matches the audience. Revocation is the remedy for a public write credential the issuer regrets, and the exposure runs until every relay that ingested it has the revocation.

---

## Revocation

### Revocation artifact

A revocation is a standalone signed artifact that permanently invalidates a credential. Its protected header `typ` MUST equal the exact string `did:dfos:revocation`, and a JWS carrying any other `typ` is not a revocation.

**JWS header:**

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

| Field           | Type           | Description                                                                            |
| --------------- | -------------- | -------------------------------------------------------------------------------------- |
| `version`       | `1`            | Schema version (literal `1`)                                                           |
| `type`          | `"revocation"` | Literal discriminator                                                                  |
| `did`           | string         | Issuer DID revoking the credential                                                     |
| `credentialCID` | CID            | CID of the credential being revoked                                                    |
| `createdAt`     | string         | Timestamp in the [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) |

### Rules

- **Issuer-only.** Only the credential's issuer DID can revoke it. The `kid` DID in the JWS header MUST match the `did` field in the payload.
- **Permanent.** There is no un-revoke operation. To restore access, issue a new credential.
- **CID-addressed.** The revocation artifact has its own CID, derived from the payload and embedded in the header.
- **Gossiped.** Revocations propagate across relays on the proof plane like any other signed operation.

### Relay enforcement

Relays maintain a revocation set keyed by `(issuerDID, credentialCID)`. During credential verification the relay checks whether the credential's CID appears in the revocation set **for that credential's issuer**. This scoping is what stops a rogue DID from revoking credentials it did not issue. A revoked credential fails verification regardless of its expiry or signature validity.

Revocation MUST be checked at **every level** of a presented credential, the **leaf** AND each **parent** in its delegation chain. Checking only parents is insufficient: an unchecked revoked leaf would still authorize access. This applies to **both** authorization surfaces: the read path (standing authorization and per-request credential checks) and the write path (the inline `authorization` on a delegated content operation, verified at ingest).

### Revocation against the basis

Revocation is **forward-looking against the basis**. A revocation `R` covers an artifact verified at basis time `T` if and only if:

```
R.createdAt <= T
```

The boundary is **inclusive**: a revocation signed at the same second as an operation invalidates it. `R.createdAt` comes from the revocation's own signed payload, so no relay can move the boundary by misreporting it; a caller that re-verifies the revocation JWS reads the boundary out of the verified bytes. The rule applies at every level of the presented credential, leaf and each parent, all evaluated at that one basis.

For a committed operation the basis is the operation's `createdAt`, so revoking a credential does not undo operations already in the log: an operation authorized when it was signed keeps verifying, and a parent revoked after the operation does not invalidate it either. That is the append-only semantics of a content chain, and it makes every verifier reach the same verdict forever, with one exception: while the issuing identity is deleted, the credentials it issued authorize nothing anywhere in history (**Deleted issuers**, below).

**Admission is separate.** Whether to admit a NEW operation is a local freshness decision, not a validity decision: a relay that holds a revocation for the authorizing credential refuses the operation whatever its `createdAt` claims. Two relays on either side of a revocation's arrival reach different admission verdicts, and nothing in the log depends on when a relay chose to admit an operation.

A verifier with no revocation source, or one that answers only timelessly, MUST fall back to the timeless answer. That is the stricter direction: it can reject history the basis rule would accept, never admit what the basis rule rejects.

### Deleted issuers

Identity deletion is the one credential rule that does not run against the basis. While an identity is deleted, the credentials it issued are invalidated **retroactively**: a credential from a deleted issuer authorizes nothing, on any surface, at any point in history, and verification of committed history rejects operations that relied on it. Revocation withdraws one grant and leaves the record that grant authorized standing; deletion withdraws the authority itself.

Deletion is absolute, not permanent: it is the identity chain's deleted state, and the controller leaves that state with an explicit `restore` operation ([PROTOCOL, Terminal states](https://protocol.dfos.com/spec#terminal-states)). Once restored, the identity's previously issued, unrevoked credentials are honored again. Deletion suspends the issuer's authority; revocation is the permanent, per-grant kill and survives any number of delete and restore transitions.

---

## Relationship to request authentication

Credentials and the request-authentication proofs of [INTEGRATIONS](https://protocol.dfos.com/integrations#api-authentication) are all DID-signed Ed25519 JWS artifacts, and they answer different questions.

| Concern           | Request / identity proof                             | DFOS credential                                     |
| ----------------- | ---------------------------------------------------- | --------------------------------------------------- |
| Question answered | "Is this DID making exactly this request, now?"      | "Does this DID have permission to do this?"         |
| Role              | Authentication                                       | Authorization                                       |
| JWS `typ`         | `did:dfos:identity-proof` / `did:dfos:request-proof` | `did:dfos:credential`                               |
| Lifetime          | Seconds (the verifier-owned freshness window)        | Long (hours to months)                              |
| Binding           | One exact request at one host                        | Specific DID or `"*"` audience                      |
| Content-addressed | No (`cid` not in header)                             | Yes (`cid` in header)                               |
| Revocable         | No (expires in seconds)                              | Yes (via revocation artifact)                       |
| Delegation        | None                                                 | Via `prf` chains                                    |
| Basis time        | Now (always an ephemeral presentation)               | `createdAt` when committed inline, now at read time |

A typical gated request carries both: an **identity proof** proving the caller controls a DID, and a **credential** proving that DID has access to the requested resource.

---

## Worked examples

### Simple credential

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

Alice is the root authority (`prf: []`). Bob presents this credential to a relay when writing to content chain `cv7n8vkvr64cctf3294h9k4eanhff8z`. The relay verifies Alice's signature against her key as effective at the basis, confirms the credential is neither expired nor revoked at that basis, and checks that the requested resource and action match an `att` entry.

### 2-hop delegation

A space DID grants a member write access, and the member delegates to their device:

```
Space (root) -> Member -> Device (leaf)
```

**Hop 1, space issues a root credential to the member:**

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

**Hop 2, the member delegates to the device with a narrower expiry:**

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

Verification walk for the device's credential:

1. Verify the device credential signature (signed by the member).
2. Verify the parent in `prf` (signed by the space).
3. Audience linkage: the device credential's `iss` (`member`) matches the parent's `aud` (`member`).
4. Expiry: the device credential's `exp` does not exceed the parent's `exp`, and both exceed the basis.
5. Attenuation: `chain:content1/write` is covered by the parent's `chain:content1/write`.
6. The parent has `prf: []`, so it is the root. Its `iss` (`space`) must match the expected root DID.

### Public credential

A space DID issues a public read credential for a content chain. Any DID reads without presenting the credential per request:

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

The relay ingests this credential as a standing authorization. When any caller requests read access to `chain:cv7n8vkvr64cctf3294h9k4eanhff8z`, the relay matches the request against its stored public credentials, with no identity proof and no per-request credential.

Because `aud` is `"*"`, any DID can also use this credential as a parent in a delegation chain, for example to issue a narrower credential to a specific collaborator with a shorter expiry.

---

## Source

The reference TypeScript implementation is [`packages/dfos-protocol/src/credentials/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/credentials), published as [`@metalabel/dfos-protocol`](https://www.npmjs.com/package/@metalabel/dfos-protocol). Its Go twin is [`packages/dfos-protocol-go/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol-go).

### Related specifications

- [Protocol](https://protocol.dfos.com/spec): encoding, chains, the time basis, and the signature verification profile
- [Relay](https://protocol.dfos.com/relay): the HTTP surface that ingests credentials and revocations and enforces them
- [Integrations](https://protocol.dfos.com/integrations): sign-in, API request authentication, and the `api:<host>` action registry
- [Guarantees](https://protocol.dfos.com/guarantees): what holds without trusting a server, what is a chosen view, and what the operator can read

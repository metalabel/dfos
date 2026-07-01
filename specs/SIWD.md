# Sign In With DFOS (SIWD)

Cryptographic identity verification for third-party applications — Ed25519 challenge-response via a universal `/authorize` endpoint. One flow, two signing paths (managed and sovereign), same JWS output. Verification is pure crypto — no DFOS server in the loop after issuance.

> **SIWD version 0.1.** Sign In With DFOS is an **optional authentication seam on its own `0.x` clock, independent of the Protocol v1 freeze** — it is **not part of the frozen protocol surface**. SIWD builds _on top of_ the frozen primitives (the identity chain, the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile), and [DFOS Credentials](https://protocol.dfos.com/credentials)) and may reference them, but the frozen protocol never depends on SIWD. The challenge-response and verification rules below are protocol-normative for any SIWD verifier; the platform endpoint, KMS custody, local CLI port, and health-check behavior are **reference-implementation** details of the DFOS platform, not normative requirements. No reference implementation of the third-party verifier exists yet in this repository — published here for review and to inform implementors. Discuss in the [DFOS](https://nce.dfos.com) space.

---

## Overview

SIWD lets any third-party application verify a user's DFOS identity. The third party redirects to a single `/authorize` URL on the DFOS platform. The user consents, the challenge is signed with their DID key, and the callback delivers a standard JWS. The third party verifies the signature against the user's identity chain — resolved from any relay — without contacting the DFOS platform.

Two signing paths exist behind the same endpoint:

| Path          | Signer                                  | Trust model                                                         |
| ------------- | --------------------------------------- | ------------------------------------------------------------------- |
| **Managed**   | Platform signs via KMS-held key         | Platform custody — user trusts the platform to sign on their behalf |
| **Sovereign** | User's local Go CLI signs via local key | Self-custody — user holds the key, platform never touches it        |

The third party never knows which path was used. Both produce the same JWS format, both reference keys in the same identity chain, both verify identically.

---

## Flow

### 1. Redirect to authorize

The third-party application redirects the user to the platform's `/authorize` endpoint:

```
https://dfos.com/authorize?
  challenge=<base64url-encoded challenge JSON>
  &redirect_uri=https://3p.com/callback
  &scope=identity
```

Query parameters:

| Parameter      | Required | Description                                                                    |
| -------------- | -------- | ------------------------------------------------------------------------------ |
| `challenge`    | Yes      | Base64url-encoded challenge object (see [Challenge Schema](#challenge-schema)) |
| `redirect_uri` | Yes      | URL the platform redirects to after signing                                    |
| `scope`        | Yes      | A single requested scope (one scope per authorization request)                 |

Scopes:

| Scope              | Meaning                                                                  |
| ------------------ | ------------------------------------------------------------------------ |
| `identity`         | Prove DID ownership only                                                 |
| `read:<contentId>` | Prove DID + return a read credential for the content chain `<contentId>` |

The `<contentId>` is the content chain's content ID as defined by the protocol. A `read:<contentId>` scope maps to exactly one [DFOS credential](https://protocol.dfos.com/credentials) attenuation: `{ "resource": "chain:<contentId>", "action": "read" }`. SIWD does not define a resource grammar of its own — the resource form, action vocabulary, and matching rules are the credential spec's `chain:<contentId>` exact-match form (see [Credentials — Resource Types](https://protocol.dfos.com/credentials)). There is no separate "chain type" dimension; every content resource is a `chain:` resource.

### 2. Consent screen

The platform authenticates the user (existing session) and presents a consent screen. The screen describes what the third party is requesting — identity verification alone, or identity plus scoped resource access.

If the user has local signing enabled, both signing options are presented. Otherwise, only managed signing is available.

### 3. Signing

The user's DID key signs the challenge as a JWS compact token. See [Managed Signing Path](#managed-signing-path) and [Sovereign Signing Path](#sovereign-signing-path) for details.

### 4. Callback

The platform (or local CLI) redirects to the `redirect_uri` with the signed challenge:

```
https://3p.com/callback?
  jws=<signed challenge JWS>
  &did=did:dfos:<id>
```

If a credential was requested via `scope`, it is included as an additional parameter:

```
  &credential=<DFOS credential JWS>
```

---

## Challenge Schema

The challenge is a JSON object, base64url-encoded in the `challenge` query parameter:

```json
{
  "domain": "3p.com",
  "nonce": "a8f2e93b...",
  "timestamp": "2026-04-13T15:30:00.000Z",
  "statement": "Sign in to 3P App",
  "did": "did:dfos:<id>"
}
```

| Field       | Required | Description                                                                                                                          |
| ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `domain`    | Yes      | Origin domain of the requesting application. MUST match the domain in `redirect_uri`.                                                |
| `nonce`     | Yes      | Unique value generated by the third party, used for replay prevention.                                                               |
| `timestamp` | Yes      | ISO 8601 timestamp of challenge creation.                                                                                            |
| `statement` | No       | Human-readable description shown on the consent screen.                                                                              |
| `did`       | No       | If provided, binds the challenge to a specific DID. The platform MUST reject signing if the authenticated user's DID does not match. |

The challenge is signed as a JWS using the user's DID key with `alg: "EdDSA"`. The JWS `kid` header contains the DID URL of the signing key (`did:dfos:<id>#<keyId>`), following the same convention as identity and content chain operations.

---

## Managed Signing Path

The platform holds the user's DID key material in a KMS (Key Management Service). When the user consents via the managed path:

1. Platform verifies the user's session.
2. Platform signs the challenge with the user's KMS-held key.
3. Platform redirects to `redirect_uri` with the signed JWS and DID.

The KMS key is one of the user's `authKeys` declared in the identity chain — the authentication key set that verification resolves against (see step 2 below). The signature is indistinguishable from any other Ed25519 signature over the challenge — the third party verifies it against the identity chain like any other key.

The KMS custody model and the platform's session handling are **reference-implementation** details; what is normative is only that the signature is produced by a key declared in the identity chain and verifies under the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile).

---

## Sovereign Signing Path

Users who hold their own keys via the DFOS Go CLI can sign challenges locally. The platform does not touch the key material.

### Configuration

The user enables local signing in their platform settings:

| Setting               | Type    | Description                                                          |
| --------------------- | ------- | -------------------------------------------------------------------- |
| `localSigningEnabled` | boolean | Whether the sovereign signing option is presented on consent screens |
| `localSigningPort`    | number  | Port the local CLI listens on (default: `8420`)                      |

> These settings, the `localhost` port, and the preflight `GET /health` probe are **reference-implementation** behavior of the DFOS platform and Go CLI, not protocol-normative. A SIWD verifier never observes them — it sees only the resulting JWS.

### Flow

1. User selects "Sign locally" on the consent screen.
2. Platform redirects to `http://localhost:<port>/authorize` with the same `challenge` and `redirect_uri` parameters.
3. The Go CLI receives the request, presents consent (terminal or local web UI), and signs the challenge with the locally-held key.
4. The CLI redirects to `redirect_uri` with the signed JWS and DID.

The local key MUST be declared in the user's identity chain (`authKeys`). The third party resolves the identity chain and finds the key — same verification as the managed path.

### Failure handling

If the user selects sovereign signing but the CLI is not running, the browser fails to connect to localhost. The user navigates back and falls through to managed signing. No state is corrupted — the challenge is stateless and can be signed by either path.

The platform MAY perform a preflight health check (`GET http://localhost:<port>/health`) to disable the sovereign signing button when the CLI is not reachable.

---

## Third-Party Verification

Verification is identical regardless of signing path. The JWS signature MUST be checked under the DFOS [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile) — the same profile every DFOS verifier applies — not unprofiled "standard Ed25519 verification":

1. **Decode the JWS** — extract the challenge payload, `kid` header (DID URL of signing key), and signature. Before any signature work, apply the profile header gates: the protected header `alg` MUST equal the exact string `"EdDSA"`; a `crit` member MUST cause rejection; and an embedded header key (`jwk`, `x5c`, or any key-bearing member) MUST cause rejection. The key is never read from the header.
2. **Resolve the DID** — fetch the identity chain from any DFOS relay and replay it to its **current state**. Extract the public key matching the `kid` from the current `authKeys`. Keys that have been rotated out, and identities that have been deleted or revoked, MUST NOT verify — a challenge signed by a key that is no longer current (or by a deleted/revoked identity) MUST be rejected.
3. **Verify the signature** — Ed25519 verification of the JWS against the resolved public key, with the canonical-scalar gate (`S < L`) and the 64-byte length check from the profile.
4. **Validate the nonce** — confirm the `nonce` in the challenge payload matches the server-side value issued to this session. Discard the nonce after use.
5. **Validate the timestamp** — reject challenges older than a reasonable window (implementation-defined, e.g., 5 minutes).
6. **Validate the domain** — confirm the `domain` in the challenge matches the verifier's own origin.

If a credential was returned, the third party stores it and presents it to relays for scoped access. See [Optional Credential Return](#optional-credential-return).

No DFOS platform server is contacted during verification. The third party only needs access to a relay (any relay) to resolve the DID's identity chain.

---

## Optional Credential Return

When `scope` includes resource access beyond `identity`, the callback includes a DFOS credential alongside the signed challenge.

### User-owned content

For content owned by the user's DID, the credential is issued by that DID: a standard [DFOS credential](https://protocol.dfos.com/credentials) with `iss` = the user's DID, `aud` = the third-party app's DID, and a single attenuation `{ "resource": "chain:<contentId>", "action": "read" }` covering the requested content chain. The envelope, signing, CID derivation, and validity bounds are exactly as the [credential spec](https://protocol.dfos.com/credentials) defines — SIWD adds no fields and no separate credential format.

### Space-owned content

For content owned by a space (a separate DID), the credential is issued by the **space's DID**, not the user's. The platform mediates: the user consents, the platform verifies the user's membership and permissions within the space, then issues the credential from the space's DID.

The third party presents the credential to any relay hosting that content. The relay verifies the credential against the space's identity chain and grants scoped access.

---

## Security Considerations

### Replay prevention

The `nonce` field is the primary replay defense. The third party MUST:

- Generate a cryptographically random nonce per authorization request.
- Store it server-side, bound to the user's session.
- Reject any callback where the nonce does not match or has already been consumed.
- Expire unused nonces after a short window.

The `timestamp` field provides a secondary bound — challenges with stale timestamps SHOULD be rejected even if the nonce is valid.

### Redirect URI validation

The platform MUST validate `redirect_uri` against a registered allowlist for the requesting application. Open redirectors allow phishing — an attacker could substitute their own callback URL to capture signed challenges.

The `domain` field in the challenge MUST match the domain of the `redirect_uri`. The platform MUST reject requests where these diverge.

### Challenge binding

If the `did` field is present in the challenge, the platform MUST refuse to sign with any other DID. This prevents an attacker from substituting a different user's identity into a challenge intended for a specific user.

### Localhost security (sovereign path)

The sovereign path redirects to `localhost`, which is not TLS-protected. This is acceptable because:

- The signing key never leaves the local machine.
- The challenge is not secret — it is a value the user is explicitly consenting to sign.
- The redirect back to `redirect_uri` uses HTTPS.

The CLI SHOULD bind exclusively to `127.0.0.1` (not `0.0.0.0`) to prevent network-adjacent access.

### Token lifetime

Signed challenges are single-use authentication proofs, not bearer tokens. Third parties SHOULD establish their own session after verification and discard the JWS.

Credentials returned via `scope` have an explicit `exp` (expiration) field. Third parties MUST respect expiration and re-request credentials when they expire.

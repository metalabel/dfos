# DFOS API Authentication

Proof-of-possession authentication for credential-gated HTTP APIs. A **request proof** is a short-lived JWS, signed by the key of the party a [DFOS credential](https://protocol.dfos.com/credentials) was issued to, that binds one exact HTTP request — method, host, path, body — to that credential, right now. The credential says what its holder may do; the proof says the holder is the one doing it, and doing exactly this. Neither is a bearer token, and neither works alone.

> **Status — API-AUTH 0.1, an optional capability on its own `0.x` clock, independent of the Protocol v1 freeze.** The request-proof envelope (`did:dfos:request-proof`), the verification obligations below, and the [`api:<host>` resource form](https://protocol.dfos.com/credentials) are published for review and early implementation — they are **not part of the frozen protocol surface**, and the frozen protocol never depends on them. API-AUTH builds on frozen primitives (the identity chain, the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile), [DFOS Credentials](https://protocol.dfos.com/credentials)) and sits outside the frozen v1 vector set on purpose: nothing here touches identity or content chains. Reference vectors ship in the TypeScript and Go packages now; the full five-language sweep lands when this spec exits `0.x`. Discuss in the [DFOS](https://nce.dfos.com) space.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-client) · [npm](https://www.npmjs.com/package/@metalabel/dfos-client)

---

## Motivation

A [SIWD](https://protocol.dfos.com/siwd) credential-returning scope hands a third party a durable authorization: a credential issued by the user, audience-bound to the third party's DID, attenuated to an API resource. What it deliberately does not hand over is a way to _spend_ that credential as a bearer token — a credential alone proves that a grant exists, not that the party presenting it is the party it was granted to. The gap between those two statements is where every stolen-token attack lives.

The request proof closes the gap the way the rest of the protocol closes gaps: with a signature over exact bytes. Each API request carries the credential **and** a fresh JWS signed by the credential's audience key, binding the credential's CID to the one request being made — this method, this host, this path, this body, this moment. A captured credential is inert without the audience key; a captured proof authorizes nothing but the single request it already described, for the few seconds its freshness window allows. The verifier — any API host, with no DFOS platform server in the loop — checks both artifacts and serves the request.

This is the same shape the wider ecosystem converged on as [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449): a proof-of-possession JWS over the request coordinates, presented alongside the grant it exercises. DFOS needs its own envelope rather than DPoP itself because the grant being exercised is a DFOS credential (CID-addressed, delegation-chained, revocable) and the signing key is a DID key resolved from an identity chain — the binding points are protocol objects, not OAuth ones.

### What this deliberately is not

- **Not a session.** There are no cookies, no server-side session state, no login. Every request is authenticated independently by its own proof. A browser application that cannot hold the audience key routes through its own backend, which holds the key and signs (see [Security Considerations](#security-considerations)).
- **Not a bearer token.** The proof is worthless without the request it describes, and the credential is worthless without the proof. The `Authorization` scheme is deliberately not `Bearer` — nothing carried here is one.
- **Not relay surface.** The proof is never ingested by a relay, never gossiped, never content-addressed for reference. It moves in an HTTP header to an API host and dies with the freshness window. It is registered in the [protocol `typ` registry](https://protocol.dfos.com/spec#typ-header) for routing only.
- **Not a signing family.** `did:dfos:request-proof` is not a [SIGNING](https://protocol.dfos.com/signing) `payloadTyp`: the presenter signs proofs with its **own** key, continuously and mechanically — there is no other party to ask and nothing for a human to approve, so nothing to courier.

---

## The Request Proof

### JWS Header

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:request-proof",
  "kid": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_r9ev34fvc23z999veaaft83nn29zvhe"
}
```

| Field | Value                      | Description                                          |
| ----- | -------------------------- | ---------------------------------------------------- |
| `alg` | `"EdDSA"`                  | Ed25519 signature algorithm                          |
| `typ` | `"did:dfos:request-proof"` | Protocol-specific type discriminator                 |
| `kid` | DID URL                    | `did:dfos:<id>#<keyId>` — identifies the signing key |

**There is no `cid` header, deliberately.** Content addressing exists in this envelope family to make artifacts referenceable — for revocation, for correlation, for audit. A request proof is referenced by nothing: it is never stored, never revoked (it expires in seconds), and correlates to nothing but the request it rides. Deriving a CID would cost a dag-cbor encode on every API request and buy nothing. The content-addressed artifact in this exchange is the credential, and the proof binds to it by carrying the credential's CID **in its payload**, under the signature.

**kid names the credential's audience.** The `kid` MUST be a DID URL containing `#`, and its DID portion MUST equal the `aud` of the presented leaf credential — the proof is signed by the party the grant was issued to, always. This is the possession being proven.

**Key resolution is current-state.** The presenter's signing key is resolved against the **current** state of its identity chain — rotated-out keys are rejected, and a deleted presenter's proofs are rejected. This is the auth-token rule, not the credential rule, and for the same reason [SIGNING](https://protocol.dfos.com/signing) applies it to sign requests: a proof is ephemeral, with a hard freshness window and no revocation primitive, so rotation is how a presenter whose key is compromised stops that key from minting proofs in its name. Any current key role (auth, assert, controller) may sign.

### Payload

```json
{
  "method": "GET",
  "host": "api.dfos.com",
  "path": "/v0/profile",
  "bodyHash": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "credentialCID": "bafyrei...",
  "iat": 1772841600
}
```

| Field           | Type    | Required | Description                                                                  |
| --------------- | ------- | -------- | ---------------------------------------------------------------------------- |
| `method`        | string  | yes      | The HTTP method, uppercase (`GET`, `POST`, …)                                |
| `host`          | string  | yes      | The API's bare lowercase hostname — no scheme, no port                       |
| `path`          | string  | yes      | The exact origin-form request target — path plus query string, byte for byte |
| `bodyHash`      | string  | yes      | Unpadded base64url of the SHA-256 of the raw request body octets             |
| `credentialCID` | string  | yes      | CID of the leaf credential presented alongside this proof                    |
| `iat`           | integer | yes      | Issued-at — unix seconds (positive integer)                                  |

All six members are required — there are no optionals, so the canonical form below carries no ambiguity. Unknown top-level members are ignored by verifiers, per the protocol's MUST-ignore-unknown rule; a future revision of this spec may register additional members additively.

**`path` is the wire string, not a normalization.** The value is the origin-form request target exactly as the request line carries it — the path, plus `?` and the query string when one is present, byte for byte. It MUST begin with `/` and MUST NOT contain a fragment (fragments never reach the wire). There is no canonicalization — no percent-decoding, no query-parameter reordering, no trailing-slash equivalence. The presenter constructs the request and the proof from the same string, so byte equality is free for the honest party; the verifier compares against the request target it actually received. A deployment whose infrastructure rewrites paths before the verifier sees them must compare against the original request line — the honest statement is that path-rewriting middleware in front of the verifier is the deployment's problem to un-rewrite, not the protocol's to canonicalize around.

**`bodyHash` covers the raw body octets** — the bytes as transmitted, before any parsing, after any transfer decoding. A request with no body hashes zero octets, whose digest is the constant `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`; there is deliberately no absent-member form for bodyless requests, so every proof is checked the same way and the empty-versus-missing distinction — which HTTP itself does not reliably preserve through intermediaries — never becomes a verification question. The encoding is unpadded base64url (RFC 4648 §5, no `=` padding) of the 32 digest bytes; padded or non-canonical encodings are invalid.

**`iat` and no `exp`, deliberately.** The proof carries when it was made and nothing about how long it lives — the verifier owns the freshness window (see [Verification Algorithm](#verification-algorithm)). A presenter-chosen `exp` would let the presenter widen the replay window unilaterally, which is exactly backwards: the party bearing the replay risk sets the bound.

### Canonical Signing Input

The signer and the verifier MUST agree on the exact bytes signed. The **canonical signing input** is the payload object serialized as minimal UTF-8 JSON (no insignificant whitespace) with its members in this fixed order:

```
method, host, path, bodyHash, credentialCID, iat
```

These bytes are the JWS payload segment — what the `alg: "EdDSA"` signature covers. This is the standard canonical-serialization rule the whole envelope family uses ([SIGNING → canonical serialization](https://protocol.dfos.com/signing)); as with [SIWD's challenge](https://protocol.dfos.com/siwd), the reference builder in each language emits canonical bytes by construction, and the byte contract lives in exactly one place per language: the signed-fetch and verify helpers in [`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client) and their byte-twins in `dfos-protocol-go`.

### HTTP Carriage

A credential-gated request carries two headers:

```
Authorization: DFOS <request-proof JWS>
X-Credential: <leaf credential JWS>
```

The `Authorization` scheme is the literal token `DFOS` — not `Bearer`, because the proof is not a bearer token and naming it one invites bearer handling (logging, caching, forwarding) that this artifact exists to make useless. `X-Credential` is the same header the [relay content plane](https://protocol.dfos.com/web-relay) already uses for per-request credentials; the leaf token embeds its full delegation chain in `prf`, so one header carries the whole grant. A verifier MUST respond `401` with a `WWW-Authenticate: DFOS` challenge when either header is missing or malformed.

This carriage is normative for the `api:<host>` resource family — every host that serves it, canonical deployment or fork, authenticates the same way. That uniformity is what lets one client implementation sign for any of them.

### Size Bounds

| Bound             | Value                      | Applies to                         |
| ----------------- | -------------------------- | ---------------------------------- |
| request-proof JWS | **4096 bytes**             | the serialized proof token         |
| credential JWS    | **262144 bytes** (256 KiB) | the credential spec's existing cap |

Verifiers MUST reject either token over its cap **before any decode** — a DoS guard, checked at the header layer. Both bounds are validity-determining and identical across implementations. The proof cap is generous by an order of magnitude for any conforming payload; the credential cap is [CREDENTIALS.md](https://protocol.dfos.com/credentials)'s own, restated rather than redefined.

The credential cap is what the **protocol** accepts; what a deployment's **transport** accepts is usually far less — CDN and serverless header ceilings commonly sit in the 8–20 KB range, which a root credential clears trivially and a deep delegation chain may not. That gap is deployment policy, not protocol surface: a deployment whose grants legitimately outgrow its header budget raises the budget or adopts a body-borne carriage as a future additive registration, and this spec caps nothing at the transport's number.

---

## Verification Algorithm

To verify a credential-gated request, given the two tokens, the received request, a way to resolve identities, a revocation source, and the current time:

1. **Size.** Reject a proof token over **4096 bytes** or a credential token over **262144 bytes**, before any decode.
2. **Decode** the proof JWS and apply the [Signature Verification Profile](https://protocol.dfos.com/spec#signature-verification-profile) header gates: `typ` MUST be exactly `did:dfos:request-proof`, `alg` exactly `EdDSA`, a `crit` member rejects, an embedded key member (`jwk`, `x5c`, …) rejects. A missing or non-string `typ` or `kid` rejects; the `kid` MUST contain `#`.
3. **Payload schema.** All six members present: `method` a non-empty uppercase string, `host` a non-empty lowercase string, `path` a string beginning with `/`, `bodyHash` the unpadded base64url of 32 bytes, `credentialCID` a non-empty string, `iat` a positive integer. Unknown members are ignored.
4. **Freshness.** `|now − iat|` MUST NOT exceed the verifier's acceptance window **W**. W is verifier policy, RECOMMENDED **60 seconds** and **MUST NOT exceed 300 seconds**. The window is symmetric on purpose — the future-facing half is the clock-skew allowance, and a forward-dated proof outliving the window is exactly what it forbids.
5. **Request binding.** `method` equals the received request's method; `host` equals the verifier's own serving hostname; `path` byte-equals the received origin-form request target; `bodyHash` equals the SHA-256 of the received body octets (zero octets when there is no body). Any mismatch rejects.
6. **Resolve the presenter** named by the `kid`'s DID to its **current** identity state. Unresolvable → **unverifiable**. Deleted → reject. No key matching the `kid` fragment in current state → reject.
7. **Signature.** Verify the proof JWS under that key, with the profile's canonical-scalar gate (`S < L`) and 64-byte length check.
8. **Credential chain.** Verify the presented credential in full under [CREDENTIALS.md](https://protocol.dfos.com/credentials) — signatures, schema, CID integrity, linear delegation, depth, audience linkage, monotonic attenuation — with expiry evaluated against the **wall clock** (this is a read-path, at-read decision per the credential spec's [Expiry Basis](https://protocol.dfos.com/credentials)) and **revocation checked at every level** against the verifier's current knowledge.
9. **Credential binding.** Re-derive the leaf credential's CID from its parsed payload; it MUST equal the proof's `credentialCID`. The leaf's `aud` MUST be a named DID equal to the `kid`'s DID portion — a leaf with `aud: "*"` MUST be rejected on this surface (see [Security Considerations](#security-considerations)).
10. **Root.** The chain's root `iss` MUST be the DID that owns the resource being served. Under the v0 [action registry](#the-apihost-resource-and-its-actions) the root issuer _is_ the resource owner — a `read:profile` request is a request for the root issuer's profile; the credential selects the subject, and a route parameter never does.
11. **Attenuation coverage.** Some `att` entry on the leaf MUST cover the request: its `resource` MUST byte-equal `api:<host>` for the verifier's own host (exact match — no wildcard form exists for `api:`), and its canonical action set (per the credential spec's [action canonicalization](https://protocol.dfos.com/credentials)) MUST contain the route's required action token.

No step consumes or mutates state, so implementations MAY reorder for efficiency (the cheap local checks 3–5 before the resolving checks 6–8 is the natural order); every step MUST pass.

**All of this is day one.** Revocation in the verify path (even while revocation tooling is administrative), the freshness window, and at-read credential expiry are not hardening to defer — they are the difference between this design and a bearer token with extra steps. A verifier that skips step 8's revocation check has removed the user's only timely lever over a standing grant.

**Verdicts are machine-distinguishable**, as everywhere in the envelope family: **invalid** ("checked and failed") versus **unverifiable** ("could not check" — an unresolvable presenter, an unreachable revocation source). The recommended HTTP mapping: **401** for proof-layer failures (steps 1–7, with a `WWW-Authenticate: DFOS` challenge), **403** for credential-layer failures (steps 8–11), **503** for unverifiable — a transient resolution failure is the server's condition, not the caller's, and MUST NOT be reported as a credential judgment.

---

## The `api:<host>` Resource and Its Actions

The credential side of this capability is one additive resource form, registered in [CREDENTIALS.md → Resource Types](https://protocol.dfos.com/credentials) with its consuming rules here.

**`<host>` is the API's bare lowercase hostname** — no scheme, no port, no path. Host-as-id means the resource names the surface by where it is served, so a fork or self-hosted deployment gets the same form for free: a credential for `api:api.example.org` gates that host's API exactly as `api:api.dfos.com` gates the canonical one, with no registry of deployments anywhere.

**Actions are enumerated registry tokens.** This spec's v0 registry defines exactly one:

| Action         | Grants                                         |
| -------------- | ---------------------------------------------- |
| `read:profile` | Read access to the granting user's own profile |

New tokens register here additively as API surface grows (`read:posts`, and eventually write-bearing tokens once revocation tooling is user-facing). A grant carrying several tokens is an ordinary comma-separated action list (`read:profile,read:posts`), and narrowing is dropping tokens — the credential spec's action-set machinery, unchanged.

**There is no action wildcard, and `read:*` is a trap, not a shorthand.** Per the frozen [action lattice](https://protocol.dfos.com/credentials), `*` is a **literal token**: an `att` entry with action `read:*` matches only a route requiring the literal action `read:*` — which no route ever will, because the registry above enumerates real tokens. Such an entry passes attenuation (any set may carry it) and grants nothing at verification. Growth is enumeration, always: more tokens, never a pattern.

**Attenuation is exact, per the general rule.** `api:` follows the credential spec's default for every non-`chain:` form: coverage is exact byte equality of the full resource string, no wildcard form is defined, and coverage never crosses resource types. `api:*` is an ordinary id covering only itself, which is never a served host.

### Issuance

How a third party obtains an `api:<host>` credential is not this spec's concern — the proof binds to whatever valid credential is presented. The canonical issuance moment is a [SIWD](https://protocol.dfos.com/siwd) credential-returning scope: the user consents at the hosting platform's front door, and the credential comes back through the callback — `iss` the user's DID (signed custodially today, by the user's own key under self-custody, same shape), `aud` the third party's `client_did`, one `att` entry on the platform's API host, `exp` at the issuer's discretion with revocation as the timely lever. Delegation onward is ordinary credential machinery: the third party MAY sub-delegate its grant through `prf` chains (to its own services, or eventually to a browser-session key — a named seam, below), and the verification walk holds every hop to monotonic attenuation.

---

## Relationship to Auth Tokens

The protocol now has exactly **two** ephemeral proof-of-possession shapes, and the doctrine is that it will not grow a third:

| Concern           | Auth token ([WEB-RELAY.md](https://protocol.dfos.com/web-relay)) | Request proof (this spec)                                        |
| ----------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- |
| Question answered | "Does this caller control this DID, for this relay?"             | "Is the credential's audience making exactly this request, now?" |
| Binding           | Audience — a relay hostname                                      | Request — method, host, path, body hash — plus a credential CID  |
| JWS `typ`         | `JWT`                                                            | `did:dfos:request-proof`                                         |
| Lifetime          | Short (minutes; relay-capped)                                    | Shorter (seconds; the freshness window)                          |
| Key resolution    | Current-state                                                    | Current-state                                                    |
| Stands alone      | Yes — it is the whole AuthN statement                            | No — meaningless without its credential and its request          |
| Content-addressed | No                                                               | No                                                               |

The auth token is **aud-bound**: it proves key possession to one named counterparty and lets that counterparty attribute a whole connection's worth of requests. The request proof is **request-bound**: it proves key possession over one exact request and rides a durable grant. Every authenticated surface the protocol grows picks one of these two shapes by asking which binding it needs — a third shape would mean a surface needed a binding neither provides, and that is the moment to extend one of these additively (both ignore unknown members), never to mint a new envelope.

---

## Security Considerations

**A stolen credential is a metadata leak, not an access leak.** The credential names the grant — who authorized whom, over what, until when — and PoP makes that all it is: without the audience key, a captured credential authorizes nothing anywhere. This is why front-channel credential delivery at the SIWD callback is a considered position rather than an accident (see the [SIWD spec](https://protocol.dfos.com/siwd)); the artifact that must never leak is the audience key, which never crosses a channel at all.

**Within-window replay of an identical request is the accepted bound.** A captured proof replays only as the byte-identical request — same method, host, path, body — inside the freshness window, against the same host. For the read-only v0 registry that is a re-read returning the same response: the deliberate trade for a verifier that keeps no per-request state. The bound is honest, and it is also why the v0 registry is read-only. **Write-bearing actions change the calculus** — a replayed write re-executes — and a deployment gating writes MUST add per-request uniqueness: a `jti`-style member registered additively on this envelope, consumed by an atomic check-and-delete at the verifier, exactly the [consumed discipline](https://protocol.dfos.com/siwd) SIWD already specifies for artifacts whose redemption has side effects. That is a named seam this shape is built to take, not a v0 feature.

**`aud: "*"` is refused because it un-asks the question.** A public credential has no audience, so there is no audience key, so there is nothing whose possession a proof could prove — any keyholder anywhere could mint a passing proof, which is a bearer grant wearing a proof's clothes. The credential spec already warns that public-plus-write is a world-writable bearer token; on this surface even public-plus-read is refused, because the entire point of the surface is that presentation proves audience.

**Revocation is the user's lever, and the verify path is where it has teeth.** `exp` is signer-discretionary and may be months out; what keeps a standing grant answerable is that step 8 re-checks revocation on every request against the verifier's current knowledge. That knowledge is as fresh as the verifier's revocation source — an API host SHOULD resolve revocations from the relays its users' identities actually list, and a deployment choosing a cache interval is choosing its revocation latency, a policy it should state.

**The browser is not a keyholder — today.** A browser application cannot hold the audience key non-extractably, so the supported browser shape is a backend-for-frontend: the browser holds an ordinary session with the third party's own backend, and the backend holds the key and signs proofs. The named future seam is a delegated session key — the third party sub-delegates an attenuated child credential to a non-extractable browser-held key, DBSC-parallel — which needs one additive registration (how a leaf `aud` names a bare session key) and nothing this spec forecloses: the chain walk, the exact-match resource rule, and the proof envelope all hold unchanged one `prf` hop deeper.

**Transport security is assumed, not replaced.** The proof authenticates the request; it does not encrypt anything. `api:` surfaces are HTTPS surfaces, and the freshness window is sized against replay, not against an adversary reading traffic in the clear.

**DoS controls are the caps.** Both size bounds are checked before any decode, and steps 1–5 reject without a single network resolution — an unauthenticated flood is refused at parse cost. Verifiers SHOULD rate-limit by presenter DID after step 6 and by connection before it.

---

## Conformance

The envelope is covered by cross-implementation vectors in the TypeScript and Go reference packages: deterministic proofs from fixed seeds (the canonical signing input is byte-compared across languages), and an adversarial set — wrong-case method, path mismatch including query-string and trailing-slash variants, body-hash mismatch, padded and non-canonical `bodyHash` encodings, stale and forward-dated `iat`, credential-CID mismatch, an `aud: "*"` leaf, action-token case sensitivity, and a `read:*` grant presented against a `read:profile` route (which MUST fail coverage — the literal-`*` rule is only as real as the vector that attacks it). The five-language sweep lands at `0.x` exit, per the status block.

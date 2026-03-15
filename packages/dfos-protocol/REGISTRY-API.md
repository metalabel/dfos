# DFOS Registry API

Minimal HTTP API for chain storage, retrieval, and resolution. Any server implementing these endpoints with these semantics is a compatible DFOS registry.

The protocol is transport-agnostic — chains can be exchanged through any mechanism. This API defines one standard transport binding: a REST interface for submitting chains, resolving identities and entities, and retrieving operations and documents.

[Protocol Specification](https://protocol.dfos.com/spec) · [OpenAPI Spec](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/openapi.yaml) · [Reference Implementation](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/registry/server.ts)

---

## Overview

The registry stores verified chains and serves resolved state. It enforces **linear chain integrity** — it accepts chains that are the same length or longer than what's stored, and rejects forks (two different operations at the same chain position).

Six endpoints, two concerns:

| Concern             | Endpoints                                       |
| ------------------- | ----------------------------------------------- |
| **Identity chains** | Submit chain, resolve identity, list operations |
| **Content chains**  | Submit chain, resolve entity, list operations   |
| **Lookup**          | Resolve operation by CID                        |

All request and response bodies are JSON (`application/json`).

---

## Identity Endpoints

### `POST /identities` — Submit or extend an identity chain

Submit an ordered array of JWS tokens (genesis-first). The registry verifies the chain, derives the DID from the genesis CID, and stores it.

**Request:**

```json
{
  "chain": ["eyJhbGciOiJFZERTQSI...", "eyJhbGciOiJFZERTQSI..."]
}
```

| Field   | Type     | Description                                                |
| ------- | -------- | ---------------------------------------------------------- |
| `chain` | string[] | Ordered JWS compact tokens, genesis-first. Minimum 1 item. |

**Responses:**

| Status | Meaning                                                    |
| ------ | ---------------------------------------------------------- |
| `201`  | Chain accepted (new or extended) — returns `IdentityState` |
| `200`  | Chain already stored, no change — returns `IdentityState`  |
| `400`  | Invalid chain (verification failed)                        |
| `409`  | Fork conflict with stored chain                            |

---

### `GET /identities/{did}` — Resolve current identity state

Returns the current key state for a DID.

**Parameters:**

| Name  | In   | Pattern                              | Example                           |
| ----- | ---- | ------------------------------------ | --------------------------------- |
| `did` | path | `did:dfos:[2346789acdefhknrtvz]{22}` | `did:dfos:e3vvtck42d4eacdnzvtrn6` |

**Response (`IdentityState`):**

```json
{
  "did": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "isDeleted": false,
  "authKeys": [{ "id": "key_...", "type": "Multikey", "publicKeyMultibase": "z6Mk..." }],
  "assertKeys": [{ "id": "key_...", "type": "Multikey", "publicKeyMultibase": "z6Mk..." }],
  "controllerKeys": [{ "id": "key_...", "type": "Multikey", "publicKeyMultibase": "z6Mk..." }]
}
```

---

### `GET /identities/{did}/operations` — List identity chain operations

Returns operations newest-first, paginated.

**Parameters:**

| Name     | In    | Description                                                  |
| -------- | ----- | ------------------------------------------------------------ |
| `did`    | path  | The DID to list operations for                               |
| `cursor` | query | Opaque pagination cursor (CID of last item on previous page) |
| `limit`  | query | Page size, 1–100, default 25                                 |

**Response (`PaginatedOperations`):**

```json
{
  "operations": [
    { "cid": "bafyrei...", "jwsToken": "eyJ...", "createdAt": "2026-03-07T00:01:00.000Z" },
    { "cid": "bafyrei...", "jwsToken": "eyJ...", "createdAt": "2026-03-07T00:00:00.000Z" }
  ],
  "nextCursor": null
}
```

---

## Content Endpoints

### `POST /entities` — Submit or extend a content chain

Same mechanics as identity submission. The registry verifies the chain (resolving signing keys from stored identity chains), derives the entity ID from the genesis CID, and stores it.

**Request:** Same `{ "chain": [...] }` format as identity submission.

**Responses:** Same status code semantics — `201` accepted, `200` noop, `400` invalid, `409` fork.

---

### `GET /entities/{entityId}` — Resolve current entity state

Returns the current state for a content chain entity.

**Parameters:**

| Name       | In   | Pattern                     | Example                  |
| ---------- | ---- | --------------------------- | ------------------------ |
| `entityId` | path | `[2346789acdefhknrtvz]{22}` | `67t27rzc83v7c22n9t6z7c` |

**Response (`EntityState`):**

```json
{
  "entityId": "67t27rzc83v7c22n9t6z7c",
  "isDeleted": false,
  "currentDocumentCID": "bafyrei...",
  "genesisCID": "bafyrei...",
  "headCID": "bafyrei..."
}
```

| Field                | Description                                         |
| -------------------- | --------------------------------------------------- |
| `currentDocumentCID` | CID of current document, null if cleared or deleted |
| `genesisCID`         | CID of the genesis operation                        |
| `headCID`            | CID of the most recent operation                    |

---

### `GET /entities/{entityId}/operations` — List content chain operations

Same pagination mechanics as identity operations.

---

## Lookup Endpoints

### `GET /operations/{cid}` — Resolve a single operation by CID

Returns the JWS token for any operation (identity or content) by its CID.

**Response:**

```json
{
  "cid": "bafyrei...",
  "jwsToken": "eyJ..."
}
```

---

## Errors

All error responses follow a standard shape:

```json
{
  "error": "BAD_REQUEST",
  "message": "Human-readable description"
}
```

| Error Code    | Used By                                                    |
| ------------- | ---------------------------------------------------------- |
| `BAD_REQUEST` | Invalid chain, malformed request                           |
| `NOT_FOUND`   | Identity, entity, operation, or document not found         |
| `CONFLICT`    | Fork detected — submitted chain diverges from stored chain |

---

## Chain Submission Semantics

The registry enforces **linear chain extension**:

- **New chain** — genesis operation not seen before → store and return `201`
- **Extension** — submitted chain is longer than stored, shares the same prefix → replace stored chain, return `201`
- **Noop** — submitted chain is identical to stored → return `200`
- **Fork** — submitted chain diverges from stored chain at some operation → reject with `409`

This means a registry is **eventually consistent with the longest valid chain** it receives. It does not implement consensus — if two registries receive different valid extensions, they may diverge. Fork detection is the caller's responsibility.

---

## Authentication

Registry endpoints that require authentication use **EdDSA JWTs** signed with the same Ed25519 keys from identity chains. The JWT convention is not part of the chain protocol — it's an application-layer auth mechanism for services.

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "key_ez9a874tckr3dv933d3ckd"
}
```

```json
{
  "iss": "dfos",
  "sub": "did:dfos:e3vvtck42d4eacdnzvtrn6",
  "aud": "dfos-api",
  "exp": 1772902800,
  "iat": 1772899200,
  "jti": "session_ref_example_01"
}
```

| Field | Description                                                   |
| ----- | ------------------------------------------------------------- |
| `kid` | Bare key ID (not a DID URL — the `sub` claim carries the DID) |
| `sub` | The DID of the authenticating identity                        |
| `aud` | Target audience (e.g., `"dfos-api"`)                          |

The signing mechanics are identical to operation JWS — `ed25519.sign(UTF8(base64url(header) + "." + base64url(payload)), privateKey)`. The key is resolved from the identity chain via `kid` + `sub`.

---

## Reference Implementation

A complete reference server is available in the protocol package:

- [`registry/server.ts`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/registry/server.ts) — Hono-based HTTP server implementing all endpoints
- [`registry/store.ts`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/registry/store.ts) — In-memory chain store with linear enforcement
- [`openapi.yaml`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/openapi.yaml) — OpenAPI 3.1 machine-readable specification

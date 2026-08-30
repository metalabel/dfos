# relay-conformance

Go integration test suite that exercises the full [DFOS web relay](https://protocol.dfos.com/web-relay) HTTP surface. Runs against any live relay via the `RELAY_URL` environment variable — use it to verify both the TypeScript and Go relay implementations, or any third-party relay.

## Run

```bash
# Against any relay
RELAY_URL=http://localhost:4444 go test -v -count=1 ./...

# Against the TS relay (starts it automatically)
./scripts/run-conformance.sh
```

Authenticated requests sign an identity proof bound to the relay's own configured
authority, so the target must be booted with one (`authority` /
`RelayOptions.Authority` / `dfos serve --authority`) or every authenticated route
answers 503. The suite binds proofs to the authority of the URL it dials; set
`RELAY_AUTHORITY` when the relay is configured for a different host than the one
you reach it at, as behind a proxy or a tunnel.

## Coverage

Tests covering:

- Well-known discovery and relay metadata
- Identity lifecycle (create, update, delete, batch, idempotency, controller key rotation). Every genesis fixture is SINGLE-KEY — one key declared in `authKeys`, `assertKeys` and `controllerKeys`, because the genesis signature is that key's own possession proof and one signature proves one key. A fixture that needs a second key gets there the way the protocol does: a single-key genesis, then an update introducing the key with its possession envelope
- Content lifecycle (create, update, delete, fork acceptance, DAG logs, deterministic head selection, post-delete rejection, notes, long chains)
- Content update after auth key rotation, multiple independent chains
- Operations by CID, operation log pagination
- Countersignatures (dedup, empty result, multi-witness, self-countersign, non-existent operation, cursor pagination over `/proof/v1/countersignatures/:cid`)
- Blob upload/download (CID verification, auth, credential-based access, multi-version, idempotent upload)
- Delegated content operations (write credentials, delegated blob upload, delegated delete)
- Credentials (expiry, scope mismatch, type enforcement, deleted issuer behavior)
- Signature verification (tampered signature, wrong signing key)
- Identity-proof authentication (the gate on write-shaped and read-shaped routes, jti replay refusal, proofs bound to another request or other bytes, a non-DFOS scheme, and the well-known `ingestion` advertisement)
- Auth edge cases (wrong host, stale proof, rotated-out key)
- Proof-required ingestion (anonymous submission refused 403 at the admission ladder; the same batch admitted under a proof)
- Batch processing (3-step dependency sort, content-identity sort, large batch, dedup, mixed valid/invalid, multi-chain)
- Input validation (malformed JSON, empty operations, invalid JWS)
- Future timestamp guard (reject identity/content ops >24h ahead)
- Artifact ingestion and sequencer cross-batch dependency resolution
- Revocation status routes (`/revocations/v1` — self-proving JWS answers, honest absence, malformed-param 400s, capability-gated, paginated issuer feed with `limit`/`after`/`next` cursor draining)
- Signing mailbox (deposit authorization, subject polling, responses, declines, expiry, limits, and disabled-capability 501s)
- Index queries (`/index/v0` — operation, artifact, identity, content, countersignature, credential, and credit projections with filters and pagination, plus the disabled-capability 501s)
- Key possession and the void semantics — an update introducing an UNPROVED key is accepted and sequenced (possession evidence must never reach a relay's accept/reject verdict), and the key it introduced is absent from the identity route's effective key arrays, named on `voidKeys` with its role and introducing operation, absent from every DID-document verification relationship, and absent from the `key=` reverse index; the same operation shape carrying a valid [KEY-PROOF](https://protocol.dfos.com/key-proof) envelope lands in effective state, in `provedKeys`, and in `key=`
- The two key-addressed filters as one class — `signerKey=` on `/index/v0/operations` (every row kind including the bare-kid genesis, ingest-time freeze across a key rotation, AND-composition, pagination under both orderings, and a row whose signer the chain declared but never proved recording no signer key at all) and `key=` on `/index/v0/identities` (has-ever-PROVED across all three key arrays, deleted chains still matching, rotation survival, and a chain that merely DECLARES a key matching nothing), both matched byte-for-byte as declared and both opaque (an unmatched value is an empty 200, never a 400). Both self-skip against a relay that does not implement the parameter, detected behaviorally — an unrecognized filter is dropped rather than rejected on these routes. The present-but-empty value is deliberately left to the parity harness instead: the specification is silent on it, so pinning it here would gate a third-party relay on an unstated posture

## Dependencies

The test suite depends on [`dfos-protocol-go`](../dfos-protocol-go) for protocol operations (signing, CID derivation, credential minting). The `go.mod` uses a local `replace` directive.

## Scripts

| Script                            | Description                                                                |
| --------------------------------- | -------------------------------------------------------------------------- |
| `scripts/parity-serve.ts`         | Start a TS relay with the pinned identity used by the parity harness       |
| `scripts/run-conformance.sh`      | Start a TS relay on a random port, run the full suite, clean up            |
| `scripts/run-index-disabled.sh`   | Run index-disabled conformance against the TS and Go relays                |
| `scripts/run-parity.sh`           | Run dual-relay proof-plane parity against the TS and Go relays             |
| `scripts/run-proof-required.sh`   | Run proof-required ingestion conformance against the TS relay              |
| `scripts/run-signing.sh`          | Run SIGNING 0.1 conformance against the TS and Go relays                   |
| `scripts/run-write-disabled.sh`   | Run write-disabled conformance against the TS and Go relays                |
| `scripts/serve-conformance.ts`    | Start a TS relay with `MemoryRelayStore` for testing                       |
| `scripts/serve-index-disabled.ts` | Start a TS relay with the `/index/v0` family disabled (501 on every route) |
| `scripts/serve-proof-required.ts` | Start a proof-required TS relay, plus an open seed door on the next port   |
| `scripts/serve-signing.ts`        | Start a signing-enabled TS relay for conformance testing                   |
| `scripts/serve-write-disabled.ts` | Start a seeded, write-disabled TS relay for read-only conformance testing  |

## License

MIT

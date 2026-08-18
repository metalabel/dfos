# relay-conformance

Go integration test suite that exercises the full [DFOS web relay](https://protocol.dfos.com/web-relay) HTTP surface. Runs against any live relay via the `RELAY_URL` environment variable — use it to verify both the TypeScript and Go relay implementations, or any third-party relay.

## Run

```bash
# Against any relay
RELAY_URL=http://localhost:4444 go test -v -count=1 ./...

# Against the TS relay (starts it automatically)
./scripts/run-conformance.sh
```

## Coverage

Tests covering:

- Well-known discovery and relay metadata
- Identity lifecycle (create, update, delete, batch, idempotency, controller key rotation)
- Content lifecycle (create, update, delete, fork acceptance, DAG logs, deterministic head selection, post-delete rejection, notes, long chains)
- Content update after auth key rotation, multiple independent chains
- Operations by CID, operation log pagination
- Countersignatures (dedup, empty result, multi-witness, self-countersign, non-existent operation, cursor pagination over `/proof/v1/countersignatures/:cid`)
- Blob upload/download (CID verification, auth, credential-based access, multi-version, idempotent upload)
- Delegated content operations (write credentials, delegated blob upload, delegated delete)
- Credentials (expiry, scope mismatch, type enforcement, deleted issuer behavior)
- Signature verification (tampered signature, wrong signing key)
- Auth edge cases (wrong audience, expired token, rotated-out key)
- Batch processing (3-step dependency sort, content-identity sort, large batch, dedup, mixed valid/invalid, multi-chain)
- Input validation (malformed JSON, empty operations, invalid JWS)
- Future timestamp guard (reject identity/content ops >24h ahead)
- Artifact ingestion and sequencer cross-batch dependency resolution
- Revocation status routes (`/revocations/v1` — self-proving JWS answers, honest absence, malformed-param 400s, capability-gated, paginated issuer feed with `limit`/`after`/`next` cursor draining)
- Signing mailbox (deposit authorization, subject polling, responses, declines, expiry, limits, and disabled-capability 501s)
- Index queries (`/index/v0` — identity, content, countersignature, and credential projections with filters and pagination)

## Dependencies

The test suite depends on [`dfos-protocol-go`](../dfos-protocol-go) for protocol operations (signing, CID derivation, credential minting). The `go.mod` uses a local `replace` directive.

## Scripts

| Script                            | Description                                                               |
| --------------------------------- | ------------------------------------------------------------------------- |
| `scripts/parity-serve.ts`         | Start a TS relay with the pinned identity used by the parity harness      |
| `scripts/run-conformance.sh`      | Start a TS relay on a random port, run the full suite, clean up           |
| `scripts/run-parity.sh`           | Run dual-relay proof-plane parity against the TS and Go relays            |
| `scripts/run-signing.sh`          | Run SIGNING 0.1 conformance against the TS and Go relays                  |
| `scripts/run-write-disabled.sh`   | Run write-disabled conformance against the TS and Go relays               |
| `scripts/serve-conformance.ts`    | Start a TS relay with `MemoryRelayStore` for testing                      |
| `scripts/serve-signing.ts`        | Start a signing-enabled TS relay for conformance testing                  |
| `scripts/serve-write-disabled.ts` | Start a seeded, write-disabled TS relay for read-only conformance testing |

## License

MIT

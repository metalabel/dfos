# protocol-verify

Cross-language verification of the [DFOS protocol](https://protocol.dfos.com/spec). Five independent implementations re-derive CIDs, verify Ed25519 signatures, check credential structures, and re-derive identity operations (including one carrying a services discovery set) from the same reference fixtures — proving the protocol specification is unambiguous across languages.

Each suite is **standalone**: it uses only its language's native Ed25519, dag-cbor, and SHA-256 implementations. None import from `@metalabel/dfos-protocol`, `dfos-protocol-go`, or any other DFOS library. The claim is about the _protocol_, not any particular library.

## Reference Constants

[`vectors.json`](vectors.json) is the single source of every expected value — JWS tokens, CIDs, DIDs, multikeys, canonical CBOR bytes, document-CID inputs and outputs, and the reject corpus. Each suite reads it at test time by relative path. The only literals left in a suite's source are the two seed phrases (`dfos-protocol-reference-key-1`, `dfos-protocol-reference-key-2`) that every value is derived from, and the protocol's own constant strings.

The artifact is **generated, not curated**: `packages/dfos-protocol/tests/protocol-reference.spec.ts` derives every vector from those fixed seeds and asserts the checked-in file is byte-identical to a fresh generation, so an expected value cannot drift away from the reference implementation. Regenerate a deliberate change with:

```
UPDATE_VECTORS=1 pnpm --filter @metalabel/dfos-protocol exec vitest run tests/protocol-reference.spec.ts
```

`scripts/check-inline-vectors.mjs` is the other half of the guard: it fails if any suite has pasted a vector back inline. That is not hypothetical — the services-genesis and content-create vectors had already split into two self-consistent sets, {TypeScript, Python} against {Go, Rust, Swift}, with all five suites green and no signal.

Standalone-ness is unchanged. Reading a JSON fixture is not a library import: a third party still needs nothing but one suite's source file, `vectors.json`, and their language's native crypto. The independence being claimed is between the five _verifiers_, not between their copies of the answers — and a shared answer sheet makes disagreement visible instead of invisible.

## Suites

| Language   | Path      | Run                                                                                             |
| ---------- | --------- | ----------------------------------------------------------------------------------------------- |
| Go         | `go/`     | `cd go && go test -v`                                                                           |
| TypeScript | `ts/`     | `cd ts && npx tsx verify.ts`                                                                    |
| Python     | `python/` | `uv run --python 3.14 --with pynacl --with dag-cbor --with base58 -- python verify_protocol.py` |
| Rust       | `rust/`   | `cd rust && cargo test --verbose`                                                               |
| Swift      | `swift/`  | `cd swift && swift test`                                                                        |

## What Each Suite Verifies

1. **Key derivation** — deterministic Ed25519 keypair from SHA-256 seed
2. **Multikey encoding** — base58btc multibase with ed25519-pub codec prefix
3. **dag-cbor canonical encoding** — length-first key sorting, integer (not float) encoding
4. **CID derivation** — CIDv1 from dag-cbor bytes (sha256 multihash, base32lower)
5. **DID derivation** — `did:dfos:` suffix from SHA-256 of CID bytes, custom alphabet
6. **JWS verification** — identity genesis, key rotation, content creation signatures
7. **JWT verification** — standard claims with EdDSA
8. **Document CID** — the content document the create operation commits to, re-encoded as canonical dag-cbor and re-hashed
9. **Services genesis** — an identity create whose payload carries a full-state services discovery array (relay locator + content/artifact anchors); the operation CID and DID are re-derived over the decoded payload
10. **DFOS credentials** — UCAN-style credentials with resource/action attenuations
11. **Number encoding determinism** — integers MUST encode as CBOR integers, not floats
12. **Possession proof** — the key proof the rotation carries: a `did:dfos:key-add` envelope whose payload is closed to exactly seven members in one order, whose presented octets are byte-compared against the canonical serialization, and whose signature verifies under the key its own payload names (key 2), inside an operation signed by key 1

### Out of cross-language scope

**Countersignatures** (`typ: did:dfos:countersign`, see PROTOCOL.md → Countersignatures) are a stateless single-JWS primitive but are intentionally **not** covered by these five suites. Countersignature signing/verification is exercised only by the TypeScript and Go unit tests, not as a shared cross-language reference vector — adopting a new language does not require implementing it.

## Adding a New Language

1. Create a new directory (e.g., `kotlin/`)
2. Implement the 12 verification sections above using only native libraries
3. Read the expected values from `../vectors.json` — never paste them inline
4. Add the suite's source path to `scripts/check-inline-vectors.mjs`
5. Add a CI job in `.github/workflows/test-matrix.yml`

If any suite disagrees with the others, the protocol spec is ambiguous and needs clarification.

## License

MIT

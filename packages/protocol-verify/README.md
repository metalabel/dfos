# protocol-verify

Cross-language verification of the [DFOS protocol](https://protocol.dfos.com/spec). Six independent implementations re-derive CIDs, verify Ed25519 signatures, check credential structures, and verify beacon announcements from the same reference fixtures — proving the protocol specification is unambiguous across languages.

Each suite is **standalone**: it uses only its language's native Ed25519, dag-cbor, and SHA-256 implementations. None import from `@metalabel/dfos-protocol`, `dfos-protocol-go`, or any other DFOS library. The claim is about the _protocol_, not any particular library.

## Reference Fixtures

All suites read deterministic test vectors from [`../dfos-protocol/examples/`](../dfos-protocol/examples/). These fixtures are generated from fixed seeds (`dfos-protocol-reference-key-1`, `dfos-protocol-reference-key-2`) so every value is reproducible.

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
8. **Document CID** — content document hashing
9. **Beacon signatures** — manifest pointer announcements with countersignatures
10. **DFOS credentials** — UCAN-style credentials with resource/action attenuations
11. **Number encoding determinism** — integers MUST encode as CBOR integers, not floats

## Adding a New Language

1. Create a new directory (e.g., `kotlin/`)
2. Implement the 11 verification sections above using only native libraries
3. Hard-code the same reference constants (JWS tokens, expected CIDs, etc.) from any existing suite
4. Add a CI job in `.github/workflows/ci.yml`

If any suite disagrees with the others, the protocol spec is ambiguous and needs clarification.

## License

MIT

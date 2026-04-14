# dfos-protocol-go

Go implementation of [DFOS protocol](https://protocol.dfos.com) primitives. Signing, verification, CID derivation, credentials, and chain operations as `package dfos`.

## Install

```bash
go get github.com/metalabel/dfos/packages/dfos-protocol-go
```

## Usage

```go
import dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"

// Create an identity
ctrl := dfos.NewMultikeyPublicKey(dfos.GenerateKeyID(), pubKey)
token, did, opCID, err := dfos.SignIdentityCreate(
    []dfos.MultikeyPublicKey{ctrl},  // controllers
    []dfos.MultikeyPublicKey{auth},  // authentication
    []dfos.MultikeyPublicKey{},      // delegates
    keyID, privateKey,
)

// Verify a JWS
header, payload, err := dfos.VerifyJWS(token, pubKey)

// Compute a document CID (dag-cbor canonical encoding)
cid, bytes, err := dfos.DocumentCID(map[string]any{"type": "post", "body": "hello"})

// Create a DFOS credential
cred, err := dfos.CreateCredential(
    issuerDID, subjectDID, kid, "DFOSContentRead",
    5*time.Minute, contentID, privateKey,
)
```

## API

All protocol operations are covered:

| Function             | Description                                  |
| -------------------- | -------------------------------------------- |
| `SignIdentityCreate` | Sign an identity genesis operation           |
| `SignIdentityUpdate` | Sign an identity key rotation                |
| `SignIdentityDelete` | Sign an identity deletion (terminal)         |
| `SignContentCreate`  | Sign a content chain genesis                 |
| `SignContentUpdate`  | Sign a content chain update                  |
| `SignContentDelete`  | Sign a content chain deletion                |
| `SignBeacon`         | Sign a manifest beacon                       |
| `SignArtifact`       | Sign a standalone inline document            |
| `SignCountersign`    | Countersign a target operation by CID        |
| `CreateAuthToken`    | Create a relay-scoped JWT auth token         |
| `CreateCredential`   | Issue a DFOS credential (read/write)         |
| `VerifyJWS`          | Verify an Ed25519 JWS token                  |
| `VerifyCredential`   | Verify a DFOS credential                     |
| `DocumentCID`        | Canonical dag-cbor encode and CIDv1 hash     |
| `BuildMerkleRoot`    | Compute SHA-256 merkle root over content IDs |

## Tests

```bash
go test -v -cover ./...
```

41 tests, 85% statement coverage.

## Dependencies

Only two direct dependencies:

- [`fxamacker/cbor/v2`](https://github.com/fxamacker/cbor) — CBOR encoding (for dag-cbor canonical form)
- [`mr-tron/base58`](https://github.com/mr-tron/base58) — Base58 encoding (for multikey DID derivation)

Ed25519 uses the Go standard library (`crypto/ed25519`).

## License

MIT

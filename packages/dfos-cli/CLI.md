# DFOS CLI

A command-line interface for the DFOS protocol — manages identities, signs operations, interacts with relays, and stores chains locally. The sovereign actor in the DFOS architecture.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-cli) · [Protocol](https://protocol.dfos.com)

---

## Install

### One-liner (Linux / macOS)

```bash
curl -sSL https://protocol.dfos.com/install.sh | sh
```

### Homebrew (macOS)

```bash
brew install metalabel/tap/dfos
```

### Container

```bash
docker pull ghcr.io/metalabel/dfos:latest
```

### Windows

Download the latest release from [GitHub Releases](https://github.com/metalabel/dfos/releases/latest). Extract the zip and add `dfos.exe` to your PATH.

### From source

```bash
cd packages/dfos-cli && make build
```

---

## Quickstart

```bash
# create your identity
dfos identity create --name myname

# publish your first post
dfos post create --title "hello world" --body "gm"

# see it
dfos post list

# run a relay
dfos serve
```

---

## Philosophy

The DFOS protocol defines signed chain primitives — identity and content chains, beacons, credentials — but says nothing about how a user manages keys or communicates with relays. The CLI is the user-side agent that bridges this gap.

Relays are dumb pipes that verify and store. The CLI is the sovereign actor: it generates keys, signs operations, decides what to publish and when, and independently verifies what relays serve back. Private key material never leaves the local machine.

The CLI is designed for both human operators and AI agents. Every command that produces output supports `--json` for structured machine-readable responses. Every interactive prompt has a flag equivalent. Stdin is accepted wherever a file is expected.

---

## Architecture

```
┌──────────────────────────┐
│     OS Keychain          │  Ed25519 private key seeds
│  (never on disk)         │  macOS Keychain / Linux secret-service / Windows Credential Manager
└──────────┬───────────────┘
           │
┌──────────▼───────────────┐
│   ~/.dfos/               │  Configuration + local chain store
│   ├── config.toml        │  Relays, identities, contexts, defaults
│   └── store/             │  Chain data (owned + fetched)
│       ├── identities/    │  One JSON file per DID
│       ├── content/       │  One JSON file per content ID
│       ├── beacons/       │  One JSON file per DID
│       └── blobs/         │  Raw document bytes
└──────────┬───────────────┘
           │
┌──────────▼───────────────┐
│     Relays (HTTP)        │  Verify, store, serve
│  relay.dfos.com          │  Relays are peers, not authorities
│  localhost:4444          │
└──────────────────────────┘
```

The CLI has three layers of state:

- **OS Keychain**: private key material only. One entry per Ed25519 key, keyed by `dfos` service + `did:dfos:xxx#key_yyy` account. Hex-encoded 32-byte seed. Never written to disk.
- **Local store** (`~/.dfos/store/`): chain data, operation logs, and blobs. Both chains you own (have private keys for) and chains you've fetched from relays. Flat JSON files per entity.
- **Config** (`~/.dfos/config.toml`): relay URLs, identity names, active context, defaults.

---

## Context Model

A **context** is a (named-identity, named-relay) pair. Contexts determine which identity signs operations and which relay receives them.

### Configuration

```toml
active_context = "alice@local"

[relays.local]
url = "http://localhost:4444"

[relays.prod]
url = "https://relay.dfos.com"

[identities.alice]
did = "did:dfos:f2r3vt89fnh9ntkk7neffe"

[identities.bob]
did = "did:dfos:a8c4rr6d29t2zehn2tc9hv"

[defaults]
auth_token_ttl = "5m"
credential_ttl = "24h"
```

Contexts are implicit: `alice@local` resolves to identity "alice" + relay "local" without needing an explicit `[contexts]` section. Named contexts can be defined for non-obvious names.

### Resolution Precedence

Every command resolves its active (identity, relay) pair via:

```
--ctx flag  →  DFOS_CONTEXT env  →  active_context in config  →  error
--identity  →  DFOS_IDENTITY env →  from resolved context
--relay     →  DFOS_RELAY env    →  from resolved context     →  (optional for local-only ops)
```

The `@` syntax is shorthand: `alice@local` = identity "alice" + relay "local". If both the identity and relay names exist in config, the context resolves without pre-registration.

---

## Key Management

### OS Keychain Integration

One keychain entry per Ed25519 key:

| Field   | Value                            |
| ------- | -------------------------------- |
| Service | `dfos`                           |
| Account | `did:dfos:xxx#key_yyy`           |
| Secret  | hex-encoded 32-byte Ed25519 seed |

During identity genesis (before the DID is known), keys are stored under a temporary account (`pending:<keyId>`) and renamed after the DID is derived from the genesis CID.

The CLI discovers which keys belong to which identity by querying the identity's chain state (from local store or relay) and checking which keys have private material in the keychain.

### In-Memory Mode

`DFOS_NO_KEYCHAIN=1` switches to in-memory key storage. Keys exist only in the current process and are lost on exit. Designed for CI, testing, and environments without an OS keychain daemon.

### Security Properties

- Private keys exist in memory only during signing operations
- No key material is ever written to the filesystem
- `identity keys` shows keychain presence/absence, never key material
- After key rotation, old keys remain in the keychain (needed for historical chain re-verification) but are no longer used for new operations

---

## Local-First Workflow

The default mode is local. Operations are signed and stored in `~/.dfos/store/` without network access. Publishing to relays is explicit.

### Create-Then-Publish

```bash
# create identity (local only)
dfos identity create --name alice
# → keys stored in keychain, genesis stored in ~/.dfos/store/identities/

# create content (local only)
dfos content create post.json
# → blob stored in ~/.dfos/store/blobs/, chain in ~/.dfos/store/content/

# publish when ready
dfos identity publish alice --relay local
dfos content publish <contentId> --relay local
```

### Direct-to-Relay

If `--relay` is present on create commands, the CLI creates and publishes in one step:

```bash
dfos identity create --name alice --relay local
dfos content create post.json --relay local
```

### Smart Dependency Resolution

If you create content with `--relay` but the identity hasn't been published to that relay, the CLI detects the dependency and either prompts or auto-publishes (with `--yes`).

---

## Local Store

Each stored entity is a JSON file with chain data plus local metadata:

```json
{
  "did": "did:dfos:f2r3vt89fnh9ntkk7neffe",
  "log": ["eyJ..."],
  "state": { "did": "...", "isDeleted": false, "authKeys": [...], ... },
  "local": {
    "name": "alice",
    "origin": "created",
    "publishedTo": ["local", "prod"]
  }
}
```

- `origin: "created"` — we generated the keys and signed genesis
- `origin: "fetched"` — downloaded from a relay (no private keys)
- `publishedTo` — which named relays have accepted this chain

### Fetching Remote Chains

The CLI can download and store any chain from any relay, without owning the private keys:

```bash
dfos identity fetch did:dfos:xxx --relay prod --name carol
dfos content fetch abc123 --relay prod
```

Fetched identities appear in `identity list` with `KEYS 0/N` — visible public keys but no private material in the keychain. This enables local verification, credential checking, and countersigning against remote identities.

---

## Content Create

Content creation accepts any JSON document. The CLI enforces one convention: documents should have a `$schema` field pointing to a content model schema.

```bash
# from file
dfos content create post.json

# from stdin
echo '{"$schema":"...","body":"hello"}' | dfos content create -

# from heredoc
dfos content create - <<'EOF'
{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"hello"}
EOF

# with operation note
dfos content create post.json --note "initial draft"
```

If the document has no `$schema` field, the CLI warns but proceeds. The relay is document-agnostic — schema enforcement is a client-side convention, not a protocol rule.

---

## Credentials

The CLI issues VC-JWT credentials for content access control:

```bash
# grant read access
dfos content grant <contentId> <did> --read

# grant write access (allows extending the content chain)
dfos content grant <contentId> <did> --write

# with custom TTL
dfos content grant <contentId> <did> --read --ttl 1h
```

Credentials are printed to stdout (or as JSON with `--json`). The recipient passes them to relay endpoints via the `X-Credential` header, or to the CLI via `--credential`:

```bash
dfos content download <contentId> --credential <vc-jwt> --relay local
```

Credential transport is out-of-band — the CLI mints and consumes them, but doesn't transmit them between parties.

---

## Verification

`content verify` re-verifies a chain's integrity locally — re-derives all CIDs, re-checks all Ed25519 signatures, and optionally verifies blob integrity. Zero trust in the relay.

```bash
dfos content verify <contentId>
```

This catches relay corruption, data tampering, and implementation bugs (including the CBOR number encoding trap — see PROTOCOL.md § Number Encoding).

---

## Raw API Access

`dfos api` is the escape hatch for agents and power users — raw HTTP to the relay with automatic auth token injection:

```bash
# unauthenticated
dfos api GET /.well-known/dfos-relay
dfos api GET /identities/did:dfos:xxx

# with auto auth (mints a fresh JWT, injects Authorization header)
dfos api GET /content/abc123/blob --auth

# POST with body
dfos api POST /operations --body '{"operations":["eyJ..."]}'

# custom headers
dfos api PUT /content/abc123/blob --auth -H "X-Document-CID: bafyrei..." --body-file doc.bin

# response headers
dfos api GET /identities/did:dfos:xxx -i
```

The `--auth` flag resolves the active identity, loads the auth key from the keychain, fetches the relay's DID from well-known, mints a short-lived JWT, and injects it. One flag replaces the entire auth token lifecycle.

---

## Environment Variables

| Variable           | Purpose                                           |
| ------------------ | ------------------------------------------------- |
| `DFOS_CONTEXT`     | Override active context (`identity@relay`)        |
| `DFOS_IDENTITY`    | Override active identity name                     |
| `DFOS_RELAY`       | Override active relay name                        |
| `DFOS_CONFIG`      | Config file path (default: `~/.dfos/config.toml`) |
| `DFOS_NO_KEYCHAIN` | In-memory keys only (CI/testing)                  |
| `DFOS_DEBUG`       | Debug logging (HTTP traffic, key resolution)      |

---

## Commands

| Method | Command                          | Description                                 |
| ------ | -------------------------------- | ------------------------------------------- |
| `GET`  | `identity list`                  | List all known identities (owned + fetched) |
| `GET`  | `identity show [name\|did]`      | Show identity state                         |
| `GET`  | `identity keys [name\|did]`      | Show key state + keychain availability      |
| `POST` | `identity create --name`         | Generate keys + sign genesis                |
| `POST` | `identity update`                | Rotate keys (sign update operation)         |
| `POST` | `identity delete`                | Permanently delete identity                 |
| `POST` | `identity publish [name]`        | Submit identity chain to a relay            |
| `GET`  | `identity fetch <did>`           | Download identity chain from relay          |
| `GET`  | `content show <id>`              | Show content chain state                    |
| `GET`  | `content log <id>`               | Show operation history                      |
| `GET`  | `content download <id>`          | Download blob (stdout or file)              |
| `POST` | `content create <file\|->`       | Create content chain                        |
| `POST` | `content update <id> <file\|->`  | Update content chain (supports delegation)  |
| `POST` | `content delete <id>`            | Permanently delete content chain            |
| `POST` | `content publish <id>`           | Submit content chain + blob to a relay      |
| `GET`  | `content fetch <id>`             | Download content chain from relay           |
| `POST` | `content grant <id> <did>`       | Issue read/write credential                 |
| `GET`  | `content verify <id>`            | Re-verify chain integrity locally           |
| `GET`  | `beacon show [did\|name]`        | Show latest beacon                          |
| `POST` | `beacon announce <id...>`        | Build merkle root, sign, submit             |
| `POST` | `beacon countersign <did\|name>` | Countersign someone's beacon                |
| `POST` | `witness <cid>`                  | Countersign an operation                    |
| `GET`  | `countersigs <cid>`              | Show countersignatures for operation/beacon |
| `GET`  | `auth token`                     | Mint short-lived auth token (stdout)        |
| `GET`  | `auth status`                    | Show current auth state                     |
| `*`    | `api <METHOD> <path>`            | Raw HTTP to relay with optional `--auth`    |
| `GET`  | `relay list`                     | List configured relays                      |
| `GET`  | `relay info [name]`              | Show relay metadata                         |
| `POST` | `relay add <name> <url>`         | Register a named relay                      |
| `DEL`  | `relay remove <name>`            | Unregister a relay                          |
| `SET`  | `use <context>`                  | Set active context                          |
| `GET`  | `config list`                    | Show full configuration                     |
| `GET`  | `status`                         | At-a-glance overview                        |

---

## What's Deferred

- **Schema validation**: validate documents against bundled JSON schemas (currently warns on missing `$schema` only)
- **Key backup/recovery**: mnemonic seed phrases or encrypted export
- **Shell completion**: cobra generates these, needs testing and docs
- **Batch refresh** (`identity fetch --all`): re-fetch all tracked remote identities

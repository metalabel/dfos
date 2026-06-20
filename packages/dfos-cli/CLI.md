# DFOS CLI

The sovereign actor in the DFOS architecture. Generates keys, signs operations, stores chains locally, decides what to publish and when. Relays are dumb pipes — the CLI holds the keys.

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
echo '{"body":"gm"}' | dfos content create -

# see it
dfos content list

# run a relay
dfos serve
```

---

## Philosophy

The DFOS protocol defines signed chain primitives — identity and content chains, credentials, countersignatures — but says nothing about how a user manages keys or communicates with relays. The CLI is the user-side agent that bridges this gap.

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
│   ~/.dfos/               │  Configuration + local relay
│   ├── config.toml        │  Relays, identities, contexts, defaults
│   └── relay.db           │  SQLite — chains, operations, blobs
└──────────┬───────────────┘
           │
┌──────────▼───────────────┐
│     Relays (HTTP)        │  Verify, store, serve
│  relay.dfos.com          │  Relays are peers, not authorities
│  localhost:4444          │
└──────────────────────────┘
```

The CLI embeds a full relay locally — the same SQLite-backed relay that runs as a network service via `dfos serve`. Every CLI command reads and writes to this local relay. Running `dfos serve` exposes it over HTTP with peer sync, gossip, and read-through.

The CLI has three layers of state:

- **OS Keychain**: private key material only. One entry per Ed25519 key, keyed by `dfos` service + `did:dfos:xxx#key_yyy` account. Hex-encoded 32-byte seed. Never written to disk.
- **Local relay** (`~/.dfos/relay.db`): SQLite database storing identity chains, content chains, operations, countersignatures, and blobs. Both chains you own (have private keys for) and chains you've fetched from relays.
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
--peer      →  DFOS_RELAY env    →  from resolved context     →  (optional for local-only ops)
```

The `@` syntax is shorthand: `alice@local` = identity "alice" + relay "local". If both the identity and relay names exist in config, the context resolves without pre-registration.

---

## Key Management

### Backends

The CLI stores each Ed25519 seed under an account key of the form `did:dfos:xxx#key_yyy`. There are two storage backends:

| Backend     | Location                | When used                                          |
| ----------- | ----------------------- | -------------------------------------------------- |
| OS keychain | system keychain/keyring | default, when an OS keychain is reachable          |
| File store  | `~/.dfos/keys/`         | keychain probe fails, or `DFOS_NO_KEYCHAIN` is set |

On startup the CLI probes the OS keychain with a test write/read/delete cycle (the gh CLI pattern). If the probe succeeds, keys go in the keychain. If it fails — which is the common case on headless Linux, containers, and CI where no keychain daemon is running — the CLI prints a warning to stderr and **falls back to the file store**. Setting `DFOS_NO_KEYCHAIN` to any non-empty value skips the probe and uses the file store directly.

`dfos status` reports the active backend in the `Keys:` line (`keychain` or `file (<path>)`), so you can always see where your keys actually live.

#### Keychain backend

One keychain entry per key:

| Field   | Value                            |
| ------- | -------------------------------- |
| Service | `dfos`                           |
| Account | `did:dfos:xxx#key_yyy`           |
| Secret  | hex-encoded 32-byte Ed25519 seed |

Protection is whatever the host keychain provides (e.g. macOS Keychain, libsecret/gnome-keyring).

#### File store backend (`~/.dfos/keys/`)

When the keychain is unavailable, each key is written to its own file under `~/.dfos/keys/`, named after the account (`#` and `:` replaced with path-safe characters). **The file contains the hex-encoded 32-byte Ed25519 seed in plaintext — it is not encrypted.** The directory is created `0700` and each key file `0600` (owner read/write only), so the protection is filesystem permissions and nothing more.

Threat model for the file store:

- A seed file grants full signing authority for that key to anyone who can read it. Treat `~/.dfos/keys/` like an SSH private key directory.
- There is no passphrase, no encryption at rest, and no hardware backing. Disk theft, a permissive backup, a synced home directory, or root on the box all expose the seeds.
- If you need encryption at rest, run on a host with a working OS keychain (the default path) or place `~/.dfos/keys/` on an encrypted volume.

During identity genesis (before the DID is known), keys are stored under a temporary account (`pending:<keyId>`) and renamed after the DID is derived from the genesis CID — this happens in whichever backend is active.

The CLI discovers which keys belong to which identity by querying the identity's chain state (from local store or relay) and checking which keys have private material in the active backend.

### Security Properties

- Private keys are loaded into memory only during signing operations
- With the keychain backend, seeds are held by the OS keychain; with the file store backend, seeds are written **unencrypted** to `~/.dfos/keys/` at mode `0600` (see threat model above)
- `identity keys` shows key presence/absence, never key material
- After key rotation, old keys remain in the active backend (needed for historical chain re-verification) but are no longer used for new operations

---

## Local-First Workflow

The default mode is local. Operations are signed and stored in `~/.dfos/store/` without network access. Publishing to relays is explicit.

### Create-Then-Publish

```bash
# create identity (local only)
dfos identity create --name alice
# → keys stored in keychain, genesis stored in ~/.dfos/relay.db

# create content (local only)
dfos content create post.json
# → blob and chain stored in ~/.dfos/relay.db

# publish when ready
dfos identity publish alice --peer local
dfos content publish <contentId> --peer local
```

### Direct-to-Relay

If `--peer` is present on create commands, the CLI creates and publishes in one step:

```bash
dfos identity create --name alice --peer local
dfos content create post.json --peer local
```

### Smart Dependency Resolution

If you create content with `--peer` but the identity hasn't been published to that relay, the CLI detects the dependency and auto-publishes the identity chain before submitting the content.

---

## Multi-Device Identities (1-of-N)

An identity can hold up to 16 controller keys and 16 auth keys. **Any one current key in a role set can sign** — so the same identity can act from multiple devices, each holding its own key. This is _availability_, not key recovery: with a key on more than one device, losing a single device is not loss of the identity. A surviving device can keep publishing and can even rotate out the lost key.

The handoff never moves a private key. A new device generates its own keypair locally; only its **public** key crosses to a device holding a controller key, which adds it to the chain.

End-to-end, adding device **B** to an identity already controlled by device **A**:

```bash
# 1. On A: create the identity (already has controller + auth keys).
dfos identity create --name alice --peer prod

# 2. On B: get the chain locally.
dfos identity fetch alice --peer prod --name alice

# 3. On B: generate a device key. Prints {id, publicKeyMultibase}.
#    The private seed stays on B; nothing secret is printed.
dfos identity device-pubkey
#   ID:         key_...
#   Public key: z6Mk...

# 4. Hand the id + public key to A (copy/paste, QR, air-gap — public only).

# 5. On A: add B's public key, signed with A's held controller key.
dfos identity add-key --auth-key --id key_... --pubkey z6Mk... --peer prod

# 6. On B: re-fetch so B sees its now-in-chain key.
dfos identity fetch alice --peer prod

# B can now publish content / credentials independently, signing with its
# own key.
dfos content create post.json --peer prod
```

Notes:

- **`device-pubkey` defaults to the auth role**, which is sufficient for publishing content and credentials. Pass `--controller` only to print a controller-role hint; granting a controller key is a higher-trust act (a controller can rotate, delete, and add further keys), and the role is ultimately decided by A's `add-key` flags (`--auth-key` vs `--controller-key`), not by B.
- **B must re-fetch after A's `add-key` propagates.** Between `device-pubkey` and that re-fetch, B holds a private key that is not yet in the published set, so a publish attempt will report "no held auth key" until B syncs.
- This is set up _in advance_. There is no way to add a key after every device key is lost — `add-key` itself must be signed by a held controller key.

## Local Relay

The CLI stores all chain data in a SQLite database at `~/.dfos/relay.db`. This is the same relay implementation that powers network relays via `dfos serve` — the CLI just runs it embedded, without HTTP.

Identity chains, content chains, operations, countersignatures, and blobs all live in this single database. Local metadata (identity names, publish state) is tracked in `config.toml`.

### Fetching Remote Chains

The CLI can download and store any chain from any relay, without owning the private keys:

```bash
dfos identity fetch did:dfos:xxx --peer prod --name carol
dfos content fetch abc123 --peer prod
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

The CLI issues DFOS credentials for content access control. `dfos cred` is an alias for `dfos credential`.

```bash
# grant read access
dfos credential grant <contentId> <did> --read

# grant write access (allows extending the content chain)
dfos credential grant <contentId> <did> --write

# with custom TTL
dfos credential grant <contentId> <did> --read --ttl 1h

# wildcard credential covering all content
dfos credential grant <contentId> <did> --read --broad

# scope to a specific content ID (different from the positional arg)
dfos credential grant <contentId> <did> --read --scope <otherContentId>

# revoke a credential
dfos credential revoke <credentialCID>

# revoke and push to a peer immediately
dfos credential revoke <credentialCID> --peer prod
```

Credentials are printed to stdout (or as JSON with `--json`). The recipient passes them to relay endpoints via the `X-Credential` header, or to the CLI via `--credential` (reads) or `--authorization` (writes):

```bash
# present a read credential for downloads
dfos content download <contentId> --credential <jws> --peer local

# present a write credential for delegated mutations
dfos --ctx bob@prod content update <contentId> new.json --authorization <jws>
```

Credential transport is out-of-band — the CLI mints and consumes them, but doesn't transmit them between parties.

---

## Discovery Services

An identity can publish a **services** set — an additive discovery vocabulary carried in its chain state. Services are full-state on every `identity create` / `identity update`: an update **replaces** the entire set, and an unspecified set is carried forward unchanged. Each entry has a common `{id, type}` envelope; the namespace is **open**, so unrecognized types are preserved verbatim and ignored by the core.

Two types are structurally recognized:

- **`DfosRelay`** — `{id, type, endpoint}`, a transport endpoint where this identity's chains can be fetched.
- **`ContentAnchor`** — `{id, type, label, anchor}`, a stable pointer to a content chain (31-char content id) or an artifact (CIDv1 `baf…`), addressable by `label` (e.g. `profile`, `avatar`).

Bounds (enforced at sign time by the protocol layer): at most 16 entries, unique ids, `id`/`type` each 1..64 chars, and an 8192-byte cap on the encoded services array.

```bash
# attach services at genesis
dfos identity create --name alice \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com \
  --service id=profile,type=ContentAnchor,label=profile,anchor=cv7n8vkvr64cctf3294h9k4eanhff8z

# replace the entire set on update (also rotate keys in the same op if you like)
dfos identity update \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com

# open namespace: any type, carried through verbatim
dfos identity update --service id=site,type=Website,url=https://alice.example

# empty the set
dfos identity update --clear-services

# view the resolved set
dfos identity services alice
dfos identity services alice --json
```

Each `--service` spec is a comma-separated `key=value` list; `id` and `type` are required, every value is a string.

---

## Solemnization (Witness)

`witness` countersigns an operation by CID — a collective endorsement that solemnizes it. This is the protocol's only inter-subjective primitive: a separate identity attesting to someone else's operation. An optional `--relation` tags the nature of the endorsement (open namespace, 1..64 chars). There is no withdrawal primitive — a countersignature is a standing attestation.

```bash
# plain endorsement
dfos witness <operationCID> --peer prod

# tagged with a relation
dfos witness <operationCID> --relation endorses --peer prod
dfos witness <operationCID> --relation coauthors --peer prod

# inspect countersignatures on an operation
dfos countersigs <operationCID>
```

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

| Variable               | Purpose                                           |
| ---------------------- | ------------------------------------------------- |
| `DFOS_CONTEXT`         | Override active context (`identity@relay`)        |
| `DFOS_IDENTITY`        | Override active identity name                     |
| `DFOS_RELAY`           | Override active relay name                        |
| `DFOS_CONFIG`          | Config file path (default: `~/.dfos/config.toml`) |
| `DFOS_NO_KEYCHAIN`     | Skip OS keychain; use file store `~/.dfos/keys/`  |
| `DFOS_NO_UPDATE_CHECK` | Disable automatic version update checks           |
| `DFOS_DEBUG`           | Debug logging (HTTP traffic, key resolution)      |

---

## Commands

| Method | Command                          | Description                                 |
| ------ | -------------------------------- | ------------------------------------------- |
| `GET`  | `identity list`                  | List all known identities (owned + fetched) |
| `GET`  | `identity show [name\|did]`      | Show identity state                         |
| `GET`  | `identity keys [name\|did]`      | Show key state + keychain availability      |
| `GET`  | `identity services [name\|did]`  | Show resolved discovery services            |
| `POST` | `identity create --name`         | Generate keys + sign genesis (`--service`)  |
| `POST` | `identity update`                | Rotate keys / set services (`--service`)    |
| `POST` | `identity device-pubkey`         | Generate a device keypair, print its pubkey |
| `POST` | `identity add-key`               | Add another device's pubkey (1-of-N)        |
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
| `POST` | `credential grant <id> <did>`    | Issue read/write credential                 |
| `POST` | `credential revoke <cid>`        | Revoke a credential                         |
| `GET`  | `content verify <id>`            | Re-verify chain integrity locally           |
| `POST` | `witness <cid>`                  | Countersign an operation (`--relation`)     |
| `GET`  | `countersigs <cid>`              | Show countersignatures for an operation     |
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

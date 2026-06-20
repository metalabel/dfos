---
name: dfos
description: Install, configure, and use the DFOS protocol CLI. Use when the user wants to create identities, publish content, issue credentials, manage relays, or interact with the DFOS protocol. Triggers on mentions of DFOS, dfos CLI, DIDs, content chains, services, relays, or protocol operations.
---

# DFOS CLI

> **Three similarly-named things — don't conflate them:**
>
> - **`dfos`** (this skill) — the Go protocol CLI from the OSS repo (`~/projects/metalabel-dfos-open-source`), installed via the curl one-liner from `protocol.dfos.com` (or Homebrew). For _using_ the protocol: identities, content, credentials, relays.
> - **`dfos-cli` skill** — for _developing_ that same Go CLI: the rebuild-from-source loop in the OSS repo (local relay, keychain cleanup, iterating on CLI source).
> - **`dfos-dx`** — unrelated in-monorepo Node devops script (`./packages/tool-dfos-dx/bin/dfos-dx`) for deploys and migrations. Nothing to do with the protocol CLI.

The `dfos` CLI is a local-first relay node for the DFOS protocol. It manages identities, content chains, and credentials. Your machine is a relay — all data is stored locally first, then optionally published to remote peers.

## Installation

Check if `dfos` is already installed:

```bash
dfos version
```

If not installed, install via the preferred method for the platform:

**macOS (Homebrew)**:

```bash
brew install metalabel/tap/dfos
```

**Linux / macOS (curl)**:

```bash
curl -sSL https://protocol.dfos.com/install.sh | sh
```

**Container**:

```bash
docker pull ghcr.io/metalabel/dfos:latest
```

After installation, verify: `dfos version`. The CLI is a single static binary with no runtime dependencies.

### Updating

```bash
# Homebrew
brew upgrade metalabel/tap/dfos

# Reinstall via script (fetches latest)
curl -sSL https://protocol.dfos.com/install.sh | sh
```

The CLI checks for updates automatically on each run (non-blocking, cached 24h). If a newer version exists, it prints a notice to stderr.

## Core Concepts

- **Identity**: An Ed25519 keypair with a DID (`did:dfos:...`). Keys are stored in the OS keychain (macOS Keychain, Linux secret-service) with automatic file-based fallback at `~/.dfos/keys/`.
- **Content chain**: An append-only chain of signed operations over a document (arbitrary JSON). Each operation has a CID (IPFS CIDv1, `bafyrei...`). Content IDs are 31-char strings over a 19-symbol unambiguous alphabet (e.g., `cv7n8vkvr64cctf3294h9k4eanhff8z`). The document blob is stored separately.
- **Services**: An identity's discovery vocabulary — a controller-signed, full-state set of relay locators and stable content anchors carried in the identity chain. Answers "given a DID, where do I reach it and what stable content does it publish?"
- **Credential**: A DFOS credential (UCAN-style JWS) granting scoped read or write access to content.
- **Relay/Peer**: A node that stores and syncs protocol operations. The CLI itself embeds a local relay backed by `~/.dfos/relay.db` — all operations work offline. Remote peers are HTTP relays you can publish to and fetch from. `dfos serve` exposes your local relay over HTTP so others can peer with you.
- **Context**: A (identity, relay) pair. Most commands need both — set a default with `dfos use alice@prod` or override per-command with `--ctx alice@prod`.

## Quick Start (Local-Only)

```bash
# 1. Create an identity
dfos identity create --name alice

# 2. Set as active identity (no relay needed)
dfos use alice

# 3. Create some content
dfos content create - <<'EOF'
{"$schema":"https://schemas.dfos.com/post/v1","body":"hello world"}
EOF

# 4. List and verify
dfos content list
dfos content verify <contentId>
```

No relay needed — the CLI **is** a local relay. All data lives in `~/.dfos/relay.db`.

## Quick Start (With Relay)

```bash
# 1. Add a public relay
dfos peer add prod https://relay.dfos.com

# 2. Create an identity and publish to the relay
dfos identity create --name alice --peer prod

# 3. Set as default context
dfos use alice@prod

# 4. Verify setup
dfos status
```

Passing `--peer` on `identity create` auto-publishes the identity genesis operation to the relay after local creation.

### Adding a Relay

A relay is any HTTP node speaking the DFOS relay protocol; the canonical public relay is `https://relay.dfos.com`:

```bash
dfos peer add prod https://relay.dfos.com
```

Use `dfos peer info <name>` to verify connectivity.

## Local-First by Default

The CLI **is** a local relay. All data lives in `~/.dfos/relay.db` — no remote peer or HTTP server needed for local operations. Creating identities, content, and credentials all work offline.

For local-only work, set the active identity with `dfos use <name>` (no `@relay`), pass `--identity <name>` on each command, or set the `DFOS_IDENTITY=<name>` env var:

```bash
dfos identity create --name alice

# Option 1: set as active identity
dfos use alice
dfos content create - <<'EOF'
{"body":"hello"}
EOF
dfos content list

# Option 2: pass --identity on each command
dfos --identity alice content verify <contentId>

# Option 3: use the env var
DFOS_IDENTITY=alice dfos content list
```

Remote peers (`--peer`) are only needed when you want to **publish to** or **fetch from** another relay. `dfos serve` exposes your local relay over HTTP so other peers can connect to it — you never need it for local work.

In headless or CI environments, set `DFOS_NO_KEYCHAIN=1` to use file-based key storage instead of the OS keychain (which may prompt interactively).

## Configuration

**Config file**: `~/.dfos/config.toml`

```toml
active_context = "alice@prod"

[relays.prod]
url = "https://relay.dfos.com"
did = "did:dfos:..."

[identities.alice]
did = "did:dfos:..."

[defaults]
auth_token_ttl = "5m"
credential_ttl = "24h"
```

**Context resolution** (highest priority first):

1. `--ctx` flag (or `--identity` / `--peer` individually)
2. `DFOS_CONTEXT` environment variable
3. `active_context` in config.toml

**Environment variables**:

| Variable               | Purpose                                          |
| ---------------------- | ------------------------------------------------ |
| `DFOS_CONTEXT`         | Override active context (`identity@relay`)       |
| `DFOS_IDENTITY`        | Override active identity name                    |
| `DFOS_RELAY`           | Override active relay name                       |
| `DFOS_CONFIG`          | Config file path (default `~/.dfos/config.toml`) |
| `DFOS_NO_KEYCHAIN`     | Force file-based key storage (useful in CI)      |
| `DFOS_DEBUG`           | Enable debug logging                             |
| `DFOS_NO_UPDATE_CHECK` | Disable version check                            |

## Command Reference

### Identity

```bash
dfos identity create --name <name> [--peer <relay>]    # generate keys + sign genesis
dfos identity list                                      # list all known identities
dfos identity show <name|did>                           # show identity state
dfos identity keys <name|did>                           # show key state + keychain status
dfos identity update [--rotate-auth] [--rotate-controller]  # rotate keys
dfos identity delete [name|did]                          # sign identity deletion
dfos identity publish <name|did> --peer <relay>         # push to relay
dfos identity fetch <did> --peer <relay> [--name <n>]   # pull from relay
```

### Content

```bash
# Create content chain (from file, stdin, or heredoc)
dfos content create <file|-|> [--peer <relay>] [--note <msg>]

# Inspect
dfos content list                           # list all content chains
dfos content show <contentId>               # show chain state
dfos content log <contentId>                # operation history
dfos content download <contentId> [-o file] # download blob

# Mutate
dfos content update <contentId> <file|-|> [--peer <relay>] [--note <msg>]
dfos content delete <contentId> [--peer <relay>]

# Publish / fetch
dfos content publish <contentId> --peer <relay>
dfos content fetch <contentId> --peer <relay>

# Verify integrity locally
dfos content verify <contentId>
```

**Stdin and heredoc creation** (common for scripting):

```bash
echo '{"body":"hello"}' | dfos content create - --peer prod

dfos content create - --peer prod <<'EOF'
{"$schema":"https://schemas.dfos.com/post/v1","body":"hello world"}
EOF
```

Content without a `$schema` field triggers a warning. Pass `--no-schema-warn` to suppress, or include a `$schema` URL in the JSON. Schemas are convention-based — any URL works. Common schemas: `https://schemas.dfos.com/post/v1` (posts/articles), `https://schemas.dfos.com/profile/v1` (identity profiles).

### Credentials

`dfos cred` is an alias for `dfos credential`.

```bash
# Grant read access (default 24h TTL)
dfos credential grant <contentId> <did> --read

# Grant write access
dfos credential grant <contentId> <did> --write

# Custom TTL
dfos credential grant <contentId> <did> --read --ttl 1h

# Wildcard credential covering all content
dfos credential grant <contentId> <did> --read --broad

# Scope to a specific content ID
dfos credential grant <contentId> <did> --read --scope <otherContentId>

# Revoke a credential
dfos credential revoke <credentialCID>

# Revoke and push to a peer immediately
dfos credential revoke <credentialCID> --peer prod

# Delegated write (bob updates alice's content using a write credential)
dfos --ctx bob@prod content update <contentId> new.json --authorization <credential-jws>

# --credential = presenting a READ credential (downloads)
# --authorization = presenting a WRITE credential (mutations)
```

### Services (discovery vocabulary)

Services are full-state discovery entries carried in the identity chain — relay locators (`DfosRelay`) and stable content anchors (`ContentAnchor`). They are set as a complete set on `identity create`/`update` via repeatable `--service` flags; the new set replaces the prior set in full (omit the flag on an update to clear it).

```bash
dfos identity services <name|did>          # show resolved services for an identity

# Set the full services set on create or update (repeat --service per entry):
dfos identity update <name> \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com \
  --service id=profile,type=ContentAnchor,label=profile,anchor=<contentId|baf...>
```

Each `--service` spec is a comma-separated `key=value` list requiring `id` and `type`; recognized types (`DfosRelay`, `ContentAnchor`) carry their own fields, and the namespace is open (unknown types pass through verbatim). An `anchor` is a stable content identifier: a 31-char content ID (mutable content chain) or a `baf...` artifact CID (immutable). The `label` is a free client-semantic key (e.g. `profile`, `avatar`).

### Witness / Countersignatures

```bash
dfos witness <operationCID> [--relation <tag>] --peer <relay>   # countersign an operation
dfos countersigs <cid> --peer <relay>                           # list countersignatures
```

A countersignature is a public witness attestation — the protocol's inter-subjective primitive (endorsement, co-authorship, solemnization). The optional `--relation` tag (open namespace: `endorses`, `coauthors`, `witnessed`, …) names the nature of the attestation.

### Auth Tokens

```bash
dfos auth token [--ttl <duration>]     # mint JWT (stdout, pipe-friendly)
dfos auth status                        # show current auth state

# Use in scripts
TOKEN=$(dfos auth token)
curl -H "Authorization: Bearer $TOKEN" https://relay.dfos.com/content/abc/blob
```

### Raw API Access

For operations not covered by named commands:

```bash
dfos api GET /.well-known/dfos-relay
dfos api GET /identities/<did> --auth
dfos api POST /operations --body '{"operations":["eyJ..."]}' --auth
dfos api POST /operations --body-file ops.json --auth
dfos api PUT /endpoint --auth -H "X-Custom: value" --body-file data.bin
dfos api GET /endpoint -i    # include response headers
```

### Peer / Relay Management

```bash
dfos peer add <name> <url>       # register relay (fetches + caches metadata)
dfos peer remove <name>           # unregister
dfos peer list                    # show configured peers
dfos peer info [name]             # inspect + verify peer
```

`dfos relay` is an alias for `dfos peer`.

### Config

```bash
dfos config list                  # show full config
dfos config get <key>             # get value
dfos config set <key> <value>     # set value
```

### Server & Sync

```bash
dfos serve [--port 4444]          # expose local relay over HTTP
dfos sync                          # sync all local data with all configured peers (global, not context-scoped)
```

### Context & Status

```bash
dfos use <identity@relay>          # set active context
dfos status                        # overview: context, identity, relay status
dfos version                       # show version
```

## JSON Output

All data commands support `--json` for machine-readable output. Always use `--json` when piping or capturing values:

```bash
dfos identity show alice --json | jq .did
dfos content create post.json --peer prod --json | jq -r .contentId
dfos credential grant <id> <did> --read --json | jq -r .credential
dfos identity list --json | jq '.[].did'
dfos peer list --json | jq '.[].url'
```

## Common Workflows

### Publish content end-to-end

```bash
dfos peer add prod https://relay.dfos.com
dfos identity create --name alice --peer prod
dfos use alice@prod

CONTENT=$(dfos content create - --peer prod --json <<'EOF' | jq -r .contentId
{"$schema":"https://schemas.dfos.com/post/v1","body":"hello world"}
EOF
)

echo "Published: $CONTENT"
dfos content show "$CONTENT"
```

### Grant access to another identity

```bash
BOB_DID=$(dfos identity show bob --json | jq -r .did)
CRED=$(dfos credential grant "$CONTENT" "$BOB_DID" --read --json | jq -r .credential)

# Bob downloads using the credential
dfos --ctx bob@prod content download "$CONTENT" --credential "$CRED"
```

### Publish discovery + witness

```bash
# Anchor the content under a semantic label in alice's discovery vocabulary
dfos identity update alice \
  --service id=profile,type=ContentAnchor,label=profile,anchor="$CONTENT" --peer prod

# A witness countersigns the content's genesis operation (an act of solemnization)
GENESIS=$(dfos content show "$CONTENT" --json | jq -r .genesisCID)
dfos --ctx witness@prod witness "$GENESIS" --relation witnessed --peer prod
```

### Local-first (create offline, publish later)

```bash
dfos identity create --name alice           # local only, no relay
dfos --identity alice content create post.json  # local only

# later, when ready:
dfos peer add prod https://relay.dfos.com
dfos identity publish alice --peer prod
dfos content publish <contentId> --peer prod
```

## Error Recovery

- **"no active context"**: Run `dfos use <identity>@<relay>` or pass `--ctx`.
- **"identity not found on relay"**: The CLI auto-publishes identity before content publish. If it fails, run `dfos identity publish <name> --peer <relay>` manually.
- **"key not found"**: Check `dfos identity keys <name>`. If keychain is inaccessible, set `DFOS_NO_KEYCHAIN=1` to use file-based keys.
- **"relay unreachable"**: Check `dfos peer info <name>` — verifies connectivity and metadata.
- **"content verify failed"**: Chain integrity issue. Re-fetch from relay: `dfos content fetch <id> --peer <relay>`.
- **"blob bytes do not match documentCID"**: Remote relay rejected the blob upload. Create content locally first (`dfos content create file.json`), then publish separately (`dfos content publish <id> --peer <relay>`).
- **"content not found on peer" / 0 operations fetched**: The content doesn't exist on that relay. Verify the content ID and check which relay it was published to with `dfos content show <id>`.
- **"read credential required"**: You're trying to download content you don't own and no public standing authorization exists. The creator must either issue a public credential (`dfos credential grant <contentId> <your-did> --read` with `aud: *` for standing auth) or a private credential to present with `--credential <credential-jws>`.
- **"unknown identity" on content publish**: If content includes delegated operations (writes by non-creators via credentials), all referenced identities must be published to the relay first. Publish each delegate's identity before the content.
- **"signer is not the chain creator"**: Content mutations (update, delete) must be signed by the creator identity or via a write credential. Switch to the creator's context, or use `--authorization <credential-jws>` with a DFOS write credential.

## Confirmation Behavior

Destructive commands (`identity delete`, `content delete`, key rotation) execute **immediately and irreversibly** — there is no interactive confirmation prompt and no undo. A `delete` is signed and published the moment you run it. Identity deletion is a permanent, gossiped fact (a controller can later supersede it via a fork, but the `delete` never leaves the log).

**Key loss is not recoverable, but it is survivable — register a second device key in advance.** There is no seed backup or recovery flow, but availability is a multi-key story, not a recovery one: an identity holds up to 16 controller and 16 auth keys, and **any one held key can act (1-of-N)**. Generate a key on a second device with `dfos identity device-pubkey`, then add it from a device holding a controller key with `dfos identity add-key`. The private key never leaves the second device — only its public key crosses. With keys on more than one device, losing a single device is not loss of the identity. This is availability, not recovery: it must be set up _before_ a loss, while you still hold a controller key.

Double-check the target and `--peer` before running:

```bash
dfos identity delete alice
dfos content delete <contentId> --peer prod
```

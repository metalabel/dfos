---
name: dfos
description: Install, configure, and use the DFOS protocol CLI — create identities (DIDs), publish content chains, issue read/write credentials, manage relays and peers, set discovery services, and countersign operations. Use when the user mentions DFOS, the dfos CLI, did:dfos identities, content chains, content IDs, credentials, relays, peers, services discovery, witnessing, or protocol operations.
---

# DFOS CLI

The `dfos` CLI is a **local-first relay node** for the DFOS protocol. It manages
identities, content chains, and credentials. Your machine _is_ a relay: every
operation is signed and stored locally first (in `~/.dfos/relay.db`), then
_optionally_ published to remote peers. Everything works offline; remote peers
are only needed to share with others.

## Mental model (read this first)

- **Two chain types.** An **identity chain** is a self-sovereign, append-only log
  of signed operations that embeds its key sets; its identifier is a
  `did:dfos:<31-char>` DID. A **content chain** is an append-only log over a JSON
  document (referenced by hash, not embedded); its identifier is a bare 31-char
  **content ID**. Both are rooted at a genesis `create` operation. The DID that
  signs a content chain's genesis permanently owns it.
- **The proof is public; the content is access-controlled.** The protocol commits
  to content _hashes_, never plaintext — **it does not encrypt**. Identity ops,
  content ops, credentials, services, and countersignatures live on a public
  "proof plane." Confidentiality of the actual document bytes is enforced at the
  application/relay layer (a relay operator can read what it stores). This is
  undisclosed-by-default, **not** end-to-end encrypted.
- **Local-first.** No relay or network is needed to create identities, content, or
  credentials. A remote **peer** matters only when you publish to or fetch from
  someone else.

## Discovering the command surface

This document is the _judgment layer_ — the mental model, the non-obvious
distinctions, and common workflows. It deliberately does **not** enumerate every
flag, because the binary is the source of truth and flags evolve. For exact,
version-matched usage:

```bash
dfos --help              # all commands
dfos <command> --help    # flags + args for any command/subcommand
```

Every data command also accepts `--json` for machine-readable output — **always
use `--json` when capturing values in scripts.** Aliases: `identity`→`id`,
`credential`→`cred`, `peer`→`relay`.

## Installation

Check first: `dfos version`. If missing, install (single static binary, no runtime
deps):

```bash
# macOS (Homebrew)
brew install metalabel/tap/dfos

# Linux / macOS (curl)
curl -sSL https://protocol.dfos.com/install.sh | sh
```

The CLI self-checks for updates on each run (non-blocking, cached 24h, prints an
upgrade hint to stderr; silent in pipes/CI and on `dev` builds; disable with
`DFOS_NO_UPDATE_CHECK=1`). Upgrade with `brew upgrade metalabel/tap/dfos` or by
re-running the curl script.

> The Docker image `ghcr.io/metalabel/dfos:latest` runs a **relay server**
> (`dfos serve`), not the interactive CLI — use it to host a node, not to install
> the command.

### Keeping this skill in sync with the binary

The skill is embedded in the CLI, so it always matches the installed version:

```bash
dfos skill print                 # emit SKILL.md to stdout
dfos skill install               # write ./.claude/skills/dfos/SKILL.md
dfos skill install --global      # write ~/.claude/skills/dfos/SKILL.md
```

## Core concepts

- **Identity / DID** — an Ed25519-backed identity. Its DID is `did:dfos:` + a
  31-char id over the alphabet `2346789acdefhknrtvz` (e.g.
  `did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr`). Keys live in the OS keychain
  (macOS Keychain / Linux secret-service) with a file fallback at `~/.dfos/keys/`.
- **Content ID** — the bare 31-char identifier of a content chain, same encoding
  as a DID suffix but with no prefix (e.g. `cv7n8vkvr64cctf3294h9k4eanhff8z`).
- **CID** — an IPLD CIDv1 (`bafyrei…`, ~59 chars). Addresses _immutable exact
  bytes_: a specific operation (`operationCID`), a committed document
  (`documentCID`), or a standalone artifact. Distinct from the _living_ content
  ID / DID, which name a whole chain.
- **Services** — an identity's discovery vocabulary: a controller-signed,
  full-state set of `DfosRelay` locators and `ContentAnchor` entries carried in
  the identity chain. Answers "given a DID, where do I reach it and what stable
  content does it publish?"
- **Credential** — a signed grant of scoped **read** or **write** access to
  content, issued by the content creator to a delegate DID.
- **Countersignature** — a public witness attestation referencing an operation by
  CID (endorsement, co-authorship, solemnization). The protocol's only
  inter-subjective primitive.
- **Context** — an `(identity, peer)` pair. Most remote commands need both. Set a
  default with `dfos use alice@prod`, or override per-command with
  `--ctx`/`--identity`/`--peer`.

## Quick start — local-only

```bash
dfos identity create --name alice          # generate keys + sign genesis (no relay needed)
dfos use alice                             # set active identity (local-only context)

dfos content create - <<'EOF'
{"$schema":"https://schemas.dfos.com/post/v1","body":"hello world"}
EOF

dfos content list
dfos content verify <contentId>            # re-verify chain integrity locally
```

All data lives in `~/.dfos/relay.db`. No relay needed.

## Quick start — with a relay

```bash
dfos peer add prod https://relay.dfos.com  # register + verify a peer
dfos identity create --name alice --peer prod   # create locally AND auto-publish genesis
dfos use alice@prod                        # relay-bound context
dfos status                                # context, identity, peer health
```

`--peer` on `identity create` auto-publishes the genesis operation after local
creation (and sets it as the active context if none is set yet). The canonical
public relay is `https://relay.dfos.com`.

## Context & configuration

Config file: `~/.dfos/config.toml`.

```toml
active_context = "alice@prod"

[identities.alice]
did = "did:dfos:..."

[relays.prod]
url = "https://relay.dfos.com"
did = "did:dfos:..."

[defaults]
auth_token_ttl = "5m"
credential_ttl = "24h"
```

**Context resolution** (highest priority first): `--ctx` flag → `DFOS_CONTEXT`
env → `active_context` in config. The resolved identity/peer can be individually
overridden by `--identity`/`DFOS_IDENTITY` and `--peer`/`DFOS_RELAY`. A bare name
(no `@peer`) is a **local-only** context; `identity@peer` is **relay-bound**.

| Variable               | Purpose                                              |
| ---------------------- | ---------------------------------------------------- |
| `DFOS_CONTEXT`         | Override active context (`identity@peer`)            |
| `DFOS_IDENTITY`        | Override active identity name                        |
| `DFOS_RELAY`           | Override active relay (peer) name                    |
| `DFOS_CONFIG`          | Config file path (default `~/.dfos/config.toml`)     |
| `DFOS_NO_KEYCHAIN`     | Force file-based key storage at `~/.dfos/keys/` (CI) |
| `DFOS_NO_UPDATE_CHECK` | Disable the background version check                 |

In headless/CI environments set `DFOS_NO_KEYCHAIN=1` to avoid interactive
keychain prompts.

## Command map

One line each — run `dfos <command> --help` for flags.

**Identity** (`dfos identity …`, alias `id`)
`create` · `list` · `show` · `keys` · `log` · `update` · `delete` ·
`publish` · `fetch` · `services` · `add-key` · `device-pubkey` · `remove`

**Content** (`dfos content …`)
`create` · `list` · `show` · `log` · `download` · `update` · `delete` ·
`publish` · `fetch` · `verify` · `remove`

**Credentials** (`dfos credential …`, alias `cred`) — `grant` · `revoke`
**Peers** (`dfos peer …`, alias `relay`) — `add` · `remove` · `list` · `info`
**Auth** (`dfos auth …`) — `token` · `status`
**Config** (`dfos config …`) — `list` · `get` · `set`
**Inspect & attest** — `dfos operation show <cid>` (alias `op`) · `dfos witness <opCID>` · `dfos countersigs <cid>`
**Top-level** — `use` · `status` · `version` · `serve` · `sync` · `api` · `skill`

## Key distinctions (the things that bite)

- **`--credential` vs `--authorization`.** `--credential <jws>` presents a **read**
  credential to _download_ content you don't own. `--authorization <jws>` presents
  a **write** credential to _mutate_ content you don't own (`content update` /
  `content delete`). They are not interchangeable.
- **Services are full-state.** On `identity update`, `--service` (repeatable)
  **replaces the entire services set**; services you don't pass are **carried
  forward** unchanged; `--clear-services` empties the set. `--service` and
  `--clear-services` are mutually exclusive.
- **`identity update` has no positional name.** It acts on the active/`--identity`
  identity, signed with a controller key. To target alice: `dfos use alice` first,
  or `dfos --identity alice identity update …`. (The read-only identity subcommands
  `show`/`keys`/`services`/`delete` take an optional `[name|did]`; `log` and `fetch`
  **require** the `<name|did>` argument.)
- **Publishing auto-resolves the creator, not delegates.** `content create --peer`
  and `content publish` auto-publish _your_ identity to the peer first. But a
  **delegated** writer's identity (someone updating via a write credential) must
  already be published to that peer — the CLI won't push it for you.
- **`sync` is global.** `dfos sync` pulls from _all_ configured peers, ignoring the
  active context. Use `content fetch` / `identity fetch` / `content publish` for
  peer-scoped transfers.
- **`remove` ≠ `delete`.** `identity remove` drops a local config name (the chain
  data stays in the relay); `content remove` is just a no-op that points you at
  `content delete` — local content can't be selectively un-ingested. Neither signs
  a protocol delete; `delete` is the irreversible protocol operation (see below).

## Common workflows

### Publish content end-to-end

```bash
dfos peer add prod https://relay.dfos.com
dfos identity create --name alice --peer prod
dfos use alice@prod

CONTENT=$(dfos content create - --peer prod --json <<'EOF' | jq -r .contentId
{"$schema":"https://schemas.dfos.com/post/v1","body":"hello world"}
EOF
)
dfos content show "$CONTENT"
```

Content without a `$schema` field prints a warning (`document has no $schema
field (use --no-schema-warn to suppress)`). Schemas are convention-based — any
URL works; common ones are `https://schemas.dfos.com/post/v1` and
`…/profile/v1`.

### Grant another identity read access

```bash
BOB_DID=$(dfos identity show bob --json | jq -r .did)
GRANT=$(dfos credential grant "$CONTENT" "$BOB_DID" --read --json)
CRED=$(echo "$GRANT" | jq -r .credential)        # the JWS to hand to bob
CRED_CID=$(echo "$GRANT" | jq -r .credentialCID) # the id you revoke later

# Bob downloads by presenting the read credential:
dfos --ctx bob@prod content download "$CONTENT" --credential "$CRED"
```

Flags: `--write` grants delegated write; `--ttl` sets lifetime (default 24h);
`--scope <contentId>` narrows a grant to one chain; `--broad` issues a wildcard
credential covering all of your content. Revoke with
`dfos credential revoke "$CRED_CID" [--peer prod]` — note revocation only blocks
**future** fetches; a party who already downloaded the content keeps their copy.

### Delegated write

```bash
# Bob updates alice's content using a write credential alice granted him.
# (Bob's identity must already be published to the peer.)
dfos --ctx bob@prod content update "$CONTENT" new.json --authorization "$WRITE_CRED" --peer prod
```

### Discovery + witness

```bash
# Anchor content under a semantic label in alice's discovery vocabulary
# (--service REPLACES the whole set, so include every entry you want to keep):
dfos use alice@prod
dfos identity update \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com \
  --service id=profile,type=ContentAnchor,label=profile,anchor="$CONTENT" \
  --peer prod

# A witness countersigns the content's genesis operation:
GENESIS=$(dfos content show "$CONTENT" --json | jq -r .genesisCID)
dfos --ctx witness@prod witness "$GENESIS" --relation witnessed --peer prod
dfos countersigs "$GENESIS" --peer prod
```

A `ContentAnchor`'s `anchor` is a stable target: a 31-char content ID (mutable
chain) or a `bafyrei…` artifact CID (immutable). `--relation` is an open-namespace
tag (1–64 chars: `endorses`, `coauthors`, `witnessed`, …).

### Local-first, publish later

```bash
dfos identity create --name alice              # local only
dfos --identity alice content create post.json # local only
# …later…
dfos peer add prod https://relay.dfos.com
dfos identity publish alice --peer prod
dfos content publish <contentId> --peer prod
```

### Raw API & auth tokens (escape hatch)

```bash
TOKEN=$(dfos auth token)                        # mint short-lived JWT (default 5m)
dfos api GET /.well-known/dfos-relay
dfos api POST /proof/v1/operations --body-file ops.json --auth
```

## Destructive operations & key survival

**Destructive commands run immediately and irreversibly — no prompt, no undo.**
`identity delete`, `content delete`, and key rotation sign and (with `--peer`)
publish the moment you run them. A delete is the only terminal state for a chain:
no further operations may follow it, though the existing log remains for
verification. Double-check the target and `--peer` first.

**Key loss is unrecoverable but survivable — set up redundancy in advance.** There
is no seed phrase or recovery flow. Availability is a multi-key story: an identity
holds up to 256 controller and 256 auth keys, and **a single controller key
authorizes identity operations (1-of-N — no multisig or threshold)** while auth
keys authenticate to relays. On a second device run `dfos identity device-pubkey` (private seed
never leaves it), then from a device holding a controller key run
`dfos identity add-key` with the printed public key. Now losing one device is not
losing the identity. This must be done _before_ a loss, while you still hold a
controller key.

## Error recovery

Common failures and the fix (relay-origin messages reach you wrapped as
`local relay rejected: …` / `peer rejected: …`):

- **`No active context…`** → `dfos use <identity@peer>` (or pass `--ctx`).
- **`no peer configured…`** → `dfos peer add <name> <url>` or pass `--peer`.
- **`identity '<n>' … not found in local relay`** → create it, or
  `dfos identity fetch <did> --peer <p>`.
- **`no held <role> key … on this device`** → run on the device that holds the
  key, or add this device via `device-pubkey` + `add-key`.
- **`Warning: OS keychain not available …`** → harmless; it falls back to
  `~/.dfos/keys/`. Force file storage with `DFOS_NO_KEYCHAIN=1`.
- **`connect to relay: …` / connection refused** → check `dfos peer info <name>`;
  start the peer (`dfos serve`) if it's yours.
- **`Content chain '<id>' FAILED verification`** → re-fetch:
  `dfos content fetch <id> --peer <p>`.
- **`blob bytes do not match documentCID`** (relay 400 on upload) → recreate the
  content from the exact source bytes, then publish.
- **`content '<id>' not found on peer (0 operations fetched)`** → wrong content ID
  or it wasn't published to that peer.
- **`read credential required`** (relay 403 on download) → you don't own it and no
  standing read grant exists; obtain a read credential and pass `--credential`.
- **`unknown identity: <did>`** on publish → a referenced identity (often a
  delegated writer) isn't on the peer; publish that identity first.
- **`signer <did> is not the chain creator — authorization credential required`**
  → sign as the creator, or attach a write credential via `--authorization`.

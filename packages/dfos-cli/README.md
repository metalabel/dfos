# DFOS CLI

The sovereign actor in the DFOS architecture. Generates keys, signs operations, decides what to publish and when, independently verifies what relays serve back. Private key material never leaves the local machine.

Keys live in the OS keychain. Operations are signed locally and submitted to [relays](https://protocol.dfos.com/web-relay) via HTTP. Local-first by default — create identities and content offline, publish when ready.

## Install

```bash
# macOS / Linux (recommended)
curl -sSL https://protocol.dfos.com/install.sh | sh

# Homebrew
brew install metalabel/tap/dfos

# Go
go install github.com/metalabel/dfos/packages/dfos-cli/cmd/dfos@latest
```

Or build from source:

```bash
cd packages/dfos-cli
make build
./dfos version
```

Building an app with Sign In With DFOS? The setup guide is at <https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup>.

## Quick Start

```bash
# add a relay
dfos relay add local http://localhost:4444

# create a vault — the seed new keys derive from. The 24-word phrase prints
# once; write it down. It is the only copy.
dfos vault create personal

# create an identity (mints ed25519 keys from the vault; stored in the OS
# keychain, or unencrypted in ~/.dfos/keys/ when no keychain is available)
dfos identity create --name alice --peer local

# set the standing defaults (the only thing that writes them)
dfos config set default-identity alice
dfos config set default-peer local

# create content from a file
dfos content create post.json --peer local

# create content from stdin
echo '{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"hello"}' | dfos content create - --peer local

# show content chain
dfos content show <contentId>

# download content blob
dfos content download <contentId>

# sign an identity proof for one request (for scripting)
dfos auth proof GET /signing/v0/requests

# raw HTTP to the relay (with auto auth)
dfos relay call GET /proof/v1/identities/did:dfos:xxx
dfos relay call GET /content/abc123/blob --auth
```

## Multiparty Flow

```bash
dfos relay add local http://localhost:4444

# create three identities
dfos identity create --name alice --peer local
dfos identity create --name bob --peer local
dfos identity create --name witness --peer local

# alice creates content
CONTENT=$(dfos --as alice content create - --peer local --json <<'EOF' | jq -r .contentId
{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"private message"}
EOF
)

# alice grants bob read access
BOB=$(dfos identity show bob --json | jq -r .did)
CRED=$(dfos --as alice credential grant "$CONTENT" "$BOB" --read --json | jq -r .credential)

# bob downloads with credential
dfos --as bob content download "$CONTENT" --credential "$CRED" --peer local

# witness countersigns (solemnizes) the genesis operation, optionally tagged
CID=$(dfos content show "$CONTENT" --json | jq -r .genesisCID)
dfos --as witness witness "$CID" --relation endorses --peer local

# verify
dfos content verify "$CONTENT"
```

## Login

`dfos login` signs in to the authorize host that speaks for an identity and stores the credential it returns. The CLI opens a consent screen in a browser, listens on a local port for the redirect, and verifies the signed challenge itself before storing anything.

```bash
# sign in as the resolved identity
dfos login

# sign in as a named identity, asking for a scope that returns a credential
dfos login alice --scope read:profile

# print the URL instead of opening a browser
dfos login --no-browser
```

The authorize endpoint comes from the identity's own chain — a `DfosAuthorizationServer` service entry — with `--authorize-url` as the fallback when the chain names none. Because a CLI holds no domain, it asks with a per-install client identity minted on first login, and proves control of that identity's keys as part of the request. Credentials land in `~/.dfos/credentials/`. See [CLI.md](./CLI.md#login-sign-in-with-dfos) for the full flow and flags.

## Discovery Services

An identity can publish an additive **services** set — relay endpoints and content anchors — carried in its chain state. Services are full-state on each create/update (an update replaces the set), and the type namespace is open.

```bash
# attach services at genesis
dfos identity create --name alice \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com \
  --service id=profile,type=ContentAnchor,label=profile,anchor=cv7n8vkvr64cctf3294h9k4eanhff8z

# replace the set on update, or clear it
dfos identity update --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com
dfos identity update --clear-services

# view the resolved set
dfos identity services alice
```

## Identity Resolution

Identity and peer resolve independently, each from the same three tiers, first
answer wins:

```
identity:  --as <name|did>   ->  DFOS_AS      ->  default-identity in config
peer:      --relay <name>    ->  DFOS_RELAY   ->  default-peer in config
```

```bash
dfos config set default-identity alice   # the config tier; nothing else writes it
dfos --as bob --relay prod status        # per-invocation override
dfos whoami                              # what this shell would act as
```

There is no mutable active context: no command updates the config tier as a side
effect, so concurrent invocations carrying different `--as` values cannot race.
Commands that sign print the resolved principal to stderr unless `--quiet`.

There is one spelling per mechanism. `--as` and `--relay` are the only global
selectors; a `--peer` is always a command's own flag, and it outranks `--relay`
for that command.

Environment variables:

```
DFOS_AS               Identity to act as (name or did:dfos:...)
DFOS_RELAY            Peer to talk to (name)
DFOS_CONFIG           Config file path (default: ~/.dfos/config.toml). Keys,
                      vaults, credentials, and relay.db all sit beside it.
DFOS_NO_KEYCHAIN      Skip OS keychain; use file store ~/.dfos/keys/ and
                      ~/.dfos/vaults/ (unencrypted, 0600)
DFOS_NO_UPDATE_CHECK  Disable automatic version update checks
```

## Local-First

Operations are stored locally by default. Use `--peer` on create commands to publish immediately, or publish later:

```bash
dfos identity create --name alice       # local only
dfos content create post.json           # local only
dfos identity publish alice --peer prod # submit when ready
dfos content publish <id> --peer prod   # submit when ready
```

## Commands

| Command                        | Description                                             |
| ------------------------------ | ------------------------------------------------------- |
| `vault create`                 | Generate a seed vault; print its phrase once            |
| `vault import`                 | Adopt an existing BIP-39 phrase as a vault              |
| `vault list`                   | List vaults, fingerprints, and counters                 |
| `vault show`                   | Show one vault and the keys it minted                   |
| `identity create`              | Mint keys from a vault + sign genesis                   |
| `identity list`                | List all known identities                               |
| `identity show`                | Show identity state                                     |
| `identity keys`                | Show key state + keychain availability                  |
| `identity services`            | Show resolved discovery services                        |
| `identity well-known`          | Emit the app description with carried chain (`--patch`) |
| `identity publish`             | Submit to a relay                                       |
| `identity fetch`               | Download from a relay                                   |
| `identity update`              | Rotate keys / set services                              |
| `identity delete`              | Delete identity (restorable)                            |
| `identity restore`             | Restore a deleted identity                              |
| `identity log`                 | Show operation history                                  |
| `identity remove`              | Drop a name from config (data stays)                    |
| `content create`               | Create content chain                                    |
| `content show`                 | Show content chain state                                |
| `content update`               | Update content chain                                    |
| `content download`             | Download blob                                           |
| `content publish`              | Submit to a relay                                       |
| `content fetch`                | Download from a relay                                   |
| `content log`                  | Show operation history                                  |
| `content list`                 | List locally stored content chains                      |
| `content delete`               | Permanently delete content chain                        |
| `credential grant`             | Issue read/write credential                             |
| `credential revoke`            | Revoke a credential                                     |
| `content verify`               | Re-verify chain integrity                               |
| `witness`                      | Countersign (solemnize) an operation                    |
| `login`                        | Sign in via SIWD, store the credential                  |
| `auth proof`                   | Sign an identity proof for one request (stdout)         |
| `auth status`                  | Show auth state                                         |
| `api add/list/refresh/rm/call` | Call an API that advertises the OpenAPI convention      |
| `peer call`                    | Raw HTTP to a peer (alias: `relay call`)                |
| `peer add/remove/list/info`    | Manage relays (alias: `relay`)                          |
| `config list/get/set`          | Manage configuration                                    |
| `status`                       | At-a-glance overview                                    |
| `sync`                         | Sync with all configured relays                         |
| `serve`                        | Run the local relay as an HTTP server                   |
| `operation show`               | Inspect a protocol operation                            |
| `countersigs`                  | Show countersignatures for an operation                 |
| `skill print/install`          | Print or install the DFOS Claude Code skill             |
| `version`                      | Show version info                                       |

See [CLI.md](./CLI.md) for the full command reference (flags, examples, and the `--json` contract).

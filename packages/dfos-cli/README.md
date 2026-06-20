# DFOS CLI

The sovereign actor in the DFOS architecture. Generates keys, signs operations, decides what to publish and when, independently verifies what relays serve back. Private key material never leaves the local machine.

Keys live in the OS keychain. Operations are signed locally and submitted to [relays](https://protocol.dfos.com/web-relay) via HTTP. Local-first by default — create identities and content offline, publish when ready.

## Install

```bash
go install github.com/metalabel/dfos/packages/dfos-cli/cmd/dfos@latest
```

Or build from source:

```bash
cd packages/dfos-cli
make build
./dfos version
```

## Quick Start

```bash
# add a relay
dfos relay add local http://localhost:4444

# create an identity (generates ed25519 keys; stored in the OS keychain,
# or unencrypted in ~/.dfos/keys/ when no keychain is available)
dfos identity create --name alice --peer local

# set active context
dfos use alice@local

# create content from a file
dfos content create post.json --peer local

# create content from stdin
echo '{"$schema":"https://schemas.dfos.com/post/v1","body":"hello"}' | dfos content create - --peer local

# show content chain
dfos content show <contentId>

# download content blob
dfos content download <contentId>

# mint an auth token (for scripting)
dfos auth token

# raw HTTP to the relay (with auto auth)
dfos api GET /identities/did:dfos:xxx
dfos api GET /content/abc123/blob --auth
```

## Multiparty Flow

```bash
dfos relay add local http://localhost:4444

# create three identities
dfos identity create --name alice --peer local
dfos identity create --name bob --peer local
dfos identity create --name witness --peer local

# alice creates content
CONTENT=$(dfos --ctx alice@local content create - --peer local --json <<'EOF' | jq -r .contentId
{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"private message"}
EOF
)

# alice grants bob read access
BOB=$(dfos identity show bob --json | jq -r .did)
CRED=$(dfos --ctx alice@local credential grant "$CONTENT" "$BOB" --read --json | jq -r .credential)

# bob downloads with credential
dfos --ctx bob@local content download "$CONTENT" --credential "$CRED" --peer local

# witness countersigns (solemnizes) the genesis operation, optionally tagged
CID=$(dfos content show "$CONTENT" --json | jq -r .genesisCID)
dfos --ctx witness@local witness "$CID" --relation endorses --peer local

# verify
dfos content verify "$CONTENT"
```

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

## Context Model

A context is an (identity, relay) pair. Use the `@` shorthand:

```bash
dfos use alice@local           # set default context
dfos --ctx bob@prod status     # per-command override
```

Environment variables:

```
DFOS_CONTEXT       Override active context
DFOS_IDENTITY      Override identity name
DFOS_RELAY         Override relay name
DFOS_CONFIG        Config file path (default: ~/.dfos/config.toml)
DFOS_NO_KEYCHAIN   Skip OS keychain; use file store ~/.dfos/keys/ (unencrypted, 0600)
DFOS_DEBUG         Debug logging
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

| Command                      | Description                            |
| ---------------------------- | -------------------------------------- |
| `identity create`            | Generate keys + sign genesis           |
| `identity list`              | List all known identities              |
| `identity show`              | Show identity state                    |
| `identity keys`              | Show key state + keychain availability |
| `identity services`          | Show resolved discovery services       |
| `identity publish`           | Submit to a relay                      |
| `identity fetch`             | Download from a relay                  |
| `content create`             | Create content chain                   |
| `content show`               | Show content chain state               |
| `content update`             | Update content chain                   |
| `content download`           | Download blob                          |
| `content publish`            | Submit to a relay                      |
| `content fetch`              | Download from a relay                  |
| `content log`                | Show operation history                 |
| `credential grant`           | Issue read/write credential            |
| `credential revoke`          | Revoke a credential                    |
| `content verify`             | Re-verify chain integrity              |
| `witness`                    | Countersign (solemnize) an operation   |
| `auth token`                 | Mint auth token (stdout)               |
| `auth status`                | Show auth state                        |
| `api`                        | Raw HTTP to relay                      |
| `relay add/remove/list/info` | Manage relays                          |
| `use`                        | Set active context                     |
| `config list/get/set`        | Manage configuration                   |
| `status`                     | At-a-glance overview                   |

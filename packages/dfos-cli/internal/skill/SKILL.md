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
  content does it publish?" The namespace is open; extension types registered by
  specs outside the core ride it too — `DfosOrigin`, the domain this identity
  claims, and `DfosAuthorizationServer`, the authorize origin that speaks for
  this DID (where a client holding only the DID finds the sign-in server its
  person authenticates to, registered by
  [SIWD.md](https://protocol.dfos.com/siwd)).
- **Credential** — a signed grant of scoped **read** or **write** access to
  content, issued by the content creator to a delegate DID.
- **Countersignature** — a public witness attestation referencing an operation by
  CID (endorsement, co-authorship, solemnization). The protocol's only
  inter-subjective primitive.
- **Resolution stack** — how each invocation picks its identity and its peer:
  `--as <name|did>` → `DFOS_AS` → `default-identity` in config, and
  `--relay <name>` → `DFOS_RELAY` → `default-peer`. First answer wins; there is no
  mutable "current" pointer.
- **Vault** — a named seed: a BIP-39 mnemonic, a fingerprint, and a derivation
  counter, and nothing else. New keys derive from it at mint time
  (`identity create`, `identity update --rotate-*`) along
  `m/1684434803'/<index>'` by SLIP-0010 ed25519. Signing never consults a vault.
  Nothing about a vault — the word, the phrase, the seed, the fingerprint —
  reaches the wire, so identities minted from one seed are unlinkable to
  everyone but their holder.

## Quick start — local-only

```bash
dfos vault create personal                 # seed the keys come from; prints the phrase once
dfos identity create --name alice          # mint ONE key from the vault + sign genesis (no relay needed)
dfos config set default-identity alice     # standing default (or pass --as alice per command)

dfos content create - <<'EOF'
{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"hello world"}
EOF

dfos content list
dfos content verify <contentId>            # re-verify chain integrity locally
```

All data lives in `~/.dfos/relay.db`. No relay needed.

## Quick start — with a relay

```bash
dfos peer add prod https://relay.dfos.com  # register + verify a peer
dfos identity create --name alice --peer prod   # create locally AND auto-publish genesis
dfos config set default-identity alice     # standing defaults
dfos config set default-peer prod
dfos whoami                                # identity, signing key, credentials, peer
```

`--peer` on `identity create` auto-publishes the genesis operation after local
creation. Creating an identity does NOT select it — nothing follows "last
created". The canonical public relay is `https://relay.dfos.com`.

## Resolution & configuration

Config file: `~/.dfos/config.toml`.

```toml
default_identity = "alice"
default_peer = "prod"
default_vault = "personal"

[identities.alice]
did = "did:dfos:..."

[relays.prod]
url = "https://relay.dfos.com"
did = "did:dfos:..."

[defaults]
credential_ttl = "24h"
```

**Resolution** (highest priority first, identity and peer resolved
independently):

```
identity:  --as <name|did>  →  DFOS_AS     →  default-identity in config
peer:      --relay <name>   →  DFOS_RELAY  →  default-peer in config
```

`default-vault` is the same tier for minting: the vault new keys derive from when
no `--vault` names one. There is no environment tier for it.

The config tier is written by `dfos config set` and by nothing else — with the
single exception that creating the FIRST vault on a machine with none sets
`default-vault` — so parallel
agents each carrying their own `--as`/`DFOS_AS` never disturb one another.
Commands that sign echo the resolved principal and the mechanism it came from to
stderr (`Signing as alice (did:dfos:…) — via --as`) unless `--quiet`; a signing
command with nothing resolvable fails and names all three mechanisms. Public
reads are anonymous and silent. `--ctx`, `--identity`, `--peer`,
`DFOS_CONTEXT`, and `DFOS_IDENTITY` are deprecated aliases at the same tier as
the mechanism they alias.

| Variable               | Purpose                                               |
| ---------------------- | ----------------------------------------------------- |
| `DFOS_AS`              | Identity to act as (name or `did:dfos:…`)             |
| `DFOS_RELAY`           | Peer to talk to (name)                                |
| `DFOS_IDENTITY`        | Deprecated alias of `DFOS_AS`                         |
| `DFOS_CONTEXT`         | Deprecated alias naming both halves (`identity@peer`) |
| `DFOS_CONFIG`          | Config file path (default `~/.dfos/config.toml`)      |
| `DFOS_NO_KEYCHAIN`     | Force file-based key and mnemonic storage (CI)        |
| `DFOS_NO_UPDATE_CHECK` | Disable the background version check                  |

In headless/CI environments set `DFOS_NO_KEYCHAIN=1` to avoid interactive
keychain prompts. `DFOS_CONFIG` moves the whole of a machine's dfos state
together — config, `relay.db`, credentials, vaults, and file-backed keys all sit
beside the config file — so pointing it at a scratch directory isolates a run
completely.

## Command map

The whole verb surface, one line per group. Flags and semantics are not here:
run `dfos <command> --help`, which is the binary itself and therefore always
current, or read [CLI.md](https://protocol.dfos.com/cli) for the full reference.

**Identity** (`dfos identity …`, alias `id`)
`create` · `list` · `show` · `status` (compare the local chain against the
identity's relay: in-sync / behind / ahead-unpublished / diverged, and `unknown`
with exit 1 when no relay could answer — silence is never agreement) · `keys` ·
`log` · `update` · `delete` · `restore` · `publish` · `fetch` · `services` ·
`well-known` · `add-key` · `device-pubkey` · `bind-domain` · `verify-binding` ·
`remove` · `forget`

**Content** (`dfos content …`)
`create` · `list` · `show` · `log` · `download` · `update` · `delete` ·
`publish` · `fetch` · `verify` · `remove`

**Vaults** (`dfos vault …`) — `create` · `import` · `list` · `show`
**Keys** (`dfos keys …`) — `list` · `show` · `prune` · `remove <key-id|public-key|account>` (one named key, dry run until `--yes`, `candidate` and `orphan` only) · `prove <code-or-uri>` (present a key to a key-add ceremony: a carriage is an authority and a code, and the identity, roles, chain head and nonce all come from resolving it; mints or names a key, shows the identity and the roles being consented to, refuses a key any identity has ever proved, posts one seven-member KEY-PROOF envelope and never retries. Presenting is not adoption — the key stays a local candidate until a chain declares it)
**Credentials** (`dfos credential …`, alias `cred`) — `grant` · `revoke`
**Sign-in** — `dfos login [name|did]` (`--host <name-or-host>` to pick from an API's advertised actions) · cached records: `dfos creds list` · `show` · `rm`
**Peers** (`dfos peer …`, alias `relay`) — `add` · `repin` · `remove` · `list` · `info` · `gc`
**Auth** (`dfos auth …`) — `proof` · `status`
**API client** (`dfos api …`) — `add` · `list` · `refresh` · `rm` · `call`
**Config** (`dfos config …`) — `list` · `get` · `set`
**Inspect & attest** — `dfos operation show <cid>` (alias `op`) · `dfos witness <opCID>` · `dfos countersigs <cid>`
**Top-level** — `whoami` · `status` · `version` · `recover` · `serve` · `sync` · `api` · `skill`

## Key distinctions (the things that bite)

- **`--credential` vs `--authorization`.** `--credential <jws>` presents a **read**
  credential to _download_ content you don't own. `--authorization <jws>` presents
  a **write** credential to _mutate_ content you don't own (`content update` /
  `content delete`). They are not interchangeable.
- **A vault is a mint-time choice, never a signing one.** `--vault` (and
  `default-vault`) affect only commands that create new key material:
  `identity create` and `identity update --rotate-*`. Signing resolves the
  identity, then uses whichever published auth key this device holds — it never
  asks a vault anything. Passing `--vault` to a signing command does nothing.
  Rotation is sticky to the vault that minted the identity's current keys, so
  `default-vault` cannot quietly move an identity onto a different seed;
  `--vault` on `identity update` overrides that.
- **A vault-backed mint asks the relay before it spends an index.** Two machines
  holding one phrase keep two counters, so both can hand out index N — one
  private key under two DIDs, invisible on either chain. Before `identity create`
  or `identity update --rotate-*` stores a key or signs an operation, it asks the
  resolved relay's identity index whether the key its reserved index derives
  already proves somewhere (`GET /index/v0/identities?key=`, one query per
  reserved key) and REFUSES the whole operation on a hit
  (`reason: mint-index-already-proved`). The reserved index stays burned, which
  is safe — the recovery scan's gap limit walks through burned indices by design.
  The probe is best-effort and loud: a relay that cannot answer and one that
  stops answering each mint anyway behind a one-line note naming what went
  unasked, while zero rows mints silently. With NO relay resolved, an imported
  vault carries the same note and one created on this machine does not — an
  imported phrase already exists elsewhere, a locally generated one does not.
  `--no-mint-probe` skips the probe entirely.
  `recover` converges the counter over what a seed has already spent; the probe
  refuses the forward collision that converged counter cannot see.
- **Services are full-state.** On `identity update`, `--service` (repeatable)
  **replaces the entire services set**; services you don't pass are **carried
  forward** unchanged; `--clear-services` empties the set. `--service` and
  `--clear-services` are mutually exclusive.
- **`identity update` has no positional name.** It acts on the resolved identity,
  signed with a controller key. To target alice: `dfos --as alice identity update …`,
  or set `default-identity`. (The read-only identity subcommands
  `show`/`keys`/`services`/`delete` take an optional `[name|did]`; `log` and `fetch`
  **require** the `<name|did>` argument.)
- **Publishing auto-resolves the creator, not delegates.** `content create --peer`
  and `content publish` auto-publish _your_ identity to the peer first. But a
  **delegated** writer's identity (someone updating via a write credential) must
  already be published to that peer — the CLI won't push it for you.
- **`sync` is the bulk pull, and it is switchable.** `dfos sync` takes each peer's
  _whole_ operation log; `--peer <name>` narrows it to one. A `[relays.<name>]`
  entry with `sync = false` is skipped by name and reason, and `sync --peer` on it
  refuses. Explicit transfers — `identity fetch` / `content fetch` /
  `content publish` — are never gated by that switch, so
  `dfos peer add <name> <url> --no-sync` registers a peer for those alone.
- **A peer's `did` is a pin, not a label.** Commands acting through a named peer
  refuse when it serves a different DID than config pins, naming both. An entry
  with no `did` is pinned on first contact, announced on stderr; `dfos peer repin
<name>` is the only thing that moves one afterwards. `peer info` reports a
  mismatch (exit 1) instead of refusing, and rewrites neither the pin nor the
  per-peer policy flags — those are yours once the peer is registered.
- **`remove` ≠ `delete`.** `identity remove` drops a local config name (the chain
  data stays in the relay); `content remove` is just a no-op that points you at
  `content delete` — local content can't be selectively un-ingested. Neither signs
  a protocol delete; `delete` is the irreversible protocol operation (see below).
  `keys remove` is the one `remove` that really removes something: it deletes a
  named key's seed from the keystore (see below).
- **No identity command removes key material.** `remove`, `forget`, and `delete`
  all leave the keys in the keystore, and `forget` leaves the chain in the relay
  too — so a forgotten identity's keys still read as declared. `dfos keys list`
  shows what this machine holds and what claims it; `dfos keys prune` (a dry run
  until `--yes`) removes only keys **no** local chain declares, which in practice
  is the leftovers of an interrupted `identity create`. A deleted
  identity's keys are never orphans — deletion is not revocation, and `restore`
  is real — and neither the local relay's own key nor a vault mnemonic is
  reachable from `prune` at all. `dfos keys remove <key-id|public-key|account>`
  (also a dry run until `--yes`) is the by-name path for one key, and it acts on
  two statuses: `orphan`, and `candidate` — the key a `keys prove` ceremony left
  behind, which `prune` is built never to reach because the chain that claims it
  is not this machine's. It refuses everything else and says why.

## Common workflows

### Publish content end-to-end

```bash
dfos peer add prod https://relay.dfos.com
dfos identity create --name alice --peer prod
dfos config set default-identity alice

CONTENT=$(dfos content create - --peer prod --json <<'EOF' | jq -r .contentId
{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"hello world"}
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
dfos --as bob --relay prod content download "$CONTENT" --credential "$CRED"
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
dfos --as bob --relay prod content update "$CONTENT" new.json --authorization "$WRITE_CRED" --peer prod
```

### Discovery + witness

```bash
# Anchor content under a semantic label in alice's discovery vocabulary
# (--service REPLACES the whole set, so include every entry you want to keep):
dfos --as alice identity update \
  --service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com \
  --service id=profile,type=ContentAnchor,label=profile,anchor="$CONTENT" \
  --peer prod

# A witness countersigns the content's genesis operation:
GENESIS=$(dfos content show "$CONTENT" --json | jq -r .genesisCID)
dfos --as witness --relay prod witness "$GENESIS" --relation witnessed --peer prod
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

### Calling a DFOS-gated API

`dfos api` is a generic client for any host that advertises the API-AUTH OpenAPI
convention. Register it once, then call operations by name; the document says
which artifact each route needs and the CLI signs that one.

```bash
dfos api add dfos api.dfos.com            # discover and cache the document
dfos api list                             # what is registered, and how stale
dfos api call dfos protocol.getProtocolInfo
dfos api call dfos GET /spaces/{space} --param space=nce
dfos api refresh dfos                     # refetch when the staleness line says so
```

The profile is read from the operation's security requirements: nothing for an
anonymous route, an identity proof for the identity-proof scheme alone, and a
request proof plus `X-Credential` when the request-proof and credential schemes
are ANDed. `--profile <anon|identity|delegated>` forces one. A 401 prints the
host's challenge and stops — nothing is retried under stronger auth. A 403 prints
the actions the route requires next to the actions the credential grants.

The delegated profile spends a credential obtained by `dfos login --host <name-or-host>`,
which lists the actions that host advertises and asks which of them to request. The
credential is matched to the host by its `api:<host>` attenuation, not by its audience.
`dfos creds list` shows what is stored.

### Raw relay access & identity proofs (escape hatch)

```bash
dfos relay call GET /.well-known/dfos-relay
dfos relay call POST /proof/v1/operations --body-file ops.json --auth
dfos auth proof PUT /content/abc/blob/bafy... --body doc.json --jti   # print a proof for curl
```

`--auth` signs an identity proof bound to that one request — method, host, path,
and body. There is no reusable token: a proof authorizes the request it was signed
for and goes stale in about a minute, so sign one per call.

## Destructive operations & key survival

**Destructive commands run immediately — no prompt.** `identity delete`,
`identity restore`, `content delete`, and key rotation sign and (with `--peer`)
publish the moment you run them. Identity delete suspends signing and only
`identity restore` may immediately follow it; content delete remains terminal.
The existing log remains for verification. Double-check the target and `--peer`
first.

**Key custody is two separate stories — set both up in advance.**

_Backup_ is the vault. Keys minted from a vault are described completely by its
24-word phrase plus the fixed path `m/1684434803'/<index>'`, so the phrase written
on paper is the backup. The phrase is the only copy of that seed: it exists on the
machine that holds the vault and nowhere else. Keys created with `--no-vault`, or
on a machine with no vault, have no phrase covering them and live only in the
keystore.

_Availability_ is a multi-key story, and a vault does not replace it: an identity
holds up to 256 controller and 256 auth keys, and **a single controller key
authorizes identity operations (1-of-N — no multisig or threshold)** while auth
keys authenticate to relays. On a second device run `dfos identity device-pubkey` (private seed
never leaves it), then from a device holding a controller key run
`dfos identity add-key` with the printed public key. Now losing one device is not
losing the identity. This must be done _before_ a loss, while you still hold a
controller key.

**`identity create` mints ONE key and declares it controller, auth, and assert.**
Two keys off one seed in one keychain on one machine are one custody arrangement
under two names — every event that reaches one reaches the other — so the genesis
declares one key three times, which is what is actually true. Custody splits at
the first key-add: `identity add-key` (a key generated on another device) or
`keys prove` (a key presented to a ceremony someone else custodies the chain for).
Rotation is scoped to the roles its flags name — `--rotate-auth` alone leaves the
displaced key still controller and assert, and the report says so — while
`--rotate-controller --rotate-auth --rotate-assert` retires it outright and mints
ONE replacement for all three.

**Key ids and keystore accounts are content-addressed.** A `key_id` is
`key_` + the protocol's 31-character ID encoding of `SHA-256(publicKeyMultibase)`,
so every machine holding a key computes the same handle for it with nothing
exchanged (`identity add-key --id` is optional and defaults to it). The keystore
stores each seed under `key:<publicKeyMultibase>`; accounts an earlier version
wrote as `<did>#<key_id>` are still read and are never rewritten.

_Restoring the backup_ is `dfos recover`. After a machine is lost, the whole path
is two commands: `dfos vault import restored` to adopt the phrase, then
`dfos recover --vault restored --peer <relay>`. It rederives keys at
`m/1684434803'/<index>'`, asks the relay's identity index which of them any
identity has ever proved (`GET /index/v0/identities?key=`, has-ever-proved, so
keys a rotation left behind are found too, while a membership no proof admitted
never enters the index), pulls those chains into the local
relay, writes the private keys back into the keystore, rebuilds the vault's
minted-key records, and raises the vault's derivation counter past every index it
found in use — without which the next mint would hand a recovered index to a
second identity. Only public keys go on the wire.

Four things about it are worth knowing before you run it:

- **The scan stops after 20 consecutive unused indices** (`--scan-depth N`
  changes it). A hole shorter than that does not end the walk.
- **The relay that answered is named in the output, and its silence is never an
  answer.** A relay serving no index (501), an unreachable one, one that quits
  mid-scan, and one predating the `key=` filter (which would ignore the parameter
  and answer an unfiltered page — caught by a sentinel probe before the scan) are
  all loud failures, never "no keys found". `--manifest-only` is the deliberate
  degradation, and it banners that no scan ran.
- **It writes by default** and is idempotent; `--dry-run` predicts the real run
  without writing — it fetches each found identity's chain and verifies it in
  memory, so its records, counter floor, and `scanComplete` are the real run's,
  reported in the would-mood (`would-install`, `would-recover`).
- **What it cannot see:** a derived key no identity operation ever declared is
  invisible to any index, one relay's absence is not global absence, and keys
  minted with `--no-vault` are not derivable from any phrase at all
  (`dfos keys list` is what shows those).

## Error recovery

Common failures and the fix (relay-origin messages reach you wrapped as
`local relay rejected: …` / `peer rejected: …`):

- **`no identity to sign with…`** → pass `--as <name|did>`, set `DFOS_AS`, or run
  `dfos config set default-identity <name|did>`.
- **`no peer to talk to…`** → `dfos peer add <name> <url>`, then pass `--relay <name>`
  or run `dfos config set default-peer <name>`.
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

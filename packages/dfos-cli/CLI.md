# DFOS CLI

The sovereign actor in the DFOS architecture. Generates keys, signs operations, stores chains locally, decides what to publish and when. Relays are dumb pipes — the CLI holds the keys.

This spec is under active review. Discuss it in the [DFOS](https://nce.dfos.com) space.

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
# create the seed your keys derive from, and write the phrase down
dfos vault create personal

# create your identity — its keys are minted from that vault
dfos identity create --name myname

# publish your first post — every signing command names the identity it acts as
echo '{"$schema":"https://schemas.dfos.com/post/v1","format":"short-post","body":"gm"}' | dfos --as myname content create -

# tired of typing it: set the standing default
dfos config set default-identity myname

# see what this shell would sign as
dfos whoami

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
│     OS Keychain          │  Ed25519 private key seeds + vault mnemonics
│  (never on disk)         │  macOS Keychain / Linux secret-service / Windows Credential Manager
└──────────┬───────────────┘
           │
┌──────────▼───────────────┐
│   ~/.dfos/               │  Configuration + local relay
│   ├── config.toml        │  Peers, identities, static defaults
│   ├── credentials/       │  Login credentials, one file per subject DID
│   ├── vaults/            │  Vault metadata — fingerprint, counter, minted keys
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

The CLI has four layers of state:

- **OS Keychain**: secret material only. One entry per Ed25519 key, keyed by `dfos` service + `did:dfos:xxx#key_yyy` account, holding a hex-encoded 32-byte seed; one entry per vault, keyed by `vault:<name>`, holding its mnemonic. Never written to disk.
- **Local relay** (`~/.dfos/relay.db`): SQLite database storing identity chains, content chains, operations, countersignatures, and blobs. Both chains you own (have private keys for) and chains you've fetched from relays.
- **Vault metadata** (`~/.dfos/vaults/`): one `0600` TOML per vault — its fingerprint, its derivation counter, and which index minted which published key. No secret; the mnemonic is in the keychain.
- **Config** (`~/.dfos/config.toml`): peer URLs, identity names, and the static defaults the resolution stack falls back to. Nothing writes it as a side effect of another command.

`DFOS_CONFIG` names the config **file**, not the directory — `DFOS_CONFIG=/tmp/scratch/config.toml`, not `DFOS_CONFIG=/tmp/scratch`. A path naming a directory is refused with the contract rather than a bare "is a directory". Everything on disk sits beside that file: point it at another directory and the relay database, the credentials, the vaults, and the file-backed keys all move with it.

---

## Identity Resolution

Every invocation resolves two things independently: the **identity** it acts as, and the **peer** it talks to. Both resolve from the same three-tier stack, in this order, and stop at the first one that answers:

```
identity:  --as <name|did>   →  DFOS_AS      →  default-identity in config
peer:      --relay <name>    →  DFOS_RELAY   →  default-peer in config
```

The stack has no mutable pointer in it. The config tier is written by exactly one thing — `dfos config set` — and no command updates it as a side effect: nothing follows "last used" or "last created", and creating an identity does not select it. That is what makes concurrent invocations safe. Two agents running side by side each carry their own `--as` or their own `DFOS_AS`, and neither can disturb what the other signs as.

`--as` takes an identity name from config **or** a bare `did:dfos:` identifier. A DID needs no local registration.

A verb that takes its subject as a positional argument — `identity update <name|did>`, like `delete`, `restore`, `show`, `log`, `forget`, and `remove` before it — acts on that identity, ahead of the whole stack. A target typed on the command line is the most explicit statement of intent available, so it outranks `--as`, `DFOS_AS`, and `default-identity`, and the disclosure line names `positional argument` as the mechanism it resolved through. With no positional the stack resolves as it always does.

### Disclosure

A command about to sign says who it is signing as, on stderr, before it signs:

```
$ dfos --as alice content create post.json
Signing as alice (did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar) — via --as
Content created:
  ...
```

The line names the mechanism that resolved, so an unexpected principal is visible at the moment it matters. `--quiet` suppresses it. Public reads sign nothing and say nothing about identity.

A signing command with nothing resolvable fails, and names all three mechanisms rather than falling back to a guess:

```
$ dfos content create post.json
no identity to sign with — name one:
  --as <name|did>                             for this invocation
  DFOS_AS=<name|did>                          for this environment
  dfos config set default-identity <name|did> as the standing default
```

### Deprecated aliases

`--ctx`, `--identity`, `--peer`, `DFOS_CONTEXT`, and `DFOS_IDENTITY` are deprecated aliases of the canonical selectors. They keep working, hidden from help, at the tier of the mechanism they alias — a flag alias beats an environment variable, an environment alias beats the config default. `--ctx`/`DFOS_CONTEXT` name both halves at once as `identity@peer`, a named `[contexts]` entry, or an identity on its own.

### Configuration

```toml
default_identity = "alice"
default_peer = "local"
default_vault = "personal"

[relays.local]
url = "http://localhost:4444"

[relays.prod]
url = "https://relay.dfos.com"
did = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
sync = false

[identities.alice]
did = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"

[identities.bob]
did = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"

[defaults]
credential_ttl = "24h"
```

```bash
dfos config set default-identity alice     # or a bare did:dfos: identifier
dfos config set default-peer prod          # the peer must already be registered
dfos config set default-vault personal     # the vault must already exist
dfos config get default-identity
dfos config list                           # every key, the peers, and the identities
dfos config list --json                    # the same, key for key with the TOML
```

`config list` reads like the rest of the CLI: a plain report by default, naming every writable key including the ones that are unset, and under `--json` the config document itself — the same snake_case namespace the TOML uses, so `jq` output round-trips back into `config set`.

`default-vault` is the same tier for minting that `default-identity` is for signing: the fallback when no `--vault` names one. `dfos config set` is the only thing that writes it, with the one exception that creating the first vault on a machine with none sets it.

A `[relays.<name>]` entry carries four kinds of key, and the difference is what each one answers to:

| Key                                                         | Kind    | Meaning                                                                              |
| ----------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `url`                                                       | address | Where the peer is                                                                    |
| `did`                                                       | pin     | Which identity that address must serve (see [Peer Identity Pin](#peer-identity-pin)) |
| `content`, `proof`, `log`, `gossip`, `read_through`, `sync` | policy  | What this machine does with the peer; absent means on (see [Peer Sync](#peer-sync))  |
| `profile_name`                                              | label   | Display name from the peer's profile artifact                                        |

Policy is the operator's. It is seeded from the peer's advertised capabilities the first time the peer is registered, and nothing rewrites it after that — not `peer add` over an existing entry, not `peer info`. Only the label is refreshed freely, and only the pin commands move the pin.

An `active_context` line left over from an earlier configuration is inert: resolution never reads it, and `dfos whoami` reports it as such.

---

## whoami

`dfos whoami` answers the question an operator has before running a signing command: what would this shell act as, right now.

```
$ dfos whoami
Identity:    alice (did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar)
  Via:       config default-identity
Signing key: did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar#key_8fh3n2 (keychain)
  Vault:     personal [1c9b28e4] at m/1684434803'/1'
Credentials: 1 stored in /Users/you/.dfos/credentials
  * did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar  aud did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z  valid
Peer:        prod (https://relay.dfos.com)
  Via:       config default-peer
```

Each section has an explicit negative state rather than an omission: `none selected` for an unresolved identity or peer, `not held` with the reason when this device holds none of the identity's published auth keys, `none stored` for an empty credential store, and `none — this key was generated standalone` for a signing key no vault minted. The `Vault:` line is local provenance: it says which phrase and which index cover the key being signed with, and it played no part in resolving that key. `--json` emits the whole report as one document. whoami reads only — it signs nothing and writes nothing.

---

## Vaults

A vault is a named seed, and that is the whole of it: a name, a BIP-39 mnemonic, a fingerprint, and a derivation counter. It binds no identity, scopes no configuration, and holds no peers. Its one job is to be the source new key material is derived from, at the one moment that matters — mint time.

```bash
dfos vault create personal          # generate a 24-word phrase, print it once
dfos vault import recovered         # adopt a phrase you already hold (read from stdin)
dfos vault list                     # names, fingerprints, counters, the default marker
dfos vault show personal            # one vault and every key it minted
```

### What a vault touches, and what it does not

Choosing a seed is a **mint-time** concern. `identity create` and `identity update --rotate-*` derive their new keys from a vault; nothing else consults one. Signing in particular does not: it resolves the identity, intersects that identity's published auth keys with the keys this device holds, and signs with what it finds. A vault fingerprint recorded next to a minted key is provenance for the operator, never an input to resolution.

Nothing about a vault reaches the wire. The word "vault", the mnemonic, the seed, and the fingerprint stay on the machine that holds them — no operation payload, no signed message, and no request to a peer carries any of them. An identity minted from a vault publishes public keys and nothing else, exactly like one that was not. Two identities minted from one seed are unlinkable to everyone but their holder, and that property holds only because none of this local state leaks upward.

### Selecting a vault

New key material comes from `--vault <name>`, and otherwise from `default-vault` in config. There is no environment tier and no "last used": a seed is the most consequential choice the CLI makes, so it is made explicitly or from a value written into config on purpose.

```bash
dfos identity create --name alice                  # mints from default-vault
dfos identity create --name alias --vault burner   # mints from a named vault
dfos identity create --name detached --no-vault    # standalone keys, from no seed
```

With no vault selected — none exists, no default is set, or `--no-vault` is passed — keys are generated straight into the keystore and exist only there. Those keys are legal and complete; what they lack is a phrase that covers them.

`dfos config set default-vault <name>` writes the default, and it is the only thing that writes it, with one exception: creating the **first** vault on a machine that has none sets it, because there is nothing there to displace.

Rotation is sticky. `identity update --rotate-auth` and `--rotate-controller` draw their replacements from the vault that minted the identity's **current** keys, so an identity stays on one seed and its phrase does not silently stop covering it. `default-vault` is not consulted — that would move an identity onto a different seed the moment someone changed a default. `--vault` overrides the stickiness for **that invocation only** — it moves no pointer, so a later bare rotate resolves the seed afresh from whichever vault minted the identity's controller key at that moment. An identity whose keys came from no vault rotates into standalone keys.

### Derivation

Keys derive by SLIP-0010 for ed25519, hardened at every level, from the BIP-39 seed of the vault's mnemonic (PBKDF2-HMAC-SHA512, 2048 iterations, no passphrase). The path is:

```
m / 1684434803' / <index>'
```

`1684434803` is `0x64666f73` — the four ASCII bytes of `dfos`. The index is a single flat counter per vault, dense and ascending from 0, incremented once per key regardless of role: an `identity create` consumes two consecutive indices (controller, then auth) and a rotation consumes one per rotated key. An index consumed by an operation that then failed is burned rather than reused, because a gap costs nothing and handing one index to two identities costs everything.

This path is fixed. A vault's mnemonic and this path are together the full description of every key the vault minted, so any SLIP-0010 ed25519 implementation derives the same keys from the same words.

### Storage

| Piece                                        | Location                                  | Protection                          |
| -------------------------------------------- | ----------------------------------------- | ----------------------------------- |
| Mnemonic                                     | OS keychain, account `vault:<name>`       | whatever the host keychain provides |
| Mnemonic (keychain unavailable)              | `~/.dfos/vaults/<name>.seed`, mode `0600` | filesystem permissions              |
| Metadata (fingerprint, counter, minted keys) | `~/.dfos/vaults/<name>.toml`, mode `0600` | filesystem permissions              |

The mnemonic follows the same probe-and-fall-back rule as the keystore: the OS keychain when one is reachable, a `0600` file when it is not, and the file store directly under `DFOS_NO_KEYCHAIN`. The metadata file holds no secret — a fingerprint and a list of public key ids — and is readable by hand.

The fingerprint is the first four bytes of SHA-256 over the seed's SLIP-0010 master key, hex-encoded. It identifies the **seed**, not the name it is filed under: the same phrase reaches the same fingerprint on every machine that holds it.

### One seed, one vault

A machine holds a given seed once. `vault import` refuses a phrase some vault here already holds, and the refusal names that vault and its fingerprint:

```
this phrase is already vault 'personal' [d1f9f14b] — one seed, one vault:
a second vault over the same phrase would mint identical keys from its own counter
```

The refusal is by fingerprint, so a re-cased or re-spaced form of the phrase does not slip past it. `vault create` runs the same check on the seed it generates.

The rule is a custody rule, not a bookkeeping one. The derivation counter belongs to the vault, so two vaults over one phrase each hand out indices from their own counter starting at 0 — mint an identity from each and the two identities hold **byte-identical** controller and auth private keys, with nothing on screen to say so. There is no `--force`: several accounts branching under one mnemonic is a shape that is refused by design, because a phrase whose holder cannot tell which identity it controls has stopped being a backup. A second identity gets a second phrase.

### Seeing the phrase

The mnemonic goes to **stderr**, always, from every command that prints it: `vault create` when it generates one, and `vault show --reveal-mnemonic` when it reveals one. It never goes to stdout and never into `--json` output, so a redirected or piped invocation does not write a seed into a file by accident — `dfos vault show personal --reveal-mnemonic > report.txt` writes a report, and the phrase stays on the terminal.

`vault create` prints it once, fenced and numbered. `vault show` does not print it at all unless asked: `vault show <name> --reveal-mnemonic` does, behind a typed confirmation — the vault's own name, not a `y` — because the phrase then lives in that terminal's scrollback and in anything recording the session. The confirmation is read from stdin, so a non-interactive invocation fails closed rather than revealing anything. No flag puts a `mnemonic` field in a `--json` document; a script that needs the phrase captures stderr.

`vault import` reads the phrase from stdin — a prompt at a terminal, a piped line otherwise. It is never an argument: argv lands in shell history and is readable in the process list. The words are checked against the BIP-39 English wordlist and their checksum, and the seed against every vault this machine already holds, before anything is stored.

A vault's phrase is the only copy of its seed. There is no second copy on any machine, with any relay, or at Metalabel. What that phrase gets you back is [Recovery](#recovery).

---

## Recovery

`dfos recover` is the disaster path: the machine is gone, and what survives is a vault's 24-word phrase. It rebuilds what that phrase controls.

```bash
dfos vault import restored              # adopt the phrase (read from stdin)
dfos recover --vault restored --peer prod
```

Those two commands are the whole flow. `vault import` is the one way a phrase enters a machine — it checks the words against the BIP-39 wordlist and their checksum, and it never reads a phrase from argv — and `recover` is what turns the adopted seed back into working identities.

### The two stages

**Derive.** Keys come back out of the seed at `m/1684434803'/<index>'` for index 0, 1, 2, … . This is local arithmetic and it never ends on its own, so something has to say when to stop.

**Ask.** For each derived **public** key, `recover` asks a relay's identity index which identities have ever declared it: `GET /index/v0/identities?key=<multibase>`. Rows back means the index is in use; no rows means it is not. The scan stops after **20 consecutive unused** indices — a gap limit, not a ceiling, so a hole shorter than 20 does not end the walk. `--scan-depth N` changes the number.

The gap limit works because minting is sequential: a vault's counter hands out dense ascending indices and never reuses one, so real holes are short. An index consumed by a mint that then failed is burned, which is exactly the kind of hole a gap limit is for.

Only public keys go on the wire. The mnemonic, the seed, and the fingerprint never leave the machine — the query carries a public key and nothing else.

### The oracle is named, and its silence is not an answer

"Used" and "unused" are one relay's answers. `recover` names that relay in its output (`Oracle: prod (https://relay.dfos.com)`), and it resolves it through the ordinary peer stack — `--peer` on the command, `--relay`, `DFOS_RELAY`, then `default-peer`.

The index is optional and non-authoritative, which makes four different silences look alike, and each one is a loud failure rather than an empty result:

| What happened                                                            | What `recover` does                                                               |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| The relay answers **501** on `/index/v0/*` (`capabilities.index` off)    | Fails, naming the relay and the missing capability                                |
| The relay is unreachable, or answers something that is not an index page | Fails, naming the relay and the response                                          |
| The relay stops answering **mid-scan**                                   | Fails, naming the index it stopped at — everything past it is unknown, not unused |
| The relay **ignores** `key=` and answers an unfiltered page              | Fails, naming the version needed (`web-relay >= 0.39.0`)                          |

The last one has no status code to catch it by: `key=` is an opaque string match, so a relay that predates the filter sees an unknown parameter, drops it, and answers `200` with a page of identities that have nothing to do with the key asked about. Every index would look used and the scan would never stop. So before the scan runs, `recover` asks one sentinel query — a syntactically real multikey whose 32 bytes are a published hash, so no chain can have declared it. Rows coming back to that query prove the filter was not applied.

`--manifest-only` is the deliberate degradation: it skips the scan and the relay entirely and recovers exactly what this machine's own vault records already name. It prints a banner saying the scan did not run and that the report says nothing about keys the seed minted elsewhere. It is the only path that reports without asking, and it never happens on its own.

### What comes back

For each identity the scan finds, `recover` pulls the chain from the oracle into the local relay, reads the key id the chain declares each recovered public key under, and writes the private key into the keystore under `<did>#<keyId>`. Then it rebuilds the vault's minted-key records and registers the identity in config — using the relay's projected profile name where there is one, and a DID-derived label otherwise, with a numeric suffix on a collision. A name already in config is kept; recovery adds and never renames.

Signing afterwards needs nothing further: it resolves the identity, intersects its published auth keys with the keys this device holds, and signs.

Two details matter:

- **A key a rotation left behind is still recovered.** `key=` is a **has-ever-declared** lookup, so it finds the chains a key controlled before an update rotated it out — which is the case a phrase-holder is most likely to be in. Those keys land in the keystore and are reported as superseded.
- **A deleted identity is still found, fetched, and reported as deleted.** Deletion is not revocation, and `identity restore` is real.

The report ends with the end state per identity: `recovered`, `already-present`, or `found-but-not-fetched`. Re-running converges — nothing is duplicated and nothing is renamed.

### The counter

An imported vault starts with its derivation counter at 0, because this machine has no record of what the seed minted elsewhere. `recover` raises that counter past every index it learned is in use, so the next `identity create` from the vault cannot hand a spent index to a second identity. This is the half of recovery that matters even when every key was already present, and it is the half where a mistake is unrecoverable: two identities minted at one index sign with the same Ed25519 private key.

The scan is not the only thing the run learns from. A chain pulled from the oracle declares public keys, and the seed in hand derives them, so `recover` matches every key its fetched chains name against forward derivations and feeds those indices to the counter too. This closes the case the scan structurally cannot reach: rotations move an identity's current auth key to a fresh index each time, and enough of them — or enough burned indices in between — put that index past where the gap limit ended the walk. The chain names the key regardless, so the index is known, the private key is derived and installed, and the counter clears it.

A key a fetched chain names that this seed cannot derive was minted elsewhere. It moves nothing here.

### When the scan stopped short

An index found past the walk is proof the gap limit ended it early, and `recover` says so rather than reporting a clean recovery:

```
! SCAN DEPTH TOO SHALLOW — current key(s) beyond scan depth.
  The scan walked 22 indices and stopped after 20 consecutive unused ones. A chain
  this run fetched declares key(s) this vault's seed derives at index 24,
  past that stop. They are recovered here and the counter clears them.
  ...
  Re-run with --scan-depth 25 (or more): dfos recover --vault restored --scan-depth 25
```

The keys it names are recovered and the counter clears them. What it warns about is the shortfall itself: the same gap that hid a known identity's key hides an identity whose **every** key sits past it, along with every index that identity holds. `--scan-depth N` walks through a gap that wide.

`--json` carries the same fact as data rather than prose: `scanComplete`, `beyondScanIndices`, and `recommendedScanDepth`. `scanComplete: false` with indices listed is the proven shortfall; `false` with none listed is the unproven kind — a chain this run could not read, so what it declares was never checked against a derivation at all. A `--dry-run` on a machine holding no chains reports exactly that.

An oracle failure under `--json` carries a `reason` code beside its prose — `oracle-no-index`, `oracle-unreachable`, or `oracle-key-param-ignored` — because the operator's next move differs for each and a sentence is not something to branch on.

### What recovery cannot see

- **A derived key no identity operation ever declared is invisible to any index.** It is still derivable from the phrase; nothing can find it for you, because there is nothing anywhere that records it.
- **One relay's index-absence is not global absence.** A key the named oracle does not know may be declared on a chain it never ingested.
- **An identity behind a gap longer than the limit is out of reach.** The walk ends on `--scan-depth` consecutive unused indices, so an identity whose every key sits past a longer run of them is never asked about. `--scan-depth N` is the lever, and the report names it whenever a fetched chain proves the walk stopped short.
- **Keys minted outside a vault are not derivable from any phrase.** `--no-vault` keys, and keys created on a machine with no vault, live only in the keystore that was lost. `recover` says nothing about them; `dfos keys list` is the tool that shows what a machine holds.

### Dry run

`recover` writes by default. It is additive and idempotent — it stores keys, ingests chains, adds config names, and raises a counter, and it deletes nothing — and it is the command an operator reaches for at the worst moment, so making the disaster path take two invocations buys nothing. (`keys prune` is dry-run-by-default for the opposite reason: it deletes.)

`--dry-run` scans and reports without writing anything: no keystore writes, no config writes, no chain pulls. Because it pulls no chains it cannot read key ids either, so identities it finds report as `found-but-not-fetched` — an honest account of what a look-only run can know.

---

## Key Management

> The task-oriented view of key custody — what is and isn't backed up, what key loss costs, and the deploy-time provisioning recipe — lives at [docs.dfos.com/docs/developers/sign-in-with-dfos/key-custody](https://docs.dfos.com/docs/developers/sign-in-with-dfos/key-custody). The full app-integration walkthrough is at [docs.dfos.com/docs/developers/sign-in-with-dfos/setup](https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup).

### The key ledger

`dfos keys` reports every key this machine holds:

```bash
dfos keys list                 # the whole manifest
dfos keys show <key-id>        # one key: also accepts its public key or its full account
dfos keys prune                # what removing the orphans would cost — removes nothing
dfos keys prune --yes          # remove them
dfos keys prove <code-or-uri>  # prove a key to a key-add ceremony
```

The manifest is **derived**, not stored. Every column is folded on the spot out of state that already exists — the keystore backend, each vault's minted-key records, the identity chains in the local relay, and `login-client.json` — and no file records it. A cached list of keys is a list that can disagree with the keystore, and `prune` acts on what it reads.

Each key gets an **origin** (where its seed came from) and a **status** (what currently claims it):

| Origin         | Meaning                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `vault`        | a vault's minted-key record names it, with the derivation index that produced it                  |
| `standalone`   | generated straight into the keystore; no vault record names it, so this keystore is its only copy |
| `pending`      | held under a `pending:` account — an `identity create` interrupted before its DID existed         |
| `candidate`    | held under a `candidate:` account — a key [`keys prove`](#proving-a-key-to-a-ceremony) presented  |
| `login-client` | this installation's Sign In With DFOS client key                                                  |

| Status                                    | Meaning                                                                                                  |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `declared`                                | an identity chain in the local relay names it in a current role (`controller` / `auth` / `assert`)       |
| `superseded`                              | that identity's chain is local and no longer names the key — a rotation left it behind                   |
| `login-client`                            | infrastructure: the per-install sign-in client key                                                       |
| `candidate`                               | presented to a key-add ceremony; the chain that adopts it is the ceremony operator's, not this machine's |
| `orphan`                                  | nothing in the local relay declares it and nothing else claims it                                        |
| `unreadable` / `unnamed` / `unrecognized` | the key's status cannot be established from what this machine can see                                    |

Roles are reported for a `superseded` key as well as a `declared` one: a declared key's `roles` are its current roles, and a superseded key's are the roles it held before the rotation that retired it, read back out of the chain's own log. The status field is what separates the two, and the human table spells the second out as `was auth, no longer current`.

A key with origin `vault` is derivable again from that vault's phrase, which is what [`dfos recover`](#recovery) does; a `standalone` key is not, and this keystore is its only copy.

`prune` removes keys with status `orphan` and nothing else. It is a dry run until `--yes`, and it prints, per key, whether the seed is derivable again from a vault's recovery phrase or exists only in this keystore. Five rules bound it:

- **A key any local identity declares is never an orphan** — including a **deleted** identity's. Deletion is not revocation, and `identity restore` exists.
- **A candidate is not an orphan.** A key proven to a key-add ceremony is claimed by a chain the ceremony operator custodies, which this machine may never hold; absence of a local declaration says nothing about it.
- **Uncertainty is not an orphan.** A key whose status cannot be established is listed as skipped, with the reason, and left alone.
- **The local relay's own key is out of reach by construction.** It lives in `relay.db`'s `relay_meta` table, not in the keystore, so a fold over the keystore cannot see it, list it, or delete it.
- **Vault mnemonics are out of reach too.** They share the OS keychain service with key seeds, so the keystore drops them inside the enumerator that produces the list, and `prune` re-checks before every delete.

`identity forget` removes a local name and touches no key material, and it leaves the chain in the local relay — so a forgotten identity's keys still read as `declared`, and `prune` leaves them alone.

What `keys list` can see depends on whether the active backend can enumerate itself. The file store lists its own directory. The macOS keychain is listed through `security dump-keychain`, filtered to the `dfos` service. The Linux secret-service and Windows backends expose no search at all: there, `keys list` reports the keys the local relay, the vaults, and the login client already name — every key in use, and no leftovers — and says on its first line that the listing is partial.

### Proving a key to a ceremony

A **key-add ceremony** is how a key held on this machine is added to an identity whose chain someone else custodies: the ceremony operator's own surface displays a code, and `dfos keys prove` is what completes it from the machine that actually holds a key. The envelope, its carriage, and the obligations on both sides are [KEY-PROOF](https://protocol.dfos.com/key-proof).

```bash
dfos keys prove app.example/ABCD2345                  # the short code an operator displays
dfos keys prove 'https://app.example/…?ceremony=…&nonce=…'  # the carriage URI a QR code carries
dfos keys prove app.example/ABCD2345 --key z6Mk…      # prove a key this machine already holds
```

Both carriage forms are accepted. A short code is `<authority>/<CODE>`, eight characters of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` — the confusable glyphs are not in the alphabet — and it resolves with one `GET https://<authority>/.well-known/dfos-key-proof?code=<CODE>`. **One resolution per invocation**: the route is rate limited at the operator, a ceremony lives ten minutes, and a code that did not resolve is not going to. The resolved URI's authority must byte-equal the authority typed, and a resolution pointing anywhere else is refused out loud — that rule is what stops a code from redirecting a ceremony off the host the human named.

By default the command **mints** the key it proves, from the default vault or `--vault` (`--no-vault` generates one straight into the keystore). That is the shape the ceremony is for: a new self-held key being added to an identity someone else custodies the chain for. `--key <public-key|key-id|account>` proves a key this machine already holds instead — signing a key proof is a keystore-level act and needs no vault and no chain.

Two gates stand before the signature, and neither is skipped quietly:

- **The audience is shown, and confirmed.** The completion endpoint's authority and the ceremony purpose print before anything is signed, and a terminal is asked to confirm. Audience binding is what makes a relayed challenge useless — a proof names the authority its human confirmed and is dead bytes everywhere else — and it only defends a human who saw the authority. `--quiet` does not suppress the disclosure; `--yes` is how a script asserts a human already checked it.
- **One key, one DID.** Before signing, a named oracle relay is asked whether any identity has ever declared this key, through the same `key=` lookup [`dfos recover`](#recovery) scans with. Any answer that is not "nothing declares it" refuses: the lookup is has-ever-declared, its rows survive rotation and deletion, and one key in two chains publishes an irreversible public link between them. An oracle that cannot answer — no peer configured, a 501, an unreachable relay, one predating the `key=` filter — is a refusal too, never a silent skip. `--force-linked` is the explicit override for both cases, and it prints what it is overriding.

A completion is posted once and is **never retried**. A verifier consumes the ceremony's nonce before it verifies the envelope, so a ceremony that fails verification is spent: the failure names what the operator said, distinguishes a refusal from a host that could not be reached, and points at minting a fresh code. The key survives the failure — it stays in the keystore, and `--key` re-presents that same key to the new ceremony rather than minting another.

What goes on the wire is the JWS and the ceremony identifier. The envelope's four members are the nonce, the audience, the candidate's **public** key, and a timestamp; the private key stays in the keystore, and the payload has no member for content, intent, or authority to ride in.

On completion the key is held under a `candidate:` account and reported by `keys list` with status `candidate`, which `prune` never removes. An operator that names the identity its ceremony added the key to gets the key filed under `<did>#<keyId>` instead, with the vault provenance recorded — and from then on signing resolves that identity and uses the key this device holds.

### Backends

The CLI stores each Ed25519 seed under an account key of the form `did:dfos:xxx#key_yyy`. This is true whether the key was derived from a vault or generated standalone: the keystore is the one place private key material lives, so every signing path is identical regardless of where the key came from. There are two storage backends:

| Backend     | Location                | When used                                          |
| ----------- | ----------------------- | -------------------------------------------------- |
| OS keychain | system keychain/keyring | default, when an OS keychain is reachable          |
| File store  | `~/.dfos/keys/`         | keychain probe fails, or `DFOS_NO_KEYCHAIN` is set |

The file store lives inside the config directory, so `DFOS_CONFIG` relocates the keys along with `config.toml`, `relay.db`, and the vaults — pointing it at a scratch directory isolates all of this machine's dfos state, not part of it.

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

When the keychain is unavailable, each key is written to its own file under `~/.dfos/keys/`, named by percent-encoding its account: every byte outside `[A-Za-z0-9.-]` becomes `%XX`, so `did:dfos:xxx#key_yyy` is filed as `did%3Adfos%3Axxx%23key%5Fyyy`. The encoding is reversible, which is what lets the store enumerate itself for `dfos keys list`. Files written under the earlier scheme (`#`→`__`, `:`→`_`) are still read, and are rewritten under the current name the next time that account is written; one whose account that scheme made ambiguous is listed as an unnamed entry rather than guessed at. **The file contains the hex-encoded 32-byte Ed25519 seed in plaintext — it is not encrypted.** The directory is created `0700` and each key file `0600` (owner read/write only), so the protection is filesystem permissions and nothing more.

Threat model for the file store:

- A seed file grants full signing authority for that key to anyone who can read it. Treat `~/.dfos/keys/` like an SSH private key directory.
- There is no passphrase, no encryption at rest, and no hardware backing. Disk theft, a permissive backup, a synced home directory, or root on the box all expose the seeds.
- If you need encryption at rest, run on a host with a working OS keychain (the default path) or place `~/.dfos/keys/` on an encrypted volume.

During identity genesis (before the DID is known), keys are stored under a temporary account (`pending:<keyId>`) and renamed after the DID is derived from the genesis CID — this happens in whichever backend is active. A genesis interrupted between the mint and the rename leaves the `pending:` account behind; no chain can ever name it, so `dfos keys list` reports it as an orphan and `dfos keys prune` removes it.

The CLI discovers which keys belong to which identity by querying the identity's chain state (from local store or relay) and checking which keys have private material in the active backend.

### Security Properties

- Private keys are loaded into memory only during signing operations
- With the keychain backend, seeds are held by the OS keychain; with the file store backend, seeds are written **unencrypted** to `~/.dfos/keys/` at mode `0600` (see threat model above)
- `identity keys` shows key presence/absence, never key material; `dfos keys list` / `show` report public keys, ids, and metadata, and never a seed in any output including `--json`
- After key rotation, old keys remain in the active backend (needed for historical chain re-verification) but are no longer used for new operations; `dfos keys list` reports them as `superseded`, and `prune` leaves them alone
- A vault-minted key is stored exactly like a generated one; what the vault adds is a written-down phrase that, with the documented derivation path, describes the same key

---

## Local-First Workflow

The default mode is local. Operations are signed and stored in `~/.dfos/relay.db` without network access. Publishing to relays is explicit.

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

An identity can hold up to 256 controller keys and 256 auth keys. **Any one current key in a role set can sign** — so the same identity can act from multiple devices, each holding its own key. This is _availability_, not key recovery: with a key on more than one device, losing a single device is not loss of the identity. A surviving device can keep publishing and can even rotate out the lost key.

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

Inspect the local store alongside the normal context and peer status:

```bash
dfos status --store
dfos status --store --json
```

The store block reports the database path and file size, total sequenced operations, counts by operation kind, and pending raw operations. It is entirely local and still works when the configured peer is unreachable.

Compact the SQLite file and run the relay's revoked follower-blob cleanup in one shot:

```bash
dfos relay gc
dfos relay gc --json
```

`relay gc` reports the database size before and after `VACUUM`. The blob sweep is a no-op unless content following is eager, and its current API does not report a removal count. GC never deletes operations, chains, or other proof-plane data.

Identity chains, content chains, operations, countersignatures, and blobs all live in this single database. Local metadata (identity names, publish state) is tracked in `config.toml`.

### Fetching Remote Chains

The CLI can download and store any chain from any relay, without owning the private keys:

```bash
dfos identity fetch did:dfos:xxx --peer prod --name carol
dfos content fetch abc123 --peer prod
```

A fetched identity given a `--name` appears in `identity list` with `KEYS 0/N` — visible public keys but no private material in the keychain. This enables local verification, credential checking, and countersigning against remote identities.

Without a name, the KEYS column reads `?`: probing the keystore costs one lookup per declared key, so it runs only for identities a local name points at. `?` is the absence of a probe, not a count of zero — a footnote under the table says so, and `identity fetch <did> --name <name>` registers the name that turns it into a count. A deleted identity is marked `(deleted)` on its row, the same fact `keys list` marks on its keys and `whoami` reports as `State: deleted`.

`identity list --json` reports each identity's DID, local name, head CID, last-operation timestamp, operation count, and resolved state. The operation log itself is omitted — a roster that inlines every base64 operation of every chain is mostly bytes nobody asked for. `--include-log` emits the full stored shape instead, and `identity log <did>` shows one chain's operations.

To forget only this machine's registration for an identity:

```bash
dfos identity forget alice
dfos identity forget did:dfos:xxx
```

This removes the named identity and its referencing contexts from config, clears a `default-identity` that pointed at it, and removes that DID's cached login credential. Private keys remain in the OS keystore, public chain data remains in the local relay, and no chain operation is signed or published. Use `relay gc` for local space maintenance.

`identity remove <name>` drops the name alone, leaving contexts and any cached credential in place. It clears the same dangling pointers a removed name would leave behind, and reports them in the same field names `forget` uses — `activeContextCleared` and `defaultIdentityCleared` under `--json`, and a line each in the human output — so which config state moved is read off the result rather than out of `config.toml`.

### Peer Sync

`dfos sync` is the bulk transfer: it pulls a peer's whole operation log into the local relay and sequences it. That is unbounded in the peer's corpus rather than in what was asked for — a busy relay's log is every chain it holds — so it is the one peer interaction that answers to a switch.

```bash
dfos sync                  # every peer the switches allow
dfos sync --peer prod      # that peer alone
```

The `sync` key under `[relays.<name>]` decides whether a peer is polled. Absent means yes, which is what a config written without the key says and what `peer add` registers:

```toml
[relays.prod]
url = "https://relay.dfos.com"
sync = false
```

The two plane flags decide it as well: `proof = false` says this machine does not use the peer's proof plane, and `log = false` says it does not use its operation log. Either takes the peer out of the pull, and a peer that advertises neither would answer it with a 501 every cycle anyway. `content` does not gate it — that is the document plane, and bulk sync is the proof plane's log.

The plane flags are seeded from the peer's advertised capabilities the first time it is registered, and are the operator's from then on. Nothing refreshes them: `peer info` shows what the peer advertises beside what this machine has configured, and writes neither. A posture that a metadata refresh could undo is not a posture.

A skipped peer is named, with the reason, on every run — "did not pull" and "pulled nothing" are otherwise the same output:

```
Syncing with 1 peer(s): local
Skipping 1 peer(s): prod (sync = false)
```

`dfos sync --peer prod` against a peer the config says not to poll refuses and names the switch and the file holding it, rather than silently syncing or silently doing nothing.

Explicit single-chain traffic is a different thing and no switch here touches it: `identity fetch`, `content fetch`, `content publish`, `api call`, and `login` reach the peer they are told to reach. A machine that registers a relay for those flows alone registers it with `dfos peer add <name> <url> --no-sync`, and holds every chain it asked for and nothing else.

`gossip` (push newly sequenced operations) and `read_through` (fetch on a local 404) are the other two switches, spelled the same way and defaulting the same way. They are the config.toml half of the `serve --peers` object form.

### Local commands are local

A one-shot `dfos` command never gossips. The local relay it opens has gossip off for every peer, whatever `gossip` says under `[relays.<name>]` and whatever `--peers` supplied — the switch is overridden, not defaulted, because an absent switch means on and the ordinary registration writes no switch at all.

The three directions are therefore distinct, and only one of them puts local state on a peer:

| What you run                                                       | Where it goes                                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `identity create`, `content create`, `credential grant`, `witness` | The local relay. Nothing leaves the machine.                       |
| `content publish`, `identity publish`, `--peer`, `login`           | The peer you named, and no other.                                  |
| `dfos sync`                                                        | Pulls from the peers the switches allow. It pushes nothing.        |
| `dfos serve`                                                       | Participates in the mesh: each peer's own `gossip` switch decides. |

`serve` is the mesh participant, and relaying what it sequences is what makes it a node rather than a private store. Everything else writes locally and sends when told to.

The distinction is not cosmetic. A local command that gossiped would put an operation on a relay while reporting `publishedTo: null`, because the push is a background goroutine the command never hears back from — an operator would have no way to know from the output that anything left the machine.

### Peer Identity Pin

The `did` under `[relays.<name>]` is a pin: the identity that address must serve for the name to mean what it meant when it was registered. `dfos peer add` writes it from the peer's well-known, and every command that acts through a named peer checks it — one well-known fetch per peer per invocation, memoized.

A peer that serves a different DID than the one pinned is refused, by name, with both DIDs:

```
peer 'prod' is not the relay this machine pinned:
  pinned: did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar (~/.dfos/config.toml)
  serves: did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z
  'dfos peer repin prod' accepts the new identity
```

The CLI cannot tell a relay that re-keyed from a different relay answering at that URL. The operator can, so accepting the new identity is a command they run:

```bash
dfos peer repin prod
```

`peer repin` is the only thing that moves a pin. `peer add` over an existing entry refreshes its label and refuses to move the pin when the URL is unchanged; a changed URL is a new registration and pins fresh. `peer info` prints the full report — including the mismatch, in as many words — and exits non-zero rather than refusing to look; it is the command you run to see a mismatch, and it never rewrites the pin it just reported on.

An entry with no `did` — one written by hand, or registered while the peer was unreachable — is pinned on first contact, to whoever answers. The write is announced:

```
Pinned peer 'prod' to did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar on first contact ('dfos peer repin prod' to change).
```

Every invocation after that is checked against it. A well-known that cannot be fetched pins nothing and refuses nothing: an unreachable peer is a reachability problem, and the operation the caller was running reports it in its own words.

What a pin does not establish is who the peer is in the world — only that it is the same one as last time. `peer info`'s profile line is scoped the same way: a valid profile signature says the peer's self-description was signed by a key in its own HEAD state, which is a claim about internal consistency and not about identity.

---

## Serve

`dfos serve` exposes the embedded local relay over HTTP, turning the machine into a reachable node with peer sync, gossip, and read-through. Every flag has an environment-variable fallback for container deployment (except `--no-write`, which is deliberately explicit).

```bash
dfos serve --port 4444 --peers https://relay.example.com
```

| Flag               | Default            | Env                 | Purpose                                                                   |
| ------------------ | ------------------ | ------------------- | ------------------------------------------------------------------------- |
| `--port`           | `4444`             | `PORT`              | Port to listen on                                                         |
| `--db`             | `~/.dfos/relay.db` | `SQLITE_PATH`       | Database path                                                             |
| `--name`           | `DFOS Relay`       | `RELAY_NAME`        | Relay profile name in the well-known                                      |
| `--peers`          | —                  | `PEERS`             | Peer URLs: comma-separated, a JSON array, or per-peer objects             |
| `--sync-interval`  | `30s`              | `SYNC_INTERVAL`     | Peer sync interval                                                        |
| `--resync`         | `false`            | `RESYNC=true`       | Reset peer cursors for a full re-sync on boot                             |
| `--no-sync`        | `false`            | `NO_SYNC=true`      | Pull no peer's log: serve and ingest, but boot local-only                 |
| `--no-write`       | `false`            | —                   | LITE pull-only node: reject `POST /operations`, sync from peers only      |
| `--no-index`       | `false`            | `INDEX=false`       | Disable `/index/v0`: advertise `index: false` and return 501              |
| `--content-follow` | `none`             | `CONTENT_FOLLOW`    | Materialize granted public content blobs from peers (`none` \| `eager`)   |
| `--authority`      | —                  | `AUTHORITY`         | This relay's own `host[:port]` — the host identity proofs bind            |
| `--ingestion`      | `open`             | `INGESTION`         | Admission for `POST /operations` (`open` \| `proof-required` \| `closed`) |
| `--gossip-proof`   | `false`            | `GOSSIP_PROOF=true` | Sign gossip-out pushes with this relay's own identity proof               |

Peers accept three forms. Comma-separated URLs and a JSON array of URLs configure
every peer with defaults; a JSON array of objects sets the per-peer switches
(`gossip` pushes new operations, `readThrough` fetches on a local 404, `sync` polls
the peer's `/log` — all default to `true`):

```bash
dfos serve --peers 'https://relay-a.example.com,https://relay-b.example.com'
dfos serve --peers '["https://relay-a.example.com","https://relay-b.example.com"]'
dfos serve --peers '[{"url":"https://relay-a.example.com"},{"url":"https://relay-b.example.com","gossip":false}]'
```

A value starting with `[` must parse as JSON, every peer must be an absolute
`http(s)` URL, and unknown per-peer fields are rejected — a bad peer config fails
at boot rather than erroring on every sync tick for the life of the process.

`--peers` is merged with the relays in `config.toml`, whose entries carry the same
three switches under their own keys (`gossip`, `read_through`, `sync` — see
[Peer Sync](#peer-sync)). A relay named in both is configured once and the
`--peers` entry wins, since it is the one supplied for this run. Peer state — the
sync cursor above all — is keyed by URL, so the duplicate would otherwise pull
twice against a single shared cursor. The dropped duplicate is logged, and the
boot banner marks every peer with a switch turned off.

The boot banner names what the sync loop is about to do, before it does it — the first thing `serve` does with a registered peer is pull its whole log, and a boot that drags a corpus onto the machine says so first:

```
  Peers:  2 configured
    - local (http://localhost:4444)
    - prod (https://relay.dfos.com) (disabled: sync)
  Pull:   will sync 1 peer(s) now and every 30s: local
```

`--no-sync` is the other half: the node serves, ingests submissions, and gossips what it sequences, and reaches for no peer's log at all. The banner reads `Pull: none — --no-sync, so this node serves what it already holds`. Per-peer `sync = false` is the same posture scoped to one relay; `--no-sync` is the whole boot.

`--no-write` is the pull-only posture: the node ingests exclusively through peer sync and refuses submissions outright, so its served state is entirely derived from relays it chose to follow.

`--authority` is the host callers reach this relay at, and it is what every
identity proof is checked against. It is configuration, never read from a request
header or URL — a relay that took the host from the request would have no host
binding at all. Without it, the authenticated routes (blob upload, non-public blob
download, the mailbox poll) answer 503 rather than blaming the caller for the
operator's omission. Behind TLS on 443 that is the bare hostname
(`relay.example.com`); locally it includes the port (`localhost:4444`).

`--ingestion` sets who may submit operations. `open` (the default) accepts
anonymous submissions; `proof-required` refuses them with 403 and admits only a
submission carrying an identity proof; `closed` presents no ingestion surface at
all and answers 501. `--no-write` forces `closed` regardless. The mode is
advertised in the well-known as `ingestion`, so a client can see the posture
before it submits.

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
dfos --as bob --relay prod content update <contentId> new.json --authorization <jws>
```

Credential transport is out-of-band — the CLI mints and consumes them, but doesn't transmit them between parties.

---

## Discovery Services

An identity can publish a **services** set — an additive discovery vocabulary carried in its chain state. Services are full-state on every `identity create` / `identity update`: an update **replaces** the entire set, and an unspecified set is carried forward unchanged. Each entry has a common `{id, type}` envelope; the namespace is **open**, so unrecognized types are preserved verbatim and ignored by the core.

Two types are structurally recognized:

- **`DfosRelay`** — `{id, type, endpoint}`, a transport endpoint where this identity's chains can be fetched.
- **`ContentAnchor`** — `{id, type, label, anchor}`, a stable pointer to a content chain (31-char content id) or an artifact (CIDv1 `baf…`), addressable by `label` (e.g. `profile`, `avatar`).

Extensions ride the same open namespace — `DfosOrigin` (see **Origin Binding** below) is one, written by `identity bind-domain` and given meaning by a spec outside the frozen core rather than by a core verifier. `DfosAuthorizationServer` is a second: `{id, type, endpoint}`, the authorize origin that speaks for this DID — where a client holding only the DID finds the sign-in server its person authenticates to. It is registered by [SIWD.md](https://protocol.dfos.com/siwd), not by the core.

Bounds (enforced at sign time by the protocol layer): at most 256 entries, unique ids, non-empty `id`/`type`, and a 32768-byte cap on the encoded services array. Individual field lengths are not separately capped — the aggregate byte cap is the single bound.

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

### App description carriage (identity well-known)

`identity well-known` emits the active or named local identity's `client_did` and full, genesis-first `identity_chain` for `/.well-known/dfos-app.json`. By default it prints those two members as JSON; `--patch` writes them into an existing app description while preserving `name` and `redirect_uris`.

```bash
# print the two app-description members
dfos identity well-known alice

# patch an existing app description in place
dfos identity well-known alice --patch public/.well-known/dfos-app.json
```

Carriage is limited to 100 operations; longer chains must be published to a relay. The member set and exact carriage semantics are specified by `specs/SIWD.md` under “The App Description Document.”

---

## Origin Binding (bind a domain)

An identity can claim a **domain** — a `DfosOrigin` services entry, `{id, type, domain}`, signed into the chain by a controller key — and the domain attests the DID back by publishing it. Each half alone is a claim anyone could make; together they prove one party controls both, and any consumer can check the pair with a chain resolution plus one HTTPS or DNS lookup. No DFOS server is in the loop. The normative spec is [ORIGIN-BINDING.md](https://protocol.dfos.com/origin-binding); the `DfosOrigin` type is an extension the core carries verbatim and never structurally validates, so all of its rules live in consumers like this CLI.

```bash
# claim the domain in the chain, and print what the domain must serve
dfos identity bind-domain example.com

# verify the pair — chain claim vs the domain's attestation
dfos identity verify-binding                      # active identity
dfos identity verify-binding alice                # a local identity name or DID
dfos identity verify-binding example.com          # domain-first walk
dfos identity verify-binding example.com --json
```

`bind-domain <domain>` takes a **bare lowercase hostname** — no scheme, no port, no path, no underscores; internationalized names must already be in A-label (Punycode) form. It carries every other service entry forward unchanged, replaces an existing `DfosOrigin` entry in place (an identity claims at most one domain), and re-running it with the same domain signs nothing. `--id <id>` picks the entry id (default `origin`, or the existing entry's id); `--peer <name>` pushes the operation immediately.

The domain then serves **either** attestation — whichever its hosting allows:

| Method | What to publish                                                                |
| ------ | ------------------------------------------------------------------------------ |
| HTTPS  | `https://<domain>/.well-known/dfos-did` containing exactly the DID, plain text |
| DNS    | `_dfos.<domain>.  TXT  "did=did:dfos:<id>"`                                    |

A SIWD app already serving `/.well-known/dfos-app.json` with a matching `client_did` attests too: `verify-binding` falls back to it when `dfos-did` is **absent** (404), so every existing SIWD application is attest-back-capable with no new file. The fallback applies to absence only — a `dfos-did` document that is present but malformed blocks it.

`verify-binding` checks both methods and folds them into the spec's verdicts, which map to exit codes so scripts can branch without parsing output:

| Verdict    | Exit | Meaning                                                                                        |
| ---------- | ---- | ---------------------------------------------------------------------------------------------- |
| `bound`    | 0    | At least one method attests this DID, and no method answers anything else                      |
| `broken`   | 1    | A method answers a different DID, the methods disagree, or DNS carries multiple `did=` records |
| `stale`    | 2    | A claim exists and every method is silent (network, TLS, timeout, 404, NXDOMAIN)               |
| `no-claim` | 0    | The chain claims no domain, so there is nothing to verify                                      |

Exit `1` is also the CLI's generic error status (unresolvable target, chain not held locally, malformed input); those print an error on stderr instead of a verdict. **Silence is never contradiction:** hosting and DNS fail and recover routinely, so `stale` means _could not check_ and `broken` means _checked and contradicted_ — the two must not be conflated. A verified binding proves control of the domain at verification time, never personhood or endorsement, which is why every output names the domain instead of collapsing into a checkmark.

---

## Login (Sign In With DFOS)

`dfos login` signs in to the authorize host that speaks for an identity and stores the credential it returns. It runs the [SIWD](https://protocol.dfos.com/siwd) loopback flow: the CLI opens a consent screen in a browser, listens on a local port for the redirect, and verifies the signed challenge itself before anything is stored.

```bash
# sign in as the resolved identity
dfos --as alice login

# sign in as a named local identity, or a bare DID
dfos login alice
dfos login did:dfos:xxx

# request a scope that returns a credential
dfos login alice --scope read:profile

# sign in FOR an API: its advertised actions are listed, and you pick
dfos login alice --host dfos
dfos login alice --host api.dfos.com

# take the whole catalog without being asked
dfos login alice --host dfos --all-scopes

# no browser (containers, SSH): print the URL and wait
dfos login --no-browser --timeout 10m

# name the authorize endpoint when the chain names none
dfos login alice --authorize-url https://app.example.com
```

**Where the authorize endpoint comes from.** The subject's identity chain is fetched from the configured peer as an operation log, re-verified locally, and read for a `DfosAuthorizationServer` service entry — `{id, type, endpoint}`, where `endpoint` is the canonical authorize _origin_. The `/authorize` surface is appended to it, so a base path is kept and extended (`https://x.example/base` → `https://x.example/base/authorize`). **One entry, or none:** zero entries, more than one, an endpoint that is empty or not an absolute `http(s)` URL, and an endpoint that is not a bare origin (it carries a query, a fragment, or userinfo) all name nothing, and the CLI falls back to `--authorize-url`; with no fallback it errors and names both the missing entry and the flag. Ambiguity degrades to the fallback, never to a choice.

**Choosing what to ask for.** Without `--host`, the scope is whatever you typed — an opaque string handed to the authorize host verbatim. `--host` names the API the credential is for, by registered name or by host, and reads that API's OpenAPI document for the actions it advertises: the catalog on its request-proof scheme (action token → description, per [API-AUTH](https://protocol.dfos.com/api-auth)) unioned with every token an operation requires. A registered name resolves against the local registry and reads the cached document; a bare host runs the same discovery `api add` runs — the well-known probe, then `/openapi.json` — and offers to keep what it found under a local name.

The listed actions are then yours to pick from, by number or by token, with enter taking all of them. Three rules bound that ask: an explicit `--scope` is an instruction and is used exactly as typed, `--all-scopes` takes the whole catalog without prompting, and a run with no terminal and no explicit scope **errors and prints the choices** rather than choosing for you — a scope picked on your behalf is a grant you never made. Tokens stay opaque throughout: they are copied from document to prompt to scope string to credential unchanged, and the descriptions are display text nothing decides from.

**Which host a credential is for.** The host lives in the credential's attenuation, as the `api:<host>` resource — not in `aud`, which is this installation's login client DID, the party the grant was issued to. That is the resource `dfos api call` selects on, so a `--host` login says out loud when what came back does not name it.

**How this machine asks.** A CLI holds no domain, so it asks under SIWD's **loopback credential tier**: a per-install client identity, minted on first login and recorded at `~/.dfos/login-client.json` with its key in the keystore. The request carries that identity's DID, an ask proof signed by its current authentication key, and its one-operation chain — which is what lets a credential-returning scope have something to be issued to. The DID is stable across logins, so the consent you give names the same party each time; if its key goes missing the command errors instead of minting a new DID behind your back (delete the file to start over, and expect to consent again). Key control is all this proves about the software: origin and authorship are unverifiable from the host's side, which is why a credential minted here carries a hard expiry ceiling.

**The fragment relay.** A credential comes back in the URL _fragment_, which a browser never sends to a server, so the local listener answers with a small page whose inline script posts the whole URL back to it — the only path by which the fragment reaches the process that minted the challenge. The page scrubs the URL from the address bar as soon as the post lands. The listener accepts requests only at the literal `127.0.0.1:<port>` it was reached at, so a rebound hostname pointed at the same port cannot drive it, and a POST that is not a callback at all is logged and ignored rather than ending the wait — a stray request from elsewhere on the machine cannot cancel a sign-in in progress.

**What is checked before anything is stored.** The returned artifact must carry `typ: did:dfos:siwd`, the signer must be the DID the challenge was bound to, and the signature must verify against a **current** authentication key of the signer's freshly re-fetched chain — resolved through the configured peer, whose operation log is replayed and re-verified locally. Only then is the challenge consumed: its payload segment must equal this run's challenge bytes exactly, compared once and then spent, which is the spec's rule that consumption is the _final_ verification step so nothing invalid can ever spend it. A returned credential is checked once more before it is written — it must be issued to this installation's client DID, since one issued to anyone else is inert here. Any failure exits non-zero and stores nothing.

Credentials land in the config directory's `credentials/<did>.json` (mode `600`, directory `700`) — `~/.dfos/credentials/` by default, and beside `DFOS_CONFIG` wherever that points — alongside the client DID they were issued to. The summary printed on success is decoded from the artifact locally — no network call. `scope=identity` returns no credential, and that is a success too: the sign-in was verified, there was just nothing to store.

The separate `creds` group manages these local login records (not protocol grants and revocations):

```bash
# subject DID, client DID, obtained time, expiry, and expired status
dfos creds list

# full stored record plus locally decoded, unverified payload claims
dfos creds show alice
dfos creds show did:dfos:xxx --json

# remove the local cached record without a prompt
dfos creds rm alice
```

`creds list` prints `-` when an expiry claim is absent or cannot be decoded; an empty store prints a friendly message (`[]` with `--json`). `creds show` resolves configured identity names and also accepts a bare DID. Decoding here is intentionally unsafe inspection: signature verification happens when a credential is presented, not while listing the local cache.

| Flag              | Default    | Meaning                                                                                         |
| ----------------- | ---------- | ----------------------------------------------------------------------------------------------- |
| `--scope`         | `identity` | Passed to the host verbatim; space-separate several. Never parsed here.                         |
| `--host`          | —          | API the credential is for — a registered name or a host — whose advertised actions are offered. |
| `--all-scopes`    | `false`    | With `--host`, ask for every advertised action without prompting.                               |
| `--authorize-url` | —          | Authorize endpoint (or bare origin) to use when the chain names none.                           |
| `--no-browser`    | `false`    | Print the URL and wait without attempting to open a browser.                                    |
| `--timeout`       | `5m`       | How long to wait for the callback.                                                              |

`--scope` and `--all-scopes` are mutually exclusive, and `--all-scopes` needs a `--host` to have a catalog to take.

The global `--as` and `--relay` flags select the subject and the peer to resolve chains through when no positional argument names the subject. With `--json` the command emits `{did, clientDid, scope, host?, resource?, credentialPath?, credential?}`.

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

## Calling an API

`dfos api` is a generic client for any host that advertises the [API-AUTH OpenAPI convention](https://protocol.dfos.com/api-auth#advertising-in-openapi). Register the API under a local name, then call its operations by name; the document says which authentication artifact each route needs, and the CLI signs that one. Nothing here is specific to the canonical deployment — a fork or a self-hosted API registers and calls exactly the same way.

```bash
# register by host — the document is discovered
dfos api add dfos api.dfos.com

# or by document URL, or from disk
dfos api add mine https://api.example.org/v3/openapi.json
dfos api add local --file ./openapi.json

# what is registered, and how old each cached document is
dfos api list

# call an operation by its operationId
dfos api call dfos protocol.getProtocolInfo

# or by method and path template, with parameters
dfos api call dfos GET /spaces/{space} --param space=nce
dfos api call dfos spaces.listSpaces --param limit=10

# refetch a document; unregister an API
dfos api refresh dfos
dfos api rm mine
```

### Registration is discovery

A bare host — or a scheme and host with no path — is discovered: the host's `/.well-known/dfos-relay` is read for an `openapi` member (absolute or root-relative, per [WEB-RELAY.md](https://protocol.dfos.com/web-relay)), and `/openapi.json` is assumed when it advertises none. A URL carrying a path names the document outright. `--file` reads one from disk and makes no request at all.

The document is fetched, parsed, and validated at registration, so a source that is not an OpenAPI 3.x document fails there rather than on some later call. `api list` reports which of the three routes found it (`well-known`, `conventional`, `direct`, `file`).

### A cached document goes stale visibly

`api call` reads the cached document and does not refetch. Past 24 hours it says so on stderr — `spec for dfos is 3d old — 'dfos api refresh dfos'` — and proceeds: a stale document still describes the call, and the host's own verdict still decides it. `api refresh` re-runs resolution from the source the registration recorded, so a host that moves its document is followed.

### The requirement combination names the artifact

The security schemes an operation requires, ANDed within one requirement object, are what say which claim the route needs. Schemes are identified structurally — by `type`, `scheme`, header name, and the `x-dfos-typ` marker — never by component name, so a host is free to name its schemes anything.

| The operation requires                      | The CLI sends                                                      |
| ------------------------------------------- | ------------------------------------------------------------------ |
| nothing, or `security: []`                  | no artifact                                                        |
| the identity-proof scheme alone             | `Authorization: DFOS <identity proof>`                             |
| identity-proof AND credential schemes       | an identity proof plus `X-Credential`                              |
| request-proof AND credential schemes        | `Authorization: DFOS <request proof>` plus `X-Credential`          |
| several requirement objects                 | the cheapest one it can satisfy; the anonymous alternative last    |
| the request-proof scheme with no credential | nothing — no conforming client can call that route, and it says so |

An operation's `x-dfos-actions` is an OR of alternatives, each a single action token or an array of tokens that must all be covered. Under the delegated combination its absence is the presentation-suffices class: a valid credential for the host and no particular token. Action tokens are the host's vocabulary — they are copied from document to request to error message verbatim, never enumerated or interpreted here.

`--profile <anon|identity|delegated>` (and its shorthand `--anon`) forces a profile instead. The document ranks as a default, not a constraint.

### Credentials, and what a refusal means

The delegated profile presents a stored login credential and signs the request proof with the key that credential was issued to — this installation's login client key. The credential is selected by what it grants: some `att` entry naming `api:<host>` for the host being called. It is the **attenuation** that is matched, never `aud` — the audience is this installation's client DID on every stored credential, so it says nothing about which host a grant is for. `--as` picks between several; without it, exactly one candidate is required, because guessing which grant to spend is the one thing a credential client must never do. `dfos login --host <name-or-host>` obtains a credential for a specific host and lists that host's advertised actions to choose from; `dfos creds list` shows what is stored. When nothing covers the host, or when the presented grant does not carry what a route requires, the error names that spelling.

A non-2xx renders by tier, because the tiers mean different things:

- **401** — the proof layer refused. The host's `WWW-Authenticate` challenge is printed with it. Nothing is retried under a stronger profile: a client that escalated on its own would sign a second time over the same coordinates.
- **403** — the credential layer refused. The actions the operation requires and the actions the presented credential grants on `api:<host>` are both printed, verbatim.
- **503** — the host could not complete the check. That is the host's condition, not a verdict on the request.

Everything but the response document goes to stderr — the staleness line, the signer announcement, `-i` headers — so stdout carries one document.

| Flag               | Meaning                                                        |
| ------------------ | -------------------------------------------------------------- |
| `--param name=val` | A path or query parameter, matched against the operation's own |
| `--data`           | A request body, as a JSON string                               |
| `--data-file`      | A request body from a file (`-` for stdin)                     |
| `--profile`        | Force `anon`, `identity`, or `delegated`                       |
| `--anon`           | Shorthand for `--profile anon`                                 |
| `-i`, `--include`  | Print the response status and headers to stderr                |

---

## Raw Relay Access

`dfos relay call` is the escape hatch for agents and power users — raw HTTP to the peer, with `--auth` signing the request:

```bash
# unauthenticated
dfos relay call GET /.well-known/dfos-relay
dfos relay call GET /proof/v1/identities/did:dfos:xxx

# with auto auth (signs an identity proof for this request, injects Authorization)
dfos relay call GET /content/abc123/blob --auth

# POST with body
dfos relay call POST /proof/v1/operations --body '{"operations":["eyJ..."]}'

# custom headers
dfos relay call PUT /content/abc123/blob/bafyop... --auth -H "Content-Type: application/octet-stream" --body-file doc.bin

# response headers
dfos relay call GET /proof/v1/identities/did:dfos:xxx -i
```

The `--auth` flag resolves the active identity, loads the auth key from the keychain, and signs an identity proof bound to this exact request — its method, the peer's host, the path as sent, and the body bytes. The proof always carries a `jti`, which the write-shaped routes require and the read-shaped ones ignore, so one flag is correct on every route.

`call` is a subcommand of the peer group, so `dfos peer call` is the same command under the group's own name. `dfos api <METHOD> <path>` — an uppercase method and a path as the two bare arguments — is a deprecated alias of `dfos relay call <METHOD> <path>`: it takes the same arguments and flags and prints the same output, plus one deprecation line on stderr. It sits beside the [API client](#calling-an-api) subcommands, which cobra dispatches first, so the two spellings never collide.

### Signing a proof by hand

`dfos auth proof` prints a proof for scripting — a `curl` call, a test fixture, a request the CLI has no command for:

```bash
dfos auth proof GET /signing/v0/requests
dfos auth proof POST /proof/v1/operations --body ops.json --jti
dfos auth proof GET '/index/v0/content?limit=10' --peer prod
```

It prints the JWS on the first line and a ready-to-paste `Authorization: DFOS <jws>` header on the second (`--json` gives both as fields).

A proof authorizes one request and nothing else: it binds that method, that host, that path — query string included, byte for byte — and that body, and the relay accepts it only within about a minute of signing. Sign one per request, at the moment you make it. `--jti` adds the per-request uniqueness member that the write-shaped surfaces (`POST /proof/v1/operations`, `PUT` blob) require and that makes a second presentation of the same proof a 401.

---

## Environment Variables

| Variable               | Purpose                                               |
| ---------------------- | ----------------------------------------------------- |
| `DFOS_AS`              | Identity to act as (name or `did:dfos:…`)             |
| `DFOS_RELAY`           | Peer to talk to (name)                                |
| `DFOS_IDENTITY`        | Deprecated alias of `DFOS_AS`                         |
| `DFOS_CONTEXT`         | Deprecated alias naming both halves (`identity@peer`) |
| `DFOS_CONFIG`          | Config file path (default: `~/.dfos/config.toml`)     |
| `DFOS_NO_KEYCHAIN`     | Skip OS keychain; use file store `~/.dfos/keys/`      |
| `DFOS_NO_UPDATE_CHECK` | Disable automatic version update checks               |

---

## Commands

| Method | Command                         | Description                                                  |
| ------ | ------------------------------- | ------------------------------------------------------------ |
| `GET`  | `identity list`                 | List all known identities (owned + fetched; `--include-log`) |
| `GET`  | `identity show [name\|did]`     | Show identity state                                          |
| `GET`  | `identity keys [name\|did]`     | Show key state + keychain availability                       |
| `GET`  | `identity services [name\|did]` | Show resolved discovery services                             |
| `GET`  | `identity well-known [name]`    | Emit the app-description members (`--patch`)                 |
| `POST` | `identity create --name`        | Generate keys + sign genesis (`--service`)                   |
| `POST` | `identity update [name\|did]`   | Rotate keys / set services (`--service`)                     |
| `POST` | `identity device-pubkey`        | Generate a device keypair, print its pubkey                  |
| `POST` | `identity add-key`              | Add another device's pubkey (1-of-N)                         |
| `POST` | `identity bind-domain <domain>` | Claim a domain in the chain (`DfosOrigin`, `--id`)           |
| `GET`  | `identity verify-binding [t]`   | Verify a binding (exit: bound 0 / broken 1 / stale 2)        |
| `POST` | `identity delete`               | Delete identity (restorable)                                 |
| `POST` | `identity restore`              | Restore a deleted identity                                   |
| `POST` | `identity publish [name\|did]`  | Submit identity chain to a relay                             |
| `GET`  | `identity fetch <did\|name>`    | Download identity chain from relay                           |
| `GET`  | `identity log <name\|did>`      | Show identity operation history                              |
| `DEL`  | `identity remove <name>`        | Drop an identity name from config (data stays in relay)      |
| `DEL`  | `identity forget <name\|did>`   | Forget local config + cached login credential                |
| `GET`  | `content show <id>`             | Show content chain state                                     |
| `GET`  | `content log <id>`              | Show operation history                                       |
| `GET`  | `content download <id>`         | Download blob (stdout or file)                               |
| `POST` | `content create <file\|->`      | Create content chain                                         |
| `POST` | `content update <id> <file\|->` | Update content chain (supports delegation)                   |
| `POST` | `content delete <id>`           | Permanently delete content chain                             |
| `DEL`  | `content remove <id>`           | Explain that local content cannot be un-ingested             |
| `POST` | `content publish <id>`          | Submit content chain + blob to a relay                       |
| `GET`  | `content fetch <id>`            | Download content chain from relay                            |
| `GET`  | `content list`                  | List locally stored content chains                           |
| `POST` | `credential grant <id> <did>`   | Issue read/write credential                                  |
| `POST` | `credential revoke <cid>`       | Revoke a credential                                          |
| `GET`  | `content verify <id>`           | Re-verify chain integrity locally                            |
| `POST` | `witness <cid>`                 | Countersign an operation (`--relation`)                      |
| `GET`  | `countersigs <cid>`             | Show countersignatures for an operation                      |
| `GET`  | `operation show <cid>`          | Inspect a protocol operation                                 |
| `POST` | `login [name\|did]`             | Sign in via SIWD, store the credential (`--host`, `--scope`) |
| `GET`  | `creds list`                    | List cached SIWD login credentials                           |
| `GET`  | `creds show <name\|did>`        | Show a cached record + decoded claims                        |
| `DEL`  | `creds rm <name\|did>`          | Remove a cached SIWD login credential                        |
| `GET`  | `auth proof <METHOD> <path>`    | Sign an identity proof for one request (`--body`, `--jti`)   |
| `GET`  | `auth status`                   | Show current auth state                                      |
| `POST` | `api add <name> [source]`       | Register an API and cache its OpenAPI document (`--file`)    |
| `GET`  | `api list`                      | List registered APIs and their documents' age                |
| `POST` | `api refresh <name>`            | Refetch a registered API's document                          |
| `DEL`  | `api rm <name>`                 | Unregister an API and drop its cached document               |
| `*`    | `api call <name> <op>`          | Call one operation, signing what the document names          |
| `*`    | `relay call <METHOD> <path>`    | Raw HTTP to relay with optional `--auth`                     |
| `*`    | `api <METHOD> <path>`           | Deprecated alias of `relay call`                             |
| `GET`  | `peer list`                     | List configured relays (alias: `relay`)                      |
| `GET`  | `peer info [name]`              | Show relay metadata                                          |
| `POST` | `peer add <name> <url>`         | Register a named relay (`--no-sync`: no bulk log sync)       |
| `SET`  | `peer repin <name>`             | Pin a peer to the identity it serves now                     |
| `DEL`  | `peer remove <name>`            | Unregister a relay                                           |
| `DEL`  | `relay gc`                      | GC follower blobs + compact the local SQLite store           |
| `GET`  | `config list`                   | Show full configuration                                      |
| `GET`  | `config get <key>`              | Read a single config value                                   |
| `SET`  | `config set <key> <value>`      | Write a config value                                         |
| `GET`  | `status [--store]`              | At-a-glance overview, optionally with local-store stats      |
| `GET`  | `whoami`                        | Resolved identity, signing key, credentials, and peer        |
| `POST` | `sync [--peer <name>]`          | Pull the operation log from configured peers                 |
| `*`    | `serve`                         | Run the local relay as an HTTP server                        |
| `*`    | `skill print` / `skill install` | Print or install the DFOS Claude Code skill (`--global`)     |
| `GET`  | `version`                       | Show the installed CLI version                               |

---

## What's Deferred

- **Schema validation**: validate documents against bundled JSON schemas (currently warns on missing `$schema` only)
- **Key backup/recovery**: mnemonic seed phrases or encrypted export
- **Shell completion docs**: `dfos completion <bash|zsh|fish>` is cobra-generated and works today; per-shell installation is not documented here
- **Batch refresh** (`identity fetch --all`): re-fetch all tracked remote identities

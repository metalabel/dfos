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

# create your identity — one key, minted from that vault
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
│   ├── credentials/       │  Login credentials, one file per subject DID + API host
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

- **OS Keychain**: secret material only. One entry per Ed25519 key, keyed by `dfos` service + `key:<publicKeyMultibase>` account, holding a hex-encoded 32-byte seed; one entry per vault, keyed by `vault:<name>`, holding its mnemonic. Never written to disk.
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

The same rule governs the peer half: **the closest name wins.** A few commands carry a `--peer` of their own — `recover` names the relay it asks the used/unused question of, `identity fetch` names the relay it pulls from — and that flag outranks the whole peer stack, the global `--relay` included. `dfos --relay stale recover --peer authoritative` asks `authoritative`. The global aliases keep their own ordering between themselves: `--relay` still outranks the deprecated global `--peer`.

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
dfos identity create --name detached --no-vault    # a standalone key, from no seed
```

With no vault selected — none exists, no default is set, or `--no-vault` is passed — the key is generated straight into the keystore and exists only there. That key is legal and complete; what it lacks is a phrase that covers it.

`dfos config set default-vault <name>` writes the default, and it is the only thing that writes it, with one exception: creating the **first** vault on a machine that has none sets it, because there is nothing there to displace.

Rotation is sticky. `identity update --rotate-controller`, `--rotate-auth`, and `--rotate-assert` draw their replacement from the vault that minted the identity's **current** keys, so an identity stays on one seed and its phrase does not silently stop covering it. `default-vault` is not consulted — that would move an identity onto a different seed the moment someone changed a default. `--vault` overrides the stickiness for **that invocation only** — it moves no pointer, so a later bare rotate resolves the seed afresh from whichever vault minted the identity's controller key at that moment. An identity whose keys came from no vault rotates into a standalone key.

### Derivation

Keys derive by SLIP-0010 for ed25519, hardened at every level, from the BIP-39 seed of the vault's mnemonic (PBKDF2-HMAC-SHA512, 2048 iterations, no passphrase). The path is:

```
m / 1684434803' / <index>'
```

`1684434803` is `0x64666f73` — the four ASCII bytes of `dfos`. The index is a single flat counter per vault, dense and ascending from 0, incremented once per **key** and never per role: an `identity create` consumes one index, and a rotation consumes one however many roles it names. An index consumed by an operation that then failed is burned rather than reused, because a gap costs nothing and handing one index to two identities costs everything.

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

The rule is a custody rule, not a bookkeeping one. The derivation counter belongs to the vault, so two vaults over one phrase each hand out indices from their own counter starting at 0 — mint an identity from each and the two identities hold the **byte-identical** private key, with nothing on the chain to say so. There is no `--force`: several accounts branching under one mnemonic is a shape that is refused by design, because a phrase whose holder cannot tell which identity it controls has stopped being a backup. A second identity gets a second phrase.

### Minting asks before it spends an index

One seed, one vault is a rule about one machine. A phrase is portable, so two machines holding one phrase keep two counters, neither can see what the other spent, and both hand out index N — one Ed25519 private key under two DIDs, with nothing on either chain to show it. `vault import` says so when a phrase is adopted, and `recover` raises the counter past every index a relay can prove the seed spent. The mint-collision probe is the check in between, at the mint itself.

Every vault-backed mint — `identity create`, and `identity update --rotate-*` — reserves its index and then asks the resolved relay's identity index whether the key that index derives already proves anywhere. It is the same `GET /index/v0/identities?key=<multibase>` lookup recovery scans with, one query per reserved key, and only the public key goes on the wire. Rows back mean another holder of this phrase minted here first, and the whole operation is refused before a key is stored or an operation signed:

```
refusing to mint from vault 'restored': index 3 is already spent.
prod (https://relay.dfos.com) reports the key this vault derives at index 3 already proves for did:dfos:abc123. Another holder of this phrase minted here first — signing with it would put one private key under two identities.
'dfos recover --vault restored' converges this machine's counter past every spent index. The reserved index stays burned, which is safe: the recovery scan's gap limit walks through burned indices by design. --no-mint-probe mints anyway.
```

The reservation happened before the question was asked, so a refusal burns the index — the safe direction, because a burned index is a hole and a hole is what the gap limit walks through. Under `--json` the refusal carries `reason: mint-index-already-proved` beside the index, the public key, the relay, and the DIDs the rows named.

The probe is **best-effort, and loud about it.** It is a pre-check on top of minting, not a gate in front of it: a relay's silence never stops a local-first mint, and it is never read as permission either. What the mint could not establish is said out loud.

| What happened                                                         | What the mint does                                                 |
| --------------------------------------------------------------------- | ------------------------------------------------------------------ |
| No relay resolves — the local-first mint                              | Mints; an imported vault carries a note, one created here does not |
| The relay serves no index (501), ignores `key=`, or cannot be reached | Mints, naming the relay and the cause                              |
| The relay stops answering after the capability check                  | Mints, naming the relay                                            |
| Zero rows for every reserved key                                      | Mints, silently — an unspent index is the ordinary case            |
| Rows for any reserved key                                             | Refuses, above                                                     |

```
Note: the mint-collision probe did not run — no relay to ask. If this phrase is held on another machine, index 3 may already be spent there; 'dfos recover --vault restored' converges the counter.
```

The no-relay note is scoped by where the seed came from, because that is what makes its sentence true: a vault created on this machine mints local-first without it, and an imported one carries it, since an imported phrase is by definition one that already exists somewhere else. Every other note fires for any vault-backed mint — those are cases where a relay was expected to answer and did not.

The relay is the one the ordinary peer stack names: the command's own `--peer`, then `--relay`, `DFOS_RELAY`, then `default-peer`. `--no-mint-probe` mints without asking and prints nothing — an operator who opted out is not told what the opt-out cost. A mint from no vault asks nothing at all, because a key drawn from entropy has no index to collide on.

The probe and `recover` are two halves of one rule, in opposite directions. `recover` converges this machine's counter over what the seed has already spent; the probe refuses the forward collision a converged counter still cannot see — an index another holder spent after this machine last recovered.

### Seeing the phrase

The mnemonic goes to **stderr**, always, from every command that prints it: `vault create` when it generates one, and `vault show --reveal-mnemonic` when it reveals one. It never goes to stdout and never into `--json` output, so a redirected or piped invocation does not write a seed into a file by accident — `dfos vault show personal --reveal-mnemonic > report.txt` writes a report, and the phrase stays on the terminal.

`vault create` prints it once, fenced and numbered. `vault show` does not print it at all unless asked: `vault show <name> --reveal-mnemonic` does, behind a typed confirmation — the vault's own name, not a `y` — because the phrase then lives in that terminal's scrollback and in anything recording the session. The confirmation is read from stdin, so a non-interactive invocation fails closed rather than revealing anything. No flag puts a `mnemonic` field in a `--json` document; a script that needs the phrase captures stderr.

`vault import` reads the phrase from stdin — a prompt at a terminal, a piped line otherwise. It is never an argument: argv lands in shell history and is readable in the process list. The words are checked against the BIP-39 English wordlist and their checksum, and the seed against every vault this machine already holds, before anything is stored.

At a terminal the prompt reads the phrase with **echo off**: nothing appears as it is typed, and nothing of it stays in the scrollback, in a multiplexer's history, or in whatever is recording the session. A terminal that refuses to surrender its echo bit gets a hard failure naming the piped form, not a quiet fall-through to typing a seed in clear text. Piping is how the import is scripted — `printf '%s' "$PHRASE" | dfos vault import restored` — and a piped stdin has no echo to worry about either way.

A vault's phrase is the only copy of its seed. There is no second copy on any machine, with any relay, or at DFOS Inc. What that phrase gets you back is [Recovery](#recovery).

---

## Recovery

`dfos recover` is the disaster path: the machine is gone, and what survives is a vault's 24-word phrase. It rebuilds what that phrase controls.

```bash
dfos vault import restored              # adopt the phrase (read from stdin)
dfos recover --vault restored --peer prod
```

Those two commands are the whole flow. `vault import` is the one way a phrase enters a machine — it checks the words against the BIP-39 wordlist and their checksum, and it never reads a phrase from argv — and `recover` is what turns the adopted seed back into working identities.

They are also in that order for a reason the import says out loud. An imported vault's derivation counter starts at 0, and that zero reads like a fresh vault while meaning the opposite: a phrase being imported has by definition existed elsewhere, and other holders may have minted keys this machine cannot see. Minting from index 0 against a seed another machine has already spent indices on hands two unrelated identities the byte-identical private key, with nothing on either chain to show it. `recover` is what raises the counter past every index the network can prove the seed spent, so it runs before the first mint.

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

For each identity the scan finds, `recover` pulls the chain from the oracle into the local relay, reads the key id the chain declares each recovered public key under, and writes the private key into the keystore under its content address, `key:<publicKeyMultibase>`. The chain still gates the write — a public key no accepted operation declares is a key `recover` reports rather than installs — and a key this machine already holds under either addressing is reported `already-present` rather than written a second time. Then it rebuilds the vault's minted-key records and registers the identity in config — using the relay's projected profile name where there is one, and a DID-derived label otherwise, with a numeric suffix on a collision. A name already in config is kept; recovery adds and never renames.

Signing afterwards needs nothing further: it resolves the identity, intersects its published auth keys with the keys this device holds, and signs.

Two details matter:

- **A key a rotation left behind is still recovered.** `key=` is a **has-ever-proved** lookup, so it finds the chains a key controlled before an update rotated it out — which is the case a phrase-holder is most likely to be in. Those keys land in the keystore and are reported as superseded. A membership no proof admitted never enters the index, so a key some other chain merely declared is not something recovery will hand back.
- **A deleted identity is still found, fetched, and reported as deleted.** Deletion is not revocation, and `identity restore` is real.

The report ends with the end state per identity: `recovered`, `already-present`, or `found-but-not-fetched`. Re-running converges — nothing is duplicated and nothing is renamed.

### The counter

An imported vault starts with its derivation counter at 0, because this machine has no record of what the seed minted elsewhere. `recover` raises that counter past every index it learned is in use, so the next `identity create` from the vault cannot hand a spent index to a second identity. This is the half of recovery that matters even when every key was already present, and it is the half where a mistake is unrecoverable: two identities minted at one index sign with the same Ed25519 private key.

The scan is not the only thing the run learns from. A chain pulled from the oracle declares public keys, and the seed in hand derives them, so `recover` matches every key its fetched chains name against forward derivations and feeds those indices to the counter too. This closes the case the scan structurally cannot reach: rotations move an identity's current auth key to a fresh index each time, and enough of them — or enough burned indices in between — put that index past where the gap limit ended the walk. The chain names the key regardless, so the index is known, the private key is derived and installed, and the counter clears it.

A key a fetched chain names that this seed cannot derive was minted elsewhere. It moves nothing here.

A converged counter is a statement about what the seed had spent when the scan ran. An index another holder of the phrase spends after that is invisible to it, which is the question [the mint-collision probe](#minting-asks-before-it-spends-an-index) asks at the next mint.

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

`--json` carries the same fact as data rather than prose: `scanComplete`, `beyondScanIndices`, and `recommendedScanDepth`. `scanComplete: false` with indices listed is the proven shortfall; `false` with none listed is the unproven kind — a chain this run could not read, so what it declares was never checked against a derivation at all. `--dry-run` reads the oracle's chains too, so its `scanComplete` reports what it verified rather than what this machine happened to hold, and a dry run that reaches every chain reports the same shortfall the real run does.

An oracle failure under `--json` carries a `reason` code beside its prose — `oracle-no-index`, `oracle-unreachable`, or `oracle-key-param-ignored` — because the operator's next move differs for each and a sentence is not something to branch on.

### What recovery cannot see

- **A derived key no identity operation ever declared is invisible to any index.** It is still derivable from the phrase; nothing can find it for you, because there is nothing anywhere that records it.
- **One relay's index-absence is not global absence.** A key the named oracle does not know may be declared on a chain it never ingested.
- **An identity behind a gap longer than the limit is out of reach.** The walk ends on `--scan-depth` consecutive unused indices, so an identity whose every key sits past a longer run of them is never asked about. `--scan-depth N` is the lever, and the report names it whenever a fetched chain proves the walk stopped short.
- **Keys minted outside a vault are not derivable from any phrase.** `--no-vault` keys, and keys created on a machine with no vault, live only in the keystore that was lost. `recover` says nothing about them; `dfos keys list` is the tool that shows what a machine holds.

### Dry run

`recover` writes by default. It is additive and idempotent — it stores keys, ingests chains, adds config names, and raises a counter, and it deletes nothing — and it is the command an operator reaches for at the worst moment, so making the disaster path take two invocations buys nothing. (`keys prune` is dry-run-by-default for the opposite reason: it deletes.)

`--dry-run` predicts the run it stands in for. It runs the same scan, fetches each found identity's chain from the oracle, and verifies it in memory — so it folds the same key ids, computes the same vault records, the same counter floor, and the same `scanComplete` verdict a real run would. It writes none of it: no keystore writes, no config writes, no local-relay ingestion.

The report speaks in the would-mood, because a dry run that found a recoverable key has to read as having found one. Keys come back `would-install` where a real run says `recovered`, identities `would-recover`, and the vault line reads `N would be added by a real run`. `already-present` is unchanged in both modes — it is a present-tense fact about this machine. The last line is the verdict:

```
DRY RUN: 2 recoverable keys across 1 identity — nothing was written. Re-run without --dry-run to restore.
```

A chain the oracle cannot serve, or one that does not verify, is a loud named failure in a dry run exactly as in a real one: the identity reports `found-but-not-fetched` with the reason, its keys report `not-installed`, `scanComplete` goes false, and the verdict names the identities that could not be read rather than rounding them down to "nothing to do".

---

## Key Management

> The task-oriented view of key custody — what is and isn't backed up, what key loss costs, and the deploy-time provisioning recipe — lives at [docs.dfos.com/docs/developers/sign-in-with-dfos/key-custody](https://docs.dfos.com/docs/developers/sign-in-with-dfos/key-custody). The full app-integration walkthrough is at [docs.dfos.com/docs/developers/sign-in-with-dfos/setup](https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup).

### One key at genesis

`dfos identity create` mints **one** key, from one derivation index, and declares it in all three role arrays — `controllerKeys`, `authKeys`, `assertKeys`. The same entry appears in each: same id, same `publicKeyMultibase`.

That is a statement about custody rather than about roles. Two keys minted from one seed, written into one keychain, on one machine, are one custody arrangement wearing two names — every event that reaches one reaches the other, so a controller/auth separation drawn there separates nothing. A role split becomes real when a second custodian holds a key the first cannot reach, and the CLI has exactly one moment where that happens: [`keys add`](#proving-a-key-to-a-ceremony), which presents a key to a ceremony someone else custodies the chain for. It is the only one because a key enters a chain carrying its own signature over the introduction, and the device that holds the key is the only party that can produce it. **The first key-add is the split.**

The chain grammar requires exactly this shape at genesis. PROTOCOL.md's single-key rule declares one key as the sole entry of all three role arrays, self-signed — the signature is the key's own possession proof — and states no separation rule past it; a key id is an opaque string. One key in three arrays is what genesis is.

`identity keys` reports one row per key with the roles beside it, because a key is a thing and its roles are an attribute of it:

```
KEY ID                               ROLES                      HELD
key_k7h2an38v2drtec7648vnvfdd4rdr44  controller, auth, assert   present
```

That table reads the chain in this machine's relay. [`identity status`](#is-this-machines-chain-current) carries the same roster folded from the freshest chain that verifies — the identity's own relay's, where it is at least as current as this machine's — and resolves each held key to the vault that minted it or to this keystore alone.

Rotation is scoped to the roles its flags name. `--rotate-auth` on a single-key identity replaces `authKeys` with a freshly minted key and carries `controllerKeys` and `assertKeys` forward untouched — so the displaced key is still the identity's controller and assert key, and the report says so rather than calling it retired:

```
  New key:        auth:key_3kfv7dc73nat93f9rkednzf389288n8
  Still declared: key_k7h2an38v2drtec7648vnvfdd4rdr44 — controller, assert
```

Naming every role (`--rotate-controller --rotate-auth --rotate-assert`) is what fully retires a key; the report then says `Retired:` and names no roles. Several flags in one invocation mint **one** replacement key and put it in each named role — one custody, one key, the rule genesis follows.

### Key ids are derived from the key

A key's `key_id` is computed from its public key, not drawn from randomness:

```
key_id = "key_" + DeriveID(publicKeyMultibase)
```

`DeriveID` is the protocol's own identifier encoding, the one behind every `did:dfos:` and every content id: SHA-256 over the input, then one character per digest byte from the 19-symbol alphabet `2346789acdefhknrtvz` by `byte % 19`, for 31 characters. The input is the multibase **string** a chain carries, not the raw key bytes. Nothing about the shape changes — the result is a `key_` identifier of the same 31 characters as before, and the chain grammar cannot tell the difference.

What it buys is one property, and it matters exactly once: every machine that holds a key computes the same handle for it, with no shared secret and nothing exchanged. A recovery that rederives a key from a phrase names it the way the machine that minted it did, `identity device-pubkey` and `identity add-key` agree on an id without passing one between them (`--id` is optional, and defaults to the derived one), and "what this chain declares" compares to "what this device holds" by equality.

Pinned vector, for anyone implementing the same derivation:

| Input `publicKeyMultibase`                         | `key_id`                              |
| -------------------------------------------------- | ------------------------------------- |
| `z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp` | `key_v8ctratnzd9dfz4azdr2acdvh633f74` |

An `--id` given explicitly still wins wherever the CLI accepts one: a key id is an opaque string, and a ceremony run elsewhere may already have told the world what a key is called.

### The key ledger

`dfos keys` reports every key this machine holds:

```bash
dfos keys list                 # the whole manifest
dfos keys show <key-id>        # one key: also accepts its public key or its full account
dfos keys prune                # what removing the orphans would cost — removes nothing
dfos keys prune --yes          # remove them
dfos keys remove <key-id>      # what removing ONE named key would cost — removes nothing
dfos keys remove <key-id> --yes  # remove it
dfos keys add <code-or-uri>    # add a key to an identity through a key-add ceremony
```

The manifest is **derived**, not stored. Every column is folded on the spot out of state that already exists — the keystore backend, each vault's minted-key records, the identity chains in the local relay, and `login-client.json` — and no file records it. A cached list of keys is a list that can disagree with the keystore, and `prune` acts on what it reads.

Each key gets an **origin** (where its seed came from) and a **status** (what currently claims it):

| Origin         | Meaning                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `vault`        | a vault's minted-key record names it, with the derivation index that produced it                  |
| `standalone`   | generated straight into the keystore; no vault record names it, so this keystore is its only copy |
| `pending`      | held under a `pending:` account — an `identity create` an earlier version interrupted             |
| `candidate`    | held under a `candidate:` account — a key [`keys add`](#proving-a-key-to-a-ceremony) presented    |
| `login-client` | this installation's Sign In With DFOS client key                                                  |

| Status                                    | Meaning                                                                                                                                       |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `declared`                                | an identity chain in the local relay names it in a current role (`controller` / `auth` / `assert`), whether that membership is proved or void |
| `superseded`                              | that identity's chain is local and no longer names the key — a rotation left it behind                                                        |
| `login-client`                            | infrastructure: the per-install sign-in client key                                                                                            |
| `candidate`                               | presented to a key-add ceremony; the chain that adopts it is the ceremony operator's, not this machine's                                      |
| `orphan`                                  | nothing in the local relay declares it and nothing else claims it                                                                             |
| `unreadable` / `unnamed` / `unrecognized` | the key's status cannot be established from what this machine can see                                                                         |

Roles are reported for a `superseded` key as well as a `declared` one: a declared key's `roles` are its current roles, and a superseded key's are the roles it held before the rotation that retired it, read back out of the chain's own log. The status field is what separates the two, and the human table spells the second out as `was auth, no longer current`.

A `superseded` verdict **names its basis**, because it is a claim about one copy of a chain and reads like a claim about the world. The reason line ends `(as of local head <cid>, <timestamp>; the identity's relay was not consulted)`, and the `--json` entry carries the same two facts under `asOf` with the CID whole. The verdict is only as current as that head: a chain forked locally, or simply never synced, says "no longer names this key" about a key the identity's own relay still declares live, in exactly the same words. [`dfos identity status <name>`](#is-this-machines-chain-current) is what asks the relay, and the `keys remove` refusal for a superseded key points at it.

A role a chain declares but no possession proof admitted is marked **`<role> (void)`**. It is listed rather than dropped, because the chain really does name the key there — and marked rather than merged, because a void membership confers nothing: it is not in effective state, it never resolves, and it never enters the `key=` index. A key whose every role is void carries `void: true` and a reason saying so, and it is never an orphan: something claims it, the claim is simply empty.

A key with origin `vault` is derivable again from that vault's phrase, which is what [`dfos recover`](#recovery) does; a `standalone` key is not, and this keystore is its only copy.

A selector that names no key this machine holds gets one of two misses, because they are two different situations. A selector nothing here knows about reports `no key matching '<sel>'`. A selector that names a key an identity registered here **declares** reports `'<sel>' is declared by <identity> as <roles> and not held on this machine`, and points at `dfos identity status <identity>` for the full roster — the private half living on another device is the ordinary state of a chain read on more than one machine, and "no key matching" reads as a lost seed.

`prune` removes keys with status `orphan` and nothing else. It is a dry run until `--yes`, and it prints, per key, whether the seed is derivable again from a vault's recovery phrase or exists only in this keystore. Five rules bound it:

- **A key any local identity declares is never an orphan** — including a **deleted** identity's. Deletion is not revocation, and `identity restore` exists.
- **A candidate is not an orphan.** A key proven to a key-add ceremony is claimed by a chain the ceremony operator custodies, which this machine may never hold; absence of a local declaration says nothing about it.
- **Uncertainty is not an orphan.** A key whose status cannot be established is listed as skipped, with the reason, and left alone.
- **The local relay's own key is out of reach by construction.** It lives in `relay.db`'s `relay_meta` table, not in the keystore, so a fold over the keystore cannot see it, list it, or delete it.
- **Vault mnemonics are out of reach too.** They share the OS keychain service with key seeds, so the keystore drops them inside the enumerator that produces the list, and `prune` re-checks before every delete.

`remove` takes **one** key, named by its key id, its public key, or the account it is stored under. It is a dry run until `--yes`, it prints the same recovery cost per key, and it acts on two statuses: `orphan`, and `candidate` — the one status `prune` is built never to reach. A key proven to a ceremony that was abandoned, or replaced by a second ceremony, is claimed by a chain this machine cannot see and is retained by the rule above for as long as the keystore holds it; `remove` is the by-name path to it. That is the whole difference between the two commands: `prune` sweeps a class, `remove` executes a decision about one key.

Every other status is refused, and the refusal says why:

- **`declared`** is chain business. A declared key is rotated out of the chain that names it — `dfos identity update --rotate-controller | --rotate-auth | --rotate-assert` — not deleted out from under it.
- **`superseded`** is kept for the reason `prune` keeps it: this machine's view of a chain can be behind the network's, so "no longer current here" is a statement about this relay and not about the world. The refusal names the local head that verdict was read from and points at `dfos identity status <name>`, which asks the identity's relay.
- **`login-client`** is infrastructure. Deleting the seed under the file that names it leaves `dfos login` holding a client identity it cannot prove; deleting `login-client.json` is what mints a new one, and the authorize host asks for consent again.
- **`unreadable` / `unnamed` / `unrecognized`**: uncertainty is neither a candidate nor an orphan, and a status that cannot be established cannot be judged.

`identity forget` removes a local name and touches no key material, and it leaves the chain in the local relay — so a forgotten identity's keys still read as `declared`, and `prune` leaves them alone.

What `keys list` can see depends on whether the active backend can enumerate itself. The file store lists its own directory. The macOS keychain is listed through `security dump-keychain`, filtered to the `dfos` service. The Linux secret-service and Windows backends expose no search at all: there, `keys list` reports the keys the local relay, the vaults, and the login client already name — every key in use, and no leftovers — and says on its first line that the listing is partial.

### Proving a key to a ceremony

A **key-add ceremony** is how a key held on this machine is added to an identity whose chain someone else custodies: the ceremony operator's own surface displays a code, and `dfos keys add` is what presents a key to it from the machine that actually holds one. The envelope, its carriage, and the obligations on both sides are [KEY-PROOF](https://protocol.dfos.com/key-proof).

```bash
dfos keys add app.example/ABCD2345                  # the short code an operator displays
dfos keys add 'https://app.example/…?code=ABCD2345' # the carriage URI a QR code carries
dfos keys add app.example/ABCD2345 --key z6Mk…      # prove a key this machine already holds
dfos keys add app.example/ABCD2345 --name 'work laptop'   # what the operator files the key under
dfos keys add app.example/ABCD2345 --no-wait        # stop at presented, for a script
```

`keys prove` is an alias of `keys add`: one command, two names, both permanent. `add` is the name an operator's dialog prints, and it is what this document uses.

**A carriage is two values: an authority and a code.** Both forms carry exactly that — a short code is `<authority>/<CODE>`, eight characters of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` with the confusable glyphs left out of the alphabet; a carriage URI is a URL naming the same resolution with its `code` member, and a QR code is that URI verbatim. Neither carries the signing context, so every form funnels through one `GET https://<authority>/.well-known/dfos-key-proof?code=<CODE>` and nothing is signed before it has resolved. A URL carrying a ceremony and a nonce in its query is not a carriage and is refused by name: a context nobody resolved is a context somebody else chose.

**One resolution per invocation**: the route is rate limited at the operator, a ceremony lives ten minutes, and a code that did not resolve is not going to.

Resolving a live code answers the whole signing context — the presentation endpoint, the nonce, the audience, the purpose, the identity being joined (`adopts`: its DID, handle, and display name), the role set, the chain head the introduction builds on, and when the ceremony lapses. Four rules stand over that answer, and each refuses out loud:

- The resolved `audience` must byte-equal the authority typed, **and** the presentation endpoint's authority must too. Either one moving is what would let a code redirect a ceremony off the host the human named.
- The identity, the roles, and the head must all be present. They are what the payload binds and what the human is shown, so a resolution naming less than all of them is one no proof can honestly be signed against — every missing member is named at once, rather than one refusal per re-run.
- The role set must be canonical: a non-empty selection from `auth`, `assert`, and `controller`, in that order, comma-joined, no spaces, no repeats. `assert,auth` and `auth, assert` are not spellings of a role set, they are schema violations, and catching them here means the refusal lands before a key is minted.
- A resolution naming some other ceremony purpose is not this command's to complete. An absent purpose is tolerated — silence is not a claim about another ceremony — but a different one is.

Nothing the resolution answers is trimmed before it is signed or compared. Every one of those members is a byte contract, and repairing a spelling would mean signing bytes the operator did not send.

**The carriage names no identity; resolving it names everything.** A shoulder-surfed code or an intercepted QR is an authority and a short-lived token, and neither says whom the ceremony is for. The resolution says all of it, deliberately: a human who cannot see whom they are joining cannot consent to joining them, and what it discloses are public identity facts reached through a single-shot code over TLS. What an interceptor gains is the knowledge that one public identity is mid-ceremony, and the ability to attempt a presentation with a key they do not hold.

A code is read off one screen and typed on another, so it is taken the way it was displayed: spaces and dashes between the characters are dropped, and case is normalized. Neither mark is in the alphabet, so neither can be a character of the code — `ABCD-2345`, `abcd 2345`, and `ABCD2345` are the same code.

By default the command **mints** the key it proves, from the default vault or `--vault` (`--no-vault` generates one straight into the keystore). That is the shape the ceremony is for: a new self-held key being added to an identity someone else custodies the chain for. `--key <public-key|key-id|account>` proves a key this machine already holds instead — signing a key proof is a keystore-level act and needs no vault and no chain.

On a machine that holds no vault yet, a pasted code refuses without minting anything and says the thing that is easy to assume otherwise: **the ceremony is not spent.** Resolving a code asks a question and consumes nothing — only a presentation spends the nonce — so the code on the other screen is still live, and the recovery is `dfos vault create <name>` followed by the same paste. No seed is ever created as a side effect of a ceremony; a phrase nobody wrote down covers nothing.

Two gates stand before the signature, and neither is skipped quietly:

- **The audience and the position are shown, and confirmed.** The identity being joined — display name, handle, and full DID — the roles being consented to, the audience, the purpose, the chain head, and the key's six-word fingerprint all print before anything is signed, and a terminal is asked to confirm. Audience binding is what makes a relayed challenge useless: a proof names the authority its human confirmed and is dead bytes everywhere else. Position binding is what keeps consent to sign as an author from being consent to become a controller. Neither defends anyone who did not see it, so each role prints as the power it actually confers rather than as a bare token — `controller` reads "CONTROL this identity: add and remove its keys, including yours". `--quiet` does not suppress the disclosure; `--yes` is how a script asserts a human already checked it.
- **One key, one DID.** Before signing, a named oracle relay is asked whether any identity has ever **proved** this key, through the same `key=` lookup [`dfos recover`](#recovery) scans with. Any answer that is not "nothing has proved it" refuses: the lookup is has-ever-proved, its rows survive rotation and deletion, and one key proved into two chains publishes an irreversible public link between them. A declaration nobody proved is not a link and is not a refusal — it is void, it never indexes, and it obligates nobody, so refusing on it would let anyone freeze a key out of its own ceremony by declaring it and proving nothing. An oracle that cannot answer — no relay to ask, a 501, an unreachable relay, one predating the `key=` filter — is a refusal too, never a silent skip. `--force-linked` is the explicit override for both cases, and it prints what it is overriding.

The oracle is this machine's configured peer whenever it has one. A short code's resolution may also answer a `relay` member — an absolute URL of a relay serving the `key=` index — and that relay is used **only** when this machine has no peer at all, for that one check. "No peer at all" means exactly that: a `--relay` this machine cannot resolve, or a peer whose DID pin has moved, is a relay the operator did name, and the ceremony's relay does not stand in for it — those refuse, with the pin refusal keeping its own words. It is never registered, never pinned, and never written to config: a holder that adopted an operator's relay as a standing peer would be extending trust the ceremony never asked for. The disclosure says which oracle answered and, when it came from the resolution, says that too. A `relay` member that is absent, blank, unparseable, or cleartext off loopback is simply no relay — a courtesy never fails a ceremony — and a machine with neither a peer nor a resolution relay gets the refusal above, naming both halves.

`--name` labels the key in the operator's own list of signing keys, and defaults to `<user>@<hostname>`. It travels beside the envelope as an unsigned `description`, so it is a label the operator may keep, rename, or refuse by its own bounds, and it is nothing the proof depends on; `--name ''` sends no label at all. The disclosure block shows it before it goes, since it is going to the operator.

**The six words are what a human compares.** A key's **word fingerprint** is the first six bytes of `SHA-256` over its multikey string — the UTF-8 bytes of the `z…` form — each byte rendered through the [PGP word list](https://en.wikipedia.org/wiki/PGP_word_list), the even table at even offsets and the odd table at odd ones. The reference genesis key `z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp` renders as `mohawk cumbersome zulu dinosaur goldfish opulent`. The CLI prints it beside the key in the disclosure block, before anything is signed, and again on the receipt; the operator's dialog renders the same six words from the same string, through the same function in the protocol kits, so the two surfaces agree by construction. Comparing them is the human half of catching a proof that landed in the wrong ceremony — 48 base58 characters get read at their ends and six words get read whole, and the even/odd alternation means a transposed pair reads with the wrong syllable count instead of reading fine. What the fingerprint is **not** is a validator: nothing matches, indexes, or verifies against it, the multikey string is the identifier everywhere bytes are compared, and two keys sharing a fingerprint costs a human a second look and costs the protocol nothing. `--json` carries it as `fingerprint`.

A presentation is posted once and is **never retried**. A presentation refused at the signature arm burns its ceremony, and nothing in the answer tells the command which arm refused it — so it treats every failure as spending the ceremony rather than retrying against a nonce that may already be dead. The failure names what the operator said, distinguishes a refusal from a host that could not be reached, and points at minting a fresh code. The key survives it — it stays in the keystore, and `--key` re-presents that same key to the new ceremony rather than minting another.

What goes on the wire is the JWS, the ceremony's code, and the label. The envelope's seven members are the nonce, the audience, the identity being joined, the role set, the chain head the introduction builds on, the candidate's **public** key, and a timestamp; the private key stays in the keystore, and the payload has no member for content, intent, or authority to ride in. The code travels beside the envelope rather than inside it — the nonce is the binding, so linking an envelope to a ceremony is the verifier's own bookkeeping.

**Presenting is not adoption**, so the command waits for the decision. A verified proof leaves the ceremony awaiting a human's approval on the operator's own surface, and nothing reaches the chain until that happens — so after the presentation the CLI polls `GET <origin>/v1/key-proof/status?code=<CODE>` every two seconds, backing off to five after the first thirty, until the ceremony reaches a terminal state. The status URL is **derived** from the presentation endpoint's origin with a fixed path, never read off an answer; the presentation endpoint's authority was already checked to byte-equal the authority the human typed, so the poll cannot reach a host they never named. The poll carries the ceremony's code and nothing else, spends nothing, and re-posts nothing.

Five outcomes end the wait, and each is reported as what it is:

- **Adopted.** A human approved it, and the answer names the chain row: the adopting DID, the key id that identity files it under, and the CID of the operation that introduced it. The key moves from its `candidate:` account to its ordinary address, `key:<publicKeyMultibase>`, and the vault records the provenance the DID and key id make possible. The receipt reports `Adopted`, with the key id, the chain operation, and the key's public address, `https://explore.dfos.com/#/key/<publicKeyMultibase>`, with the whole key in the URL. An answer naming a _different_ identity than the one the human consented to files **nothing** — the provenance it would write is a claim nobody saw — and the receipt says so plainly.
- **Refused.** A human declined. The key stays a held candidate, no chain declares it, and `dfos keys remove <public-key>` is the way out.
- **Expired.** The ceremony lapsed before anyone decided. Nothing was refused; the key stays a held candidate, and a fresh code with `--key <public-key>` presents the same key again.
- **Failed.** The operator could not finish the ceremony and does not say the key was added or refused. It is treated as spent — a fresh code, the same key — and the receipt says to check the operator's own list of signing keys first, because a ceremony that finished after all leaves a key `dfos identity fetch` can bring here.
- **The wait ends without a decision** — Ctrl-C, five consecutive unanswered polls, a status route that reports the ceremony is gone without saying how it ended, or fifteen minutes of nothing. None of those undo anything: the proof is still presented, the decision is still a human's to make on the operator's surface, and the key is still held here as a candidate. The receipt says exactly that, and `--json` carries `waitStopped` beside the status.

**`--no-wait`** presents and stops, for scripts: the same document as ever plus `fingerprint`, `status: "presented"`, and no poll. It changes nothing about the ceremony — the decision is still a human's — only that nobody here is watching for it.

**A head that moves under a live ceremony is re-signed, not lost.** `prevCID` binds a proof to one chain position, so when the custodian publishes something between the presentation and the decision, the stored envelope names a head that is no longer the head and the status answers `stale`. The recovery is [KEY-PROOF](https://protocol.dfos.com/key-proof)'s: the **same** code is re-resolved — a live ceremony re-resolves, answering the same nonce against the current head — the **same** key signs again, and the replacement is presented. That is not a retry of a refused presentation; a presented ceremony accepts a replacement envelope only from the `publicKeyMultibase` already on it, so it is a path only the holder who opened the ceremony can walk. The human is told it happened and the receipt names the head the envelope finally bound. Three re-signs is the cap: a head that will not settle stops the wait loudly rather than spending signatures in a loop. And the position cannot move across a re-sign — a re-resolution answering a different identity, role set, or audience is refused rather than signed, because those are what the human consented to and only the head was allowed to differ.

Until a chain declares it, the key is held under a `candidate:` account and reported by `keys list` with status `candidate`, which `prune` never removes; `dfos keys remove <public-key>` is how a candidate from a ceremony that went nowhere leaves the keystore. An operator that answers the adoption at presentation time — naming the same identity the human consented to — files the key the same way an adoption learned from the poll does, through one gate and one rename.

### Backends

The CLI stores each Ed25519 seed under an account key of the form `key:<publicKeyMultibase>` — a key is addressed by its **content**, and by nothing else. This is true whether the key was derived from a vault or generated standalone: the keystore is the one place private key material lives, so every signing path is identical regardless of where the key came from.

Addressing by the public key is what makes a keystore entry a fact about a key rather than a fact about a relationship. The scheme it replaces named a key `<did>#<key_id>`, after the identity that declared it: a name that did not exist until a chain did, that changed when a key was adopted by a second identity, and under which one seed written twice was two entries with nothing to say they were the same bytes. A content address cannot be two addresses for one key, so the same seed arriving twice — a re-import, a recovery, a second identity that turns out to declare the same key — lands where it already is, and the duplicate is visible by construction instead of discoverable by audit.

`<did>#<key_id>` accounts written by earlier versions are still **read**, everywhere a key is looked up, and are never rewritten. Nothing migrates them: a key that works is left where it works, and the next key an operation mints goes to the content address. Three account namespaces are deliberately unchanged — `candidate:<publicKeyMultibase>` (already content-addressed), `pending:<key_id>` (a transient genesis account, see below), and `login-client__<key_id>` (this installation's SIWD client key, whose handle is recorded in `login-client.json`).

Nothing on the wire is affected. A `key_id` remains a local and chain-level handle; the identifier a signature and a role array carry is the `publicKeyMultibase`.

There are two storage backends:

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
| Account | `key:<publicKeyMultibase>`       |
| Secret  | hex-encoded 32-byte Ed25519 seed |

Protection is whatever the host keychain provides (e.g. macOS Keychain, libsecret/gnome-keyring).

#### File store backend (`~/.dfos/keys/`)

When the keychain is unavailable, each key is written to its own file under `~/.dfos/keys/`, named by percent-encoding its account: every byte outside `[A-Za-z0-9.-]` becomes `%XX`, so `key:z6Mk…` is filed as `key%3Az6Mk…` and a legacy `did:dfos:xxx#key_yyy` account as `did%3Adfos%3Axxx%23key%5Fyyy`. The encoding is reversible, which is what lets the store enumerate itself for `dfos keys list`. Files written under the earlier scheme (`#`→`__`, `:`→`_`) are still read, and are rewritten under the current name the next time that account is written; one whose account that scheme made ambiguous is listed as an unnamed entry rather than guessed at. **The file contains the hex-encoded 32-byte Ed25519 seed in plaintext — it is not encrypted.** The directory is created `0700` and each key file `0600` (owner read/write only), so the protection is filesystem permissions and nothing more.

Threat model for the file store:

- A seed file grants full signing authority for that key to anyone who can read it. Treat `~/.dfos/keys/` like an SSH private key directory.
- There is no passphrase, no encryption at rest, and no hardware backing. Disk theft, a permissive backup, a synced home directory, or root on the box all expose the seeds.
- If you need encryption at rest, run on a host with a working OS keychain (the default path) or place `~/.dfos/keys/` on an encrypted volume.

Identity genesis needs no temporary account: the key's address is its own public key, which exists before the DID does, so the key is written once and never renamed. A genesis that dies between the mint and the signed operation leaves a key nothing declares — `dfos keys list` reports it as an orphan and `dfos keys prune` removes it, the same answer the old `pending:<key_id>` account gave. Any `pending:` account an earlier version left behind is still read and still classified exactly as before.

The CLI discovers which keys belong to which identity by querying the identity's chain state (from local store or relay) and checking which keys have private material in the active backend. Because a content address names a key and not a relationship, that lookup runs the other way for the ledger: the DID a held key belongs to comes from a vault's minted-key record or from the identity roster in config, and only a key neither can place sends `dfos keys list` to read every chain in the local relay — which it announces on stderr before it does.

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

**A key enters a chain carrying its own signature over the introduction.** That is the rule the rest of this section follows from. A controller writing a key into a role set is a claim about somebody else's private material, and a claim is not a demonstration — so an introduction is accompanied by an envelope the introduced key signed itself ([KEY-PROOF](https://protocol.dfos.com/key-proof)), and a membership no envelope covers is **void**: excluded from effective state, resolving nowhere, entering no index, obligating nobody. Genesis is the one case that proves itself, by signing the operation that declares it.

So a second device's key reaches a chain by being **proved from the device that holds it**, not by being handed across as a public value:

```bash
# 1. On A: create the identity. One key, in all three roles.
dfos identity create --name alice --peer prod

# 2. On B: get the chain locally.
dfos identity fetch alice --peer prod --name alice

# 3. The operator custodying the chain displays a key-add code.

# 4. On B: present B's own key to that ceremony. B mints the key, shows the
#    identity, the roles, and the key's six words it is consenting to, signs the
#    proof with the key itself — the private half never leaves B — and waits.
dfos keys add app.example/ABCD2345

# 5. A human compares those six words against the operator's dialog and approves
#    there. The operator appends the introduction with B's envelope embedded, and
#    the command B is still running reports the adoption and files the key.

# 6. On B: re-fetch so B sees its now-in-chain key.
dfos identity fetch alice --peer prod

# B publishes content / credentials independently, signing with its own key.
dfos content create post.json --peer prod
```

Notes:

- **`identity add-key` signs only for a key this machine holds.** Given a key generated elsewhere it refuses, naming the key, its roles, and the two ways forward — author the operation without it, or have the device that holds it present its own proof. Appending it regardless would publish a void membership, indistinguishable on the chain from a hostile listing of somebody else's key.
- **`device-pubkey` prints a key's public half and its derived id.** Both machines compute the same id from the same public key, so nothing has to be passed across for them to agree on a name. What it does not do is put that key in a chain; only a proof does that.
- **A controller role is a higher-trust grant** than auth: a controller can rotate, delete, and introduce further keys. The roles a ceremony grants are named in its resolution and shown before anything is signed, so the device consenting sees exactly which of them it is accepting.
- **B must re-fetch after the introduction propagates.** Between presenting and that re-fetch, B holds a private key that is not yet in the published set, so a publish attempt reports "no held auth key" until B syncs.
- **This is set up _in advance_.** There is no way to add a key after every device key is lost — an introduction is appended by a held controller key, and a proof proves possession rather than conferring authority.
- **The CLI defines no command that carries a challenge from a controller to another device.** Where no ceremony operator custodies the chain, the introduction paths this CLI offers are a key it already holds, and a ceremony.

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

### Is this machine's chain current?

Every other local surface reads the chain in this machine's relay as though it were the chain. It is one copy. A copy can be behind the identity's own relay, ahead of it with operations that were never published, or forked away from it entirely — and a verdict read off it, like a key's `superseded` status, is only as current as the copy. `identity status` is what asks:

```bash
dfos identity status alice                  # ask the relay the identity advertises
dfos identity status alice --peer prod      # ask a relay you name
dfos identity status alice --json
```

It fetches the operation log the relay serves, verifies it with the same rules an ingest applies, and compares it against the local log **token for token**. Byte equality over the ordered operations is what separates "behind" from "diverged": two chains with the same operation count and different histories are a fork, and a head CID alone cannot say where they parted.

| Verdict             | Meaning                                                                                       |
| ------------------- | --------------------------------------------------------------------------------------------- |
| `in-sync`           | the relay's log and this machine's are the same operations in the same order                  |
| `behind`            | this machine's log is a prefix of the relay's — the relay holds operations this machine lacks |
| `ahead-unpublished` | the relay's log is a prefix of this machine's — operations signed here and never published    |
| `diverged`          | a shared history, then two different ones. The report locates the fork and resolves nothing   |
| `no-local-chain`    | this machine holds no chain for the identity, so only the relay's side is reported            |
| `unknown`           | the comparison could not be made. Exit status 1; every other verdict exits 0                  |

The relay that answered is **named** in every output, with the URL and whether it came from `--peer` or from the identity's advertised `DfosRelay` service. `in-sync` means that relay's head is this machine's head — one relay's answer, not a claim about the network, and nothing about a relay this command did not ask.

Silence is never agreement. A relay that cannot be reached, serves no chain for the DID, or serves a chain that does not verify is `unknown`, named, with the error — the same discipline [`recover`](#the-oracle-is-named-and-its-silence-is-not-an-answer) holds its oracle to. An identity that advertises no relay, asked without `--peer`, is `unknown` too: there was nothing to compare against, which is a different fact from a comparison that came back clean.

`diverged` is reported and not repaired. Two histories exist over one DID; the report gives the fork index and the timestamp of each side's first divergent operation, and which history this machine keeps is a decision an operator makes deliberately.

#### The possession roster

Every verdict is followed by the keys the chain declares and which of them this machine holds the private half of, so "is my chain current" and "can I still sign as this identity" are one command's answer:

```
Keys:        roster as of remote head bafyreifv…5gekcrwioi — the verified chain prod (https://relay.dfos.com) serves
  KEY ID                               ROLES                              HELD
  key_k7h2an38v2drtec7648vnvfdd4rdr44  controller, auth, assert           held (vault 'personal' — derivable from phrase)
  key_3kfv7dc73nat93f9rkednzf389288n8  auth (void)                        not held on this machine
```

The roster **names the head it was folded from**, for the reason every other line here names its source: one DID under two histories declares two rosters, and a key table with no basis cannot say which one it is reporting. The verified chain the relay serves is that head wherever it is at least as current — `in-sync`, `behind`, `diverged`, and `no-local-chain`, where the relay's chain is the only one there is and the roster is what says whether the keys of a chain this machine has lost are still in its keystore. `ahead-unpublished` reads the local head instead: the relay's log is a prefix of this machine's, so the local head is the fresher one and may declare a key the relay has never been told about. `unknown` reads the local head as well and says the comparison could not be made — a relay that cannot be reached leaves the comparison unanswerable, not the question of what this keystore holds. With neither a local chain nor a verified remote one there is no roster, and the line says so rather than printing an empty table.

The `HELD` column has three values, and they are three different answers to what the loss of this machine costs:

| Rendering                                     | Meaning                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------ |
| `held (vault '<name>' — derivable from phrase)` | the seed is here, and that vault's written-down phrase mints it again         |
| `held (standalone)`                             | the seed is here, and this keystore is its only copy                          |
| `not held on this machine`                      | the chain declares the key and the private half is elsewhere                  |

A key marked `<role> (void)` is one the chain declares and no possession proof admitted: it is not in effective state, it resolves nowhere, and holding it grants nothing. Void rows are listed with a footnote saying that, the same way [`identity keys`](#one-key-at-genesis) lists them.

`--json` carries the roster under `keys` — `id`, `roles`, `publicKey`, `held`, `void`, and `vault` for a held key a vault record names — and its basis under `keysBasis`, with `source` (`remote` or `local`), `headCID`, and `lastCreatedAt`.

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

`dfos serve` exposes the embedded local relay over HTTP, turning the machine into a reachable node with peer sync, gossip, and read-through. Every flag has an environment-variable fallback for container deployment.

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
| `--no-write`       | `false`            | `WRITE=false`       | LITE pull-only node: reject `POST /operations`, sync from peers only      |
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

`--no-write` is the pull-only posture: the node ingests exclusively through peer sync and refuses submissions outright, so its served state is entirely derived from relays it chose to follow. Its environment form is `WRITE=false` rather than a negative `NO_WRITE`, because the flag toggles an advertised capability (`capabilities.write` in the well-known) — the same shape as `INDEX=false`.

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

A SIWD app already serving `/.well-known/dfos-app.json` with a matching `client_did` attests too: `verify-binding` falls back to it on any **non-answer** at `dfos-did` — a 404, a redirect, or a `200` whose trimmed body is not exactly one DFOS DID (the application shell a host returns for every unknown path) — so every existing SIWD application is attest-back-capable with no new file. Only a body that **is** exactly one DFOS DID answers, and only an answer naming a different DID is a contradiction, so garbage at the path silences the channel rather than breaking the binding.

**Neither HTTPS fetch follows a redirect.** The attestation is the named origin speaking for itself at the registered path, and a `3xx` is that origin declining to answer there — whatever it points at, another origin or another path on the same one, the bytes would arrive from somewhere the binding did not send the verifier. `verify-binding` reads no body behind a redirect and reports it for what it is: a non-answer that attests nothing and contradicts nothing. A domain whose HTTP serving its operator does not control attests through the DNS record instead; either method alone suffices.

`verify-binding` checks both methods and folds them into the spec's verdicts, which map to exit codes so scripts can branch without parsing output:

| Verdict    | Exit | Meaning                                                                                        |
| ---------- | ---- | ---------------------------------------------------------------------------------------------- |
| `bound`    | 0    | At least one method attests this DID, and no method answers anything else                      |
| `broken`   | 1    | A method answers a different DID, the methods disagree, or DNS carries multiple `did=` records |
| `stale`    | 2    | A claim exists and every method is silent (network, TLS, timeout, 404, a redirect, NXDOMAIN)   |
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

**Combinations are shown as combinations.** A route requiring `[["read:profile", "read:email"]]` needs both tokens or refuses, and a flat list of tokens cannot say so — it presents the pair as two independent choices, so a subset looks complete and the shortfall arrives later as a 403 against a grant already minted. Every AND-alternative the document's operations require is listed under its own heading with the routes that need it, and selectable whole by a group letter:

```
Some routes need a COMBINATION — every token of the group, or the route refuses:
   A  read:profile AND read:email   (getProfile)
```

Taking part of one is still allowed — the host decides what a grant covers, never this client — but the selection says which token it leaves out and which route that costs.

**Which host a credential is for.** The host lives in the credential's attenuation, as the `api:<host>` resource — not in `aud`, which is this installation's login client DID, the party the grant was issued to. That is the resource `dfos api call` selects on, so a `--host` login says out loud when what came back does not name it. The host is resolved under the same fetch-origin doctrine `api call` sends under, so the `api:<host>` a credential is minted for is the one it will be looked for under; minting on the document's word and spending on the origin's would be a grant that matches nothing.

**How this machine asks.** A CLI holds no domain, so it asks under SIWD's **loopback credential tier**: a per-install client identity, minted on first login and recorded at `~/.dfos/login-client.json` with its key in the keystore. The request carries that identity's DID, an ask proof signed by its current authentication key, and its one-operation chain — which is what lets a credential-returning scope have something to be issued to. The DID is stable across logins, so the consent you give names the same party each time; if its key goes missing the command errors instead of minting a new DID behind your back (delete the file to start over, and expect to consent again). Key control is all this proves about the software: origin and authorship are unverifiable from the host's side, which is why a credential minted here carries a hard expiry ceiling.

**The fragment relay.** A credential comes back in the URL _fragment_, which a browser never sends to a server, so the local listener answers with a small page whose inline script posts the whole URL back to it — the only path by which the fragment reaches the process that minted the challenge. The page scrubs the URL from the address bar as soon as the post lands. The listener accepts requests only at the literal `127.0.0.1:<port>` it was reached at, so a rebound hostname pointed at the same port cannot drive it, and a POST that is not a callback at all is logged and ignored rather than ending the wait — a stray request from elsewhere on the machine cannot cancel a sign-in in progress.

**What is checked before anything is stored.** The returned artifact must carry `typ: did:dfos:siwd`, the signer must be the DID the challenge was bound to, and the signature must verify against a **current** authentication key of the signer's freshly re-fetched chain — resolved through the configured peer, whose operation log is replayed and re-verified locally. Only then is the challenge consumed: its payload segment must equal this run's challenge bytes exactly, compared once and then spent, which is the spec's rule that consumption is the _final_ verification step so nothing invalid can ever spend it. A returned credential is checked once more before it is written — it must be issued to this installation's client DID, since one issued to anyone else is inert here. Any failure exits non-zero and stores nothing.

Credentials land in the config directory's `credentials/` (mode `600`, directory `700`) — `~/.dfos/credentials/` by default, and beside `DFOS_CONFIG` wherever that points — alongside the client DID they were issued to. The summary printed on success is decoded from the artifact locally — no network call. `scope=identity` returns no credential, and that is a success too: the sign-in was verified, there was just nothing to store.

**One file per subject and host.** A credential is spent by host — `api call` selects on the `api:<host>` attenuation — so the host is part of the file's name, and signing one identity in to a second host stores beside the first rather than over it. The name is only a slot: every command matches the record's own fields, so a file written under the older subject-only name is read exactly the same way, and moves into its slot the next time that subject stores a credential.

The slot names are the credential's own `api:<host>` strings, which the issuer wrote, so each is required to be a bare `host[:port]` before it becomes a filename — a resource naming a path refuses the whole credential, and nothing is written outside `credentials/`. A credential covering several hosts occupies the slot of the first of them, so the next login for that host would land on top of it: the record already there is moved into a slot named by one of the hosts the incoming credential does _not_ cover, rather than replaced. A host a credential still covers never loses its only record to a re-login.

The separate `creds` group manages these local login records (not protocol grants and revocations):

```bash
# subject DID, the api hosts it covers, client DID, obtained time, expiry, status
dfos creds list

# full stored record plus locally decoded, unverified payload claims
dfos creds show alice
dfos creds show did:dfos:xxx --json

# one identity signed in to two hosts holds two records — name which
dfos creds show alice --host api.dfos.com
dfos creds rm alice --host api.dfos.com

# remove the local cached record without a prompt
dfos creds rm alice
```

`creds list` prints `-` when an expiry claim is absent or cannot be decoded; an empty store prints a friendly message (`[]` with `--json`). `creds show` resolves configured identity names and also accepts a bare DID. `show` and `rm` take one record: with a single credential stored for that subject they take it, and with several they name the hosts and wait for `--host <host>` rather than picking — the same refusal to guess `api call` makes. `identity forget` drops every credential the identity holds, since forgetting some of them and reporting a whole forget would be a lie — and a file in the store that will not open or parse is left in place and named in the output (`unreadableCredentialFiles` with `--json`), because nothing can say whether it is one of that identity's grants. Decoding here is intentionally unsafe inspection: signature verification happens when a credential is presented, not while listing the local cache.

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

The document is fetched, parsed, and validated at registration, so a source that is not an OpenAPI 3.x document fails there rather than on some later call. A document larger than 16 MiB is refused by size, named as its size. `api list` reports which of the three routes found it (`well-known`, `conventional`, `direct`, `file`).

A fetch that **redirects across origins is refused**, naming both origins. The origin recorded is the one every request resolves against, so a document served by another host cannot be filed under the host that was asked — register the final URL directly if that host is what you mean, or read the document with `--file`. A redirect that stays on the same origin is a moved path and changes nothing. A well-known probe that redirects off-origin is not that host's advertisement, so discovery falls through to `/openapi.json` exactly as an absent well-known does.

Re-registering an existing name against a **different** source repoints it, and that is asked about rather than done: the name is the address of every `dfos api call` written against it, so where it points is part of what those calls mean. A terminal gets a `[y/N]`; without one, the command errors and names both `--yes` and `dfos api rm <name>`. Re-registering the same source is a refresh and passes straight through.

### The request goes to the origin the document came from

A document is discovery, never authority — and the authority a document _names_ is exactly the thing it must not be trusted to name. A document fetched from host A whose `servers` entry says host B, sent to host B, is a document redirecting the wire: whoever can serve A a document aims this client anywhere, and the request that leaves carries whatever artifact the profile for B says to attach.

So the **fetch origin decides the authority**, and `servers` contributes a **path prefix only**. A `servers` url of `https://api.example.com/v1` fetched from `api.example.com` contributes `/v1`; the same entry fetched from anywhere else contributes `/v1` and nothing more, and the request goes to the origin that served the document. An ignored entry is disclosed on stderr with both ways to mean otherwise:

```
note: this document's servers entry names https://evil.example.org, which is not the origin
it came from (https://api.example.com) — the request goes to https://api.example.com/v1.
```

Same host and a different scheme is off-origin too, which can only upgrade an `http` entry to the `https` the document arrived over. A default port and the case of a host name are not differences. A relative `servers` url — the `"url": "/v1"` spelling — names no authority at all, so it resolves against the origin with nothing to disclose.

What decides that is the **authority, not the scheme**: a `"url": "//other.example.com/v1"` entry carries a host without one, so it is read as the authority it is — scheme taken from the fetch origin, then the same off-origin treatment — rather than as a path prefix.

`--trust-servers` sends the request where the document says, and says so. `--server <url>` names a base outright, over the document and the origin alike, and discloses nothing: the operator named it.

A `--file` registration has no fetch origin, so its `servers` are the only thing left and they must agree. One origin across every entry is used and echoed; two origins, a relative url, or no `servers` at all is refused by name, with `--server <url>` as the answer to each. Picking one of two origins for the operator is the same trust this doctrine withholds.

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

An operation's `x-dfos-actions` is an OR of alternatives, each a single action token or an array of tokens that must all be covered — `[read:memberships, [read:profile, read:email]]` is "either `read:memberships`, or both of the other two". Under the delegated combination its absence is the presentation-suffices class: a valid credential for the host and no particular token. Action tokens are the host's vocabulary — they are copied from document to request to error message verbatim, never enumerated or interpreted here.

An empty array, an empty alternative, and an empty token are refused rather than read: each states no requirement any credential could satisfy, and reading one as "anything goes" widens a route in silence. The two shapes that turn up wrong are named for what they are — a **map** is the scheme-level action catalog written on an operation, and a **bare token** is the array spelling missing its brackets.

The shape split is strict at both positions, and it runs the other way too: a security scheme's `x-dfos-actions` is the host's action catalog and MUST be a map of action token to description, so a **list** there is the operation's shape at the scheme's position and a **bare token** is the map spelling missing its description. Either is refused with the same naming, and for the same reason a document's own spec gives: one canonical shape per position is what makes every consumer's parse of a document identical.

`--profile <anon|identity|delegated>` (and its shorthand `--anon`) forces a profile instead. The document ranks as a default, not a constraint. A scheme this client cannot read says which kind of unreadable it is: a `scheme: dfos` scheme marked with an `x-dfos-typ` outside the registered pair is this envelope family mis-marked, and reads differently from a scheme that is not this family at all.

### Credentials, and what a refusal means

The delegated profile presents a stored login credential and signs the request proof with the key that credential was issued to — this installation's login client key. The credential is selected by what it grants: some `att` entry naming `api:<host>` for the host being called. It is the **attenuation** that is matched, never `aud` — the audience is this installation's client DID on every stored credential, so it says nothing about which host a grant is for. `--as` picks between several; without it, exactly one candidate is required, because guessing which grant to spend is the one thing a credential client must never do. `dfos login --host <name-or-host>` obtains a credential for a specific host and lists that host's advertised actions to choose from; `dfos creds list` shows what is stored. When nothing covers the host, or when the presented grant does not carry what a route requires, the error names that spelling.

A non-2xx renders by tier, because the tiers mean different things:

- **401** — the proof layer refused. The host's `WWW-Authenticate` challenge is printed with it. Nothing is retried under a stronger profile: a client that escalated on its own would sign a second time over the same coordinates.
- **403** — the credential layer refused. The actions the operation requires and the actions the presented credential grants on `api:<host>` are both printed, verbatim.
- **503** — the host could not complete the check. That is the host's condition, not a verdict on the request.

A **2xx** echoes the claim that went out — `profile → delegated (read:profile OR read:email), as the document advertises`, or `forced with --profile` when the operator overrode it. A failure already names the profile in its own message, so success was the one case where what a request carried was invisible. It is the same disclosure as the signing-principal line and obeys the same `--quiet`.

Everything but the response document goes to stderr — the staleness line, the servers disclosure, the signer announcement, the profile echo, `-i` headers — so stdout carries one document.

| Flag               | Meaning                                                           |
| ------------------ | ----------------------------------------------------------------- |
| `--param name=val` | A path or query parameter, matched against the operation's own    |
| `--data`           | A request body, as a JSON string                                  |
| `--data-file`      | A request body from a file (`-` for stdin)                        |
| `--profile`        | Force `anon`, `identity`, or `delegated`                          |
| `--anon`           | Shorthand for `--profile anon`                                    |
| `--server <url>`   | Call this base URL, over the document's `servers` and the origin  |
| `--trust-servers`  | Let the document's `servers` entry name the authority, off-origin |
| `-i`, `--include`  | Print the response status and headers to stderr                   |

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
| `GET`  | `identity status <name\|did>`   | Compare the local chain against the identity's relay, with key possession |
| `GET`  | `identity keys [name\|did]`     | Show key state + keychain availability                       |
| `GET`  | `identity services [name\|did]` | Show resolved discovery services                             |
| `GET`  | `identity well-known [name]`    | Emit the app-description members (`--patch`)                 |
| `POST` | `identity create --name`        | Generate keys + sign genesis (`--service`)                   |
| `POST` | `identity update [name\|did]`   | Rotate keys / set services (`--service`)                     |
| `POST` | `identity device-pubkey`        | Generate a device keypair, print its pubkey                  |
| `POST` | `identity add-key`              | Add a public key this machine holds to a role set            |
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
| `POST` | `api add <name> [source]`       | Register an API, cache its document (`--file`, `--yes`)      |
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
- **Shell completion docs**: `dfos completion <bash|zsh|fish>` is cobra-generated and works today; per-shell installation is not documented here
- **Batch refresh** (`identity fetch --all`): re-fetch all tracked remote identities

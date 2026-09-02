# dfos-web-relay-go

Go relay for the [DFOS protocol](https://protocol.dfos.com). Single binary, SQLite persistence, built-in peering. Verifies everything on ingestion, trusts nothing.

See [WEB-RELAY.md](../../specs/WEB-RELAY.md) for the full relay specification.

## Quick Start

```bash
# build the dfos CLI from the repo root
cd packages/dfos-cli
go build -o dfos ./cmd/dfos

# run the embedded relay (SQLite, generates a new identity on first boot)
RELAY_NAME="my-relay" ./dfos serve
```

This package is the Go relay library embedded by the `dfos serve` command.

## Docker

```bash
# build the image (from repo root)
docker build -f packages/dfos-web-relay-go/Dockerfile -t dfos-relay .

# run with persistent storage
docker run -d -p 8080:8080 -v relay-data:/data \
  -e RELAY_NAME="my-relay" \
  dfos-relay
```

The container generates Ed25519 keys on first boot and persists them in SQLite. The DID is stable across restarts as long as the `/data` volume is preserved.

## Configuration

All configuration is via environment variables:

| Variable         | Default            | Description                                                                                                                           |
| ---------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`           | `4444`             | HTTP listen port                                                                                                                      |
| `SQLITE_PATH`    | `~/.dfos/relay.db` | Path to SQLite database                                                                                                               |
| `RELAY_NAME`     | `DFOS Relay`       | Profile name (shown in well-known endpoint)                                                                                           |
| `PEERS`          | _(empty)_          | Peer relay URLs (see below)                                                                                                           |
| `RESYNC`         | `false`            | `true` resets peer cursors for a full re-sync on boot                                                                                 |
| `SYNC_INTERVAL`  | `30s`              | How often to poll peers for new operations                                                                                            |
| `CONTENT_FOLLOW` | `none`             | `eager` = pull & cache granted public document bytes (see below)                                                                      |
| `INDEX`          | _(enabled)_        | `false` disables `/index/v0` and advertises `index: false`                                                                            |
| `WRITE`          | _(enabled)_        | `false` makes this a LITE pull-only node: `POST /operations` and blob upload answer 501, and the well-known advertises `write: false` |
| `AUTHORITY`      | _(unset)_          | This relay's own `host[:port]` — the host identity proofs bind                                                                        |
| `INGESTION`      | `open`             | Admission for `POST /operations`: `open`, `proof-required`, `closed`                                                                  |
| `GOSSIP_PROOF`   | `false`            | `true` signs gossip-out pushes with this relay's identity proof                                                                       |

`AUTHORITY` is what every [API-AUTH](https://protocol.dfos.com/api-auth) identity proof
is checked against — configuration, never taken from a request header. Without it the
authenticated routes (blob upload, non-public blob download, the mailbox poll) answer 503. Behind TLS on 443 it is the bare hostname; locally it includes the port. `INGESTION`
sets who may submit operations, per
[Web Relay § Ingestion Admission](https://protocol.dfos.com/web-relay#ingestion-admission),
and is advertised in the well-known.

When embedding this library, signing is available through `RelayOptions.Signing`; it is not exposed by `dfos serve`.

### Peer Configuration

Simple (comma-separated URLs, all defaults):

```
PEERS=http://relay-b:8080,http://relay-c:8080
```

Advanced (JSON array with per-peer flags):

```
PEERS='[{"url":"http://relay-b:8080"},{"url":"http://relay-c:8080","gossip":false}]'
```

Per-peer flags (all default to `true`): `gossip`, `readThrough`, `sync` — the
three peering behaviors specified in
[Web Relay § Peering](https://protocol.dfos.com/web-relay#peering). Operator
guidance for peered deployments is at
[protocol.dfos.com/deploy](https://protocol.dfos.com/deploy).

The object form also carries `did`, the peer's identity pin — the DID that peer
must keep serving:

```
PEERS='[{"url":"http://relay-b:8080","did":"did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"}]'
```

Peer state is otherwise keyed by URL, and a URL is an address rather than an
identity. A pinned peer is checked against its `/.well-known/dfos-relay` before
each touch and re-checked on a short cadence; one that starts answering as a
different relay is skipped in every direction — no log pulled, no operation
pushed, no read-through miss answered, no blob fetched — and the refusal is
reported at `stats.peerSync` in the well-known. A peer named by URL alone carries
no pin and is not checked, and a peer that cannot be reached is not a mismatch.

A value starting with `[` must parse as JSON, every peer must be an absolute
`http(s)` URL, and unknown per-peer fields are rejected: a bad peer config fails
at boot rather than degrading into peers that error on every sync tick.

### Content following

`CONTENT_FOLLOW` controls whether this relay also pulls the document blobs it
holds a standing public-read grant for, per
[Web Relay § Content Following](https://protocol.dfos.com/web-relay#content-following):

- `none` (default) — proof plane only; byte-identical to a non-following node.
- `eager` — convergent sweep pulls granted public blobs on each sync interval.

`eager` is the only mode that follows: `lazy` read-through-on-404 is not
implemented, and any other value — including a typo — leaves the relay
non-following rather than erroring.

## Topology Testing

The included `topology.sh` generates Docker Compose configurations for multi-node relay networks:

```bash
./topology.sh ring 3    # 3 nodes in a ring
./topology.sh mesh 4    # 4 fully connected nodes
./topology.sh star 5    # 1 hub + 4 spokes
./topology.sh smoke     # run smoke test against running topology
./topology.sh down      # tear down
```

Or use the static `docker-compose.yml` for a quick 3-node ring:

```bash
docker compose up -d
```

## Using with the CLI

The [`dfos` CLI](../dfos-cli) can manage identities and content against a running relay:

```bash
# add the relay
dfos relay add local http://localhost:8080

# create and publish an identity
dfos identity create --name my-id --peer local

# create and publish content
echo '{"type":"post","title":"hello"}' | dfos content create - --as my-id --peer local
```

## Library Usage

The relay is also usable as a Go library:

```go
import relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"

store := relay.NewMemoryStore()  // or relay.NewSQLiteStore("relay.db")
r, _ := relay.NewRelay(relay.RelayOptions{
    Store:      store,
    PeerClient: relay.NewHttpPeerClient(),
    Peers:      []relay.PeerConfig{{URL: "http://peer:8080"}},
})

http.ListenAndServe(":8080", r.Handler())
```

## Key Persistence

When using SQLite, the relay stores its Ed25519 private key, key ID, and DID in a `relay_meta` table. On restart, the existing identity is loaded — no new DID is generated. Keys never leave the process.

To reset a relay's identity, delete the SQLite database (or the Docker volume) and restart.

## License

MIT

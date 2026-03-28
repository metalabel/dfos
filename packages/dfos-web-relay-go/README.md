# dfos-web-relay-go

Go implementation of the [DFOS web relay](https://protocol.dfos.com/web-relay). Single binary, SQLite persistence, built-in peering.

See [WEB-RELAY.md](../../specs/WEB-RELAY.md) for the full relay specification.

## Quick Start

```bash
# build
cd packages/dfos-web-relay-go
go build -o relay ./cmd/relay

# run (SQLite, generates new identity on first boot)
RELAY_NAME="my-relay" ./relay

# run (in-memory, no persistence)
STORE=memory ./relay
```

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

| Variable            | Default          | Description                                 |
| ------------------- | ---------------- | ------------------------------------------- |
| `PORT`              | `8080`           | HTTP listen port                            |
| `STORE`             | `sqlite`         | Storage backend: `sqlite` or `memory`       |
| `SQLITE_PATH`       | `/data/relay.db` | Path to SQLite database                     |
| `RELAY_NAME`        | `DFOS Relay`     | Profile name (shown in well-known endpoint) |
| `RELAY_DESCRIPTION` | _(empty)_        | Profile description                         |
| `PEERS`             | _(empty)_        | Peer relay URLs (see below)                 |
| `SYNC_INTERVAL`     | `30s`            | How often to poll peers for new operations  |

### Peer Configuration

Simple (comma-separated URLs, all defaults):

```
PEERS=http://relay-b:8080,http://relay-c:8080
```

Advanced (JSON array with per-peer flags):

```
PEERS='[{"url":"http://relay-b:8080"},{"url":"http://relay-c:8080","gossip":false}]'
```

Per-peer flags (all default to `true`):

- `gossip` — push new operations to this peer
- `readThrough` — fetch from this peer on local 404
- `sync` — poll this peer's `/log` for background sync

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
dfos identity create --name my-id --relay local

# create and publish content
echo '{"type":"post","title":"hello"}' | dfos content create - --ctx my-id@local --relay local
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

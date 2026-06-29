# Running a Relay

A DFOS relay is a single Go binary backed by SQLite. This guide covers the
reference deployment: a relay container behind Caddy for automatic TLS.

## Prerequisites

- Docker and Docker Compose
- A domain name with an A/AAAA record pointed at your server
- Ports 80 and 443 open (Caddy uses these for ACME challenges and HTTPS)

## Quick Start

```bash
git clone https://github.com/metalabel/dfos.git
cd dfos/deploy

# Set your domain
sed -i 's/relay.example.com/relay.yourdomain.com/' Caddyfile

docker compose up -d
```

Caddy obtains a TLS certificate automatically on first request. Verify the
relay is running:

```bash
curl https://relay.yourdomain.com/.well-known/dfos-relay
```

You should get back a JSON object with the relay's DID and profile.

## Configuration

All configuration is via environment variables on the `relay` service in
`docker-compose.yml`.

| Variable        | Default            | Description                                                    |
| --------------- | ------------------ | -------------------------------------------------------------- |
| `PORT`          | `4444`             | HTTP listen port inside the container                          |
| `RELAY_NAME`    | `DFOS Relay`       | Human-readable relay profile name                              |
| `PEERS`         | _(none)_           | Peer relay URLs to sync from (comma-separated or JSON array)   |
| `SYNC_INTERVAL` | `30s`              | How often to pull from peers and run the sequencer             |
| `SQLITE_PATH`   | `~/.dfos/relay.db` | Database file path (set to `/data/relay.db` in the container)  |
| `RESYNC`        | `false`            | Set to `true` to reset peer cursors on boot for a full re-pull |
| `CONTENT_FOLLOW`| `none`             | `eager` = also pull & cache the document bytes of public content you're granted to read (see below) |

## Peering

To connect your relay to the network, set the `PEERS` environment variable to
one or more relay URLs:

```yaml
environment:
  PEERS: 'https://relay-a.example.com,https://relay-b.example.com'
```

Or as a JSON array:

```yaml
environment:
  PEERS: '["https://relay-a.example.com", "https://relay-b.example.com"]'
```

The relay pulls new operations from each peer on every sync interval and gossips
its own sequenced operations back. Peering is additive -- adding a peer never
removes existing data.

## Content following

By default a relay syncs the **proof plane** -- identity chains, content chains,
credentials, and revocations all ride the operation log and gossip between peers.
The **content plane** (the actual document _bytes_ a content chain commits to) is
_not_ gossiped: it's content-addressed and pulled on demand, gated by a grant.

Set `CONTENT_FOLLOW=eager` to make this relay a **content follower**: on every
sync interval it sweeps the content chains it holds a standing public-read grant
for and pulls any document bytes it's missing from its peers, verifying each blob
against the `documentCID` the chain committed before storing it.

```yaml
environment:
  PEERS: 'https://relay-a.example.com'
  CONTENT_FOLLOW: 'eager'
```

The result is a relay that can serve public content **independently of its
origin** -- a real edge cache, not just a proof mirror. Following is safe to turn
on or off at any time: bytes are only ever pulled for chains you're already
authorized to read, every blob is content-address-verified, and a revoked grant
stops the chain from being served (cached bytes simply become unreachable). The
default (`none`) leaves the relay byte-identical to a proof-only node.

## Persistence

The `relay-data` Docker volume is mounted at `/data` inside the container. The
SQLite database lives at `/data/relay.db`. Back up this file to preserve your
relay's identity and all synced operations.

## Verification

Confirm the relay is healthy:

```bash
# Relay info (DID, profile, peer count)
curl https://relay.yourdomain.com/.well-known/dfos-relay

# Latest operations
curl https://relay.yourdomain.com/proof/v1/log
```

## Container Images

Multi-arch images (amd64 + arm64) are published to the GitHub Container
Registry:

```
ghcr.io/metalabel/dfos:latest
```

Pinned version tags (e.g. `ghcr.io/metalabel/dfos:X.Y.Z`) are also available.

Browse available tags at
https://github.com/metalabel/dfos/pkgs/container/dfos.

## Notes

The compose file includes log rotation, health checks, and restart policies.
On memory-constrained hosts (2 GiB or less), add a swap file to prevent
OOM kills under sustained load:

```bash
fallocate -l 512M /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
```

## Without Docker

Install the CLI directly and run the relay as a process:

```bash
curl -sSL https://protocol.dfos.com/install.sh | sh
dfos serve --port 8080 --name "My Relay" --peers "https://peer.example.com"
```

Put it behind any reverse proxy (nginx, Caddy, Cloudflare Tunnel) for TLS
termination.

### Lite (pull-only) node

To run the smallest, safest mesh citizen — a node that verifies, stores, and
serves the proof plane but accepts **no writes** — add `--no-write`:

```bash
dfos serve --port 8080 --peers "https://peer.example.com" --no-write
```

It rejects `POST /proof/v1/operations` (so neither client writes nor peer
gossip-in are accepted) and stays current by pulling from its peers. The
well-known response advertises `capabilities.write: false`.

## Without TLS

For local development or LAN use, run the container directly:

```bash
docker run -p 8080:8080 -v relay-data:/data ghcr.io/metalabel/dfos:latest
```

Or with the CLI:

```bash
dfos serve --port 8080
```

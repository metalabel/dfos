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
curl https://relay.yourdomain.com/log
```

## Container Images

Multi-arch images (amd64 + arm64) are published to the GitHub Container
Registry:

```
ghcr.io/metalabel/dfos:latest
```

Pinned version tags (e.g. `ghcr.io/metalabel/dfos:0.9.0`) are also available.

Browse available tags at
https://github.com/metalabel/dfos/pkgs/container/dfos.

## Without Docker

Install the CLI directly and run the relay as a process:

```bash
curl -sSL https://protocol.dfos.com/install.sh | sh
dfos serve --port 8080 --name "My Relay" --peers "https://peer.example.com"
```

Put it behind any reverse proxy (nginx, Caddy, Cloudflare Tunnel) for TLS
termination.

## Without TLS

For local development or LAN use, run the container directly:

```bash
docker run -p 8080:8080 -v relay-data:/data ghcr.io/metalabel/dfos:latest
```

Or with the CLI:

```bash
dfos serve --port 8080
```

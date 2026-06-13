#!/usr/bin/env bash
#
# WP-7 dual-relay parity harness.
#
# Boots BOTH relays from the SAME pinned identity fixture, replays a fixed-seed
# op set into each, and asserts byte-identical (canonicalized-JSON) proof-plane
# bodies. Also runs the two-relay convergence tests that live alongside it.
#
# Usage:
#   cd packages/relay-conformance && ./scripts/run-parity.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/../.." && pwd)"
RELAY_GO_DIR="$REPO_ROOT/packages/dfos-web-relay-go"

WORKDIR="$(mktemp -d)"
FIXTURE="$WORKDIR/parity-fixture.json"
GO_DB="$WORKDIR/go-relay.db"
GO_BIN="$WORKDIR/parity-serve-go"

TS_PID=""
GO_PID=""
cleanup() {
  [ -n "$TS_PID" ] && kill "$TS_PID" 2>/dev/null || true
  [ -n "$GO_PID" ] && kill "$GO_PID" 2>/dev/null || true
  [ -n "$TS_PID" ] && wait "$TS_PID" 2>/dev/null || true
  [ -n "$GO_PID" ] && wait "$GO_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- generate the deterministic fixture ---
echo "Generating parity fixture..."
cd "$CONFORMANCE_DIR"
go run ./parity/genfixture "$FIXTURE"

# --- build the Go parity-serve binary ---
# Pin the relay Version ldflag to the npm package version so /.well-known
# reports the SAME version string as the TS twin (which reads it from
# package.json). Version is orthogonal to protocol parity, but the gate compares
# the whole well-known body, so both must agree.
RELAY_VERSION="$(node -p "require('$REPO_ROOT/packages/dfos-web-relay/package.json').version")"
echo "Building Go parity-serve (version $RELAY_VERSION)..."
cd "$RELAY_GO_DIR"
go build -ldflags "-X github.com/metalabel/dfos/packages/dfos-web-relay-go.Version=$RELAY_VERSION" \
  -o "$GO_BIN" ./cmd/parity-serve

# --- pick two free ports ---
TS_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
GO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# --- boot the TS relay (pinned identity) ---
echo "Starting TS relay on port $TS_PORT..."
cd "$REPO_ROOT"
pnpm --filter @metalabel/dfos-web-relay exec tsx \
  "$CONFORMANCE_DIR/scripts/parity-serve.ts" "$TS_PORT" "$FIXTURE" &
TS_PID=$!

# --- boot the Go relay (pinned identity, sqlite) ---
echo "Starting Go relay on port $GO_PORT (sqlite: $GO_DB)..."
"$GO_BIN" "$GO_PORT" "$FIXTURE" "$GO_DB" &
GO_PID=$!

# --- wait for both to be ready ---
wait_ready() {
  local port="$1" pid="$2" name="$3"
  for _ in $(seq 1 60); do
    if curl -s "http://localhost:$port/.well-known/dfos-relay" > /dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "$name relay process died"
      return 1
    fi
    sleep 0.2
  done
  echo "$name relay failed to start on port $port"
  return 1
}
wait_ready "$TS_PORT" "$TS_PID" "TS"
wait_ready "$GO_PORT" "$GO_PID" "Go"

echo "Both relays ready (TS=:$TS_PORT, Go=:$GO_PORT)"
echo ""

# --- run the parity + two-relay convergence tests ---
cd "$CONFORMANCE_DIR"
TS_RELAY_URL="http://localhost:$TS_PORT" \
GO_RELAY_URL="http://localhost:$GO_PORT" \
PARITY_FIXTURE="$FIXTURE" \
  go test -v -count=1 -run 'TestDualRelayParity' ./...

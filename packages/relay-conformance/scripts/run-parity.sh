#!/usr/bin/env bash
#
# WP-7 dual-relay parity harness.
#
# Boots BOTH relays from the SAME pinned identity fixture, replays a fixed-seed
# op set into each, and asserts byte-identical (canonicalized-JSON) proof-plane
# bodies. (The two-relay convergence tests run in-package under the Go relay
# `-race` CI job, not here.)
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

# stop_tree signals the whole process TREE a relay leads, not just its leader.
#
# Each relay is started under job control (`set -m`) so it leads its OWN process
# group, whose id is the leader's pid — which is what the negative-pid form
# below addresses. This matters because the TS relay is three processes deep,
# `pnpm` wrapping `tsx` wrapping `node`, and the wrapper propagates no signal:
# killing the leader alone leaves node holding the port after the run is over.
# It also replaces the `wait` this cleanup used to do, which could hang forever
# on a wrapper that never forwards the signal it was sent.
stop_tree() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 25); do
    kill -0 -- -"$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -9 -- -"$pid" 2>/dev/null || true
}

cleanup() {
  stop_tree "$TS_PID"
  stop_tree "$GO_PID"
  TS_PID=""
  GO_PID=""
  rm -rf "$WORKDIR"
}
# EXIT alone is not enough. A run interrupted with Ctrl-C, or killed by whatever
# supervises it, is exactly when a relay gets orphaned — and bash does not run an
# EXIT trap for a signal it has no handler for. cleanup is idempotent, so running
# it on both paths is harmless.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# port_in_use answers whether something is already ANSWERING on a port. It
# connects rather than probing for bindability, so a socket lingering in
# TIME_WAIT — which no longer serves anything — does not read as occupied.
port_in_use() {
  python3 - "$1" <<'PY'
import socket, sys

s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
}

# A relay leaked by an earlier run is the one failure this harness cannot report
# honestly: it would answer as if it were a relay we just booted, and a parity
# gate comparing a FRESH twin against a STALE one is a false signal in either
# direction. So refuse the port instead of quietly sharing it.
assert_port_free() {
  local port="$1"
  if port_in_use "$port"; then
    echo "port $port is already serving — a relay leaked by an earlier run would answer" >&2
    echo "this harness with a stale build. Kill it and re-run:" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2 2>/dev/null || true
    exit 1
  fi
}

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
assert_port_free "$TS_PORT"
assert_port_free "$GO_PORT"

# --- boot the TS relay (pinned identity), leading its own process group ---
echo "Starting TS relay on port $TS_PORT..."
cd "$REPO_ROOT"
set -m
pnpm --filter @metalabel/dfos-web-relay exec tsx \
  "$CONFORMANCE_DIR/scripts/parity-serve.ts" "$TS_PORT" "$FIXTURE" &
TS_PID=$!
set +m
disown "$TS_PID" 2>/dev/null || true

# --- boot the Go relay (pinned identity, sqlite) ---
echo "Starting Go relay on port $GO_PORT (sqlite: $GO_DB)..."
set -m
"$GO_BIN" "$GO_PORT" "$FIXTURE" "$GO_DB" &
GO_PID=$!
set +m
disown "$GO_PID" 2>/dev/null || true

# --- wait for both to be ready ---
wait_ready() {
  local port="$1" pid="$2" name="$3"
  for _ in $(seq 1 60); do
    if curl -s --max-time 10 "http://localhost:$port/.well-known/dfos-relay" > /dev/null 2>&1; then
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
  go test -v -count=1 -timeout 300s -run 'TestDualRelayParity' ./...

#!/usr/bin/env bash
#
# Run the write-disabled (lite / pull-only) conformance variant against BOTH
# reference relays — the TS Hono relay and the Go relay — each booted in
# write:false mode with a user identity seeded OUT-OF-BAND (not via POST).
#
# Proves a read-only node passes conformance: POST /proof/v1/operations → 501,
# and every proof-plane read route serves chains whose resolved state
# independently recomputes from their log.
#
# Usage:
#   cd packages/relay-conformance && ./scripts/run-write-disabled.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/../.." && pwd)"
RELAY_GO_DIR="$REPO_ROOT/packages/dfos-web-relay-go"

TS_PID=""
GO_PID=""
# The TS relay runs under a `pnpm ... exec` wrapper that does NOT propagate
# SIGTERM to the node grandchild, so killing the wrapper PID and `wait`-ing on it
# hangs forever. Always reap the actual node process by its unique script path,
# and never `wait` on the wrapper.
stop_ts() {
  [ -n "$TS_PID" ] && kill "$TS_PID" 2>/dev/null || true
  pkill -f 'serve-write-disabled\.ts' 2>/dev/null || true
  TS_PID=""
}
stop_go() {
  [ -n "$GO_PID" ] && kill "$GO_PID" 2>/dev/null || true
  GO_PID=""
}
cleanup() {
  stop_ts
  stop_go
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

wait_ready() {
  local port="$1" pid="$2"
  # up to ~30s — tsx cold start can be slow on first invocation
  for _ in $(seq 1 150); do
    if curl -s "http://localhost:$port/.well-known/dfos-relay" > /dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "relay process died (port $port)" >&2
      return 1
    fi
    sleep 0.2
  done
  echo "relay failed to start on port $port" >&2
  return 1
}

run_variant() {
  local label="$1" port="$2" logfile="$3"
  local did
  did="$(grep -m1 '^SEEDED_DID=' "$logfile" | cut -d= -f2- || true)"
  echo ""
  echo "=== $label write-disabled relay on :$port (seeded did=${did:-none}) ==="
  cd "$CONFORMANCE_DIR"
  RELAY_URL="http://localhost:$port" WRITE_DISABLED_SEED_DID="$did" \
    go test -v -count=1 -timeout 90s -run 'TestWriteDisabled' ./...
}

# ---------------------------------------------------------------------------
# TS reference relay
# ---------------------------------------------------------------------------
TS_PORT="$(free_port)"
TS_LOG="$(mktemp)"
echo "Starting TS write-disabled relay on :$TS_PORT..."
pnpm --filter @metalabel/dfos-web-relay exec tsx \
  "$SCRIPT_DIR/serve-write-disabled.ts" "$TS_PORT" > "$TS_LOG" 2>&1 &
TS_PID=$!
wait_ready "$TS_PORT" "$TS_PID"
run_variant "TS" "$TS_PORT" "$TS_LOG"
stop_ts
rm -f "$TS_LOG"

# ---------------------------------------------------------------------------
# Go reference relay
# ---------------------------------------------------------------------------
echo ""
echo "Building Go write-disabled relay..."
GO_BIN_DIR="$(mktemp -d)"
GO_BIN="$GO_BIN_DIR/write-disabled-serve"
( cd "$RELAY_GO_DIR" && go build -o "$GO_BIN" ./cmd/write-disabled-serve )

GO_PORT="$(free_port)"
GO_LOG="$(mktemp)"
echo "Starting Go write-disabled relay on :$GO_PORT..."
"$GO_BIN" "$GO_PORT" > "$GO_LOG" 2>&1 &
GO_PID=$!
wait_ready "$GO_PORT" "$GO_PID"
run_variant "Go" "$GO_PORT" "$GO_LOG"
stop_go
rm -f "$GO_LOG"
rm -rf "$GO_BIN_DIR"

echo ""
echo "✓ write-disabled conformance passed against both TS and Go reference relays"

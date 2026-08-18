#!/usr/bin/env bash
# Run SIGNING 0.1 conformance against both reference relays.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/../.." && pwd)"
RELAY_GO_DIR="$REPO_ROOT/packages/dfos-web-relay-go"

TS_PID=""
GO_PID=""
stop_ts() {
  [ -n "$TS_PID" ] && kill "$TS_PID" 2>/dev/null || true
  pkill -f 'serve-signing\.ts' 2>/dev/null || true
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
  for _ in $(seq 1 150); do
    if curl -s "http://localhost:$port/.well-known/dfos-relay" >/dev/null 2>&1; then
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
  local label="$1" port="$2"
  echo ""
  echo "=== $label signing relay on :$port ==="
  (cd "$CONFORMANCE_DIR" && RELAY_URL="http://localhost:$port" \
    go test -v -count=1 -timeout 90s -run 'Test(Signing|Siwd)' ./...)
}

TS_PORT="$(free_port)"
TS_LOG="$(mktemp)"
pnpm --filter @metalabel/dfos-web-relay exec tsx "$SCRIPT_DIR/serve-signing.ts" "$TS_PORT" >"$TS_LOG" 2>&1 &
TS_PID=$!
wait_ready "$TS_PORT" "$TS_PID"
run_variant "TS" "$TS_PORT"
stop_ts
rm -f "$TS_LOG"

GO_BIN_DIR="$(mktemp -d)"
GO_BIN="$GO_BIN_DIR/signing-serve"
(cd "$RELAY_GO_DIR" && go build -o "$GO_BIN" ./cmd/signing-serve)
GO_PORT="$(free_port)"
GO_LOG="$(mktemp)"
"$GO_BIN" "$GO_PORT" >"$GO_LOG" 2>&1 &
GO_PID=$!
wait_ready "$GO_PORT" "$GO_PID"
run_variant "Go" "$GO_PORT"
stop_go
rm -f "$GO_LOG"
rm -rf "$GO_BIN_DIR"

echo ""
echo "✓ signing conformance passed against both TS and Go reference relays"

#!/usr/bin/env bash
# Run SIGNING 0.1 conformance against both reference relays.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/../.." && pwd)"
RELAY_GO_DIR="$REPO_ROOT/packages/dfos-web-relay-go"

TS_PID=""
GO_PID=""

# stop_tree signals the whole process TREE a relay leads, not just its leader.
#
# The TS relay runs under a `pnpm ... exec` wrapper that does NOT propagate
# SIGTERM to the node grandchild, so killing the wrapper pid leaves node holding
# the port. Each relay is started under job control (`set -m`) so it leads its
# OWN process group, whose id is the leader's pid — the negative-pid form below
# reaches every descendant at once. This replaces a `pkill -f serve-signing\.ts`,
# which reaped by script path and so reached MACHINE-WIDE: a concurrent run in
# another worktree, or another checkout of this repo, was fair game.
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
stop_ts() {
  stop_tree "$TS_PID"
  TS_PID=""
}
stop_go() {
  stop_tree "$GO_PID"
  GO_PID=""
}
cleanup() {
  stop_ts
  stop_go
}
# EXIT alone is not enough. A run interrupted with Ctrl-C, or killed by whatever
# supervises it, is exactly when a relay gets orphaned — and bash does not run an
# EXIT trap for a signal it has no handler for. cleanup is idempotent, so running
# it on both paths is harmless.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

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

# A relay leaked by an earlier run is the one failure this variant cannot report
# honestly: it would answer as if it were the relay we just booted, and serve an
# OLD build's verdicts to a NEW suite. A green from that is worse than a red —
# and this variant is especially exposed, since a leaked relay that does not
# advertise capabilities.signing makes every test self-skip and the run reports
# success having asserted nothing. So refuse the port instead of sharing it.
assert_port_free() {
  local port="$1"
  if port_in_use "$port"; then
    echo "port $port is already serving — a relay leaked by an earlier run would answer" >&2
    echo "this suite with a stale build. Kill it and re-run:" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2 2>/dev/null || true
    exit 1
  fi
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
assert_port_free "$TS_PORT"
TS_LOG="$(mktemp)"
set -m
pnpm --filter @metalabel/dfos-web-relay exec tsx "$SCRIPT_DIR/serve-signing.ts" "$TS_PORT" >"$TS_LOG" 2>&1 &
TS_PID=$!
set +m
disown "$TS_PID" 2>/dev/null || true
wait_ready "$TS_PORT" "$TS_PID"
run_variant "TS" "$TS_PORT"
stop_ts
rm -f "$TS_LOG"

GO_BIN_DIR="$(mktemp -d)"
GO_BIN="$GO_BIN_DIR/signing-serve"
(cd "$RELAY_GO_DIR" && go build -o "$GO_BIN" ./cmd/signing-serve)
GO_PORT="$(free_port)"
assert_port_free "$GO_PORT"
GO_LOG="$(mktemp)"
set -m
"$GO_BIN" "$GO_PORT" >"$GO_LOG" 2>&1 &
GO_PID=$!
set +m
disown "$GO_PID" 2>/dev/null || true
wait_ready "$GO_PORT" "$GO_PID"
run_variant "Go" "$GO_PORT"
stop_go
rm -f "$GO_LOG"
rm -rf "$GO_BIN_DIR"

echo ""
echo "✓ signing conformance passed against both TS and Go reference relays"

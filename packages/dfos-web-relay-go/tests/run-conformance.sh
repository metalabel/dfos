#!/usr/bin/env bash
#
# Run Go conformance tests against the dfos CLI relay.
#
# Usage:
#   cd packages/dfos-web-relay-go && ./tests/run-conformance.sh
#
# Environment:
#   STORE=sqlite  — use SQLite store (default: sqlite, since dfos serve is always SQLite)
#
# Builds the dfos CLI, starts `dfos serve` on a random port, runs conformance
# tests, then kills the relay.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELAY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$RELAY_DIR/../.." && pwd)"
CLI_DIR="$REPO_ROOT/packages/dfos-cli"

RELAY_PID=""
SQLITE_PATH=""
DFOS_CONFIG=""

# stop_tree signals the whole process TREE a relay leads, not just its leader.
#
# The relay is started under job control (`set -m`) so it leads its OWN process
# group, whose id is the leader's pid — which is what the negative-pid form
# below addresses. `dfos serve` spawns no children today, so the group is a
# single process; addressing the group anyway costs nothing and keeps this
# script's cleanup identical to the TS harness's, where the tree is real.
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

# Cleanup runs from a trap rather than from the bottom of the script. Under
# `set -e` a failing `go test` exits immediately, so trailing cleanup lines are
# never reached on exactly the runs that matter — which is how a failed run used
# to leave its relay alive, still holding its port and its temp database.
cleanup() {
  stop_tree "$RELAY_PID"
  RELAY_PID=""
  rm -f "$RELAY_DIR/dfos-test"
  if [ -n "$SQLITE_PATH" ]; then
    rm -f "$SQLITE_PATH" "${SQLITE_PATH}-wal" "${SQLITE_PATH}-shm"
    rmdir "$(dirname "$SQLITE_PATH")" 2>/dev/null || true
  fi
  if [ -n "$DFOS_CONFIG" ]; then
    rm -f "$DFOS_CONFIG"
    rmdir "$(dirname "$DFOS_CONFIG")" 2>/dev/null || true
  fi
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

# A relay leaked by an earlier run is the one failure this suite cannot report
# honestly: it would answer as if it were the relay we just built, and serve an
# OLD binary's verdicts to a NEW suite. A green from that is worse than a red.
# So refuse the port instead of quietly sharing it.
assert_port_free() {
  local port="$1"
  if port_in_use "$port"; then
    echo "port $port is already serving — a relay leaked by an earlier run would answer" >&2
    echo "this suite with a stale build. Kill it and re-run:" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2 2>/dev/null || true
    exit 1
  fi
}

# build the dfos CLI binary
echo "Building dfos CLI..."
cd "$CLI_DIR"
go build -o "$RELAY_DIR/dfos-test" ./cmd/dfos

# find an available port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
assert_port_free "$PORT"

# start dfos serve in the background with a temp db
SQLITE_PATH="$(mktemp -d)/relay.db"
echo "Starting dfos serve on port $PORT (SQLite: $SQLITE_PATH)..."

# use a temp config dir so we don't pollute the user's real config
DFOS_CONFIG="$(mktemp -d)/config.toml"
# --authority: authenticated routes 503 without one, and the suite signs its
# identity proofs against the authority of the URL it dials.
set -m
DFOS_CONFIG="$DFOS_CONFIG" SQLITE_PATH="$SQLITE_PATH" "$RELAY_DIR/dfos-test" serve --port "$PORT" --db "$SQLITE_PATH" --authority "localhost:$PORT" &
RELAY_PID=$!
set +m
disown "$RELAY_PID" 2>/dev/null || true

# wait for the relay to be ready
for i in $(seq 1 50); do
  if curl -s "http://localhost:$PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "Relay process died"
    exit 1
  fi
  sleep 0.2
done

# verify relay is up
if ! curl -s "http://localhost:$PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
  echo "Relay failed to start on port $PORT"
  exit 1
fi

echo "Relay ready at http://localhost:$PORT"
echo ""

# run Go conformance tests. Its exit status is the script's: `set -e` propagates
# a failure and the EXIT trap still reaps the relay on the way out.
cd "$REPO_ROOT/packages/relay-conformance"
RELAY_URL="http://localhost:$PORT" go test -v -count=1 ./...

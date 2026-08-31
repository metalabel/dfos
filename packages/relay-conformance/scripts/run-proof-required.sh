#!/usr/bin/env bash
#
# Run the PROOF-REQUIRED ingestion conformance variant against the TS reference
# relay.
#
# Proves the admission ladder's gated posture: an anonymous submission is
# refused 403 (request-level — no per-item results), and the same batch carrying
# an identity proof is admitted.
#
# serve-proof-required.ts opens two doors on one store: the gated relay on $PORT
# and an open one on $PORT+1. The open door is the seeding path — a proof-required
# relay cannot admit the identity genesis whose chain its own proof verification
# would need, so the submitter is created through the open door and then submits
# through the gated one.
#
# The Go twin has no proof-required serve binary (the cmd/ binaries live in
# packages/dfos-web-relay-go), so this variant covers the TS relay only. `dfos
# serve --ingestion proof-required` boots a gated Go relay by hand for manual
# checks; it has no second door, so an identity must already be in its store.
#
# Usage:
#   cd packages/relay-conformance && ./scripts/run-proof-required.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TS_PID=""

# stop_tree signals the whole process TREE the relay leads, not just its leader.
#
# The TS relay runs under a `pnpm ... exec` wrapper that does NOT propagate
# SIGTERM to the node grandchild, so killing the wrapper pid leaves node holding
# both doors (and `wait`-ing on the wrapper hangs forever). The relay is started
# under job control (`set -m`) so it leads its OWN process group, whose id is the
# leader's pid — the negative-pid form below reaches every descendant at once.
# This replaces a `pkill -f serve-proof-required\.ts`, which reaped by script
# path and so reached MACHINE-WIDE: a concurrent run in another worktree, or
# another checkout of this repo, was fair game.
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
  TS_PID=""
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

# A relay leaked by an earlier run is the one failure this variant cannot report
# honestly: it would answer as if it were the relay we just booted, and serve an
# OLD build's verdicts to a NEW suite. A green from that is worse than a red —
# and this variant is the most exposed in the family, because the seed door's
# port is DERIVED rather than probed (see below), so it is the one port here the
# kernel never promised was free. So refuse the port instead of sharing it.
assert_port_free() {
  local port="$1" label="$2"
  if port_in_use "$port"; then
    echo "$label port $port is already serving — a relay leaked by an earlier run would" >&2
    echo "answer this suite with a stale build. Kill it and re-run:" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2 2>/dev/null || true
    exit 1
  fi
}

# A free port, and the next one for the seed door. Only the first is handed out
# by the kernel; the seed door is +1 and could be anyone's, so both are checked.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
SEED_PORT=$((PORT + 1))
assert_port_free "$PORT" "gated"
assert_port_free "$SEED_PORT" "seed-door"

echo "Starting proof-required TS relay on :$PORT (seed door on :$SEED_PORT)..."
set -m
pnpm --filter @metalabel/dfos-web-relay exec tsx \
  "$SCRIPT_DIR/serve-proof-required.ts" "$PORT" &
TS_PID=$!
set +m
disown "$TS_PID" 2>/dev/null || true

# up to ~30s — tsx cold start can be slow on first invocation
for _ in $(seq 1 150); do
  if curl -s "http://localhost:$SEED_PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$TS_PID" 2>/dev/null; then
    echo "relay process died" >&2
    exit 1
  fi
  sleep 0.2
done
if ! curl -s "http://localhost:$SEED_PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
  echo "relay failed to start on port $PORT" >&2
  exit 1
fi

echo ""
echo "=== proof-required ingestion conformance ==="
cd "$CONFORMANCE_DIR"
PROOF_REQUIRED_RELAY_URL="http://localhost:$PORT" \
  PROOF_REQUIRED_SEED_URL="http://localhost:$SEED_PORT" \
  go test -v -count=1 -timeout 90s -run 'TestIngestionProofRequired' ./...

echo ""
echo "✓ proof-required ingestion conformance passed against the TS reference relay"

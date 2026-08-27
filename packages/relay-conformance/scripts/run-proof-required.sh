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
# The TS relay runs under a `pnpm ... exec` wrapper that does NOT propagate
# SIGTERM to the node grandchild, so reap the actual node process by its unique
# script path and never `wait` on the wrapper.
cleanup() {
  [ -n "$TS_PID" ] && kill "$TS_PID" 2>/dev/null || true
  pkill -f 'serve-proof-required\.ts' 2>/dev/null || true
}
trap cleanup EXIT

# A free port, and the next one for the seed door.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
SEED_PORT=$((PORT + 1))

echo "Starting proof-required TS relay on :$PORT (seed door on :$SEED_PORT)..."
pnpm --filter @metalabel/dfos-web-relay exec tsx \
  "$SCRIPT_DIR/serve-proof-required.ts" "$PORT" &
TS_PID=$!

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

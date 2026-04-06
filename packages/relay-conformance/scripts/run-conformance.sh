#!/usr/bin/env bash
#
# Run Go conformance tests against the local TS Hono relay.
#
# Usage:
#   cd packages/relay-conformance && ./scripts/run-conformance.sh
#
# Starts a TS relay on a random port, runs `go test`, then kills the relay.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# find an available port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# start the relay in the background
echo "Starting TS relay on port $PORT..."
pnpm --filter @metalabel/dfos-web-relay exec tsx "$SCRIPT_DIR/serve-conformance.ts" "$PORT" &
RELAY_PID=$!

# wait for the relay to be ready
for i in $(seq 1 50); do
  if curl -s "http://localhost:$PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 $RELAY_PID 2>/dev/null; then
    echo "Relay process died"
    exit 1
  fi
  sleep 0.2
done

# verify relay is up
if ! curl -s "http://localhost:$PORT/.well-known/dfos-relay" > /dev/null 2>&1; then
  echo "Relay failed to start on port $PORT"
  kill $RELAY_PID 2>/dev/null || true
  exit 1
fi

echo "Relay ready at http://localhost:$PORT"
echo ""

# run Go conformance tests
cd "$CONFORMANCE_DIR"
RELAY_URL="http://localhost:$PORT" go test -v -count=1 ./...
EXIT_CODE=$?

# cleanup
kill $RELAY_PID 2>/dev/null || true
wait $RELAY_PID 2>/dev/null || true

exit $EXIT_CODE

#!/usr/bin/env bash
#
# Run Go conformance tests against the Go relay.
#
# Usage:
#   cd packages/dfos-web-relay-go && ./tests/run-conformance.sh
#
# Builds and starts the Go relay on a random port, runs conformance tests, then
# kills the relay.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELAY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$RELAY_DIR/../.." && pwd)"

# build the relay binary
echo "Building Go relay..."
cd "$RELAY_DIR"
go build -o "$RELAY_DIR/relay-server" ./cmd/relay

# find an available port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# start the relay in the background
echo "Starting Go relay on port $PORT..."
PORT="$PORT" "$RELAY_DIR/relay-server" &
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
cd "$REPO_ROOT/packages/dfos-web-relay/conformance"
RELAY_URL="http://localhost:$PORT" go test -v -count=1 ./...
EXIT_CODE=$?

# cleanup
kill $RELAY_PID 2>/dev/null || true
wait $RELAY_PID 2>/dev/null || true
rm -f "$RELAY_DIR/relay-server"

exit $EXIT_CODE

#!/usr/bin/env bash
#
# Sync the canonical content schemas into the CLI's embedded copies. There is ONE
# source of truth per schema:
#
#   packages/dfos-protocol/schemas/<name>.v1.json   <- canonical (edit this); also
#                                                      what schemas.dfos.com serves
#
# Copies kept byte-identical to the canonical files:
#
#   packages/dfos-cli/internal/schemas/<name>.v1.json -> embedded in the Go binary
#
# The CLI validates documents against its embedded copies, so drift means the CLI
# accepts or rejects documents the hosted schema does not — two different
# definitions of the same $id. A Go test (internal/schemas/embed_test.go) fails on
# drift; this script is the fix.
#
# Usage:
#   ./scripts/sync-schemas.sh            # copy canonical -> all targets
#   ./scripts/sync-schemas.sh --check    # verify copies are in sync (CI / pre-commit); non-zero on drift
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANONICAL_DIR="$ROOT/packages/dfos-protocol/schemas"
EMBED_DIR="$ROOT/packages/dfos-cli/internal/schemas"
SCHEMAS=(
  "post.v1.json"
  "profile.v1.json"
)

for name in "${SCHEMAS[@]}"; do
  if [[ ! -f "$CANONICAL_DIR/$name" ]]; then
    echo "error: canonical schema not found at $CANONICAL_DIR/$name" >&2
    exit 1
  fi
done

if [[ "${1:-}" == "--check" ]]; then
  drift=0
  for name in "${SCHEMAS[@]}"; do
    if ! diff -q "$CANONICAL_DIR/$name" "$EMBED_DIR/$name" >/dev/null 2>&1; then
      echo "drift: $EMBED_DIR/$name differs from canonical (run ./scripts/sync-schemas.sh)" >&2
      drift=1
    fi
  done
  if [[ $drift -eq 0 ]]; then
    echo "embedded schema copies in sync"
  fi
  exit $drift
fi

for name in "${SCHEMAS[@]}"; do
  cp "$CANONICAL_DIR/$name" "$EMBED_DIR/$name"
  echo "synced -> ${EMBED_DIR#"$ROOT"/}/$name"
done

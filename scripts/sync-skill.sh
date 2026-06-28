#!/usr/bin/env bash
#
# Sync the canonical DFOS skill into every in-tree copy that a distribution
# channel needs. There is ONE source of truth:
#
#   skills/dfos/SKILL.md          <- canonical (edit this); also the home that
#                                    `npx skills` and the website read from.
#
# Copies kept byte-identical to the canonical file:
#
#   packages/dfos-cli/internal/skill/SKILL.md   -> embedded in the Go binary (`dfos skill`)
#   plugins/dfos/skills/dfos/SKILL.md           -> Claude Code plugin marketplace
#
# Usage:
#   ./scripts/sync-skill.sh            # copy canonical -> all targets
#   ./scripts/sync-skill.sh --check    # verify copies are in sync (CI / pre-commit); non-zero on drift
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANONICAL="$ROOT/skills/dfos/SKILL.md"
TARGETS=(
  "$ROOT/packages/dfos-cli/internal/skill/SKILL.md"
  "$ROOT/plugins/dfos/skills/dfos/SKILL.md"
)

if [[ ! -f "$CANONICAL" ]]; then
  echo "error: canonical skill not found at $CANONICAL" >&2
  exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  drift=0
  for t in "${TARGETS[@]}"; do
    if ! diff -q "$CANONICAL" "$t" >/dev/null 2>&1; then
      echo "drift: $t differs from canonical (run ./scripts/sync-skill.sh)" >&2
      drift=1
    fi
  done
  if [[ $drift -eq 0 ]]; then
    echo "skill copies in sync"
  fi
  exit $drift
fi

for t in "${TARGETS[@]}"; do
  mkdir -p "$(dirname "$t")"
  cp "$CANONICAL" "$t"
  echo "synced -> ${t#"$ROOT"/}"
done

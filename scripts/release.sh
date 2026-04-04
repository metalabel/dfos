#!/bin/sh
# Release ritual — bumps all versions, commits, tags, and pushes.
#
# Usage:
#   ./scripts/release.sh 0.7.0
#   ./scripts/release.sh 0.7.0 --dry-run
#
# What it does:
#   1. Validates version format and branch (must be on main)
#   2. Bumps root package.json to the target version
#   3. Runs pnpm version:sync to propagate to workspace packages
#   4. Commits "release: v<version>"
#   5. Tags v<version>
#   6. Pushes commit + tag together
#
# The CI release workflow triggers on the v* tag push and handles:
#   - npm publish (reads version from package.json)
#   - GoReleaser (reads version from git tag via ldflags)
#   - Homebrew formula update
#   - Docker multi-arch build + push
#   - Protocol site deploy

set -e

# --- argument parsing ---

VERSION=""
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -*) echo "Unknown flag: $arg"; exit 1 ;;
    *) VERSION="$arg" ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "Usage: ./scripts/release.sh <version> [--dry-run]"
  echo ""
  echo "Examples:"
  echo "  ./scripts/release.sh 0.7.0"
  echo "  ./scripts/release.sh 0.8.0 --dry-run"
  exit 1
fi

# strip leading v if present
VERSION="${VERSION#v}"

# --- helpers ---

info() { echo "  $1"; }
error() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

# --- validation ---

# check version format (semver: X.Y.Z with optional pre-release)
echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' || \
  error "Invalid version format: $VERSION (expected X.Y.Z or X.Y.Z-pre)"

# must be on main
BRANCH="$(git branch --show-current)"
if [ "$BRANCH" != "main" ]; then
  error "Must be on main branch (currently on: $BRANCH)"
fi

# working tree must be clean
if [ -n "$(git status --porcelain)" ]; then
  error "Working tree is not clean — commit or stash changes first"
fi

# tag must not already exist
if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
  error "Tag v${VERSION} already exists"
fi

# must be up to date with remote
git fetch origin main --quiet
LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse origin/main)"
if [ "$LOCAL" != "$REMOTE" ]; then
  error "Local main is not up to date with origin/main — pull first"
fi

info "Releasing v${VERSION}"

# --- bump versions ---

CURRENT="$(node -p "require('./package.json').version")"
info "Bumping ${CURRENT} → ${VERSION}"

# update root package.json
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  pkg.version = '${VERSION}';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# propagate to workspace packages
pnpm version:sync

# --- show what we're about to do ---

echo ""
info "Changes:"
git diff --stat
echo ""

if [ "$DRY_RUN" = true ]; then
  info "[dry-run] Would commit, tag v${VERSION}, and push"
  info "[dry-run] Reverting changes..."
  git checkout -- .
  exit 0
fi

# --- commit, tag, push ---

git add -A
git commit -m "release: v${VERSION}"
git tag -a "v${VERSION}" -m "v${VERSION}"

info "Pushing commit + tag..."
git push origin main "v${VERSION}"

echo ""
info "v${VERSION} released! CI is now building:"
info "  → npm packages"
info "  → Go binaries (6 platforms)"
info "  → Docker container (ghcr.io/metalabel/dfos:${VERSION})"
info "  → Homebrew formula"
info "  → Protocol site deploy"
echo ""
info "Watch: https://github.com/metalabel/dfos/actions"
echo ""

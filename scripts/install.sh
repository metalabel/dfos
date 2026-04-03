#!/bin/sh
# DFOS CLI installer
# Usage: curl -sSL https://protocol.dfos.com/install.sh | sh
#
# Options:
#   --version <version>   Install a specific version (default: latest)
#   --dir <path>          Install directory (default: ~/.local/bin or /usr/local/bin)

set -e

REPO="metalabel/dfos"
BINARY="dfos"

# --- argument parsing ---

VERSION=""
INSTALL_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    *)         echo "Unknown option: $1"; exit 1 ;;
  esac
done

# strip leading "v" if present (e.g., --version v0.7.0)
VERSION="${VERSION#v}"

# --- helpers ---

info() { echo "  $1"; }
error() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# --- detect platform ---

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) error "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

info "Detected platform: ${OS}/${ARCH}"

# --- resolve version ---

if [ -z "$VERSION" ]; then
  info "Fetching latest version..."
  if check_cmd curl; then
    VERSION="$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')"
  elif check_cmd wget; then
    VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')"
  else
    error "curl or wget is required"
  fi
  if [ -z "$VERSION" ]; then
    error "Could not determine latest version. Check https://github.com/${REPO}/releases"
  fi
fi

info "Installing dfos v${VERSION}"

# --- resolve install directory ---

if [ -z "$INSTALL_DIR" ]; then
  if [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
  elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
fi

mkdir -p "$INSTALL_DIR"

# --- build download URLs ---

EXT="tar.gz"
if [ "$OS" = "windows" ]; then
  EXT="zip"
fi

ARCHIVE="dfos_${VERSION}_${OS}_${ARCH}.${EXT}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIVE}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"

# --- download ---

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Downloading ${ARCHIVE}..."

if check_cmd curl; then
  curl -fsSL -o "${WORK_DIR}/${ARCHIVE}" "$DOWNLOAD_URL"
  curl -fsSL -o "${WORK_DIR}/checksums.txt" "$CHECKSUMS_URL"
elif check_cmd wget; then
  wget -q -O "${WORK_DIR}/${ARCHIVE}" "$DOWNLOAD_URL"
  wget -q -O "${WORK_DIR}/checksums.txt" "$CHECKSUMS_URL"
else
  error "curl or wget is required"
fi

# --- verify checksum ---

info "Verifying checksum..."

EXPECTED="$(grep -F "${ARCHIVE}" "${WORK_DIR}/checksums.txt" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
  error "Checksum not found for ${ARCHIVE}"
fi

if check_cmd sha256sum; then
  ACTUAL="$(sha256sum "${WORK_DIR}/${ARCHIVE}" | awk '{print $1}')"
elif check_cmd shasum; then
  ACTUAL="$(shasum -a 256 "${WORK_DIR}/${ARCHIVE}" | awk '{print $1}')"
else
  error "No sha256sum or shasum found — cannot verify download integrity"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  error "Checksum mismatch! Expected: ${EXPECTED}, Actual: ${ACTUAL}"
fi

info "Checksum verified"

# --- extract ---

info "Installing to ${INSTALL_DIR}..."

if [ "$EXT" = "zip" ]; then
  unzip -o -q "${WORK_DIR}/${ARCHIVE}" -d "$WORK_DIR"
else
  tar -xzf "${WORK_DIR}/${ARCHIVE}" -C "$WORK_DIR"
fi

# resolve binary name (Windows archives contain dfos.exe)
if [ "$OS" = "windows" ]; then
  BINARY="dfos.exe"
fi

# install binary
if [ -w "$INSTALL_DIR" ]; then
  mv "${WORK_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  chmod +x "${INSTALL_DIR}/${BINARY}"
else
  info "Requires sudo to install to ${INSTALL_DIR}"
  sudo mv "${WORK_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  sudo chmod +x "${INSTALL_DIR}/${BINARY}"
fi

# --- verify installation ---

if ! check_cmd "$BINARY"; then
  echo ""
  echo "  dfos installed to ${INSTALL_DIR}/${BINARY}"
  echo ""
  echo "  Add ${INSTALL_DIR} to your PATH:"
  echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
  echo ""
else
  echo ""
  echo "  dfos v${VERSION} installed successfully!"
  echo ""
fi

echo "  Get started:"
echo "    dfos identity create --name myname"
echo "    dfos content list"
echo ""
echo "  Docs: https://protocol.dfos.com/cli"
echo ""

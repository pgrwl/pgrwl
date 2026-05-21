#!/bin/sh
set -eu

#
# pgrwl install script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pgrwl/pgrwl/master/scripts/install.sh | sh
#   
#   curl -fsSL https://raw.githubusercontent.com/pgrwl/pgrwl/master/scripts/install.sh \
#    | PGRWL_VERSION=v1.0.34 PGRWL_INSTALL_DIR=/opt/pgrwl/bin sh
#
#   wget -qO- https://raw.githubusercontent.com/pgrwl/pgrwl/master/scripts/install.sh | sh
#
# Environment:
#   PGRWL_VERSION       Release tag to install (default: latest)
#   PGRWL_INSTALL_DIR   Install directory (default: /usr/local/bin, ignored on Windows)
#
# Requires: curl or wget, tar
#

REPO="pgrwl/pgrwl"
BIN="pgrwl"

# detect download tool
if command -v curl >/dev/null 2>&1; then
    dl_stdout() { curl -fsSL -k "$1"; }
    dl_file()   { curl -fsSL -k "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    dl_stdout() { wget --no-check-certificate -qO- "$1"; }
    dl_file()   { wget --no-check-certificate -qO "$2" "$1"; }
else
    echo "error: need curl or wget" >&2
    exit 1
fi

# detect platform 
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux|darwin) ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) echo "error: unsupported OS: $OS" >&2; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="arm" ;;
    *) echo "error: unsupported ARCH: $ARCH" >&2; exit 1 ;;
esac

# resolve latest tag 
TAG="${PGRWL_VERSION:-}"
if [ -z "$TAG" ]; then
    TAG="$(dl_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -n1 \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
fi

case "$TAG" in
    v*|[0-9]*) ;;
    *) echo "error: invalid tag: '$TAG'" >&2; exit 1 ;;
esac

# setup workspace 
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# choose destination
SUDO=""
if [ "$OS" = "windows" ]; then
    DEST="."
    BIN_FILE="${BIN}.exe"
else
    DEST="${PGRWL_INSTALL_DIR:-/usr/local/bin}"
    BIN_FILE="$BIN"

    [ -d "$DEST" ] || { echo "error: destination does not exist: $DEST" >&2; exit 1; }

    if [ ! -w "$DEST" ]; then
        command -v sudo >/dev/null 2>&1 || {
            echo "error: $DEST is not writable and sudo is not installed" >&2
            exit 1
        }
        SUDO="sudo"
    fi
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${BIN}_${TAG}_${OS}_${ARCH}.tar.gz"
echo "downloading ${URL}"

# download and install
dl_file "$URL" "$TMP/pkg.tar.gz"
$SUDO tar -xzf "$TMP/pkg.tar.gz" -C "$DEST" "$BIN_FILE"
$SUDO chmod +x "$DEST/$BIN_FILE"
echo "installed $DEST/$BIN_FILE"

#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/bin/rscan"

if [[ ! -x "$BIN" ]]; then
  echo "[rscan] binary missing: $BIN" >&2
  exit 1
fi

if command -v ldd >/dev/null 2>&1; then
  if ldd "$BIN" 2>/dev/null | grep -q "not found"; then
    echo "[rscan] missing runtime libs detected."
    echo "[rscan] run: sudo ./install-deps-debian-ubuntu.sh"
    exit 1
  fi
fi

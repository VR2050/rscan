#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "[rscan] apt-get not found. this helper only supports Debian/Ubuntu." >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[rscan] please run as root: sudo ./install-deps-debian-ubuntu.sh" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  libstdc++6 \
  libgcc-s1

echo "[rscan] runtime dependencies installed."

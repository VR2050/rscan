#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_ROOT="${1:-$ROOT_DIR/dist}"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
RSCAN_BIN="${RSCAN_BIN:-$ROOT_DIR/target/$TARGET/release/rscan}"
GHIDRA_BACKEND_DIR="${GHIDRA_BACKEND_DIR:-$ROOT_DIR/third_party/ghidra_core_headless_x86_min}"

STAMP="$(date +%Y%m%d_%H%M%S)"
PKG_NAME="rscan-linux-offline-${STAMP}"
PKG_DIR="$OUT_ROOT/$PKG_NAME"
ARCHIVE_PATH="$OUT_ROOT/${PKG_NAME}.tar.gz"

log() {
  printf '[linux-pack] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

build_rscan_if_needed() {
  if [[ -x "$RSCAN_BIN" ]]; then
    log "reuse existing binary: $RSCAN_BIN"
    return 0
  fi

  log "building rscan for $TARGET ..."
  set +e
  cargo build --release --target "$TARGET" --bin rscan
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    cat >&2 <<'EOF'
Linux build failed.
If you already have a built binary, set:
  RSCAN_BIN=/path/to/rscan scripts/package_linux_offline.sh
EOF
    exit $rc
  fi
}

write_dep_installer() {
  cat >"$PKG_DIR/install-deps-debian-ubuntu.sh" <<'EOF'
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
EOF
  chmod +x "$PKG_DIR/install-deps-debian-ubuntu.sh"
}

write_readme() {
  cat >"$PKG_DIR/README_LINUX_OFFLINE.md" <<'EOF'
# rscan Linux Offline Pack (Debian / Ubuntu)

## Included
- bin/rscan
- install-deps-debian-ubuntu.sh
- third_party/ghidra_core_headless_x86_min

## Usage
1. 解压并进入目录
2. 首次在 Debian/Ubuntu 上执行：`sudo ./install-deps-debian-ubuntu.sh`
3. 运行：`./bin/rscan --help`

## Notes
- 该包为离线运行包，不要求目标机再做源码编译。
- 若目标机 glibc 太旧，请在更低版本系统重新构建 rscan 后，用 `RSCAN_BIN` 指定再打包。
EOF
}

write_version_meta() {
  {
    echo "build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target=$TARGET"
    echo "rscan_bin=$RSCAN_BIN"
    echo "ghidra_backend_dir=$GHIDRA_BACKEND_DIR"
  } >"$PKG_DIR/VERSION.txt"
}

main() {
  require_cmd cargo
  require_cmd tar

  mkdir -p "$OUT_ROOT"
  rm -rf "$PKG_DIR"
  mkdir -p "$PKG_DIR/bin"

  build_rscan_if_needed

  if [[ ! -d "$GHIDRA_BACKEND_DIR" ]]; then
    echo "ghidra backend dir not found: $GHIDRA_BACKEND_DIR" >&2
    exit 1
  fi

  cp -f "$RSCAN_BIN" "$PKG_DIR/bin/rscan"
  chmod +x "$PKG_DIR/bin/rscan"

  mkdir -p "$PKG_DIR/third_party"
  cp -a "$GHIDRA_BACKEND_DIR" "$PKG_DIR/third_party/"

  write_dep_installer
  write_readme
  write_version_meta

  rm -f "$ARCHIVE_PATH"
  tar -czf "$ARCHIVE_PATH" -C "$OUT_ROOT" "$PKG_NAME"

  log "package ready:"
  log "  dir: $PKG_DIR"
  log "  tar: $ARCHIVE_PATH"
}

main "$@"

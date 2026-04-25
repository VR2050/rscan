#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_ROOT="${1:-$ROOT_DIR/dist}"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
ZELLIJ_VERSION="${ZELLIJ_VERSION:-v0.44.1}"
ZELLIJ_ASSET="${ZELLIJ_ASSET:-zellij-x86_64-unknown-linux-musl.tar.gz}"
ZELLIJ_SHA_ASSET="${ZELLIJ_SHA_ASSET:-${ZELLIJ_ASSET%.tar.gz}.sha256sum}"
INCLUDE_GHIDRA="${INCLUDE_GHIDRA:-0}"
RSCAN_BIN="${RSCAN_BIN:-$ROOT_DIR/target/$TARGET/release/rscan}"
ZELLIJ_BIN="${ZELLIJ_BIN:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
PKG_NAME="rscan-linux-offline-${STAMP}"
PKG_DIR="$OUT_ROOT/$PKG_NAME"
ARCHIVE_PATH="$OUT_ROOT/${PKG_NAME}.tar.gz"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '[linux-pack] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

extract_tgz() {
  local tgz="$1"
  local out="$2"
  mkdir -p "$out"
  tar -xzf "$tgz" -C "$out"
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

download_zellij_if_needed() {
  if [[ -n "$ZELLIJ_BIN" ]]; then
    if [[ ! -x "$ZELLIJ_BIN" ]]; then
      echo "ZELLIJ_BIN not found or not executable: $ZELLIJ_BIN" >&2
      exit 1
    fi
    log "reuse local zellij: $ZELLIJ_BIN"
    return 0
  fi

  require_cmd curl
  local base_url="https://github.com/zellij-org/zellij/releases/download/${ZELLIJ_VERSION}"
  local tgz_file="$TMP_DIR/${ZELLIJ_ASSET}"
  local sha_file="$TMP_DIR/${ZELLIJ_SHA_ASSET}"

  log "download zellij asset: ${ZELLIJ_ASSET}"
  curl -fL "${base_url}/${ZELLIJ_ASSET}" -o "$tgz_file"
  curl -fL "${base_url}/${ZELLIJ_SHA_ASSET}" -o "$sha_file"

  local extract_dir="$TMP_DIR/zellij"
  extract_tgz "$tgz_file" "$extract_dir"
  local found
  found="$(find "$extract_dir" -type f -name zellij | head -n 1 || true)"
  if [[ -z "$found" ]]; then
    echo "zellij binary not found in archive: $tgz_file" >&2
    exit 1
  fi

  python3 - "$tgz_file" "$sha_file" "$found" <<'PY'
import hashlib, pathlib, re, sys
archive = pathlib.Path(sys.argv[1])
sha_file = pathlib.Path(sys.argv[2])
binary = pathlib.Path(sys.argv[3])
text = sha_file.read_text(encoding="utf-8", errors="ignore")
expect = None
if "sha256:" in text:
    expect = text.split("sha256:", 1)[1].split()[0].strip()
if not expect:
    m = re.search(r"\b([a-fA-F0-9]{64})\b", text)
    if m:
        expect = m.group(1)
if not expect:
    raise SystemExit(f"unable to parse sha256 from: {sha_file}")
archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
if archive_sha.lower() != expect.lower() and binary_sha.lower() != expect.lower():
    raise SystemExit(
        "zellij sha256 mismatch: "
        f"expected {expect}, archive={archive_sha}, binary={binary_sha}"
    )
PY

  chmod +x "$found"
  ZELLIJ_BIN="$found"
}

write_launchers() {
  cat >"$PKG_DIR/run-rscan-cli.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/check-runtime.sh"
"$DIR/bin/rscan" "$@"
SH
  chmod +x "$PKG_DIR/run-rscan-cli.sh"

  cat >"$PKG_DIR/run-rscan-tui-zellij.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/check-runtime.sh"
export PATH="$DIR/bin:$PATH"
export RSCAN_ZELLIJ=1
export RSCAN_ZELLIJ_SESSION="${RSCAN_ZELLIJ_SESSION:-rscan}"
"$DIR/bin/rscan" tui
SH
  chmod +x "$PKG_DIR/run-rscan-tui-zellij.sh"
}

write_runtime_helpers() {
  cat >"$PKG_DIR/install-deps-debian-ubuntu.sh" <<'SH'
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
SH
  chmod +x "$PKG_DIR/install-deps-debian-ubuntu.sh"

  cat >"$PKG_DIR/check-runtime.sh" <<'SH'
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
SH
  chmod +x "$PKG_DIR/check-runtime.sh"
}

write_readme() {
  cat >"$PKG_DIR/README_LINUX_OFFLINE.md" <<EOF
# rscan Linux Offline Pack (Debian / Ubuntu)

## Included
- bin/rscan
- bin/zellij (${ZELLIJ_VERSION}, ${ZELLIJ_ASSET})
- run-rscan-cli.sh
- run-rscan-tui-zellij.sh
- check-runtime.sh
- install-deps-debian-ubuntu.sh
$( [[ "$INCLUDE_GHIDRA" == "1" ]] && echo "- third_party/ghidra_core_headless_x86_min (optional bundled)" )

## Quick Start
1. 解压并进入目录
2. 如果提示缺依赖，执行：\`sudo ./install-deps-debian-ubuntu.sh\`
3. CLI: \`./run-rscan-cli.sh --help\`
4. TUI + zellij: \`./run-rscan-tui-zellij.sh\`

## Notes
- 该包设计为离线运行，不依赖运行期在线下载。
- 对于 SYN/ARP/ICMP 等原始包能力，建议 root 或配置 \`CAP_NET_RAW\`。
- 若提示 glibc 版本过低，请在更低版本 Debian/Ubuntu 环境构建 \`rscan\` 后用 \`RSCAN_BIN\` 重新打包。
EOF
}

write_version_meta() {
  {
    echo "build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target=$TARGET"
    echo "zellij_version=$ZELLIJ_VERSION"
    echo "zellij_asset=$ZELLIJ_ASSET"
    echo "zellij_sha_asset=$ZELLIJ_SHA_ASSET"
    echo "include_ghidra=$INCLUDE_GHIDRA"
  } >"$PKG_DIR/VERSION.txt"
}

main() {
  require_cmd cargo
  require_cmd tar
  require_cmd python3
  mkdir -p "$OUT_ROOT"
  rm -rf "$PKG_DIR"
  mkdir -p "$PKG_DIR/bin"

  build_rscan_if_needed
  download_zellij_if_needed

  cp -f "$RSCAN_BIN" "$PKG_DIR/bin/rscan"
  cp -f "$ZELLIJ_BIN" "$PKG_DIR/bin/zellij"
  chmod +x "$PKG_DIR/bin/rscan" "$PKG_DIR/bin/zellij"

  if [[ "$INCLUDE_GHIDRA" == "1" ]]; then
    mkdir -p "$PKG_DIR/third_party"
    cp -a "$ROOT_DIR/third_party/ghidra_core_headless_x86_min" "$PKG_DIR/third_party/"
  fi

  write_launchers
  write_runtime_helpers
  write_readme
  write_version_meta

  rm -f "$ARCHIVE_PATH"
  tar -czf "$ARCHIVE_PATH" -C "$OUT_ROOT" "$PKG_NAME"

  log "package ready:"
  log "  dir: $PKG_DIR"
  log "  tar: $ARCHIVE_PATH"
}

main "$@"

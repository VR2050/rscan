#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_ROOT="${1:-$ROOT_DIR/dist}"
TARGET="${TARGET:-x86_64-pc-windows-gnu}"
ZELLIJ_VERSION="${ZELLIJ_VERSION:-v0.44.1}"
ZELLIJ_ASSET="${ZELLIJ_ASSET:-zellij-x86_64-pc-windows-msvc.zip}"
INCLUDE_GHIDRA="${INCLUDE_GHIDRA:-0}"
RSCAN_EXE="${RSCAN_EXE:-$ROOT_DIR/target/$TARGET/release/rscan.exe}"
ZELLIJ_EXE="${ZELLIJ_EXE:-}"

STAMP="$(date +%Y%m%d_%H%M%S)"
PKG_NAME="rscan-windows-offline-${STAMP}"
PKG_DIR="$OUT_ROOT/$PKG_NAME"
ZIP_PATH="$OUT_ROOT/${PKG_NAME}.zip"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '[win-pack] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

extract_zip() {
  local zip_path="$1"
  local out_dir="$2"
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$zip_path" -d "$out_dir"
    return 0
  fi
  python3 - "$zip_path" "$out_dir" <<'PY'
import sys, zipfile, pathlib
z = pathlib.Path(sys.argv[1])
o = pathlib.Path(sys.argv[2])
o.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(z, "r") as f:
    f.extractall(o)
PY
}

create_zip() {
  local src_dir="$1"
  local zip_path="$2"
  if command -v zip >/dev/null 2>&1; then
    (cd "$(dirname "$src_dir")" && zip -qr "$zip_path" "$(basename "$src_dir")")
    return 0
  fi
  python3 - "$src_dir" "$zip_path" <<'PY'
import pathlib, sys, zipfile
src = pathlib.Path(sys.argv[1]).resolve()
dst = pathlib.Path(sys.argv[2]).resolve()
with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for p in src.rglob("*"):
        if p.is_file():
            zf.write(p, p.relative_to(src.parent))
PY
}

build_rscan_if_needed() {
  if [[ -f "$RSCAN_EXE" ]]; then
    log "reuse existing binary: $RSCAN_EXE"
    return 0
  fi
  log "building rscan for $TARGET ..."
  set +e
  cargo build --release --target "$TARGET" --bin rscan
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    cat >&2 <<'EOF'
Windows build failed. Likely missing cross toolchain.
- for x86_64-pc-windows-gnu: install mingw-w64 (x86_64-w64-mingw32-gcc/g++)
- for x86_64-pc-windows-msvc: build on Windows with Visual Studio Build Tools
Or set RSCAN_EXE to an already-built rscan.exe.
EOF
    exit $rc
  fi
}

download_zellij_if_needed() {
  if [[ -n "$ZELLIJ_EXE" ]]; then
    if [[ ! -f "$ZELLIJ_EXE" ]]; then
      echo "ZELLIJ_EXE not found: $ZELLIJ_EXE" >&2
      exit 1
    fi
    log "reuse local zellij.exe: $ZELLIJ_EXE"
    return 0
  fi

  require_cmd curl
  local base_url="https://github.com/zellij-org/zellij/releases/download/${ZELLIJ_VERSION}"
  local zip_file="$TMP_DIR/${ZELLIJ_ASSET}"
  local sha_file="$TMP_DIR/${ZELLIJ_ASSET%.zip}.sha256sum"
  log "download zellij asset: ${ZELLIJ_ASSET}"
  curl -fL "${base_url}/${ZELLIJ_ASSET}" -o "$zip_file"
  curl -fL "${base_url}/$(basename "$sha_file")" -o "$sha_file"

  python3 - "$zip_file" "$sha_file" <<'PY'
import hashlib, pathlib, sys
zip_path = pathlib.Path(sys.argv[1])
sha_path = pathlib.Path(sys.argv[2])
line = sha_path.read_text(encoding="utf-8").strip()
expect = line.split("sha256:")[-1].split()[0].strip()
h = hashlib.sha256(zip_path.read_bytes()).hexdigest()
if h.lower() != expect.lower():
    raise SystemExit(f"zellij sha256 mismatch: expected {expect}, got {h}")
PY

  local extract_dir="$TMP_DIR/zellij"
  extract_zip "$zip_file" "$extract_dir"
  local found
  found="$(find "$extract_dir" -type f -iname "zellij.exe" | head -n 1 || true)"
  if [[ -z "$found" ]]; then
    echo "zellij.exe not found in archive: $zip_file" >&2
    exit 1
  fi
  ZELLIJ_EXE="$found"
}

write_launchers() {
  cat >"$PKG_DIR/run-rscan-cli.bat" <<'BAT'
@echo off
setlocal
set "ROOT=%~dp0"
"%ROOT%rscan.exe" %*
endlocal
BAT

  cat >"$PKG_DIR/run-rscan-tui-zellij.bat" <<'BAT'
@echo off
setlocal
set "ROOT=%~dp0"
set "PATH=%ROOT%;%PATH%"
set "RSCAN_ZELLIJ=1"
set "RSCAN_ZELLIJ_SESSION=rscan"
"%ROOT%rscan.exe" tui
endlocal
BAT
}

write_readme() {
  cat >"$PKG_DIR/README_WINDOWS_OFFLINE.md" <<EOF
# rscan Windows Offline Pack

## Included
- rscan.exe
- zellij.exe (${ZELLIJ_VERSION})
- run-rscan-cli.bat
- run-rscan-tui-zellij.bat
$( [[ "$INCLUDE_GHIDRA" == "1" ]] && echo "- third_party/ghidra_core_headless_x86_min (optional bundled)" )

## Quick Start
1. 打开 PowerShell 或 Windows Terminal，进入当前目录。
2. CLI: \`./run-rscan-cli.bat --help\`
3. TUI + zellij: \`./run-rscan-tui-zellij.bat\`

## Notes
- 该包为离线运行包，运行时不依赖网络下载组件。
- 原始包扫描能力在 Windows 上仍受权限与驱动条件影响（管理员权限更稳）。
- reverse 功能如需完整 Ghidra 能力，可另外设置 \`RSCAN_GHIDRA_HOME\` 到完整 Ghidra 安装目录。
EOF
}

main() {
  require_cmd cargo
  require_cmd python3
  mkdir -p "$OUT_ROOT"
  rm -rf "$PKG_DIR"
  mkdir -p "$PKG_DIR"

  build_rscan_if_needed
  download_zellij_if_needed

  cp -f "$RSCAN_EXE" "$PKG_DIR/rscan.exe"
  cp -f "$ZELLIJ_EXE" "$PKG_DIR/zellij.exe"

  if [[ "$INCLUDE_GHIDRA" == "1" ]]; then
    mkdir -p "$PKG_DIR/third_party"
    cp -a "$ROOT_DIR/third_party/ghidra_core_headless_x86_min" "$PKG_DIR/third_party/"
  fi

  write_launchers
  write_readme
  {
    echo "build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target=$TARGET"
    echo "zellij_version=$ZELLIJ_VERSION"
    echo "zellij_asset=$ZELLIJ_ASSET"
    echo "include_ghidra=$INCLUDE_GHIDRA"
  } >"$PKG_DIR/VERSION.txt"

  rm -f "$ZIP_PATH"
  create_zip "$PKG_DIR" "$ZIP_PATH"
  log "package ready:"
  log "  dir: $PKG_DIR"
  log "  zip: $ZIP_PATH"
}

main "$@"

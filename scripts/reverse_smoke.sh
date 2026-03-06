#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/rscan"
WORKSPACE="${1:-${ROOT_DIR}/workspace/reverse_smoke_ws}"

mkdir -p "$WORKSPACE"

if [[ ! -x "$BIN" ]]; then
  echo "[smoke] building release binary"
  (cd "$ROOT_DIR" && cargo build -q --release --bin rscan)
fi

echo "[smoke] backend status"
"$BIN" reverse backend-status --output json >/dev/null

sample=""
for c in /bin/ls /usr/bin/ls; do
  if [[ -f "$c" ]]; then
    sample="$c"
    break
  fi
done

if [[ -z "$sample" ]]; then
  echo "[smoke] skip: no /bin/ls or /usr/bin/ls"
  exit 0
fi

echo "[smoke] analyze: $sample"
"$BIN" reverse analyze --input "$sample" --output json >/dev/null

echo "[smoke] decompile index: $sample"
"$BIN" reverse decompile-run \
  --input "$sample" \
  --engine auto \
  --mode index \
  --workspace "$WORKSPACE" \
  --output json >/dev/null

echo "[smoke] PASS"

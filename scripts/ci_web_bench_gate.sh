#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-http://192.168.9.104:8083}"
WORDLIST="${2:-/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt}"
THREADS="${3:-50}"
BASELINE_FILE="${4:-/tmp/rscan_web_bench_baseline_ms.txt}"
MAX_REGRESSION_PCT="${5:-15}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f "$WORDLIST" ]]; then
  echo "ERROR: wordlist not found: $WORDLIST" >&2
  exit 2
fi

if ! command -v ffuf >/dev/null 2>&1; then
  echo "ERROR: ffuf not found in PATH" >&2
  exit 2
fi
if ! command -v gobuster >/dev/null 2>&1; then
  echo "ERROR: gobuster not found in PATH" >&2
  exit 2
fi

echo "[gate] build rscan release binary"
cargo build -q --release --bin rscan

echo "[gate] warm-up rscan to reduce cold-start jitter"
WARM_WORDS="$(mktemp)"
printf "index.php\nadmin\n" > "$WARM_WORDS"
./target/release/rscan web fuzz \
  -u "${TARGET_URL}/FUZZ" \
  --keywords-file "$WARM_WORDS" \
  -c 10 \
  --per-host-concurrency 10 \
  --status-min 200 \
  --status-max 403 \
  --no-follow-redirect \
  >/dev/null 2>/dev/null || true
rm -f "$WARM_WORDS"

echo "[gate] run comparative benchmark"
BENCH_LOG="$(mktemp)"
./scripts/web_bench_compare.sh "$TARGET_URL" "$WORDLIST" "$THREADS" | tee "$BENCH_LOG"
OUT_DIR="$(grep '^OUT=' "$BENCH_LOG" | tail -n1 | cut -d= -f2-)"
if [[ -z "$OUT_DIR" || ! -d "$OUT_DIR" ]]; then
  echo "ERROR: benchmark output dir parse failed" >&2
  exit 3
fi

rscan_ms="$(cat "$OUT_DIR/rscan_default.ms")"
ffuf_ms="$(cat "$OUT_DIR/ffuf_baseline.ms")"
gobuster_ms="$(cat "$OUT_DIR/gobuster_baseline.ms")"
rscan_hits="$(grep -cE 'https?://' "$OUT_DIR/rscan_default.out" || true)"
ffuf_hits="$(grep -cE '.' "$OUT_DIR/ffuf_baseline.out" || true)"

echo "[gate] out_dir=$OUT_DIR"
echo "[gate] rscan_default_ms=$rscan_ms ffuf_ms=$ffuf_ms gobuster_ms=$gobuster_ms"
echo "[gate] rscan_hits=$rscan_hits ffuf_hits=$ffuf_hits"

fail=0

# Accuracy guard: rscan default should not lose findings against ffuf baseline.
if (( rscan_hits < ffuf_hits )); then
  echo "FAIL: rscan findings dropped (rscan=$rscan_hits < ffuf=$ffuf_hits)" >&2
  fail=1
fi

# Relative speed guard: rscan should not be slower than ffuf by >25%.
limit_ffuf=$(( ffuf_ms * 125 / 100 ))
if (( rscan_ms > limit_ffuf )); then
  echo "FAIL: rscan slower than ffuf threshold (rscan=${rscan_ms}ms > ${limit_ffuf}ms)" >&2
  fail=1
fi

# Historical regression guard from baseline file.
if [[ -f "$BASELINE_FILE" ]]; then
  baseline_ms="$(tr -dc '0-9' < "$BASELINE_FILE" | head -c 32)"
  if [[ -n "$baseline_ms" ]]; then
    allowed=$(( baseline_ms * (100 + MAX_REGRESSION_PCT) / 100 ))
    if (( rscan_ms > allowed )); then
      echo "FAIL: regression beyond ${MAX_REGRESSION_PCT}% baseline (rscan=${rscan_ms}ms > ${allowed}ms, baseline=${baseline_ms}ms)" >&2
      fail=1
    fi
  fi
fi

if (( fail != 0 )); then
  echo "[gate] FAILED"
  exit 1
fi

mkdir -p "$(dirname "$BASELINE_FILE")"
echo "$rscan_ms" > "$BASELINE_FILE"
echo "[gate] PASS baseline_updated=$BASELINE_FILE value=${rscan_ms}ms"

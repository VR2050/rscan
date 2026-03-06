#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-http://192.168.9.104:8083}"
WORDLIST="${2:-/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt}"
THREADS="${3:-50}"
OUT_DIR="${4:-/tmp/web_bench_compare_$(date +%Y%m%d_%H%M%S)_$$}"

if [[ ! -f "$WORDLIST" ]]; then
  echo "wordlist not found: $WORDLIST" >&2
  exit 2
fi

if ! command -v ffuf >/dev/null 2>&1; then
  echo "ffuf not found in PATH" >&2
  exit 2
fi

if ! command -v gobuster >/dev/null 2>&1; then
  echo "gobuster not found in PATH" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RSCAN_BIN="$ROOT_DIR/target/release/rscan"
if [[ ! -x "$RSCAN_BIN" ]]; then
  echo "rscan binary missing: $RSCAN_BIN (build with: cargo build --release --bin rscan)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
wc -l "$WORDLIST" | tee "$OUT_DIR/wordlist_lines.txt"

run_case() {
  local name="$1"
  shift
  local start end ms rc
  start="$(date +%s%3N)"
  set +e
  "$@" >"$OUT_DIR/${name}.out" 2>"$OUT_DIR/${name}.err"
  rc=$?
  set -e
  end="$(date +%s%3N)"
  ms=$((end - start))
  echo "$rc" >"$OUT_DIR/${name}.rc"
  echo "$ms" >"$OUT_DIR/${name}.ms"
  echo "$name rc=$rc ms=$ms"
}

run_case rscan_default \
  "$RSCAN_BIN" web fuzz \
  -u "${TARGET_URL}/FUZZ" \
  --keywords-file "$WORDLIST" \
  -c "$THREADS" \
  --per-host-concurrency "$THREADS" \
  --status-min 200 \
  --status-max 403 \
  --no-follow-redirect

run_case rscan_smart_fast \
  "$RSCAN_BIN" web fuzz \
  -u "${TARGET_URL}/FUZZ" \
  --keywords-file "$WORDLIST" \
  -c "$THREADS" \
  --per-host-concurrency "$THREADS" \
  --smart-fast

run_case rscan_smart_fast_strict \
  "$RSCAN_BIN" web fuzz \
  -u "${TARGET_URL}/FUZZ" \
  --keywords-file "$WORDLIST" \
  -c "$THREADS" \
  --per-host-concurrency "$THREADS" \
  --smart-fast-strict

run_case ffuf_baseline \
  ffuf -noninteractive -s \
  -u "${TARGET_URL}/FUZZ" \
  -w "$WORDLIST" \
  -t "$THREADS" \
  -mc 200-403

run_case gobuster_baseline \
  gobuster dir -q --no-progress \
  -u "$TARGET_URL" \
  -w "$WORDLIST" \
  -t "$THREADS" \
  -s 200-403 \
  -b ''

python3 - "$OUT_DIR" <<'PY'
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])
wordlist_lines = int((out / "wordlist_lines.txt").read_text().split()[0])

def lines(path):
    return path.read_text(errors="ignore").splitlines()

def parse_hits(name):
    data = lines(out / f"{name}.out")
    if name.startswith("rscan"):
        return [x for x in data if "http://" in x or "https://" in x]
    if name.startswith("ffuf"):
        return [x.strip() for x in data if x.strip()]
    if name.startswith("gobuster"):
        return [x for x in data if x.strip().startswith("/")]
    return []

def norm_paths(name, hits):
    out_set = set()
    url_re = re.compile(r"https?://[^/]+(/\S*)")
    for h in hits:
        if name.startswith("rscan"):
            m = url_re.search(h)
            if m:
                out_set.add(m.group(1))
        elif name.startswith("ffuf"):
            out_set.add("/" + h.lstrip("/"))
        else:
            out_set.add(h.split()[0])
    return out_set

cases = [
    "rscan_default",
    "rscan_smart_fast",
    "rscan_smart_fast_strict",
    "ffuf_baseline",
    "gobuster_baseline",
]
print(f"OUT={out}")
print(f"wordlist_lines={wordlist_lines}")
stats = {}
for name in cases:
    rc = (out / f"{name}.rc").read_text().strip()
    ms = int((out / f"{name}.ms").read_text().strip())
    qps = wordlist_lines / max(ms / 1000.0, 0.001)
    hits = parse_hits(name)
    paths = norm_paths(name, hits)
    stats[name] = paths
    print(f"{name} rc={rc} ms={ms} qps={qps:.1f} hits={len(paths)}")

ref = stats["ffuf_baseline"]
for name in [
    "rscan_default",
    "rscan_smart_fast",
    "rscan_smart_fast_strict",
    "gobuster_baseline",
]:
    miss = sorted(ref - stats[name])
    extra = sorted(stats[name] - ref)
    print(f"{name}_diff_vs_ffuf missing={miss} extra={extra}")
PY

echo "saved: $OUT_DIR"

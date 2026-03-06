#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/rscan"
SAMPLES_FILE="${1:-${ROOT_DIR}/workspace/projects/reverse_baseline/samples.yaml}"
OUT_DIR="${2:-${ROOT_DIR}/workspace/reports/reverse_baseline_$(date +%Y%m%d_%H%M%S)}"
WORKSPACE="${3:-${ROOT_DIR}/workspace/reverse_baseline_ws}"
ENGINE="${4:-auto}"
MODE="${5:-index}"

if [[ ! -f "$SAMPLES_FILE" ]]; then
  echo "samples file not found: $SAMPLES_FILE" >&2
  exit 2
fi

mkdir -p "$OUT_DIR" "$WORKSPACE"

if [[ ! -x "$BIN" ]]; then
  echo "[baseline] building release binary"
  (cd "$ROOT_DIR" && cargo build -q --release --bin rscan)
fi

extract_samples() {
  awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*-[[:space:]]*path:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*path:[[:space:]]*/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line != "") print line
    }
  ' "$SAMPLES_FILE"
}

SAMPLES=()
while IFS= read -r p; do
  SAMPLES+=("$p")
done < <(extract_samples)

if [[ "${#SAMPLES[@]}" -eq 0 ]]; then
  echo "no samples found in $SAMPLES_FILE" >&2
  exit 2
fi

REPORT_JSON="${OUT_DIR}/report.json"
RESULTS_JSONL="${OUT_DIR}/results.jsonl"
: > "$RESULTS_JSONL"

total=0
ok=0
failed=0

for sample in "${SAMPLES[@]}"; do
  total=$((total + 1))
  start_ms="$(date +%s%3N)"
  if [[ ! -f "$sample" ]]; then
    echo "{\"sample\":\"$sample\",\"ok\":false,\"reason\":\"missing\"}" >> "$RESULTS_JSONL"
    failed=$((failed + 1))
    continue
  fi

  set +e
  analyze_out="$("$BIN" reverse analyze --input "$sample" --output json 2>&1)"
  analyze_rc=$?
  run_out="$("$BIN" reverse decompile-run --input "$sample" --engine "$ENGINE" --mode "$MODE" --workspace "$WORKSPACE" --output json 2>&1)"
  run_rc=$?
  set -e
  end_ms="$(date +%s%3N)"
  elapsed_ms=$((end_ms - start_ms))

  if [[ "$analyze_rc" -eq 0 && "$run_rc" -eq 0 ]]; then
    ok=$((ok + 1))
    status=true
  else
    failed=$((failed + 1))
    status=false
  fi

  python3 - "$sample" "$status" "$elapsed_ms" "$analyze_rc" "$run_rc" "$analyze_out" "$run_out" >> "$RESULTS_JSONL" <<'PY'
import json
import sys

sample, status, elapsed, analyze_rc, run_rc, analyze_out, run_out = sys.argv[1:]
row = {
    "sample": sample,
    "ok": status.lower() == "true",
    "elapsed_ms": int(elapsed),
    "analyze_rc": int(analyze_rc),
    "decompile_rc": int(run_rc),
    "analyze_excerpt": analyze_out[:4000],
    "decompile_excerpt": run_out[:4000],
}
print(json.dumps(row, ensure_ascii=False))
PY
done

python3 - "$REPORT_JSON" "$RESULTS_JSONL" "$total" "$ok" "$failed" <<'PY'
import json
import statistics
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
rows_path = Path(sys.argv[2])
total = int(sys.argv[3])
ok = int(sys.argv[4])
failed = int(sys.argv[5])
rows = [json.loads(x) for x in rows_path.read_text().splitlines() if x.strip()]
times = [r["elapsed_ms"] for r in rows if "elapsed_ms" in r]
summary = {
    "total": total,
    "ok": ok,
    "failed": failed,
    "success_rate": round(ok / total, 4) if total else 0.0,
    "elapsed_ms_avg": round(statistics.mean(times), 2) if times else None,
    "elapsed_ms_p95": sorted(times)[int(max(0, len(times) * 0.95 - 1))] if times else None,
    "results_file": str(rows_path),
}
report_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
print(json.dumps(summary, ensure_ascii=False))
PY

echo "[baseline] report: $REPORT_JSON"

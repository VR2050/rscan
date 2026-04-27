#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${1:-192.168.8.145}"
OUT_DIR="${2:-$ROOT_DIR/reports/ch6_live_$(date +%Y%m%d_%H%M%S)}"
RSCAN_BIN="${RSCAN_BIN:-$ROOT_DIR/target/release/rscan}"
RUN_WEB_BENCH="${RUN_WEB_BENCH:-0}"
WEB_BENCH_WORDLIST="${WEB_BENCH_WORDLIST:-/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt}"
WEB_BENCH_THREADS="${WEB_BENCH_THREADS:-50}"
WEB_FUZZ_WORDLIST="${WEB_FUZZ_WORDLIST:-}"

COMMON_TCP_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389"
COMMON_UDP_PORTS="53,67,68,69,123,137,138,139,161,162,500,514,520,4500"
WEB_DIR_PATHS=("/" "/robots.txt" "/admin" "/login" "/phpinfo.php" "/index.php")

mkdir -p "$OUT_DIR"

log() {
  printf '[ch6-pack] %s\n' "$*"
}

ensure_rscan() {
  if [[ -x "$RSCAN_BIN" ]]; then
    return 0
  fi
  log "release binary not found, building target/release/rscan"
  cargo build --release --bin rscan >/tmp/ch6_pack_build.out 2>/tmp/ch6_pack_build.err
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log "build failed; see /tmp/ch6_pack_build.out and /tmp/ch6_pack_build.err"
    return $rc
  fi
  return 0
}

run_case() {
  local name="$1"
  shift
  local start_ms end_ms elapsed rc

  printf '%q ' "$@" >"$OUT_DIR/${name}.cmd"
  printf '\n' >>"$OUT_DIR/${name}.cmd"

  start_ms="$(date +%s%3N)"
  set +e
  "$@" >"$OUT_DIR/${name}.out" 2>"$OUT_DIR/${name}.err"
  rc=$?
  set -e
  end_ms="$(date +%s%3N)"
  elapsed=$((end_ms - start_ms))

  echo "$rc" >"$OUT_DIR/${name}.rc"
  echo "$elapsed" >"$OUT_DIR/${name}.ms"

  log "$name rc=$rc ms=$elapsed"
  return 0
}

run_web_dir_case() {
  local name="$1"
  local base_url="$2"
  local args=("$RSCAN_BIN" web dir -b "$base_url" -o raw)
  local p
  for p in "${WEB_DIR_PATHS[@]}"; do
    args+=( -p "$p" )
  done
  run_case "$name" "${args[@]}"
}

extract_perf_evidence() {
  {
    echo "# PERF Observability Evidence"
    echo
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo
    echo "## src/tui/perf.rs"
    rg -n "read_cpu_stat|read_meminfo|read_proc_rss_mb|read_loadavg|/proc/stat|/proc/meminfo|VmRSS" src/tui/perf.rs
    echo
    echo "## src/tui/render/perf.rs"
    rg -n "CPU|MEM|RSS|LOAD|title\(\"PERF\"\)" src/tui/render/perf.rs
  } >"$OUT_DIR/PERF_OBSERVABILITY.md"
}

build_summaries() {
  python3 - "$OUT_DIR" "$TARGET" <<'PY'
import json
import re
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
target = sys.argv[2]

CASES = [
    "host_quick_json",
    "host_tcp_common_json",
    "host_tcp_1_1024_json",
    "host_udp_common_json",
    "web_live_http_https",
    "web_dir_small_fixed",
    "web_crawl_small",
    "web_fuzz_wordlist",
    "reverse_smoke",
]


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="ignore")


def read_int(path: Path):
    txt = read_text(path).strip()
    if not txt:
        return None
    m = re.search(r"-?\d+", txt)
    return int(m.group(0)) if m else None


def first_json_obj(text: str):
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                return json.loads(s)
            except Exception:
                continue
    return None


rows = []
for name in CASES:
    out = read_text(out_dir / f"{name}.out")
    row = {
        "name": name,
        "rc": read_int(out_dir / f"{name}.rc"),
        "ms": read_int(out_dir / f"{name}.ms"),
        "cmd": read_text(out_dir / f"{name}.cmd").strip(),
    }
    jobj = first_json_obj(out)
    if isinstance(jobj, dict):
        if isinstance(jobj.get("open_ports"), list):
            row["open_ports"] = jobj.get("open_ports")
        if isinstance(jobj.get("filtered_ports"), list):
            row["filtered_ports"] = jobj.get("filtered_ports")
        if isinstance(jobj.get("open_ports_count"), int):
            row["open_ports_count"] = jobj.get("open_ports_count")
        if isinstance(jobj.get("protocol"), str):
            row["protocol"] = jobj.get("protocol")

    if name == "web_live_http_https":
        hits = [x for x in out.splitlines() if (" OK " in x or " ERR " in x)]
        row["hits_preview"] = hits[:10]
    if name == "web_dir_small_fixed":
        urls = [x for x in out.splitlines() if x.strip().startswith(("OK", "REDIR", "CLIENT"))]
        row["hits_preview"] = urls[:20]
        row["error_preview"] = [x.strip() for x in out.splitlines() if x.strip().startswith("ERROR")][:20]
        status_buckets = {}
        for ln in out.splitlines():
            m = re.search(r"\b(OK|REDIR|CLIENT|ERR)\s+(\d{3})\b", ln)
            u = re.search(r"https?://\S+", ln)
            if m and u:
                code = m.group(2)
                status_buckets.setdefault(code, []).append(u.group(0))
        row["status_buckets"] = status_buckets
    if name == "web_crawl_small":
        seeds = [x.strip() for x in out.splitlines() if x.strip().startswith("http")]
        row["reachable_urls"] = seeds
    if name == "web_fuzz_wordlist":
        urls = [x.strip() for x in out.splitlines() if "http://" in x or "https://" in x]
        row["hits_preview"] = urls[:20]
    rows.append(row)

summary = {
    "target": target,
    "out_dir": str(out_dir),
    "generated_at": __import__("datetime").datetime.now().isoformat(),
    "cases": rows,
}
(out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

# enriched keeps same layout, with small derivations for thesis tables.
quick_ports = []
common_ports = []
full_ports = []
udp_ports = []
quick_filtered = []
common_filtered = []
full_filtered = []
udp_filtered = []
web_dir_buckets = {}
web_dir_errors = []
for r in rows:
    if r["name"] == "host_quick_json":
        quick_ports = r.get("open_ports", [])
        quick_filtered = r.get("filtered_ports", [])
    elif r["name"] == "host_tcp_common_json":
        common_ports = r.get("open_ports", [])
        common_filtered = r.get("filtered_ports", [])
    elif r["name"] == "host_tcp_1_1024_json":
        full_ports = r.get("open_ports", [])
        full_filtered = r.get("filtered_ports", [])
    elif r["name"] == "host_udp_common_json":
        udp_ports = r.get("open_ports", [])
        udp_filtered = r.get("filtered_ports", [])
    elif r["name"] == "web_dir_small_fixed":
        web_dir_buckets = r.get("status_buckets", {})
        web_dir_errors = r.get("error_preview", [])

enriched = dict(summary)
enriched["thesis_snapshot"] = {
    "host_findings": {
        "quick_open_ports": quick_ports,
        "tcp_common_open_ports": common_ports,
        "tcp_1_1024_open_ports": full_ports,
        "udp_common_open_ports": udp_ports,
        "quick_filtered_ports": quick_filtered,
        "tcp_common_filtered_ports": common_filtered,
        "tcp_1_1024_filtered_ports": full_filtered,
        "udp_common_filtered_ports": udp_filtered,
    },
    "web_findings": {
        "web_dir_status_buckets": web_dir_buckets,
        "web_dir_error_preview": web_dir_errors,
    },
}
(out_dir / "summary_enriched.json").write_text(json.dumps(enriched, ensure_ascii=False, indent=2) + "\n")

# markdown report for screenshot use
lines = []
lines.append(f"# CH6 Live Report (Target: {target})")
lines.append("")
lines.append(f"- Generated at: {summary['generated_at']}")
lines.append(f"- Binary: `target/release/rscan`")
lines.append(f"- Raw artifacts dir: `{out_dir}`")
lines.append("")
lines.append("## Timing")
lines.append("")
for r in rows:
    if r.get("ms") is not None:
        lines.append(f"- {r['name']}: {r['ms']} ms (rc={r.get('rc')})")
lines.append("")
lines.append("## Host Findings")
lines.append("")
lines.append(f"- quick open ports: `{','.join(str(x) for x in quick_ports) if quick_ports else '<none>'}`")
if not quick_ports and quick_filtered:
    lines.append(f"- quick filtered ports (network path hint): `{','.join(str(x) for x in quick_filtered[:32])}`")
lines.append(f"- tcp common open ports: `{','.join(str(x) for x in common_ports) if common_ports else '<none>'}`")
if not common_ports and common_filtered:
    lines.append(f"- tcp common filtered ports: `{','.join(str(x) for x in common_filtered[:32])}`")
lines.append(f"- tcp 1-1024 open ports: `{','.join(str(x) for x in full_ports) if full_ports else '<none>'}`")
if not full_ports and full_filtered:
    lines.append(f"- tcp 1-1024 filtered ports(sample): `{','.join(str(x) for x in full_filtered[:32])}`")
lines.append(f"- udp common open ports: `{','.join(str(x) for x in udp_ports) if udp_ports else '<none in this run>'}`")
if not udp_ports and udp_filtered:
    lines.append(f"- udp common filtered ports: `{','.join(str(x) for x in udp_filtered[:32])}`")
lines.append("")
lines.append("## Web Findings")
lines.append("")
for r in rows:
    if r["name"] == "web_live_http_https":
        lines.append("- web live:")
        for ln in r.get("hits_preview", [])[:6]:
            lines.append(f"  - `{ln.strip()}`")
    if r["name"] == "web_dir_small_fixed":
        lines.append("- web dir:")
        buckets = r.get("status_buckets", {})
        if buckets:
            for code in sorted(buckets.keys()):
                urls = ", ".join(buckets[code])
                lines.append(f"  - `{code}`: {urls}")
        else:
            lines.append("  - `<no parsed status buckets>`")
            if r.get("error_preview"):
                for e in r.get("error_preview", [])[:4]:
                    lines.append(f"  - `error`: {e}")
    if r["name"] == "web_crawl_small":
        urls = r.get("reachable_urls", [])
        lines.append(f"- web crawl reachable urls: `{', '.join(urls) if urls else '<none>'}`")
    if r["name"] == "web_fuzz_wordlist":
        lines.append("- web fuzz (user wordlist):")
        h = r.get("hits_preview", [])
        if h:
            for ln in h[:6]:
                lines.append(f"  - `{ln}`")
        else:
            lines.append("  - `<no hits in this run>`")

lines.append("")
lines.append("## Reverse Chain")
rev = next((x for x in rows if x["name"] == "reverse_smoke"), None)
if rev:
    lines.append(f"- reverse_smoke rc={rev.get('rc')} ms={rev.get('ms')}")
    if rev.get("rc") == 0:
        lines.append("- reverse smoke chain executable in this environment")
    else:
        lines.append("- reverse smoke chain failed in this run; check reverse_smoke.err")

lines.append("")
lines.append("## Figure Capture Pointers")
lines.append("- Figure 6-9: screenshot `Timing + Host Findings + Web Findings` in this file.")
lines.append("- Figure 6-13: screenshot Host Findings block.")
lines.append("- Figure 6-14: screenshot Web Findings block.")
lines.append("- Figure 6-15: combine `reverse_smoke.out` and malware assessment doc page.")

(out_dir / "CH6_LIVE_REPORT.md").write_text("\n".join(lines) + "\n")

# quick table for section 6.2.5
table_lines = []
table_lines.append("# CH6 6.2.5 Table")
table_lines.append("")
table_lines.append("| 用例 | 命令摘要 | 耗时(ms) | 关键结果 |")
table_lines.append("|---|---|---:|---|")
for r in rows:
    name = r["name"]
    if name == "host_quick_json":
        key = f"开放端口: {','.join(str(x) for x in r.get('open_ports', [])) or '<none>'}"
    elif name == "host_tcp_common_json":
        key = f"开放端口: {','.join(str(x) for x in r.get('open_ports', [])) or '<none>'}"
    elif name == "host_tcp_1_1024_json":
        key = f"开放端口: {','.join(str(x) for x in r.get('open_ports', [])) or '<none>'}"
    elif name == "host_udp_common_json":
        key = f"开放端口: {','.join(str(x) for x in r.get('open_ports', [])) or '<none>'}"
    elif name == "web_live_http_https":
        hp = r.get("hits_preview", [])
        key = hp[0].strip() if hp else "<see .out>"
    elif name == "web_dir_small_fixed":
        b = r.get("status_buckets", {})
        key = "; ".join([f"{k}:{len(v)}" for k, v in sorted(b.items())]) or "<see .out>"
    elif name == "web_crawl_small":
        urls = r.get("reachable_urls", [])
        key = f"reachable: {', '.join(urls)}" if urls else "<none>"
    elif name == "web_fuzz_wordlist":
        hp = r.get("hits_preview", [])
        key = hp[0] if hp else "<no hits>"
    elif name == "reverse_smoke":
        key = "链路可执行" if r.get("rc") == 0 else "链路失败"
    else:
        key = "-"
    cmd = (r.get("cmd") or "").replace("|", "\\|")
    ms = r.get("ms")
    table_lines.append(f"| {name} | `{cmd}` | {ms if ms is not None else '-'} | {key} |")
(out_dir / "THESIS_6_2_5_TABLE.md").write_text("\n".join(table_lines) + "\n")
PY
}

build_figure_assets() {
  cat >"$OUT_DIR/CH6_FIGURE_ASSETS.md" <<EOF_MD
# Chapter 6 Figure Assets

Generated at: $(date '+%Y-%m-%d %H:%M:%S %z')
Target: $TARGET
Output dir: $OUT_DIR

## Figure 6-6 / 6-7 (PERF panel)

Manual capture command:

\`\`\`bash
cargo run --release -- tui
\`\`\`

Capture from PERF panel fields: \`MEM\`, \`RSS\`, \`CPU\`, \`LOAD\`.

Code evidence file: \`$OUT_DIR/PERF_OBSERVABILITY.md\`.

## Figure 6-8 (Large-scale architecture)

\`\`\`mermaid
flowchart LR
  A[Host Batch\nfull-port/high-concurrency] --> S[Unified Result Sink\nsummary.json + summary_enriched.json]
  B[Web Batch\nwordlist benchmarks] --> S
  C[Reverse Batch\nbaseline scripts] --> S
  S --> R[CH6_LIVE_REPORT.md]
\`\`\`

## Figure 6-10 (Feature matrix)

| Tool | Host | Web | Vuln | Reverse | TUI/Zellij | Unified Task View |
|---|---|---|---|---|---|---|
| rscan | Yes | Yes | Yes | Yes | Yes | Yes |
| nmap | Yes | Partial(script) | NSE | No | No | No |
| rustscan | Yes | No | No | No | No | No |
| ffuf | No | Yes | No | No | No | No |
| gobuster | No | Yes | No | No | No | No |

## Figure 6-11 (Performance synthesis)

Use these two sources in one screenshot/composite:

1. \`$OUT_DIR/summary_enriched.json\` (live host/web timing + findings)
2. \`scripts/web_bench_compare.sh\` output directory (if generated)

## Figure 6-12 (UX flow compare)

\`\`\`mermaid
flowchart LR
  subgraph T[Traditional Multi-Tool Chain]
    T1[Nmap/Rustscan] --> T2[ffuf/gobuster]
    T2 --> T3[manual merge + notes]
    T3 --> T4[reverse tools]
  end

  subgraph U[rscan Integrated Workflow]
    U1[Control]
    U2[Work]
    U3[Inspect]
    U4[Reverse]
    U1 --> U2 --> U3 --> U4
  end
\`\`\`

## Figure 6-15 (Reverse chain)

\`\`\`mermaid
flowchart LR
  A[scripts/reverse_smoke.sh] --> B[reverse backend-status]
  B --> C[reverse analyze]
  C --> D[reverse decompile-run --mode index]
  D --> E[workspace artifacts + logs]
\`\`\`
EOF_MD
}

run_optional_web_bench() {
  if [[ "$RUN_WEB_BENCH" != "1" ]]; then
    log "skip web benchmark compare (RUN_WEB_BENCH=0)"
    return 0
  fi

  if [[ ! -f "$WEB_BENCH_WORDLIST" ]]; then
    log "skip web benchmark compare: wordlist missing: $WEB_BENCH_WORDLIST"
    return 0
  fi

  if ! command -v ffuf >/dev/null 2>&1; then
    log "skip web benchmark compare: ffuf not found"
    return 0
  fi

  if ! command -v gobuster >/dev/null 2>&1; then
    log "skip web benchmark compare: gobuster not found"
    return 0
  fi

  run_case web_bench_compare \
    "$ROOT_DIR/scripts/web_bench_compare.sh" \
    "http://$TARGET" \
    "$WEB_BENCH_WORDLIST" \
    "$WEB_BENCH_THREADS" \
    "$OUT_DIR/web_bench_compare"
}

pick_web_fuzz_wordlist() {
  if [[ -n "$WEB_FUZZ_WORDLIST" && -f "$WEB_FUZZ_WORDLIST" ]]; then
    echo "$WEB_FUZZ_WORDLIST"
    return 0
  fi
  local candidates=(
    "/home/vr2050/fuzzDicts/directoryDicts/top7000.txt"
    "/home/vr2050/fuzzDicts/directoryDicts/fileName10000.txt"
    "/home/vr2050/fuzzDicts/directoryDicts/Filenames_or_Directories_All.txt"
  )
  local p
  for p in "${candidates[@]}"; do
    if [[ -f "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

main() {
  log "target=$TARGET"
  log "out_dir=$OUT_DIR"

  set -e
  ensure_rscan

  run_case host_quick_json \
    "$RSCAN_BIN" host quick -H "$TARGET" -o json

  run_case host_tcp_common_json \
    "$RSCAN_BIN" host tcp -H "$TARGET" -p "$COMMON_TCP_PORTS" --tcp-mode turbo-adaptive -o json

  run_case host_tcp_1_1024_json \
    "$RSCAN_BIN" host tcp -H "$TARGET" -p "1-1024" --tcp-mode turbo-adaptive -o json

  run_case host_udp_common_json \
    "$RSCAN_BIN" host udp -H "$TARGET" -p "$COMMON_UDP_PORTS" -o json

  run_case web_live_http_https \
    "$RSCAN_BIN" web live -u "http://$TARGET" -u "https://$TARGET" -o raw

  run_web_dir_case web_dir_small_fixed "http://$TARGET"

  run_case web_crawl_small \
    "$RSCAN_BIN" web crawl -s "http://$TARGET" -d 2 -c 4 -o raw

  local fuzz_wordlist=""
  if fuzz_wordlist="$(pick_web_fuzz_wordlist)"; then
    log "web fuzz wordlist=$fuzz_wordlist"
    run_case web_fuzz_wordlist \
      "$RSCAN_BIN" web fuzz \
      -u "http://$TARGET/FUZZ" \
      --keywords-file "$fuzz_wordlist" \
      -c 50 \
      --per-host-concurrency 50 \
      --smart-fast \
      -o raw
  else
    log "web fuzz skipped: no user wordlist found"
  fi

  run_case reverse_smoke \
    "$ROOT_DIR/scripts/reverse_smoke.sh" "$OUT_DIR/reverse_smoke_ws"

  run_optional_web_bench

  extract_perf_evidence
  build_summaries
  build_figure_assets

  log "done"
  log "report: $OUT_DIR/CH6_LIVE_REPORT.md"
  log "json:   $OUT_DIR/summary_enriched.json"
  log "fig:    $OUT_DIR/CH6_FIGURE_ASSETS.md"
}

main "$@"

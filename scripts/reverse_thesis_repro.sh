#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/rscan"
APK_DIR="${1:-${ROOT_DIR}/黑灰产app}"
OUT_DIR="${2:-${ROOT_DIR}/reports/reverse_thesis_repro_$(date +%Y%m%d_%H%M%S)}"
WORKSPACE="${3:-${OUT_DIR}/ws}"

mkdir -p "${OUT_DIR}" "${WORKSPACE}"

if [[ ! -d "${APK_DIR}" ]]; then
  echo "APK 目录不存在: ${APK_DIR}" >&2
  exit 2
fi

if [[ ! -x "${BIN}" ]]; then
  echo "[repro] release 二进制不存在，开始编译..."
  (cd "${ROOT_DIR}" && cargo build -q --release --bin rscan)
fi

COMMANDS_TXT="${OUT_DIR}/命令全流程.txt"
RUN_LOG="${OUT_DIR}/执行日志.log"
SUMMARY_MD="${OUT_DIR}/复现汇总.md"
SUMMARY_JSON="${OUT_DIR}/summary.json"

: > "${COMMANDS_TXT}"
: > "${RUN_LOG}"

echo "# 复现命令全流程" >> "${COMMANDS_TXT}"
echo "# 生成时间: $(date '+%F %T')" >> "${COMMANDS_TXT}"
echo >> "${COMMANDS_TXT}"

run_cmd() {
  local cmd="$1"
  local logfile="$2"
  echo "\$ ${cmd}" | tee -a "${COMMANDS_TXT}" "${RUN_LOG}" >/dev/null
  set +e
  bash -lc "${cmd}" >> "${logfile}" 2>&1
  local rc=$?
  set -e
  echo "  -> rc=${rc}" | tee -a "${COMMANDS_TXT}" "${RUN_LOG}" >/dev/null
  echo >> "${COMMANDS_TXT}"
  return "${rc}"
}

echo "[repro] backend-status"
run_cmd "\"${BIN}\" reverse backend-status --output json --out \"${OUT_DIR}/backend_status.json\"" "${RUN_LOG}" || true

mapfile -d '' APKS < <(find "${APK_DIR}" -maxdepth 3 -type f \( -iname "*.apk" -o -iname "*.apK" -o -iname "*.APK" \) -print0 | sort -z)

if [[ "${#APKS[@]}" -eq 0 ]]; then
  echo "未在目录发现 APK: ${APK_DIR}" >&2
  exit 3
fi

RESULTS_JSONL="${OUT_DIR}/results.jsonl"
: > "${RESULTS_JSONL}"

echo "[repro] 样本数: ${#APKS[@]}"

for apk in "${APKS[@]}"; do
  base="$(basename "${apk}")"
  stem="${base%.*}"
  sample_slug="$(echo "${stem}" | tr ' /' '__')"
  sample_dir="${OUT_DIR}/${sample_slug}"
  sample_log="${sample_dir}/run.log"
  mkdir -p "${sample_dir}"
  : > "${sample_log}"

  echo "[repro] 处理样本: ${apk}"
  start_ms="$(date +%s%3N)"

  rc_analyze=0
  rc_triage=0
  rc_android=0
  rc_decompile=0

  run_cmd "\"${BIN}\" reverse analyze --input \"${apk}\" --output json --out \"${sample_dir}/analyze.json\"" "${sample_log}" || rc_analyze=$?
  run_cmd "\"${BIN}\" reverse malware-triage --input \"${apk}\" --output json --out \"${sample_dir}/triage.json\"" "${sample_log}" || rc_triage=$?
  run_cmd "\"${BIN}\" reverse android-analyze --input \"${apk}\" --output json --out \"${sample_dir}/android_analyze.json\"" "${sample_log}" || rc_android=$?
  run_cmd "\"${BIN}\" reverse decompile-run --input \"${apk}\" --engine auto --mode full --workspace \"${WORKSPACE}\" --output json --out \"${sample_dir}/decompile.json\"" "${sample_log}" || rc_decompile=$?

  end_ms="$(date +%s%3N)"
  elapsed_ms=$((end_ms - start_ms))

  python3 - "${apk}" "${sample_dir}" "${elapsed_ms}" "${rc_analyze}" "${rc_triage}" "${rc_android}" "${rc_decompile}" >> "${RESULTS_JSONL}" <<'PY'
import json
import sys
from pathlib import Path

apk, sample_dir, elapsed_ms, rc_analyze, rc_triage, rc_android, rc_decompile = sys.argv[1:]
sample_dir = Path(sample_dir)

def load_json(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

analyze = load_json(sample_dir / "analyze.json")
triage = load_json(sample_dir / "triage.json")
android = load_json(sample_dir / "android_analyze.json")

profile = android.get("profile", {}) if isinstance(android.get("profile"), dict) else {}

dangerous = (
    profile.get("dangerous_permissions")
    or android.get("permissions", {}).get("dangerous")
    or []
)
exported = (
    profile.get("exported_components")
    or android.get("components", {}).get("exported")
    or []
)
score_total = (
    android.get("score", {}).get("total")
    or android.get("risk_score")
)
cleartext = (
    profile.get("uses_cleartext_traffic")
    if "uses_cleartext_traffic" in profile
    else android.get("network", {}).get("uses_cleartext_traffic")
)
pkg = (
    profile.get("package_name")
    or android.get("manifest", {}).get("package")
)
confidence = (
    triage.get("malware_confidence")
    if "malware_confidence" in triage
    else triage.get("confidence")
)

row = {
    "sample": apk,
    "sample_dir": str(sample_dir),
    "elapsed_ms": int(elapsed_ms),
    "rc": {
        "analyze": int(rc_analyze),
        "triage": int(rc_triage),
        "android_analyze": int(rc_android),
        "decompile_run": int(rc_decompile),
    },
    "package": pkg,
    "malware_confidence": confidence,
    "score_total": score_total,
    "uses_cleartext_traffic": cleartext,
    "dangerous_permissions_count": len(dangerous),
    "exported_components_count": len(exported),
    "ok": int(rc_analyze) == 0 and int(rc_triage) == 0 and int(rc_android) == 0,
}

print(json.dumps(row, ensure_ascii=False))
PY
done

python3 - "${RESULTS_JSONL}" "${SUMMARY_MD}" "${SUMMARY_JSON}" "${OUT_DIR}" "${APK_DIR}" "${WORKSPACE}" <<'PY'
import json
import statistics
import sys
from pathlib import Path

rows_path, md_path, summary_json_path, out_dir, apk_dir, workspace = sys.argv[1:]
rows = [json.loads(x) for x in Path(rows_path).read_text(encoding="utf-8").splitlines() if x.strip()]

elapsed = [r.get("elapsed_ms", 0) for r in rows if isinstance(r.get("elapsed_ms"), int)]
summary = {
    "total": len(rows),
    "ok": sum(1 for r in rows if r.get("ok")),
    "failed": sum(1 for r in rows if not r.get("ok")),
    "elapsed_ms_avg": round(statistics.mean(elapsed), 2) if elapsed else None,
    "elapsed_ms_p95": sorted(elapsed)[max(0, int(len(elapsed) * 0.95) - 1)] if elapsed else None,
    "apk_dir": apk_dir,
    "workspace": workspace,
    "out_dir": out_dir,
    "rows": rows,
}

Path(summary_json_path).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

lines = []
lines.append("# 逆向检测复现汇总")
lines.append("")
lines.append(f"- APK目录：`{apk_dir}`")
lines.append(f"- 输出目录：`{out_dir}`")
lines.append(f"- decompile工作区：`{workspace}`")
lines.append(f"- 样本总数：**{summary['total']}**，成功：**{summary['ok']}**，失败：**{summary['failed']}**")
if summary["elapsed_ms_avg"] is not None:
    lines.append(f"- 平均耗时：**{summary['elapsed_ms_avg']} ms**（含decompile）")
lines.append("")
lines.append("## 结果表")
lines.append("")
lines.append("| 样本 | 包名 | confidence | score.total | 明文传输 | 危险权限 | 导出组件 | 耗时(ms) |")
lines.append("|---|---|---:|---:|---|---:|---:|---:|")

for r in rows:
    sample_name = Path(r["sample"]).name
    lines.append(
        f"| {sample_name} | {r.get('package') or '-'} | {r.get('malware_confidence') if r.get('malware_confidence') is not None else '-'} | "
        f"{r.get('score_total') if r.get('score_total') is not None else '-'} | {r.get('uses_cleartext_traffic') if r.get('uses_cleartext_traffic') is not None else '-'} | "
        f"{r.get('dangerous_permissions_count', 0)} | {r.get('exported_components_count', 0)} | {r.get('elapsed_ms', 0)} |"
    )

lines.append("")
lines.append("## 命令与证据")
lines.append("")
lines.append(f"1. 全流程命令：`{Path(out_dir) / '命令全流程.txt'}`")
lines.append(f"2. 执行日志：`{Path(out_dir) / '执行日志.log'}`")
lines.append(f"3. 明细JSONL：`{Path(out_dir) / 'results.jsonl'}`")
lines.append(f"4. 汇总JSON：`{summary_json_path}`")
lines.append("")
lines.append("## 复现实验一句话")
lines.append("")
lines.append("使用本项目 `rscan reverse` 子命令链路，在同一脚本中完成 `analyze -> malware-triage -> android-analyze -> decompile-run`，并自动沉淀结构化结果。")

Path(md_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "[repro] 完成"
echo "[repro] 输出目录: ${OUT_DIR}"
echo "[repro] 汇总报告: ${SUMMARY_MD}"
echo "[repro] 命令清单: ${COMMANDS_TXT}"

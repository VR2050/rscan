#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-/home/vr2050/ghidra_core_headless}"
DEST="${2:-/home/vr2050/ghidra_core_headless_x86_min}"

if [ ! -d "$SRC" ]; then
  echo "source not found: $SRC" >&2
  exit 1
fi

rm -rf "$DEST"
rsync -a "$SRC/" "$DEST/"

KEEP_FEATURES=(Base Decompiler GnuDemangler MicrosoftDemangler MicrosoftDmang Recognizers BytePatterns)
for d in "$DEST/Ghidra/Features"/*; do
  b=$(basename "$d")
  keep=0
  for k in "${KEEP_FEATURES[@]}"; do
    if [ "$b" = "$k" ]; then
      keep=1
      break
    fi
  done
  if [ "$keep" -eq 0 ]; then
    rm -rf "$d"
  fi
done

for d in "$DEST/Ghidra/Processors"/*; do
  b=$(basename "$d")
  if [ "$b" != "x86" ]; then
    rm -rf "$d"
  fi
done

cat > "$DEST/HEADLESS_README.md" <<'DOC'
# Ghidra Core Headless (x86/x64 Min)

This is a minimized headless runtime for x86/x64 only.

## Contents
- Features: Base, Decompiler, GNU/Microsoft demanglers, Recognizers, BytePatterns
- Processors: x86 only

## Run

```bash
./run-headless.sh <project_dir> <project_name> -import <binary> \
  -scriptPath <script_dir> -postScript <script.java> <out.jsonl>
```

## Notes
- GUI components removed
- Not suitable for non-x86 architectures
DOC

chmod +x "$DEST/run-headless.sh"

size=$(du -sh "$DEST" | awk '{print $1}')
echo "min build complete: $DEST (size=$size)"

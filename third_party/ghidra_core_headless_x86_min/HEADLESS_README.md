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

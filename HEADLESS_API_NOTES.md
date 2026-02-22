# Headless API Notes (for Rust Integration)

This document defines a minimal, stable command contract to integrate Ghidra headless into a Rust CLI pipeline.

## 1) Runtime Entry

Use wrapper:

```bash
./run-headless.sh <project_dir> <project_name> [ghidra args...]
```

Equivalent binary:

```bash
./support/analyzeHeadless
```

## 2) Minimal Command Contract

Common required args:

```bash
<project_dir> <project_name> \
  -import <binary_path> \
  -scriptPath <script_dir> \
  -postScript <script_name.java> <output_file>
```

Recommended optional args:

```bash
-deleteProject
-log <log_file>
-scriptlog <script_log_file>
```

Example:

```bash
./run-headless.sh /tmp gh_job_001 \
  -import /path/to/target.bin \
  -scriptPath /path/to/scripts \
  -postScript ghidra_export_pseudocode.java pseudocode.jsonl \
  -log /tmp/gh_job_001.log \
  -scriptlog /tmp/gh_job_001.script.log \
  -deleteProject
```

## 3) Script Modes You Should Keep

For staged decompile pipeline, keep these scripts in your Rust workspace output dir.

- `ghidra_export_index.java`: function index only (ea/name/signature/size/calls summary)
- `ghidra_export_function.java`: single function pseudocode export
- `ghidra_export_pseudocode.java`: full pseudocode export for all functions

Suggested staged flow for large binaries:

1. run `index`
2. pick candidate functions
3. run `function` on selected targets
4. run `full` only if needed

## 4) Output Contract

Primary output should be JSONL (one JSON object per function):

```json
{"ea":"00101189","name":"main","pseudocode":"...","signature":"int main(void)","size":123,"calls":["00101050"],"call_names":["puts"],"ext_refs":["puts"],"error":null}
```

Required keys for Rust parser stability:

- `ea` (string)
- `name` (string)
- `pseudocode` (string|null)
- `error` (string|null)

Recommended optional keys:

- `signature` (string)
- `size` (number)
- `calls` (string array)
- `call_names` (string array)
- `ext_refs` (string array)

## 5) Exit/Failure Semantics

Treat process status and files together:

1. non-zero exit code: hard failure
2. zero exit + missing output file: hard failure
3. zero exit + partial JSONL: soft failure, parse valid lines and mark job degraded

Retry strategy:

- first retry once with larger timeout
- fallback to `index` mode when full decompile fails

## 6) Rust-side Adapter Checklist

- enforce absolute paths before execution
- generate unique `project_name` per job (avoid collisions)
- set per-job timeout and kill process tree on timeout
- capture stdout/stderr into job logs
- parse JSONL line-by-line (streaming, do not load entire file for large outputs)
- validate required keys and keep raw line for malformed rows

## 7) Suggested Stable Job Layout

```text
<workspace>/jobs/<job_id>/
  meta.json
  command.txt
  stdout.log
  stderr.log
  script.log
  pseudocode.jsonl | index.jsonl | function.jsonl
```

## 8) Performance Defaults (Good Starting Point)

- prefer staged mode (`index -> function`) for large binaries
- default timeout: 600s for full, 180s for index/function
- keep `-deleteProject` for ephemeral jobs
- for long-lived sessions, reuse project only if you need cross-run state

## 9) Security/Isolation Notes

- run headless in a restricted user context when processing untrusted binaries
- avoid executing extracted scripts from unknown sources
- keep script directory controlled by your CLI, not by user input directly


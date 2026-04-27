#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/docs/diagrams}"
BASENAME="${2:-rscan_layered_architecture}"

DOT_PATH="$OUT_DIR/$BASENAME.dot"
MMD_PATH="$OUT_DIR/$BASENAME.mmd"
SVG_PATH="$OUT_DIR/$BASENAME.svg"
PNG_PATH="$OUT_DIR/$BASENAME.png"

mkdir -p "$OUT_DIR"

cat >"$DOT_PATH" <<'DOT'
digraph rscan_layered_architecture {
  rankdir=TB;
  splines=ortho;
  nodesep=0.45;
  ranksep=0.55;
  bgcolor="white";
  labelloc="t";
  label="rscan_codex Layered Architecture (with TUI focus)";
  fontsize=20;
  fontname="Helvetica";

  node [
    shape=box
    style="rounded,filled"
    color="#2F5D8A"
    fillcolor="#F4F8FF"
    fontname="Helvetica"
    fontsize=12
    margin="0.18,0.08"
  ];

  edge [
    color="#4B5B6B"
    arrowsize=0.8
    penwidth=1.2
    fontname="Helvetica"
    fontsize=10
  ];

  user [label="Users / Terminal Input\nkeyboard, command mode, shortcuts", fillcolor="#FFF7E6", color="#C27A00"];

  tui [label="TUI Layer (src/tui)\n13. Dashboard / Task Mgmt / Results\n14. Native Zellij pane orchestration\n15. Event handling + state management", fillcolor="#E8F8EE", color="#2C8A57"];

  orchestrator [label="Orchestration & Adapters\ncommand_build / command_exec / task_actions\ntranslate UI intent to CLI/task actions"];

  modules [label="Module Layer (src/modules)\nport_scan | web_scan | vuln_check | reverse"];

  cores [label="Core Capabilities (src/cores + src/services)\nhost/web/engine + service_probe"];

  data [label="Data & Runtime Truth Source\ntasks/<id>/meta.json + events/logs\njobs/<id>/... + reverse_out/<id>/...\n.rscan/zellij/panes.json", fillcolor="#F2F2F2", color="#6A6A6A"];

  advantages [label="Layering Advantages\nclear responsibilities | low coupling\ntestability | extensibility", fillcolor="#EEF7FF", color="#3A6B99"];

  user -> tui [label="interaction"];
  tui -> orchestrator [label="dispatch"];
  orchestrator -> modules [label="invoke"];
  modules -> cores [label="use"];
  cores -> data [label="persist"];
  data -> tui [label="state refresh", style=dashed, color="#2C8A57"];
  tui -> advantages [style=dotted, arrowhead=none, color="#3A6B99"];
}
DOT

cat >"$MMD_PATH" <<'MMD'
flowchart TB
    U[Users / Terminal Input<br/>keyboard, command mode, shortcuts]
    TUI[TUI Layer (src/tui)<br/>13. Dashboard / Task Mgmt / Results<br/>14. Native Zellij pane orchestration<br/>15. Event handling + state management]
    OA[Orchestration & Adapters<br/>command_build / command_exec / task_actions<br/>translate UI intent to CLI/task actions]
    M[Module Layer (src/modules)<br/>port_scan | web_scan | vuln_check | reverse]
    C[Core Capabilities (src/cores + src/services)<br/>host/web/engine + service_probe]
    D[Data & Runtime Truth Source<br/>tasks meta/events/logs + jobs/reverse_out + zellij registry]
    A[Layering Advantages<br/>clear responsibilities | low coupling | testability | extensibility]

    U --> TUI
    TUI --> OA
    OA --> M
    M --> C
    C --> D
    D -. state refresh .-> TUI
    TUI -.-> A
MMD

if command -v dot >/dev/null 2>&1; then
  dot -Tsvg "$DOT_PATH" -o "$SVG_PATH"
  dot -Tpng "$DOT_PATH" -o "$PNG_PATH"
  echo "[ok] DOT: $DOT_PATH"
  echo "[ok] MMD: $MMD_PATH"
  echo "[ok] SVG: $SVG_PATH"
  echo "[ok] PNG: $PNG_PATH"
else
  echo "[ok] DOT: $DOT_PATH"
  echo "[ok] MMD: $MMD_PATH"
  echo "[warn] graphviz 'dot' not found; skipped SVG/PNG rendering"
  echo "       install graphviz and run again to render images"
fi

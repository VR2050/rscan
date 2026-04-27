#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$DIR/bin:$PATH"
export RSCAN_ZELLIJ=1
export RSCAN_ZELLIJ_SESSION="${RSCAN_ZELLIJ_SESSION:-rscan}"
"$DIR/bin/rscan" tui

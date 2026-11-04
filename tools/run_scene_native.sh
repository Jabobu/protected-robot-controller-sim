#!/usr/bin/env bash
# Run a new, standalone headless example using a user-provided Isaac installation.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scenario=${1:-normal}
if [[ $# -gt 0 ]]; then shift; fi
case "$scenario" in
  normal|missed_grasp|obstructed|incomplete|all) ;;
  *) echo 'Usage: ISAAC_PYTHON=/path/to/isaacsim/python.sh tools/run_scene_native.sh {normal|missed_grasp|obstructed|incomplete|all} [example options]' >&2; exit 2 ;;
esac
: "${ISAAC_PYTHON:?Set ISAAC_PYTHON to the Isaac Sim 6.0.0 python.sh launcher}"
[[ -f "$ISAAC_PYTHON" && -x "$ISAAC_PYTHON" ]] || { echo "Not an executable Isaac Python launcher: $ISAAC_PYTHON" >&2; exit 2; }
ISAAC_PYTHON=$(realpath -- "$ISAAC_PYTHON")
# A local process must never inherit a container identity from its parent shell.
unset PRC_RUNTIME_IMAGE
# Local assets do not need Omniverse Hub; do not silently launch its service.
export OMNICLIENT_HUB_MODE=disabled
export PRC_RUNTIME_KIND=native
cd "$repo"
exec "$ISAAC_PYTHON" -m tools.run_scene_examples --scenario "$scenario" --no-record "$@"

#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scenario=${1:-normal}
if [[ $# -gt 0 ]]; then shift; fi
case "$scenario" in
  normal|missed_grasp|obstructed|incomplete|all) ;;
  *) echo 'Usage: tools/run_scene.sh {normal|missed_grasp|obstructed|incomplete|all} [options]' >&2; exit 2 ;;
esac
exec "$repo_dir/tools/run_docker.sh" -m tools.run_scene_examples --scenario "$scenario" "$@"

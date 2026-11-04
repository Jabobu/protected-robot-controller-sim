#!/usr/bin/env bash
# Run an Isaac Python command, e.g. -m pytest, in the same offline image.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $# -gt 0 ]] || { echo 'Usage: tools/run_docker.sh PYTHON_ARGUMENTS...' >&2; exit 2; }
source "$repo_dir/tools/docker_common.sh"
exec docker run "${docker_common[@]}" --network none "$image_id" "$@"

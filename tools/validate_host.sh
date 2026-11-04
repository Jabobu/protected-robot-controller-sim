#!/usr/bin/env bash
# Unit and synthetic replay checks only; no Isaac, ROS process or device.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
export PYTHONDONTWRITEBYTECODE=1
exec python3 -m pytest -q -p no:cacheprovider tests/unit "$@"

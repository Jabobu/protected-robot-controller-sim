#!/usr/bin/env bash
# Build only the custom interface in a caller-selected local Jazzy workspace.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${PRC_ROS_WS:?Set PRC_ROS_WS to a writable directory for ROS build outputs}"
ros_setup=${ROS_SETUP:-/opt/ros/jazzy/setup.bash}
[[ -f "$ros_setup" ]] || { echo "ROS 2 Jazzy setup not found: $ros_setup" >&2; exit 2; }
# ROS setup scripts are not nounset-safe.
set +u
source "$ros_setup"
set -u
[[ ${ROS_DISTRO:-} == jazzy ]] || { echo 'ROS 2 Jazzy is required' >&2; exit 2; }
command -v colcon >/dev/null || { echo 'colcon is required in the Jazzy environment' >&2; exit 2; }
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), "ROS build Python 3.12 required"'
mkdir -p "$PRC_ROS_WS"
workspace=$(realpath -- "$PRC_ROS_WS")
cd "$workspace"
colcon --log-base "$workspace/log" build --base-paths "$repo/ros2" --build-base "$workspace/build" --install-base "$workspace/install"
printf 'Set PRC_ROS_PREFIX=%s/install/prc_interfaces for tools/run_ros2_native.sh\n' "$workspace"

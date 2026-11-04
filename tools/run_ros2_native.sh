#!/usr/bin/env bash
# Explicitly invoked ROS endpoint or example; no service starts for GUI/scene use.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ISAAC_PYTHON:?Set ISAAC_PYTHON to the Isaac Sim 6.0.0 python.sh launcher}"
: "${PRC_ROS_PREFIX:?Set PRC_ROS_PREFIX to the locally built prc_interfaces install prefix}"
[[ -f "$ISAAC_PYTHON" && -x "$ISAAC_PYTHON" ]] || { echo 'Isaac Python launcher is not executable' >&2; exit 2; }
ISAAC_PYTHON=$(realpath -- "$ISAAC_PYTHON")
PRC_ROS_PREFIX=$(realpath -- "$PRC_ROS_PREFIX")
isaac_root=$(cd -- "$(dirname -- "$ISAAC_PYTHON")" && pwd)
ros_root="$isaac_root/exts/isaacsim.ros2.core/jazzy"
[[ -d "$ros_root/rclpy" && -d "$ros_root/lib" && -d "$PRC_ROS_PREFIX/lib/python3.12/site-packages/prc_interfaces" ]] || {
  echo 'Missing Isaac Jazzy runtime or locally built Python 3.12 prc_interfaces' >&2; exit 2;
}
mode=${1:?Expected example, server, or client}; shift
case "$mode" in
  example)
    scenario=${1:?Scenario required}; shift
    command=(-m tools.run_scene_examples --scenario "$scenario" --no-record --ros2 "$@") ;;
  server|client)
    [[ $# == 4 ]] || { echo 'Expected KEY_DIR OUTPUT_PARENT RUN_NAME SCENARIO' >&2; exit 2; }
    keys=$(realpath -- "$1"); output=$(realpath -- "$2"); run=$3; scenario=$4
    [[ $run =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid run name' >&2; exit 2; }
    if [[ $mode == server ]]; then
      command=(-m tools.ros2_server --authority-public-der "$keys/authority.der" --evidence-private-pem "$keys/evidence.pem" --output "$output/$run" --scenario "$scenario")
    else
      command=(-m tools.ros2_development_client --authority-private-pem "$keys/authority.pem" --evidence-public-der "$keys/evidence.der" --output "$output/$run" --scenario "$scenario")
    fi ;;
  *) echo 'Expected example, server, or client' >&2; exit 2 ;;
esac
unset PRC_RUNTIME_IMAGE
# Local assets do not need Omniverse Hub; do not silently launch its service.
export OMNICLIENT_HUB_MODE=disabled
export PRC_RUNTIME_KIND=native ROS_DISTRO=jazzy RMW_IMPLEMENTATION=rmw_fastrtps_cpp FASTDDS_BUILTIN_TRANSPORTS=UDPv4
export ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-0}
export PYTHONPATH="$PRC_ROS_PREFIX/lib/python3.12/site-packages:$ros_root/rclpy:$repo${PYTHONPATH:+:$PYTHONPATH}"
export LD_LIBRARY_PATH="$PRC_ROS_PREFIX/lib:$ros_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$repo"
exec "$ISAAC_PYTHON" "${command[@]}"

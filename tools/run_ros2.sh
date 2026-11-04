#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:?usage: run_ros2.sh example SCENARIO or server/client KEY_DIR OUTPUT_PARENT RUN_NAME SCENARIO}
shift
extra=()
case "$mode" in
  keygen)
    [[ $# == 2 ]] || { echo 'keygen requires OUTPUT_PARENT NEW_DIRECTORY_NAME' >&2; exit 2; }
    output=$(realpath -- "$1"); name=$2
    [[ -d $output && $name =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Output directory or new directory name invalid' >&2; exit 2; }
    net=none
    extra=(--mount "type=bind,src=$output,dst=/key-output")
    command=(tools/create_ros2_development_keys.py "/key-output/$name") ;;
  example)
    scenario=${1:?scenario required}; shift
    net=none
    command=(-m tools.run_scene_examples --scenario "$scenario" --no-record --ros2 "$@") ;;
  server|client)
    [[ $# == 4 ]] || { echo 'server/client requires KEY_DIR OUTPUT_PARENT RUN_NAME SCENARIO' >&2; exit 2; }
    keys=$(realpath -- "$1"); output=$(realpath -- "$2"); run=$3; scenario=$4
    [[ -d $keys && -d $output && $run =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Key/output directories or run name invalid' >&2; exit 2; }
    net=host
    extra=(--mount "type=bind,src=$keys,dst=/run/prc-keys,readonly" --mount "type=bind,src=$output,dst=/evidence")
    if [[ $mode == server ]]; then
      command=(-m tools.ros2_server --authority-public-der /run/prc-keys/authority.der --evidence-private-pem /run/prc-keys/evidence.pem --output "/evidence/$run" --scenario "$scenario")
    else
      command=(-m tools.ros2_development_client --authority-private-pem /run/prc-keys/authority.pem --evidence-public-der /run/prc-keys/evidence.der --output "/evidence/$run" --scenario "$scenario")
    fi ;;
  *) echo 'expected keygen, example, server, or client' >&2; exit 2 ;;
esac
source "$repo_dir/tools/docker_common.sh"
exec docker run "${docker_common[@]}" --network "$net" "${extra[@]}" \
  --env ROS_DISTRO=jazzy --env RMW_IMPLEMENTATION=rmw_fastrtps_cpp --env FASTDDS_BUILTIN_TRANSPORTS=UDPv4 --env "ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-0}" \
  --env PYTHONPATH=/opt/prc_ros/prc_interfaces/lib/python3.12/site-packages:/isaac-sim/exts/isaacsim.ros2.core/jazzy/rclpy:/workspace \
  --env LD_LIBRARY_PATH=/opt/prc_ros/prc_interfaces/lib:/isaac-sim/exts/isaacsim.ros2.core/jazzy/lib \
  "$image_id" "${command[@]}"

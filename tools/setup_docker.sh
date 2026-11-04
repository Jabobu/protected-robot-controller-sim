#!/usr/bin/env bash
# Build a local image from the pinned public bases and fetch verified model files.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if [[ ${ACCEPT_EULA:-} != Y ]]; then
  echo 'Review NVIDIA Isaac Sim terms, then set ACCEPT_EULA=Y to accept them.' >&2
  echo 'https://docs.isaacsim.omniverse.nvidia.com/6.0.0/installation/install_container.html' >&2
  exit 2
fi
# A failed rebuild must not leave an earlier image authorized for launch.
mkdir -p output
record=output/prc-docker-image-id
rm -f -- "$record"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires Linux x86-64.' >&2; exit 1; }
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
command -v nvidia-smi >/dev/null || { echo 'NVIDIA driver and nvidia-smi are required.' >&2; exit 1; }
docker info >/dev/null || { echo 'Docker daemon is unavailable to this user.' >&2; exit 1; }
nvidia-smi || { echo 'NVIDIA GPU/driver is unavailable.' >&2; exit 1; }
python3 tools/fetch_scene_model.py
docker build --platform linux/amd64 -t prc-scene:local -f docker/ROS2.Dockerfile .
image_id=$(docker image inspect prc-scene:local --format '{{.Id}}')
platform=$(docker image inspect "$image_id" --format '{{.Os}}/{{.Architecture}}')
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ && $platform == linux/amd64 ]] || { echo 'Unexpected built image identity or platform.' >&2; exit 1; }
tmp_record=$(mktemp output/.prc-docker-image-id.XXXXXX)
trap 'rm -f -- "$tmp_record"' EXIT
printf '%s\n' "$image_id" > "$tmp_record"
mv -f -- "$tmp_record" "$record"
trap - EXIT
printf 'Built image ID: %s; platform: %s; local binding: %s\n' "$image_id" "$platform" "$record"
echo 'Run a GPU example with: ACCEPT_EULA=Y ./tools/run_scene.sh normal'

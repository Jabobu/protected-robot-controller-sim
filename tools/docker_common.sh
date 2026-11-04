#!/usr/bin/env bash
# Shared launch settings. Source this file after setting repo_dir.
set -euo pipefail
if [[ ${ACCEPT_EULA:-} != Y ]]; then
  echo 'Review NVIDIA Isaac Sim terms, then set ACCEPT_EULA=Y to accept them.' >&2
  echo 'https://docs.isaacsim.omniverse.nvidia.com/6.0.0/installation/install_container.html' >&2
  exit 2
fi
image_tag=prc-scene:local
record=$repo_dir/output/prc-docker-image-id
[[ -f $record && ! -L $record ]] || { echo 'Missing local image binding. Run tools/setup_docker.sh.' >&2; exit 1; }
image_id=$(cat -- "$record")
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'Invalid local image binding. Run tools/setup_docker.sh.' >&2; exit 1; }
tag_id=$(docker image inspect "$image_tag" --format '{{.Id}}') || { echo 'PRC image is unavailable. Run tools/setup_docker.sh.' >&2; exit 1; }
[[ $tag_id == "$image_id" ]] || { echo 'PRC image tag differs from the setup record. Run tools/setup_docker.sh.' >&2; exit 1; }
label=$(docker image inspect "$image_id" --format '{{index .Config.Labels "org.prc-scene.image"}}')
platform=$(docker image inspect "$image_id" --format '{{.Os}}/{{.Architecture}}')
[[ $label == 1 && $platform == linux/amd64 ]] || { echo 'Unexpected PRC image metadata. Run tools/setup_docker.sh.' >&2; exit 1; }
printf 'PRC container image: %s (linux/amd64)\n' "$image_id" >&2
docker_common=(--rm --pull=never --gpus all --user "$(id -u):$(id -g)" --group-add 1234
  --cap-drop=ALL --security-opt=no-new-privileges --read-only --pids-limit=2048 --shm-size=2g
  --tmpfs /tmp:rw,nosuid,nodev,size=4g
  --tmpfs /isaac-sim/kit/cache:rw,nosuid,nodev,size=2g,mode=1777
  --tmpfs /isaac-sim/kit/data:rw,nosuid,nodev,size=1g,mode=1777
  --tmpfs /isaac-sim/kit/logs:rw,nosuid,nodev,size=128m,mode=1777
  --mount "type=bind,src=$repo_dir,dst=/workspace" --workdir /workspace
  --env HOME=/tmp --env PYTHONDONTWRITEBYTECODE=1 --env ACCEPT_EULA=Y
  --env OMNI_KIT_ACCEPT_EULA=YES --env PRIVACY_CONSENT=N
  --env XDG_CACHE_HOME=/tmp/.cache --env XDG_CONFIG_HOME=/tmp/.config --env XDG_DATA_HOME=/tmp/.local/share
  --env "PRC_RUNTIME_IMAGE=$image_id" --entrypoint /isaac-sim/python.sh)

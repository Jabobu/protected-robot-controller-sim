# Runtime and ROS 2 setup

The default installation builds an Isaac Sim 6.0 and ROS 2 Jazzy container.
A local Isaac installation is a separate path; its GUI and ROS instructions
are still being verified.

## Docker

Use Linux x86-64 with an NVIDIA GPU and compatible driver, Docker, NVIDIA
Container Toolkit, Python 3, network access for initial downloads and enough
disk space for Isaac Sim and its build. Check [NVIDIA’s Isaac Sim system requirements](https://docs.isaacsim.omniverse.nvidia.com/6.0.0/installation/requirements.html); its published minimum lists an RTX 4080 and 16 GB VRAM. Read and accept the applicable
[Isaac Sim terms](https://docs.isaacsim.omniverse.nvidia.com/6.0.0/installation/install_container.html)
before setting `ACCEPT_EULA=Y`:

```sh
export ACCEPT_EULA=Y
./tools/setup_docker.sh
./tools/run_scene.sh normal --no-record
./tools/run_ros2.sh example normal
```

The setup downloads the pinned model closure and builds from versioned NVIDIA
and ROS image digests. It prints the resulting local image identity. Runs are
headless; the ROS example uses temporary development keys and includes an
altered-signature rejection check. Model files and results are ignored by Git.
Use `./tools/run_scene.sh all --no-record` for all four scenarios. Do not infer
physical sensor authentication or a Jetson result from these tests.

## Existing Isaac Sim installation

For the local headless path, install Isaac Sim 6.0 separately following NVIDIA's
instructions and review its license terms. Point to its `python.sh` and choose a
new writable dependency directory outside the Isaac installation. The following
installs the same hash-locked packages used by the container without modifying
Isaac's bundled Python packages:

```sh
export ISAAC_PYTHON=/absolute/path/to/isaac-sim/python.sh
export PRC_PYTHON_DEPS=/absolute/path/to/new-prc-dependencies
"$ISAAC_PYTHON" -m pip install --no-cache-dir --only-binary=:all: --require-hashes --ignore-installed --target "$PRC_PYTHON_DEPS" -r docker/requirements.lock
export PYTHONPATH="$PRC_PYTHON_DEPS${PYTHONPATH:+:$PYTHONPATH}"
python3 tools/fetch_scene_model.py
ACCEPT_EULA=Y OMNI_KIT_ACCEPT_EULA=YES PRIVACY_CONSENT=N ./tools/run_scene_native.sh normal
```

The local launcher accepts `normal`, `missed_grasp`, `obstructed`, `incomplete`,
or `all` and runs headlessly by default. To open a new restricted viewport on a
local display and watch the normal example:

```sh
ACCEPT_EULA=Y OMNI_KIT_ACCEPT_EULA=YES PRIVACY_CONSENT=N ./tools/run_scene_native.sh normal --visual
```

The window supports camera navigation and closes when the examples finish. It
does not attach to an already running Isaac session, and visual mode cannot be
combined with ROS or separate observation-camera recording. GUI views and object
observations are unsigned; the controller's signed motion evidence is separate.
Scene edits and direct actuator changes are not authorized controller commands.
The restricted viewport and guards block or detect tested interference, but do
not establish protection against a malicious host or detect every possible edit.
Closing the window during execution stops the run; an incomplete report is not a
successful full run. Do not retry automatically after an uncertain outcome.

Development checks were observed on an RTX 3070 with 8 GiB of VRAM, below
NVIDIA's published minimum; verification on supported GPU/display hardware is
still pending.

The user supplies and accepts the terms of Isaac Sim; its installation and
NVIDIA dependencies are not bundled.

### Local ROS 2

The native ROS interface needs a ROS 2 Jazzy build environment, `colcon`, and
Python 3.12. The native launcher uses the Jazzy runtime bundled with Isaac Sim.
If Jazzy is already installed, point `ROS_SETUP` to its `setup.bash`, choose a
new writable workspace and run `./tools/build_ros2_native.sh`.

One tested alternative on Ubuntu 22.04 uses Pixi and NVIDIA's pinned
[Isaac Sim 6.0 ROS workspace](https://github.com/isaac-sim/IsaacSim-ros_workspaces/tree/IsaacSim-6.0.0/jazzy_ws).
Install Pixi separately, then from this repository:

```sh
export PRC_SCENE="$PWD"
export PRC_ROS_WS=/absolute/path/to/new-ros-workspace
# Replace the checkout path with a new, writable location.
git clone --branch IsaacSim-6.0.0 --depth 1 https://github.com/isaac-sim/IsaacSim-ros_workspaces.git /absolute/path/to/isaac-ros-6
test "$(git -C /absolute/path/to/isaac-ros-6 rev-parse HEAD)" = 9e12849d0f58fc671410cb9f3a0740cd3db1783e || { echo 'Unexpected ROS workspace commit' >&2; exit 1; }
cd /absolute/path/to/isaac-ros-6/jazzy_ws
pixi install --locked --no-config
pixi run --locked --no-config env PRC_ROS_WS="$PRC_ROS_WS" ROS_SETUP="$PWD/.pixi/envs/default/setup.bash" "$PRC_SCENE/tools/build_ros2_native.sh"
cd "$PRC_SCENE"
export PRC_ROS_PREFIX="$PRC_ROS_WS/install/prc_interfaces"
ACCEPT_EULA=Y OMNI_KIT_ACCEPT_EULA=YES PRIVACY_CONSENT=N ROS_DOMAIN_ID=74 ./tools/run_ros2_native.sh example normal
```

The pinned Pixi environment involves a substantial first download. The build and
native example were tested on one Ubuntu 22.04, Isaac 6.0, Python 3.12 setup;
other configurations require their own validation. Set `ISAAC_PYTHON` and
`PYTHONPATH` as in the local installation section above. The native ROS commands
use the host network: configure DDS domain, interface and firewall for your
environment. ROS discovery is not peer authentication; commands are verified
using the separately provisioned authority key. The native ROS launcher is
headless and cannot be combined with visual mode.

## Persistent ROS server and client

These examples create **disposable development keys**, not production keys.
Choose a new private parent directory outside the repository and a new output
folder. Keep the server and client private keys on their respective sides.

```sh
export ACCEPT_EULA=Y
mkdir -p /tmp/prc-lab/output
./tools/run_ros2.sh keygen /tmp/prc-lab keys
ROS_DOMAIN_ID=74 ./tools/run_ros2.sh server /tmp/prc-lab/keys/server /tmp/prc-lab/output server-normal normal
```

In another terminal after the server reports ready:

```sh
export ACCEPT_EULA=Y
ROS_DOMAIN_ID=74 ./tools/run_ros2.sh client /tmp/prc-lab/keys/client /tmp/prc-lab/output client-normal normal
```

The server and client modes use host networking for ROS 2 Jazzy/Fast DDS
UDPv4. Configure the intended network interfaces and firewall for the deployment;
ROS peer discovery is not identity authentication. The controller checks signed
commands against the independently provisioned authority key. A timeout after
possible dispatch is UNKNOWN: do not automatically retry or infer nonexecution.
Preserve any returned bytes. To stop the server while it is idle on a local
Linux Docker host, identify the exact server container by its run name and then
its Python child (not the shell wrapper):

```sh
docker ps --no-trunc --format '{{.ID}} {{.Command}}'
docker top <server-container-id> -eo pid,ppid,args
kill -INT <identified-server-python-pid>
```

Confirm the foreground launcher exits; do not choose a PID from a partial match.
This procedure has not been verified for remote Docker daemons or nonstandard
PID namespaces. Interrupting a possible dispatch leaves its outcome UNKNOWN.

## Tests

See [TESTING.md](TESTING.md) for the scope of host checks, simulator tests and
scene verdicts. Use an isolated writable output directory and retain failures.

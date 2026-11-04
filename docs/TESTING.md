# Tests

Host-only checks exercise protocol framing, signing, verification, replay,
model preflight and related logic using synthetic data. They are not Isaac or
physical-hardware evidence. After the Docker setup:

```sh
ACCEPT_EULA=Y ./tools/run_docker.sh -m pytest -q -p no:cacheprovider tests/unit
```

Alternatively, after setting up the local Isaac Python dependencies described
in [ROS2_RUNBOOK.md](ROS2_RUNBOOK.md#existing-isaac-sim-installation), run the
host-only checks without a Docker container or GPU:

```sh
"$ISAAC_PYTHON" -m pytest -q -p no:cacheprovider tests/unit
```

The real simulator checks start Isaac and require the documented GPU setup and
fetched model. Run acceptance and scene checks in separate processes: each suite
owns its own Isaac application. Create a fresh report directory for each run. Acceptance diagnostics use that
directory and `artifacts/s5/runs/`; scene results also use `artifacts/scene-work/`.
The acceptance hooks also create or update generated files under `artifacts/s6/`,
`artifacts/functional_release_matrix.json` and other artifact directories. Some
are not Git-ignored and may appear as untracked files. For isolation, run these
checks in a disposable clone and preserve the resulting evidence before cleanup.

```sh
mkdir -p output
report_dir=$(mktemp -d output/verification-XXXXXXXX)
ACCEPT_EULA=Y ./tools/run_docker.sh -m pytest -q --junitxml "/workspace/$report_dir/acceptance.xml" tests/acceptance/test_model.py tests/acceptance/test_controller.py tests/acceptance/test_attacks.py tests/acceptance/test_physics.py tests/acceptance/test_integrated.py
ACCEPT_EULA=Y ./tools/run_docker.sh -m pytest -q --junitxml "/workspace/$report_dir/scene.xml" tests/scene/test_scene_examples.py tests/scene/test_scene_evidence.py tests/scene/test_scene_physics.py
```

Run the standalone examples and ROS fixture with the commands in
[ROS2_RUNBOOK.md](ROS2_RUNBOOK.md). A normal run has conformant motion and two
deliveries; missed grasp has conformant motion without delivery; the joint
constraint causes deviation; interrupted acquisition produces signed partial
evidence and an unknown motion verdict. Object observations are unsigned and
are assessed separately. An altered ROS command should be rejected without a
requested drive write.

Results from a headless run do not establish GUI support, real Jetson
integration or physical sensor authenticity. Historical v1 records require
their original verifier and separately retained evidence.

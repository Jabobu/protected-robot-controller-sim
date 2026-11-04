"""S2 acceptance: actual B601 PhysX only. No mocks, skips, or synthetic sensors."""

import hashlib
from pathlib import Path
import time

import pytest

from physics_support import (
    PhysicsRecords, REPEAT_TOLERANCE, SETUP_TARGET, assert_normal, assert_obstructed,
    assert_trace, execute, measured_backend, obstruct, trajectory,
)
from protected_robot_controller.simulation._backend import BackendFault, MAX_RUN_WALL_NS


@pytest.fixture(scope="module")
def physics_records(simulation_app, pytestconfig):
    xml = pytestconfig.getoption("xmlpath", default=None)
    root = Path(xml).resolve().parent if xml else Path(__file__).resolve().parents[2] / "output"
    records = PhysicsRecords(root / "s2")
    yield records
    records.summary["status"] = "EXECUTION_FINISHED_EXTERNAL_VERDICT_PENDING"
    records.flush()


def test_physics_drives_not_teleport(physics_records, monkeypatch):
    import numpy as np

    with measured_backend(monkeypatch) as backend:
        initial = backend.initial_sample
        samples = [initial]
        targets = trajectory()
        try:
            target = targets[0]
            backend.drive(target)
            # A target write alone must leave actual output state unchanged.
            actual = np.array(backend._robot.get_joint_positions(), copy=True)[backend._indices]
            np.testing.assert_array_equal(actual, initial.positions)
            with pytest.raises(BackendFault, match="fresh physics step"):
                backend.sample_outputs()
            backend.step_physics()
            first = backend.sample_outputs()
            samples.append(first)
            assert first.physics_step == initial.physics_step + 1
            assert np.max(np.abs(np.array(first.positions[:6]) - target[:6])) > 1e-5
            for target in targets[1:]:
                backend.drive(target)
                backend.step_physics()
                samples.append(backend.sample_outputs())
        except BaseException as exc:
            physics_records.save("normal", backend, samples, targets, None,
                                 terminal="ABORTED", error=repr(exc))
            raise
        physics_records.save("normal", backend, samples, targets, None)
        assert_trace(samples, targets, backend)
        assert_normal(samples, targets)
        physics_records.observed("test_physics_drives_not_teleport", ["normal"], "NORMAL_MOTION")


def test_blocked_joint_reports_real_output(physics_records, monkeypatch):
    with measured_backend(monkeypatch) as backend:
        constraint = obstruct(backend, "joint1")
        samples, targets, _ = execute(backend, physics_records, "blocked_joint1", constraint)
        assert_trace(samples, targets, backend)
        assert targets == trajectory()  # Identical normal and jammed drive program.
        assert_obstructed(samples, targets, constraint)
        physics_records.observed("test_blocked_joint_reports_real_output", ["blocked_joint1"], "OBSTRUCTED_MOTION")


def test_gripper_output_feedback(physics_records, monkeypatch):
    import numpy as np

    with measured_backend(monkeypatch) as backend:
        samples, targets, _ = execute(backend, physics_records, "gripper")
        assert_trace(samples, targets, backend)
        assert_normal(samples, targets)
        assert backend._channels[7]["drive_enabled"] is False
        assert backend._robot.dof_properties["maxEffort"][backend._indices[7]] == 0
        fingers = np.array([s.positions[6:] for s in samples])
        assert np.all(fingers[-1] - fingers[0] > 0.008)
        # Both actual outputs move; no target is sent to the follower.
        assert np.max(np.abs(fingers[:, 0] - fingers[:, 1])) < 0.0002
        physics_records.observed("test_gripper_output_feedback", ["gripper"], "COUPLED_FINGERS_OBSERVED")


def test_bounded_effort(physics_records, monkeypatch):
    import numpy as np
    from pxr import UsdPhysics

    with measured_backend(monkeypatch) as backend:
        writes = []
        apply = backend._robot.apply_action

        def audit(action):
            writes.append(action)
            return apply(action)

        monkeypatch.setattr(backend._robot, "apply_action", audit)
        # Both arm and gripper position/slew violations must be rejected before
        # any target write. No effort override exists on this private interface.
        for i, channel in enumerate(backend._channels[:7]):
            for bad in (channel["position_limits"][0] - 0.1,
                        channel["position_limits"][1] + 0.1,
                        SETUP_TARGET[i] + channel["max_velocity"] * backend._dt * 2,
                        float("nan"), float("inf")):
                target = list(SETUP_TARGET)
                target[i] = bad
                with pytest.raises(ValueError):
                    backend.drive(target)
                assert writes == []
        samples, targets, _ = execute(backend, physics_records, "bounded_effort")
        assert len(writes) == len(targets)
        for action in writes:
            assert action.joint_efforts is None
            assert list(action.joint_indices) == list(backend._drive_indices)
        assert_trace(samples, targets, backend)
        assert_normal(samples, targets)
        # Check the live PhysX drive limits, not only JSON configuration.
        caps = backend._robot._articulation_view._physics_view.get_dof_max_forces()[0]
        for index, channel in zip(backend._indices, backend._channels):
            drive = UsdPhysics.DriveAPI.Get(backend._stage.GetPrimAtPath(channel["joint_path"]),
                                           "angular" if channel["unit"] == "rad" else "linear")
            assert drive.GetTypeAttr().Get() == "force"
            assert float(caps[index]) == pytest.approx(channel["max_effort"], abs=1e-6)
            assert drive.GetMaxForceAttr().Get() == pytest.approx(channel["max_effort"], abs=1e-6)
        efforts = np.array([s.measured_joint_efforts for s in samples])
        assert np.isfinite(efforts).all()
        # These are solver reactions, never a clipped/claimed actuator torque.
        physics_records.observed("test_bounded_effort", ["bounded_effort"], "LIVE_FORCE_CAPS_OBSERVED",
                                 {"caps": np.asarray(caps)[backend._indices].tolist(),
                                  "reaction_abs_max": np.max(np.abs(efforts), axis=0).tolist()})


def test_each_independent_actuator_can_be_blocked(physics_records, monkeypatch):
    # One exact manifest case name, with all seven independent physical runs.
    actuators = ["joint1", "joint2", "joint3", "joint4", "joint5", "joint6", "gripper"]
    names = []
    for actuator in actuators:
        with measured_backend(monkeypatch) as backend:
            assert backend._manifest["actuator_order"] == actuators
            constraint = obstruct(backend, actuator)
            name = f"obstructed_{actuator}"
            samples, targets, _ = execute(backend, physics_records, name, constraint)
            assert targets == trajectory()
            assert_trace(samples, targets, backend)
            assert_obstructed(samples, targets, constraint)
            names.append(name)
            physics_records.observed(f"obstruction_{actuator}", [name], "OBSTRUCTED_MOTION")
    assert len(names) == 7
    physics_records.observed("test_each_independent_actuator_can_be_blocked",
                             names, "OBSTRUCTED_MOTION", {"actuators": actuators})


def test_reproducible_steps_and_deadlines(physics_records, monkeypatch):
    import numpy as np

    runs = []
    elapsed = []
    for repeat in range(2):
        with measured_backend(monkeypatch) as backend:
            samples, targets, wall_ns = execute(backend, physics_records, f"repeat_{repeat}")
            assert_trace(samples, targets, backend)
            assert_normal(samples, targets)
            assert wall_ns < MAX_RUN_WALL_NS
            elapsed.append(wall_ns)
            runs.append(np.array([s.positions for s in samples]))
    assert np.all(np.abs(runs[0] - runs[1]) <= REPEAT_TOLERANCE), np.max(np.abs(runs[0] - runs[1]), axis=0)

    # Fault checks still run on the real initialized articulation. Retain a real
    # prefix, then force an expired wall-clock deadline, and separately pause it.
    for fault in ("deadline", "pause"):
        with measured_backend(monkeypatch) as backend:
            targets = trajectory()[:2]
            backend.drive(targets[0])
            backend.step_physics()
            samples = [backend.initial_sample, backend.sample_outputs()]
            backend.drive(targets[1])
            step = backend._world.current_time_step_index
            deadline = time.monotonic_ns() + 1_000_000
            if fault == "deadline":
                time.sleep(0.003)  # Real elapsed time; no substituted clock.
            else:
                backend._world.pause()
                deadline = time.monotonic_ns() + 1_000_000_000
            with pytest.raises(BackendFault, match="deadline|paused") as error:
                backend.step_physics(deadline_ns=deadline)
            assert backend._world.current_time_step_index == step
            with pytest.raises(BackendFault, match="faulted"):
                backend.sample_outputs()
            physics_records.save(f"abort_{fault}", backend, samples, targets, None,
                                 terminal="ABORTED", error=str(error.value))
    physics_records.observed("test_reproducible_steps_and_deadlines",
                             ["repeat_0", "repeat_1", "abort_deadline", "abort_pause"],
                             "REPRODUCTION_AND_ABORT_CHECKED", {"wall_time_ns": elapsed,
                                                               "position_tolerance": REPEAT_TOLERANCE})
    # Every summary entry must identify the bytes actually written in this run.
    for entry in physics_records.checker["entries"].values():
        assert entry["evidence_sha256"] == hashlib.sha256(Path(entry["evidence_path"]).read_bytes()).hexdigest()
        assert entry["verdict"] == "NOT_PROVEN"  # S2 is deliberately pre-signature.

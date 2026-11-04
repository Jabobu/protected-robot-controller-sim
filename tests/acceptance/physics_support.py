"""Trusted S2 fixtures and raw-report writer, never imported by the backend."""

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import struct
import time

from protected_robot_controller.simulation._backend import SETUP_TARGET
from protected_robot_controller.simulation.model import MANIFEST_PATH, ROOT

RAMP_STEPS = 240
HOLD_STEPS = 120
DELTA = (0.15, -0.15, -0.15, 0.15, 0.15, 0.15, 0.012)
TRACKING_TOLERANCE = (0.025, 0.03, 0.03, 0.03, 0.04, 0.025, 0.001, 0.001)
REPEAT_TOLERANCE = (1e-4,) * 6 + (1e-5,) * 2
RERUN = ("/isaac-sim/python.sh -m pytest -q tests/acceptance/test_model.py "
         "tests/acceptance/test_physics.py --junitxml=/reports/s2.xml")


def trajectory():
    return [tuple(q + d * min(step / RAMP_STEPS, 1.0) for q, d in zip(SETUP_TARGET, DELTA))
            for step in range(1, RAMP_STEPS + HOLD_STEPS + 1)]


def obstruct(backend, actuator):
    """Actual PhysX hard stops; never a getter replacement or position write.

    Both bounds remain distinct so the eight-DOF articulation is preserved.
    Tensor angular units are radians (USD authoring would require degrees).
    Only the leader is constrained for the mechanically coupled gripper.
    """
    import numpy as np

    manifest = backend._manifest
    output = manifest["actuator_order"].index(actuator)
    index = backend._indices[output]
    view = backend._robot._articulation_view._physics_view
    before = np.array(view.get_dof_limits(), copy=True)
    limits = before.copy()
    q = backend.initial_sample.positions[output]
    half_width = 1e-5 if output < 6 else 1e-6
    limits[0, index] = (q - half_width, q + half_width)
    view.set_dof_limits(limits, np.array([0], dtype=np.int32))
    readback = np.array(view.get_dof_limits(), copy=True)
    np.testing.assert_allclose(readback, limits, atol=1e-8, rtol=0)
    assert readback[0, index, 0] < readback[0, index, 1]
    return {"method": "PhysX articulation DOF hard limits", "actuator": actuator,
            "output": manifest["output_order"][output], "output_index": output,
            "runtime_index": index, "initial_position": q,
            "old_limits": before[0, index].tolist(), "limits": readback[0, index].tolist(),
            "units": manifest["channels"][output]["unit"]}


@contextmanager
def measured_backend(monkeypatch):
    from protected_robot_controller.simulation._backend import _IsaacRobotBackend

    backend = _IsaacRobotBackend()
    try:
        with monkeypatch.context() as guard:
            def forbidden(*args, **kwargs):
                raise AssertionError("Direct state assignment/reset during measured execution")
            robot = backend._robot
            # Catch high-level and tensor teleport/reset paths while capturing.
            for obj, names in [
                (robot, ("set_joint_positions", "set_joint_velocities", "set_world_pose", "post_reset")),
                (robot._articulation_view, ("set_joint_positions", "set_joint_velocities", "set_world_poses")),
                (robot._articulation_view._physics_view,
                 ("set_dof_positions", "set_dof_velocities", "set_root_transforms", "set_root_velocities")),
                (backend._world, ("reset",)),
            ]:
                for name in names:
                    guard.setattr(obj, name, forbidden)
            yield backend
    finally:
        backend.close()


class PhysicsRecords:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.summary = {
            "stage": "S2", "status": "RUNNING", "acceptance": "EXTERNAL_SUPERVISOR_ONLY",
            "scope": "Unsigned real PhysX traces; no cryptographic or physical attestation",
            "command": RERUN, "runs": {}, "tests": {},
        }
        self.checker = {"stage": "S2", "scope": "Unsigned physics only; S3/S4 checker pending", "entries": {}}
        self.flush()

    def flush(self):
        # Only evidence outputs, never source/config/model manifests.
        for name, value in (("physics_summary.json", self.summary), ("checker_summary.json", self.checker)):
            encoded = json.dumps(value, indent=2, allow_nan=False) + "\n"
            (ROOT / "artifacts" / name).write_text(encoded)
            (self.directory / name).write_text(encoded)

    def save(self, name, backend, samples, targets, constraint, *, terminal="COMPLETE", error=None):
        import cbor2
        from isaacsim.core.version import get_version

        manifest = backend._manifest
        payload = {
            "format": "PRC_S2_UNSIGNED_PHYSICS_V1", "terminal": terminal, "error": error,
            "isaac_version": list(get_version()), "runtime": manifest["runtime"],
            "physics_clock": {
                "configured_dt_seconds": float(backend._world.get_physics_dt()),
                "effective_dt_seconds": backend._physics_dt,
                "time_source": "World.current_time accumulated from PhysX step callbacks",
                "step_source": "World.current_time_step_index counted from PhysX step callbacks",
            },
            "source_commit": manifest["source"]["commit"],
            "model_manifest_sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
            "backend_sha256": hashlib.sha256((ROOT / "protected_robot_controller/simulation/_backend.py").read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "output_order": manifest["output_order"], "actuator_order": manifest["actuator_order"],
            "units": [c["unit"] for c in manifest["channels"]],
            "drive_caps": [c["max_effort"] for c in manifest["channels"]],
            "constraint": constraint, "setup_target": SETUP_TARGET,
            "targets": targets, "samples": [asdict(s) for s in samples],
            "effort_semantics": "Unclipped solver joint reactions, not isolated drive effort",
            "rerun": RERUN,
        }
        raw = cbor2.dumps(payload, canonical=True)
        if len(raw) > 1024 * 1024:
            raise AssertionError("Raw evidence exceeds 1 MiB")
        path = self.directory / f"{name}.cbor"
        path.write_bytes(raw)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.summary["runs"][name] = {
            "status": "CAPTURED_UNASSESSED", "evidence_path": str(path), "evidence_sha256": digest,
            "bytes": len(raw), "samples": len(samples), "terminal": terminal, "constraint": constraint,
        }
        self.checker["entries"][name] = {
            "verdict": "NOT_PROVEN", "reason": "S2 raw unsigned physics; signed verification is S4",
            "evidence_path": str(path), "evidence_sha256": digest,
        }
        self.flush()

    def observed(self, test, names, observation, details=None):
        self.summary["tests"][test] = {"status": "OBSERVED", "runs": names, "details": details}
        for name in names:
            self.summary["runs"][name]["status"] = observation
            self.checker["entries"][name]["physics_observation"] = observation
        self.flush()


def execute(backend, records, name, constraint=None):
    samples = [backend.initial_sample]
    targets = trajectory()
    started = time.monotonic_ns()
    try:
        for target in targets:
            backend.drive(target)
            backend.step_physics()
            samples.append(backend.sample_outputs())
    except BaseException as exc:
        records.save(name, backend, samples, targets, constraint, terminal="ABORTED", error=repr(exc))
        raise
    records.save(name, backend, samples, targets, constraint)
    return samples, targets, time.monotonic_ns() - started


def assert_trace(samples, targets, backend):
    import numpy as np

    assert len(samples) == len(targets) + 1 == RAMP_STEPS + HOLD_STEPS + 1
    initial = samples[0]
    # Independent binary32 conversion: PhysX callbacks report a float timestep,
    # not the ideal rational 1/120. Preserve the 1 ns timestamp check.
    dt = struct.unpack("f", struct.pack("f", 1 / 120))[0]
    assert backend._dt == 1 / 120
    assert backend._physics_dt == dt
    for i, sample in enumerate(samples):
        assert sample.sequence == i
        assert sample.physics_step == initial.physics_step + i
        assert abs(sample.simulation_time_ns - initial.simulation_time_ns - round(i * dt * 1e9)) <= 1
        assert len(sample.positions) == len(sample.velocities) == len(sample.measured_joint_efforts) == 8
        assert np.isfinite([sample.positions, sample.velocities, sample.measured_joint_efforts]).all()
        if i:
            assert sample.monotonic_time_ns > samples[i - 1].monotonic_time_ns
        for q, v, c in zip(sample.positions, sample.velocities, backend._channels):
            tolerance = 1e-3 if c["unit"] == "rad" else 1e-4
            assert c["position_limits"][0] - tolerance <= q <= c["position_limits"][1] + tolerance
            assert abs(v) <= c["max_velocity"] * 1.1 + tolerance
    # Distinct immutable snapshots; changing a consumer copy cannot alter them.
    assert len({id(s.positions) for s in samples}) == len(samples)
    consumer = np.array(initial.positions)
    consumer[:] = 123
    assert not np.any(np.array(initial.positions) == 123)


def assert_normal(samples, targets):
    import numpy as np

    observed = np.array([s.positions for s in samples])
    expanded = np.array([list(t) + [t[-1]] for t in targets])
    tolerance = np.array(TRACKING_TOLERANCE)
    # Check the whole ramp and hold, not merely a lucky endpoint.
    assert np.all(np.abs(observed[1:] - expanded) < tolerance), np.max(np.abs(observed[1:] - expanded), axis=0)
    delta = observed[-1] - observed[0]
    assert np.all(np.sign(delta) == np.sign(list(DELTA) + [DELTA[-1]])), delta
    assert np.all(np.abs(delta[:6]) > 0.08), delta
    assert np.all(delta[6:] > 0.008), delta
    assert np.all(np.ptp(observed[-60:], axis=0) < np.array([0.002] * 6 + [0.0002] * 2))
    assert np.max(np.abs(observed[:, 6] - observed[:, 7])) < 0.0002


def assert_obstructed(samples, targets, constraint):
    import numpy as np

    observed = np.array([s.positions for s in samples])
    index = constraint["output_index"]
    outputs = [index] if index < 6 else [6, 7]
    for output in outputs:
        stall = 0.001 if output < 6 else 0.0001
        assert np.max(np.abs(observed[:, output] - observed[0, output])) < stall
        goal = targets[-1][min(output, 6)]
        assert abs(observed[-1, output] - goal) > (0.10 if output < 6 else 0.008)
    # The engine keeps advancing and the other independent actuators still move.
    for other in range(7):
        if other != index:
            assert abs(observed[-1, other] - observed[0, other]) > (0.05 if other < 6 else 0.006)

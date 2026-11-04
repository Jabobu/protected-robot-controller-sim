"""S4: signed commands through the byte interface into real B601 PhysX.

No fallback, skip, target-derived observation, or synthetic success artifact.
Only this trusted fixture sees expectations, keys and physical fault injection.
"""

from hashlib import sha256
import json
from pathlib import Path

import pytest

from physics_support import (
    HOLD_STEPS, RAMP_STEPS, assert_normal, assert_obstructed, assert_trace,
    measured_backend, obstruct, trajectory,
)
from protected_robot_controller import limits as L
from protected_robot_controller.controller import Controller
from protected_robot_controller.interface import ControllerInterface, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import MAX_EVIDENCE_BYTES, encode, strict_decode, verify_sign1
from protected_robot_controller.simulation.model import MANIFEST_PATH, ROOT
from tools.controller_fixture import (
    EvidenceChecker, authenticated_evidence, command_for, development_keys, sign_command,
)
from tools.integrated_fixture import (
    CHECK_TOLERANCE, MIN_DISPLACEMENT, check_recorded_run, record_run,
)

RERUN = ("/isaac-sim/python.sh -m pytest -q tests/acceptance/test_integrated.py "
         "--junitxml=/reports/s4-integrated.xml")


@pytest.fixture(scope="module")
def s4_keys():
    # One ephemeral set for the trusted run; never written to disk.
    return development_keys()


@pytest.fixture(scope="module")
def s4_directory(pytestconfig):
    xml = pytestconfig.getoption("xmlpath", default=None)
    directory = (Path(xml).resolve().parent if xml else ROOT / "output") / "s4"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _request(interface, message):
    return strict_decode(interface.handle(encode(message)), MAX_RESPONSE_BYTES)


def _run(name, keys, directory, *, jam=False, pause=False, jam_actuator="joint1"):
    import numpy as np
    from isaacsim.core.version import get_version

    authority, evidence_key = keys
    samples, observations, writes = [], [], []
    # Existing S2 guard forbids all high-level/tensor teleport/reset paths.
    with pytest.MonkeyPatch.context() as patch, measured_backend(patch) as backend:
        assert sha256(MANIFEST_PATH.read_bytes()).hexdigest() == L.MODEL_MANIFEST_SHA256
        constraint = obstruct(backend, jam_actuator) if jam else None
        original_capture = backend._capture
        original_write = backend._write_targets

        def capture():
            sample = original_capture()
            # A separate read directly from PhysX at the same stepped state.
            # It does not call the backend conversion or use any target array.
            live = np.array(backend._robot.get_joint_positions(), dtype=float, copy=True)
            positions = tuple(float(live[i]) for i in backend._indices)
            observations.append({
                "counter": sample.counter,
                "physics_step": int(backend._world.current_time_step_index),
                "simulation_time_ns": round(float(backend._world.current_time) * 1e9),
                "monotonic_time_ns": sample.monotonic_time_ns,
                "positions": list(positions), "valid": [True] * 8,
            })
            assert sample.positions == positions
            assert sample.physics_step == observations[-1]["physics_step"]
            assert sample.simulation_time_ns == observations[-1]["simulation_time_ns"]
            samples.append(sample)
            return sample

        def write(target):
            writes.append(tuple(target))
            original_write(target)

        patch.setattr(backend, "_capture", capture)
        patch.setattr(backend, "_write_targets", write)
        if pause:
            original_step = backend.step_physics

            def step(*, deadline_ns):
                if backend._steps == 5:
                    backend._world.pause()  # Actual engine pause, not a sensor substitute.
                original_step(deadline_ns=deadline_ns)

            patch.setattr(backend, "step_physics", step)

        controller = Controller(authority.public_key(), evidence_key, backend)
        interface = ControllerInterface(controller)
        hello = _request(interface, {"version": 1, "type": "HELLO"})
        # Trusted fixture context is retained before execution. Both runs use
        # exactly the same ramp and hold; fresh initial measurements are signed.
        initial = [round(q * 1_000_000) for q in backend.initial_sample.positions]
        ramp = [[round(q * 1_000_000) for q in t] for t in trajectory()[:RAMP_STEPS]]
        command = command_for(hello, initial, ramp, hold_steps=HOLD_STEPS)
        command["authorization_context_digest"] = sha256(b"S4 B601 ramp and final hold fixture").digest()
        command_bytes = sign_command(command, authority)
        response = _request(interface, {"version": 1, "type": "EXECUTE", "command": command_bytes})
        assert response.keys() == {"version", "type", "evidence"}, response
        assert response["type"] == "EVIDENCE"
        bundle = response["evidence"]
        evidence = authenticated_evidence(bundle, evidence_key.public_key())
        metadata = {
            "scope": "Isaac Sim PhysX; trusted host functional experiment only",
            "source_revision": backend._manifest["source"]["commit"],
            "runtime": {"isaac_version": list(get_version()),
                        "configured_dt_seconds": backend._dt,
                        "effective_dt_seconds": backend._physics_dt},
            "constraint": constraint, "fault": "timeline pause at step 5" if pause else None,
            "observation_source": "Separate copied Articulation.get_joint_positions after each PhysX step",
            "rerun": RERUN, "target_write_count": len(writes),
            "source_sha256": {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                              for path in [Path(__file__).resolve(),
                                           ROOT / "protected_robot_controller/simulation/_backend.py",
                                           ROOT / "protected_robot_controller/controller.py",
                                           ROOT / "protected_robot_controller/interface.py"]},
        }
        # Persist authentic bytes BEFORE motion assertions, including failures.
        for destination in (ROOT / "artifacts/evidence", directory / "evidence"):
            result = record_run(destination, name, command_bytes, bundle,
                                authority.public_key(), evidence_key.public_key(),
                                observations=observations, metadata=metadata)
            assert check_recorded_run(destination, name) == result
        run = {"command": command_bytes, "bundle": bundle, "evidence": evidence,
               "samples": samples, "observations": observations, "constraint": constraint,
               "targets": trajectory(), "result": result, "writes": writes,
               "state": controller.state, "setup_sample": backend.initial_sample}
        if not pause:
            # Retain diagnostic assertion failures without preventing the other
            # physical run and its evidence from being captured.
            try:
                assert_trace(samples, trajectory(), backend)
            except AssertionError as error:
                run["trace_error"] = repr(error)
        else:
            assert backend._faulted
            assert backend._world.current_time_step_index == samples[-1].physics_step
        return run


@pytest.fixture(scope="module")
def integrated_runs(simulation_app, s4_keys, s4_directory):
    runs = {}
    # Start this attempt's summary empty so a failed run cannot reuse an old PASS.
    summary = {}
    for path in (ROOT / "artifacts/checker_summary.json", s4_directory / "checker_summary.json"):
        path.write_text(json.dumps(summary) + "\n")
    for name in ("normal", "blocked"):
        runs[name] = _run(name, s4_keys, s4_directory, jam=name == "blocked")
        summary[name] = runs[name]["result"]
        for path in (ROOT / "artifacts/checker_summary.json", s4_directory / "checker_summary.json"):
            path.write_text(json.dumps(summary, indent=2) + "\n")
    return runs


def test_signed_normal_trace_verified_success(integrated_runs, s4_keys):
    run = integrated_runs["normal"]
    assert "trace_error" not in run, run.get("trace_error")
    assert run["state"] == "COMPLETE"
    assert run["evidence"]["reason"] == "NONE"
    assert run["result"]["verdict"] == "VERIFIED_SUCCESS"
    assert_normal(run["samples"], run["targets"])
    authority, evidence_key = s4_keys
    checker = EvidenceChecker(authority.public_key(), evidence_key.public_key())
    assert checker.check(run["bundle"], run["command"], tolerance=CHECK_TOLERANCE,
                         minimum_displacement=MIN_DISPLACEMENT) == "VERIFIED_SUCCESS"
    assert checker.check(run["bundle"], run["command"], tolerance=CHECK_TOLERANCE,
                         minimum_displacement=MIN_DISPLACEMENT) == "REJECTED"


def test_signed_obstructed_trace_verified_failure(integrated_runs, s4_keys):
    run = integrated_runs["blocked"]
    assert "trace_error" not in run, run.get("trace_error")
    # Completion describes capture, never movement success. The jam stays sensed.
    assert run["state"] == "COMPLETE"
    assert run["evidence"]["partial"] is False
    assert run["result"]["verdict"] == "VERIFIED_FAILURE"
    assert_obstructed(run["samples"], run["targets"], run["constraint"])
    authority, _ = s4_keys
    normal = verify_sign1(integrated_runs["normal"]["command"], authority.public_key())
    blocked = verify_sign1(run["command"], authority.public_key())
    for field in ("trajectory", "hold_steps", "velocity_limits", "effort_limits", "outputs", "units"):
        assert normal[field] == blocked[field]


def test_evidence_contains_real_output_samples(integrated_runs, s4_keys):
    summary = json.loads((ROOT / "artifacts/checker_summary.json").read_text())
    assert set(summary) == {"normal", "blocked"}
    for name, run in integrated_runs.items():
        evidence, samples = run["evidence"], run["samples"]
        rows = evidence["samples"]
        assert evidence["sample_count"] == len(rows) == RAMP_STEPS + HOLD_STEPS + 1
        assert evidence["hold_steps"] == HOLD_STEPS
        assert evidence["outputs"] == list(L.OUTPUTS)
        assert evidence["units"] == list(L.UNITS)
        assert "verdict" not in evidence and "success" not in evidence
        # Initial read must be fresh inside execution, not the cached setup read.
        assert samples[0].monotonic_time_ns > run["setup_sample"].monotonic_time_ns
        offsets = set()
        for index, (row, sample, observer) in enumerate(zip(rows, samples, run["observations"])):
            assert row[0] == index
            assert row[1:4] == [sample.counter, sample.physics_step, sample.simulation_time_ns]
            assert row[5] == [round(q * 1_000_000) for q in observer["positions"]]
            assert row[6] == observer["valid"] == [True] * 8
            offsets.add(observer["monotonic_time_ns"] - row[4])
        assert len(offsets) == 1  # One real acquisition clock origin, entire trace.
        assert len(run["writes"]) == RAMP_STEPS + HOLD_STEPS + 1  # terminal capped hold
        assert len(run["bundle"]) <= MAX_EVIDENCE_BYTES
        command = verify_sign1(run["command"], s4_keys[0].public_key())
        assert any(row[5] != target + [target[-1]]
                   for row, target in zip(rows[1:], command["trajectory"]))
        path = ROOT / "artifacts/evidence" / f"{name}.cbor"
        assert path.read_bytes() == run["bundle"]
        assert summary[name] == {"verdict": run["result"]["verdict"],
                                 "evidence_sha256": sha256(path.read_bytes()).hexdigest()}
        assert check_recorded_run(path.parent, name) == summary[name]


def test_signed_physics_pause_preserves_partial_trace(simulation_app, s4_keys, s4_directory):
    run = _run("paused", s4_keys, s4_directory, pause=True)
    evidence = run["evidence"]
    assert run["state"] == "ABORTED"
    assert evidence["terminal_state"] == "ABORTED" and evidence["partial"] is True
    assert evidence["reason"] == "BACKEND"
    assert evidence["sample_count"] == 6  # initial plus five actual steps, no backfill
    assert evidence["expected_sample_count"] == 361
    assert run["result"]["verdict"] == "NOT_PROVEN"
    assert evidence["samples"][-1][5] == [round(q * 1_000_000) for q in run["observations"][-1]["positions"]]


@pytest.mark.parametrize("actuator", L.ACTUATORS)
def test_each_actuator_signed_obstruction_verified_failure(
        actuator, integrated_runs, s4_keys, s4_directory):
    """A3 needs signed failure on every actuator, beyond S2 unsigned traces."""
    from tools.signed_obstructions import check_signed_obstruction

    name = f"blocked_{actuator}"
    run = _run(name, s4_keys, s4_directory, jam=True, jam_actuator=actuator)
    assert "trace_error" not in run, run.get("trace_error")
    assert run["state"] == run["evidence"]["terminal_state"] == "COMPLETE"
    assert run["evidence"]["reason"] == "NONE"
    assert run["evidence"]["partial"] is False
    assert run["result"]["verdict"] == "VERIFIED_FAILURE"
    assert run["constraint"]["actuator"] == actuator
    assert_obstructed(run["samples"], run["targets"], run["constraint"])
    assert len(run["samples"]) == run["evidence"]["sample_count"] == 361
    assert len(run["writes"]) == RAMP_STEPS + HOLD_STEPS + 1
    # Reopen original signed bytes and compare every row to the independent
    # copied PhysX observations, including both fingers and the final hold.
    # The helper also checks the same signed motion program as the normal run.
    for destination in (ROOT / "artifacts/evidence", s4_directory / "evidence"):
        assert check_signed_obstruction(destination, actuator) == run["result"]

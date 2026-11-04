"""S6-04 requires fresh signed Isaac 6.0 runs and genuine retained images.

Run only inside the pinned credential-free Isaac container. Every scenario is
attempted once; failed runs remain indexed and are never replaced with retries.
No fault below is induced by changing an evidence file or a verifier policy.
"""
from hashlib import sha256
import json
import math
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Import the unchanged protocol stack before SimulationApp starts.
from protected_robot_controller import limits as L
from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode, public_bytes, strict_decode, verify_sign1
from tools.controller_fixture import authenticated_evidence, development_keys
from tools.scene_check import load_policy, replay_run
from tools.scene_evidence import scenario_operation_plan, verify_run
from tools.scene_fixture import OUTPUT, PROFILE_PATH, ROOT, TRAJECTORY_PATH
from tools.scene_objects import assess_objects, in_destination


SCENARIOS = ("normal", "missed_grasp", "obstructed", "incomplete")


def load(path):
    return json.loads(Path(path).read_bytes())


@pytest.fixture(scope="module")
def example_runs(scene_simulation_app):
    from tools.run_scene_examples import run_example

    summary = OUTPUT / "examples.json"
    earlier = load(summary).get("runs", []) if summary.exists() else []
    keys = development_keys()
    pins = {"authority_public_der_hex": public_bytes(keys[0].public_key()).hex(),
            "evidence_public_der_hex": public_bytes(keys[1].public_key()).hex()}
    from tools.runtime_provenance import current_runtime
    identity = current_runtime()
    pins["expected_runtime"] = identity["image_id"] if identity["kind"] == "container" else "native"
    runs = {}
    for scenario in SCENARIOS:
        try:
            runs[scenario] = run_example(scenario, app=scene_simulation_app, keys=keys, record=True)
        except Exception as error:
            # Preserve the runner's already-retained failure and still attempt
            # the remaining independent scenes. Never retry this scenario.
            entries = load(summary).get("runs", []) if summary.exists() else []
            fresh = [entry for entry in entries
                     if entry.get("scenario") == scenario and entry not in earlier]
            runs[scenario] = load(ROOT / fresh[-1]["manifest"]) if fresh else {}
            runs[scenario]["fixture_exception"] = repr(error)
    return {"runs": runs, "pins": pins, "earlier": earlier}


def checked(example_runs, scenario):
    """Read exact retained bytes independently of the runner's stored labels."""
    from tools.integrated_fixture import _compare_observations

    run = example_runs["runs"][scenario]
    assert "fixture_exception" not in run, run
    assert run.get("status") not in (None, "STARTED", "EXECUTION_FAILED", "OBSERVED_MISMATCH"), run
    manifest = OUTPUT / "examples" / run["run_id"] / "run.json"
    assert load(manifest) == run
    assert run["scenario"] == scenario
    assert run["profile_sha256"] == sha256(PROFILE_PATH.read_bytes()).hexdigest()
    assert run["trajectory_sha256"] == sha256(TRAJECTORY_PATH.read_bytes()).hexdigest()
    assert run["reproduction_command"] == "<Isaac Sim python.sh> -m tools.run_scene_examples --scenario " + scenario
    program, profile = load(TRAJECTORY_PATH), load(PROFILE_PATH)
    assert (ROOT / run["public_inputs"]["program"]).read_bytes() == TRAJECTORY_PATH.read_bytes()
    assert (ROOT / run["public_inputs"]["profile"]).read_bytes() == PROFILE_PATH.read_bytes()
    assert run["required_operations"] == scenario_operation_plan(program, scenario)
    assert len(run["operations"]) == (2 if scenario == "normal" else 1)
    assert run["geometry"]["setup_calls"] == run["geometry_after"]["setup_calls"] == 1
    assert run["geometry"]["joints"] == run["geometry_after"]["joints"]
    assert run["execution_guard"]["forbidden_calls"] == []
    guarded = run["execution_guard"]["guarded_methods"]
    assert any(name.endswith(".set_dof_positions") for name in guarded)
    assert any(name.endswith(".set_transforms") for name in guarded)
    assert any(name.endswith(".reset") for name in guarded)
    assert run["runtime_image"] == run["runtime_identity"]["image_id"]
    assert run["isaac_version"][0].split("-")[0].split("+")[0] == "6.0.0"
    for relative, expected in run["files"].items():
        path = ROOT / relative
        assert path.is_relative_to(manifest.parent) and path.is_file() and not path.is_symlink()
        assert sha256(path.read_bytes()).hexdigest() == expected
    structure = verify_run(manifest, **example_runs["pins"])
    assert all(segment["evidence_validation"] == "VALID" for segment in structure["segments"])
    assert structure["operation_coverage_complete"] is (scenario != "incomplete")
    replay = replay_run(manifest, **example_runs["pins"])
    assert replay["evidence_validation"] == "VALID", replay
    authority, public = (load_der_public_key(bytes.fromhex(example_runs["pins"][key]))
                         for key in ("authority_public_der_hex", "evidence_public_der_hex"))
    commands, reports = [], []
    for operation, replayed in zip(run["operations"], replay["operations"]):
        assert operation["evidence_validation"] == replayed["evidence_validation"] == "VALID"
        assert operation["motion_verdict"] == replayed["motion_verdict"]
        assert operation["object_verdict"] == replayed["object_verdict"]
        assert operation["reasons"] and replayed["reasons"]
        assert len(operation["segments"]) == 1
        segment = operation["segments"][0]
        wire, bundle = ((ROOT / segment[field]).read_bytes() for field in ("command", "report"))
        assert strict_decode((ROOT / segment["request"]).read_bytes(), MAX_REQUEST_BYTES) == {
            "version": 1, "type": "EXECUTE", "command": wire}
        assert strict_decode((ROOT / segment["response"]).read_bytes(), MAX_RESPONSE_BYTES) == {
            "version": 1, "type": "EVIDENCE", "evidence": bundle}
        command, report = verify_sign1(wire, authority), authenticated_evidence(bundle, public)
        assert report["command_digest"] == sha256(wire).digest()
        assert report["expected_sample_count"] == 1 + len(command["trajectory"]) + command["hold_steps"]
        assert report["outputs"] == list(L.OUTPUTS) and report["units"] == list(L.UNITS)
        assert command["velocity_limits"] == list(L.VELOCITY) and command["effort_limits"] == list(L.EFFORT)
        assert 0 < segment["command_bytes"] == len(wire) <= 65_536
        assert 0 < segment["report_bytes"] == len(bundle) <= 1_048_576
        _compare_observations(report, load(ROOT / segment["joint_observations"]))
        assert any(row[5] != target + [target[-1]]
                   for row, target in zip(report["samples"][1:], command["trajectory"]))
        commands.append(command)
        reports.append(report)
    observed_hold(run, commands[-1], reports[-1])
    return run, replay, commands, reports


def observed_hold(run, command, report):
    """Recompute the observed stop behavior; no requested pose substitutes for it."""
    hold = load(ROOT / run["stop_hold_observations"])
    assert hold["requested_intervals"] == 120
    rows = hold["rows"]
    assert len(rows) == 121
    assert hold["controller_state"] == run["controller_state_after_command"] == report["terminal_state"]
    assert hold["backend_faulted"] is (run["scenario"] == "incomplete")
    assert hold["drive_writes_before"] == hold["drive_writes_after"] == run["requested_drive_writes"]
    assert hold["target_writes_before"] == hold["target_writes_after"]
    assert hold["no_additional_drive_writes"] is True
    assert len(hold["stop_calls"]) == len(run["operations"])
    for stop in hold["stop_calls"]:
        assert stop["returned"] is True
        assert stop["target_writes_after"] == stop["target_writes_before"] + 1
    assert hold["stop_calls"][-1]["reason"] == report["reason"]
    assert hold["stop_calls"][-1]["physics_step"] == rows[0]["physics_step"]
    assert rows[0]["physics_step"] == report["samples"][-1][2] + (run["scenario"] == "incomplete")
    assert hold["final_positions"] == rows[-1]["positions"]
    assert hold["final_velocities"] == rows[-1]["velocities"]
    for row in rows:
        assert len(row["positions"]) == len(row["velocities"]) == 8
        assert all(type(v) in (int, float) and math.isfinite(v) for field in ("positions", "velocities") for v in row[field])
        assert row["objects"]["physics_step"] == row["physics_step"]
        assert row["objects"]["simulation_time_ns"] == row["simulation_time_ns"]
        assert set(row["objects"]["objects"]) == {"R1", "B1"}
    for before, after in zip(rows, rows[1:]):
        assert after["physics_step"] == before["physics_step"] + 1
        assert abs((after["simulation_time_ns"] - before["simulation_time_ns"]) * L.HZ - 1_000_000_000) <= 5 * L.HZ
    assert hold["max_abs_displacement"] == [
        max(abs(row["positions"][i] - rows[0]["positions"][i]) for row in rows) for i in range(8)]
    assert hold["stationary_window_intervals"] == 30
    assert hold["stationary_velocity_thresholds"] == [.01] * 6 + [.001] * 2
    stationary = all(abs(v) <= bound for row in rows[-31:]
                     for v, bound in zip(row["velocities"], hold["stationary_velocity_thresholds"]))
    assert hold["stationary_last_30_intervals"] is stationary
    writes = load(ROOT / run["target_writes"])
    assert len(writes) == hold["target_writes_after"]
    assert writes[-1]["physics_step"] == rows[0]["physics_step"]
    # On sensor loss the existing backend holds its last finite target. It
    # issues one internal fault hold and one controller-requested hold. Neither
    # is a new motion command or a successful acquisition.
    if run["scenario"] == "incomplete":
        assert len(writes) == run["requested_drive_writes"] + 2
        assert writes[-1] == writes[-2]
        assert writes[-1]["targets"] == pytest.approx([q / 1_000_000 for q in command["trajectory"][120]])
    else:
        assert len(writes) == run["requested_drive_writes"] + len(run["operations"])
        assert [round(q * 1_000_000) for q in rows[0]["positions"]] == report["samples"][-1][5]
        assert writes[-1]["targets"] == pytest.approx([q / 1_000_000 for q in command["trajectory"][-1]])


def same_first_trajectory(example_runs, command):
    """Fresh authorizations differ; the complete authored actuator program does not."""
    normal = example_runs["runs"]["normal"]
    assert normal.get("operations"), normal
    authority = load_der_public_key(bytes.fromhex(example_runs["pins"]["authority_public_der_hex"]))
    original = verify_sign1((ROOT / normal["operations"][0]["segments"][0]["command"]).read_bytes(), authority)
    for field in ("trajectory", "hold_steps", "initial_positions", "initial_tolerance", "velocity_limits", "effort_limits",
                  "outputs", "units", "physics_dt", "sample_every_steps", "config_digest"):
        assert encode(command[field]) == encode(original[field]), field


def independent_object_result(run, segment, object_id="R1", destination="A"):
    observations = load(ROOT / segment["object_observations"])
    endpoint = next(row for row in reversed(observations) if row["physics_step"] == segment["physics_step_last"])
    result = assess_objects(observations, object_id, destination, load(PROFILE_PATH), load_policy(),
                            end_step=endpoint["physics_step"], end_time_ns=endpoint["simulation_time_ns"])
    assert result["sensor_authenticated"] is False
    return result


def test_normal_sequence_conformant_and_delivered(example_runs):
    run, replay, commands, reports = checked(example_runs, "normal")
    assert replay["motion_verdict"] == "CONFORMANT"
    assert [(op["object_id"], op["destination"]) for op in run["operations"]] == [("R1", "A"), ("B1", "B")]
    assert all(op["motion_verdict"] == "CONFORMANT" and op["object_verdict"] == "DELIVERED"
               for op in replay["operations"])
    assert commands[0]["boot_id"] == commands[1]["boot_id"]
    assert commands[0]["execution_id"] != commands[1]["execution_id"]
    assert commands[1]["sequence"] == commands[0]["sequence"] + 1
    assert commands[0]["challenge"] != commands[1]["challenge"]
    assert reports[0]["samples"][-1][1:4] == reports[1]["samples"][0][1:4]
    assert reports[0]["samples"][-1][5:] == reports[1]["samples"][0][5:]
    assert all(report["terminal_state"] == "COMPLETE" and report["partial"] is False for report in reports)
    assert run["physics_steps_measured"] == run["requested_drive_writes"] == sum(len(e["samples"]) - 1 for e in reports)
    assert load(ROOT / run["fault_parameters"])["kind"] == "NONE"
    assert run["persistence_observed"] is True
    second_objects = load(ROOT / run["operations"][1]["segments"][0]["object_observations"])
    assert run["persistence_samples"] == len(second_objects)
    assert all(in_destination(row, "R1", "A", load(PROFILE_PATH), load_policy()) for row in second_objects)
    from tools.scene_fixture import contact_diagnostics, contact_requirements_met
    for operation in run["operations"]:
        segment = operation["segments"][0]
        objects = load(ROOT / segment["object_observations"])
        diagnostic = contact_diagnostics(objects, operation["object_id"], segment["phases"], load(PROFILE_PATH))
        assert contact_requirements_met(diagnostic, load(PROFILE_PATH)), diagnostic
        assert independent_object_result(run, segment, operation["object_id"], operation["destination"])["object_verdict"] == "DELIVERED"


def test_moved_object_conformant_but_not_delivered(example_runs):
    run, replay, commands, reports = checked(example_runs, "missed_grasp")
    same_first_trajectory(example_runs, commands[0])
    assert replay["motion_verdict"] == "CONFORMANT"
    assert replay["operations"][0]["object_verdict"] == "NOT_DELIVERED"
    assert reports[0]["terminal_state"] == "COMPLETE" and reports[0]["partial"] is False
    fault = load(ROOT / run["fault_parameters"])
    assert fault["kind"] == "OBJECT_RELOCATED_BEFORE_RUN"
    assert fault["object_id"] == "R1"
    segment = run["operations"][0]["segments"][0]
    assert independent_object_result(run, segment)["object_verdict"] == "NOT_DELIVERED"
    profile = load(PROFILE_PATH)
    objects = load(ROOT / segment["object_observations"])
    displaced = profile["empty_grasp_setup"]["position_m"]
    assert objects[0]["objects"]["R1"]["position"][:2] == pytest.approx(displaced[:2], abs=.001)
    original = next(obj["position_m"] for obj in profile["objects"] if obj["id"] == "R1")
    assert math.dist(original[:2], objects[0]["objects"]["R1"]["position"][:2]) > .1
    assert all(not in_destination(row, "R1", "A", profile, load_policy()) for row in objects)


def test_physx_obstruction_deviated(example_runs):
    run, replay, commands, reports = checked(example_runs, "obstructed")
    same_first_trajectory(example_runs, commands[0])
    assert replay["motion_verdict"] == "DEVIATED", replay
    assert replay["operations"][0]["captured_tracking_deviation"] is True
    assert reports[0]["terminal_state"] == "COMPLETE" and reports[0]["partial"] is False
    fault = load(ROOT / run["fault_parameters"])["constraint"]
    assert fault["kind"] == "PHYSX_ARM_DOF_CONSTRAINT"
    assert fault["method"] == "PhysX articulation DOF hard limits"
    assert fault["actuator"] == fault["output"] == "joint1"
    assert fault["output_index"] == 0 and fault["units"] == "rad"
    assert fault["direct_state_assignment"] is False
    assert fault["half_width"] == 1e-5
    assert fault["applied_at"]["relative_physics_step"] == 0
    runtime_index = fault["runtime_index"]
    assert fault["limits"] == pytest.approx([fault["initial_position"] - 1e-5, fault["initial_position"] + 1e-5], abs=1e-8)
    assert fault["old_limits"][1] - fault["old_limits"][0] > 1
    assert fault["all_limits_after"][0][runtime_index] == fault["limits"]
    assert all(before == after for index, (before, after) in enumerate(zip(
        fault["all_limits_before"][0], fault["all_limits_after"][0])) if index != runtime_index)
    tolerance = load_policy()["motion"]["tracking_tolerance"][0]
    targets = [row[0] for row in commands[0]["trajectory"]]
    actual = [row[5][0] for row in reports[0]["samples"]]
    assert max(targets) - min(targets) > 5 * tolerance
    assert max(actual) - min(actual) < 1_000  # Real hard stops at +/- 1e-5 rad.
    assert any(abs(row[5][0] - target[0]) > tolerance
               for row, target in zip(reports[0]["samples"][1:], commands[0]["trajectory"]))
    segment = run["operations"][0]["segments"][0]
    object_result = independent_object_result(run, segment)
    assert object_result["object_verdict"] == replay["operations"][0]["object_verdict"]
    assert object_result["object_verdict"] in ("DELIVERED", "NOT_DELIVERED")


def test_real_incomplete_acquisition_unknown(example_runs):
    run, replay, commands, reports = checked(example_runs, "incomplete")
    same_first_trajectory(example_runs, commands[0])
    assert replay["motion_verdict"] == "UNKNOWN", replay
    operation = replay["operations"][0]
    assert operation["captured_tracking_deviation"] is False
    report = reports[0]
    assert report["terminal_state"] == "ABORTED" and report["partial"] is True
    assert report["reason"] == "BACKEND"
    assert report["sample_count"] == len(report["samples"]) == 121 < report["expected_sample_count"]
    assert run["physics_steps_measured"] == run["requested_drive_writes"] == 121
    assert report["samples"][-1][2] - report["samples"][0][2] == 120
    assert [row[0] for row in report["samples"]] == list(range(121))
    tolerance = load_policy()["motion"]["tracking_tolerance"]
    for index, row in enumerate(report["samples"]):
        target = commands[0]["initial_positions"] if index == 0 else commands[0]["trajectory"][index - 1]
        if index:
            target = target + [target[-1]]
        allowed = commands[0]["initial_tolerance"] if index == 0 else tolerance
        assert all(abs(q - t) <= bound for q, t, bound in zip(row[5], target, allowed))
        assert row[6] == [True] * 8
    segment = run["operations"][0]["segments"][0]
    assert segment["physics_step_last"] > report["samples"][-1][2]
    objects = independent_object_result(run, segment)
    assert objects["object_verdict"] == operation["object_verdict"]
    assert objects["object_verdict"] in ("DELIVERED", "NOT_DELIVERED")
    assert operation["objects"]["endpoint_source"] == "retained independent object endpoint (unsigned)"
    acquired = load(ROOT / segment["acquired_object_observations"])
    all_objects = load(ROOT / segment["object_observations"])
    assert len(acquired) == len(report["samples"])
    assert all_objects[:len(acquired)] == acquired
    assert acquired[-1]["physics_step"] == report["samples"][-1][2]
    assert all_objects[-1]["physics_step"] == acquired[-1]["physics_step"] + 121
    fault = load(ROOT / run["fault_parameters"])["acquisition"]
    assert fault["kind"] == "NATIVE_PHYSX_ACQUISITION_INVALIDATION"
    assert fault["expected_trigger_relative_physics_step"] == 121
    assert fault["expected_complete_prefix_samples"] == 121
    assert fault["interruption_calls"] == 1 and fault["triggered"] is True
    assert fault["scheduled_step_match"] is True
    assert fault["trigger_at"]["relative_physics_step"] == 121
    assert fault["trigger_at"]["physics_step"] == report["samples"][-1][2] + 1
    assert fault["source_valid_before"] is True and fault["source_valid_after"] is False
    assert fault["native_read_failed"] is True and fault["native_read_error"]["type"]
    assert not fault.get("unexpected_native_read_success", False)
    assert fault["physics_still_playing"] is True and fault["independent_view_live"] is True
    assert fault["getter_restored"] is True and fault["source_valid_after_restore"] is False
    assert fault["source_revived"] is False and fault["synthetic_measurements"] is False
    assert fault["fixture_generated_sensor_exception"] is False
    setup = fault["setup"]
    assert setup["source_valid"] is True and setup["positions_equal"] is True and setup["shape"] == [1, 8]
    assert setup["source_dof_paths"] == setup["original_dof_paths"]
    assert setup["source_prim_paths"] == setup["original_prim_paths"]
    assert setup["original_positions_runtime_order"] == setup["source_positions_runtime_order"]
    assert "omni.physics.tensors" in setup["source_class"]
    assert "omni.physics.tensors" in setup["getter_class"]


def test_all_examples_have_genuine_simulator_recordings(example_runs):
    from tools.capture_full_model import inspect_png

    summary = load(OUTPUT / "examples.json")
    indexed = {entry["run_id"]: entry for entry in summary["runs"]}
    assert len(indexed) == len(summary["runs"])
    for old in example_runs["earlier"]:
        assert indexed[old["run_id"]] == old
        assert sha256((ROOT / old["manifest"]).read_bytes()).hexdigest() == old["sha256"]
    for scenario in SCENARIOS:
        run = example_runs["runs"][scenario]
        assert "fixture_exception" not in run, run
        entry = indexed[run["run_id"]]
        assert entry["scenario"] == scenario and entry["status"] == run["status"]
        assert sha256((ROOT / entry["manifest"]).read_bytes()).hexdigest() == entry["sha256"]
        assert len(run["recordings"]) == (4 if scenario == "normal" else 3)
        assert run["camera_enabled"] is True and run["geometry"]["camera_present"] is True
        assert run["recording_index"] in run["files"]
        assert run["stop_hold_observations"] in run["files"]
        index = load(ROOT / run["recording_index"])
        assert index["status"] == "CLOSED"
        assert index["runtime_image"] == run["runtime_image"]
        assert index["model_manifest_sha256"] == run["model_sha256"]
        assert index["output_order"] == list(L.OUTPUTS)
        assert index["camera"]["prim"] == load(PROFILE_PATH)["camera"]["prim"]
        frames = index["records"]
        assert [frame["image_path"] for frame in frames] == run["recordings"]
        assert [frame["label"] for frame in frames] == (
            ["setup", "operation-1-returned", "operation-2-returned", "post-hold"] if scenario == "normal"
            else ["setup", "operation-1-returned", "post-hold"])
        assert frames[0]["before"]["physics_step"] < frames[-1]["before"]["physics_step"]
        # Bind the frames to this actual execution and unsigned post-stop
        # interval; a valid PNG from a different scene/run is insufficient.
        public = load_der_public_key(bytes.fromhex(example_runs["pins"]["evidence_public_der_hex"]))
        reports = [authenticated_evidence((ROOT / op["segments"][0]["report"]).read_bytes(), public)
                   for op in run["operations"]]
        assert frames[0]["before"]["physics_step"] == reports[0]["samples"][0][2]
        assert [round(q * 1_000_000) for q in frames[0]["before"]["joint_positions"]] == reports[0]["samples"][0][5]
        hold = load(ROOT / run["stop_hold_observations"])
        for frame, row in ((frames[-2], hold["rows"][0]), (frames[-1], hold["rows"][-1])):
            assert frame["before"]["physics_step"] == row["physics_step"]
            assert frame["before"]["simulation_time_ns"] == row["simulation_time_ns"]
            assert frame["before"]["joint_positions"] == row["positions"]
            assert frame["before"]["objects"] == row["objects"]
        if scenario == "normal":
            assert frames[1]["before"]["physics_step"] == reports[0]["samples"][-1][2]
            assert [round(q * 1_000_000) for q in frames[1]["before"]["joint_positions"]] == reports[0]["samples"][-1][5]
            assert in_destination(frames[1]["before"]["objects"], "R1", "A", load(PROFILE_PATH), load_policy())
            assert in_destination(frames[2]["before"]["objects"], "B1", "B", load(PROFILE_PATH), load_policy())
        for frame in frames:
            assert frame["status"] == "CAPTURED", frame
            assert frame["metadata_path"] in run["files"]
            assert load(ROOT / frame["metadata_path"]) == frame
            assert frame["physics_advanced"] is False and frame["timeline_restored_without_step"] is True
            assert frame["timeline_playing_before"] == frame["timeline_playing_after"]
            assert frame["before"] == frame["after_render"] == frame["after"]
            assert frame["before"]["physics_step"] == frame["before"]["objects"]["physics_step"]
            assert frame["before"]["simulation_time_ns"] == frame["before"]["objects"]["simulation_time_ns"]
            assert len(frame["before"]["joint_positions"]) == len(frame["before"]["joint_velocities"]) == 8
            assert frame["image"] == inspect_png(ROOT / frame["image_path"])
            assert frame["capture_seconds"] > 0
        for relative in run["recordings"]:
            assert relative in run["files"]
            assert inspect_png(ROOT / relative)["sha256"] == run["files"][relative]

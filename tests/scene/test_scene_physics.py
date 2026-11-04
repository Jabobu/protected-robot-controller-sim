"""S6-01 acceptance: only real signed PhysX runs can satisfy these assertions.

Execute with /isaac-sim/python.sh in the pinned credential-free container.
No host execution, simulated fallback, automatic parameter tuning or retries.
"""
from hashlib import sha256
import json
import math
from pathlib import Path

import pytest

from tools.scene_fixture import ROOT, OUTPUT, PROFILE_PATH, TRAJECTORY_PATH


def load(path):
    return json.loads(Path(path).read_text())


@pytest.fixture(scope="module")
def calibrations(scene_simulation_app):
    from tools.controller_fixture import development_keys
    from tools.scene_fixture import run_calibration
    keys = development_keys()
    runs = {}
    # Independent scenes only BETWEEN runs. Failure is retained and does not
    # prevent the other calibration probe from being attempted and recorded.
    for scenario, camera in (("normal", False), ("empty_grasp", True)):
        try:
            runs[scenario] = run_calibration(scenario=scenario, camera=camera, keys=keys)
        except Exception as error:
            entry = load(OUTPUT / "normal.json")["runs"][-1]
            runs[scenario] = load(ROOT / entry["manifest"])
            runs[scenario]["fixture_exception"] = repr(error)
    return runs


def complete(calibrations, name="normal"):
    run = calibrations[name]
    assert "fixture_exception" not in run, run
    assert run["status"] != "EXECUTION_FAILED", run
    return run


def test_scene_geometry_and_output_mapping(calibrations):
    from protected_robot_controller import limits as L
    from tools.scene_fixture import read_configuration, expand_operation
    p, program = read_configuration()
    run = calibrations["normal"]
    assert "geometry" in run, run
    g = run["geometry"]
    assert len(g["robot_bodies"]) == 10
    assert len(g["joints"]) == 10  # fixed world root + six arm + end + two fingers
    assert all(path.startswith("/B601/Physics/") for path in g["joints"])
    assert g["table_fixed"] is True
    assert g["table_dimensions_m"] == pytest.approx(p["work_surface"]["dimensions_m"])
    assert g["setup_calls"] == 1
    assert g["output_order"] == list(L.OUTPUTS) == p["mapping"]["outputs"]
    assert [g["runtime_output_names"][i] for i in g["output_indices"]] == list(L.OUTPUTS)
    assert g["effort_caps"] == pytest.approx([36, 36, 36, 14, 14, 14, 12, 0])
    assert g["velocity_caps"] == pytest.approx([.5]*6 + [.04, .04])
    assert g["solver"] == "TGS"
    assert g["physics_dt_seconds"] == 1/120
    assert g["gravity"][0] == [0, 0, -1]
    assert g["gravity"][1] == pytest.approx(9.81)
    assert g["object_ids"] == ["B1", "R1"]
    for obj in p["objects"]:
        assert g["object_dimensions_m"][obj["id"]] == pytest.approx(obj["dimensions_m"])
        assert g["object_mass_kg"][obj["id"]] == pytest.approx(obj["mass_kg"])
        actual = g["initial_objects"]["objects"][obj["id"]]
        assert actual["position"][:2] == pytest.approx(obj["position_m"][:2], abs=.001)
        assert actual["position"][2] == pytest.approx(.06, abs=.001)
        source = p["source_area"]
        assert all(abs(x-c) < h for x,c,h in zip(actual["position"], source["center_xy_m"], source["half_extents_xy_m"]))
    for operation in program["operations"]:
        rows, phases = expand_operation(program, operation)
        assert len(rows) + program["hold_steps"] <= L.MAX_DURATION_STEPS
        assert {"approach", "grasp", "lift", "transport", "release", "retreat"} <= {x["name"] for x in phases}
        assert rows[-1] == program["initial_target"]
    assert run["profile_sha256"] == sha256(PROFILE_PATH.read_bytes()).hexdigest()
    assert run["trajectory_sha256"] == sha256(TRAJECTORY_PATH.read_bytes()).hexdigest()
    assert run["seed"] == p["seed"]
    assert run["runtime_image"] == run["runtime_identity"]["image_id"]


def test_signed_sequential_placements_persist(calibrations):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from tools.scene_calibration_check import CalibrationChecker, assess_objects, in_destination
    from tools.controller_fixture import authenticated_evidence
    from protected_robot_controller.protocol import verify_sign1
    run = complete(calibrations)
    profile = load(PROFILE_PATH)
    assert [(op["object_id"], op["destination"]) for op in run["operations"]] == [("R1", "A"), ("B1", "B")]
    checker = None
    commands, evidence, objects = [], [], []
    for op in run["operations"]:
        assert op["evidence_validation"] == "VALID", op
        assert op["motion_verdict"] == "CONFORMANT", op
        assert op["object_verdict"] == "DELIVERED", op
        assert len(op["segments"]) == 1
        seg = op["segments"][0]
        context = load(ROOT / seg["public_context"])
        authority = load_der_public_key(bytes.fromhex(context["authority_public_der_hex"]))
        public = load_der_public_key(bytes.fromhex(context["evidence_public_der_hex"]))
        if checker is None:
            checker = CalibrationChecker(authority, public, profile["candidate_policy"]["tracking_tolerance"])
        command = (ROOT / seg["command"]).read_bytes()
        report = (ROOT / seg["report"]).read_bytes()
        result = checker.assess_segment(command, report)
        assert result["evidence_validation"] == "VALID", result
        assert result["motion_verdict"] == "CONFORMANT", result
        assert len(command) == seg["command_bytes"] <= 65_536
        assert len(report) == seg["report_bytes"] <= 1_048_576
        commands.append(verify_sign1(command, authority))
        evidence.append(authenticated_evidence(report, public))
        rows = load(ROOT / seg["object_observations"])
        objects.append(rows)
        assert assess_objects(rows, op["object_id"], op["destination"], profile)["object_verdict"] == "DELIVERED"
    assert commands[0]["boot_id"] == commands[1]["boot_id"]
    assert commands[0]["execution_id"] != commands[1]["execution_id"]
    assert commands[1]["sequence"] == commands[0]["sequence"] + 1
    assert commands[0]["challenge"] != commands[1]["challenge"]
    assert evidence[0]["samples"][-1][1:4] == evidence[1]["samples"][0][1:4]
    assert evidence[0]["samples"][-1][5] == evidence[1]["samples"][0][5]
    assert objects[0][-1]["physics_step"] == objects[1][0]["physics_step"]
    assert run["persistence_observed"] is True
    assert run["persistence_samples"] == len(objects[1])
    assert all(in_destination(row, "R1", "A", profile) for row in objects[1])
    assert run["geometry_after"]["joints"] == run["geometry"]["joints"]
    assert run["physics_steps_measured"] == run["requested_drive_writes"] == sum(len(e["samples"])-1 for e in evidence)
    assert run["status"] == "OBSERVED_NORMAL"
    for path, expected in run["files"].items():
        assert (ROOT / path).is_file() and not (ROOT / path).is_symlink()
        assert sha256((ROOT / path).read_bytes()).hexdigest() == expected


def test_contact_grasp_transport_release_without_state_assignment(calibrations):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from tools.controller_fixture import authenticated_evidence
    from tools.integrated_fixture import _compare_observations
    from tools.scene_fixture import contact_diagnostics
    run = complete(calibrations)
    profile = load(PROFILE_PATH)
    policy = profile["candidate_policy"]
    guard = run["execution_guard"]
    assert guard["forbidden_calls"] == []
    assert any(name.endswith(".set_dof_positions") for name in guard["guarded_methods"])
    assert any(name.endswith(".set_transforms") for name in guard["guarded_methods"])
    assert any(name.endswith(".reset") for name in guard["guarded_methods"])
    for op in run["operations"]:
        seg = op["segments"][0]
        objects = load(ROOT / seg["object_observations"])
        diagnostics = contact_diagnostics(objects, op["object_id"], seg["phases"], profile)
        assert diagnostics == op["contact_diagnostics"]
        assert diagnostics["two_finger_contact_steps"].get("grasp_hold", 0) >= policy["minimum_contact_steps"], diagnostics
        assert diagnostics["airborne_two_finger_contact_steps"].get("transport", 0) >= policy["minimum_airborne_contact_steps"], diagnostics
        assert diagnostics["maximum_lift_m"] >= policy["minimum_lift_m"], diagnostics
        assert diagnostics["maximum_xy_displacement_m"] >= policy["minimum_transport_m"], diagnostics
        assert op["contact_requirements_met"] is True
        context = load(ROOT / seg["public_context"])
        public = load_der_public_key(bytes.fromhex(context["evidence_public_der_hex"]))
        evidence = authenticated_evidence((ROOT / seg["report"]).read_bytes(), public)
        independent = load(ROOT / seg["joint_observations"])
        _compare_observations(evidence, independent)
        reference = load(ROOT / seg["reference"])["trajectory"]
        assert any(row[5] != target+[target[-1]] for row,target in zip(evidence["samples"][1:], reference))
        assert all(evidence["samples"][0][2]+i == row[2] for i,row in enumerate(evidence["samples"]))
        assert evidence["terminal_state"] == "COMPLETE" and not evidence["partial"]
        for row in objects[-policy["settling_steps"]:]:
            state = row["objects"][op["object_id"]]
            assert all(math.sqrt(sum(x*x for x in f)) < policy["release_contact_max_n"] for f in state["finger_forces_n"])


def test_camera_optional_in_headless_mode(calibrations):
    normal = complete(calibrations)
    empty = complete(calibrations, "empty_grasp")
    assert normal["camera_enabled"] is False and normal["geometry"]["camera_present"] is False
    assert empty["camera_enabled"] is True and empty["geometry"]["camera_present"] is True
    assert empty["geometry"]["output_order"] == normal["geometry"]["output_order"]
    normal_seg = normal["operations"][0]["segments"][0]
    empty_op = empty["operations"][0]
    empty_seg = empty_op["segments"][0]
    assert empty_seg["reference_trajectory_sha256"] == normal_seg["reference_trajectory_sha256"]
    assert load(ROOT / empty_seg["reference"]) == load(ROOT / normal_seg["reference"])
    assert empty_op["evidence_validation"] == "VALID"
    assert empty_op["object_verdict"] == "NOT_DELIVERED", empty_op
    assert empty["empty_grasp_feasible_under_candidate_policy"] == (empty_op["motion_verdict"] == "CONFORMANT")
    # Infeasibility is a retained calibration result, never a widened tolerance
    # or a forced conformance label. The later campaign requires feasibility.
    assert empty_op["motion_verdict"] in ("CONFORMANT", "DEVIATED")
    assert empty_op["motion_diagnostics"]["coverage"]["count_complete"]
    camera = load(PROFILE_PATH)["camera"]
    from pxr import Gf
    view = Gf.Matrix4d().SetLookAt(Gf.Vec3d(*camera["eye_m"]), Gf.Vec3d(*camera["target_m"]), Gf.Vec3d(*camera["up"]))
    low, high = camera["framing_bounds_m"]
    # Every conservative whole-scene bounding-box corner lies inside the fixed
    # camera frustum. No camera sensor, rendering update or image drives physics.
    for corner in range(8):
        point = view.Transform(Gf.Vec3d(*(high[i] if corner & (1<<i) else low[i] for i in range(3))))
        depth = -point[2]
        assert camera["clipping_m"][0] < depth < camera["clipping_m"][1]
        assert abs(point[0]/depth) < camera["horizontal_aperture_mm"]/(2*camera["focal_length_mm"])
        assert abs(point[1]/depth) < camera["vertical_aperture_mm"]/(2*camera["focal_length_mm"])

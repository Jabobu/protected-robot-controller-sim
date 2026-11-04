"""S6 test-result publication, never a supervisor or a controller dependency.

The five existing suites populate one record in any order from pytest reports.
A repeated suite or source change starts a fresh cycle; incomplete sessions
cannot supply passing results. No expected outcome turns a missing case green.
Only artifact outputs are written; accepted tests/configuration stay immutable.
"""

from hashlib import sha256
import json
from pathlib import Path
import secrets
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "artifacts/s6"
STATE = DIRECTORY / "observed_results.json"
MATRIX = ROOT / "artifacts/functional_release_matrix.json"
REQUIRED = {
    "test_model.py": ("test_b601_model_loads", "test_all_output_channels_mapped"),
    "test_physics.py": ("test_physics_drives_not_teleport", "test_blocked_joint_reports_real_output",
                        "test_gripper_output_feedback", "test_bounded_effort",
                        "test_each_independent_actuator_can_be_blocked", "test_reproducible_steps_and_deadlines"),
    "test_controller.py": ("test_valid_signed_command_executes", "test_rejects_invalid_signature",
                           "test_rejects_wrong_controller", "test_rejects_expired_command",
                           "test_rejects_replay", "test_enforces_actuator_limits",
                           "test_signed_evidence_binds_command", "test_controller_fault_stop"),
    "test_integrated.py": ("test_signed_normal_trace_verified_success",
                           "test_signed_obstructed_trace_verified_failure", "test_evidence_contains_real_output_samples"),
    "test_attacks.py": ("test_wrong_key_and_address_no_motor_writes", "test_expired_and_replayed_no_motor_writes",
                        "test_modified_evidence_is_rejected", "test_untrusted_sensor_injection_denied",
                        "test_untrusted_motor_bypass_denied", "test_sensor_failure_not_proven",
                        "test_connection_loss_stop_behavior", "test_simulation_pause_does_not_extend_deadline",
                        "test_restart_invalidates_boot_commands"),
}
SCENARIOS = ("forged_command", "replayed_command", "altered_evidence", "sensor_injection",
             "direct_motor_bypass", "invalid_acquisition", "connection_loss")
ACTUATORS = tuple(f"joint{i}" for i in range(1, 7)) + ("gripper",)
SIGNED_OBSTRUCTION_CASES = {
    f"test_each_actuator_signed_obstruction_verified_failure[{actuator}]" for actuator in ACTUATORS
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".tmp")
    pending.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    pending.replace(path)


def source_hashes():
    files = {p for folder in ("protected_robot_controller", "tools", "tests")
             for p in (ROOT / folder).rglob("*") if p.suffix in (".py", ".scad", ".json")}
    files.update(ROOT / p for p in ("artifacts/model_manifest.json", "assets/b601_rs.usda",
                                   "README.md", "requirements-controller.txt"))
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in sorted(files) if p.is_file()}


def begin(suites, command, junit):
    # Even a partial rerun invalidates the last aggregate until its new results
    # and linked artifacts are checked. Never leave a stale success sidecar.
    (DIRECTORY / "release_observations.json").unlink(missing_ok=True)
    (DIRECTORY / "publication_error.json").unlink(missing_ok=True)
    hashes = source_hashes()
    previous = json.loads(STATE.read_text()) if STATE.exists() else {}
    # The external runner may start with integrated tests. Do not discard that
    # observed result when model tests arrive later. Repeating any suite begins
    # a new cycle, as does an abandoned session or a source/configuration change.
    prior_suites = previous.get("suites", {})
    if (set(suites) & set(prior_suites)
            or any(entry.get("status") == "RUNNING" for entry in prior_suites.values())
            or previous.get("source_sha256") != hashes):
        previous = {"stage": "S6", "run_id": secrets.token_hex(12), "source_sha256": hashes,
                    "scope": "Trusted-host SIM_FUNCTIONAL observations; external acceptance pending",
                    "suites": {}}
        for path in (ROOT / "artifacts/demo/full_arm_gripper.png", ROOT / "artifacts/demo/full_arm_gripper.json"):
            path.unlink(missing_ok=True)
    for suite in suites:
        previous["suites"][suite] = {"status": "RUNNING", "command": command, "junit": junit, "phases": []}
    write_json(STATE, previous)
    write_json(MATRIX, {f"A{i}": "NOT_RUN" for i in range(1, 9)})
    return previous


def suite_result(suite, phases, collected):
    """Require all selected cases plus every manifest name and all three phases."""
    cases = {}
    for report in phases:
        cases.setdefault(report["nodeid"], {})[report["phase"]] = report["outcome"]
    names = {node.rsplit("::", 1)[-1].split("[", 1)[0] for node in cases}
    signed_coverage = (suite != "test_integrated.py" or SIGNED_OBSTRUCTION_CASES <= {
        node.rsplit("::", 1)[-1] for node in cases})
    complete = (bool(collected) and set(cases) == set(collected)
                and set(REQUIRED[suite]) <= names
                and signed_coverage
                and all(value == {"setup": "passed", "call": "passed", "teardown": "passed"}
                        for value in cases.values()))
    return {"status": "PASS" if complete else "FAIL", "case_count": len(cases),
            "required_cases": list(REQUIRED[suite]), "collected": collected, "phases": phases}


def preserve_physics():
    summary = json.loads((ROOT / "artifacts/physics_summary.json").read_text())
    for name, run in summary["runs"].items():
        source = Path(run["evidence_path"])
        if sha256(source.read_bytes()).hexdigest() != run["evidence_sha256"]:
            raise ValueError(f"Physics raw bundle hash mismatch: {name}")
        destination = DIRECTORY / "physics" / f"{name}.cbor"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        run["evidence_path"] = str(destination.relative_to(ROOT))
    write_json(DIRECTORY / "physics_summary.json", summary)


def validate_artifacts():
    from tools.capture_full_model import IMAGE, METADATA, inspect_png
    from tools.integrated_fixture import check_recorded_run
    from tools.signed_obstructions import check_signed_obstruction

    checked = {name: check_recorded_run(ROOT / "artifacts/evidence", name) for name in ("normal", "blocked")}
    if [checked[name]["verdict"] for name in ("normal", "blocked")] != ["VERIFIED_SUCCESS", "VERIFIED_FAILURE"]:
        raise ValueError("Normal/blocked signed evidence did not verify as required")
    # S2 also writes checker_summary.json (its unsigned, nested legacy format).
    # The release summary is an OUTPUT derived from original signed bytes,
    # never an input trusted for verdicts. Publish it after all checks below.
    # Unsigned S2 obstruction records cannot establish A3. Reverify signatures,
    # real-observer agreement, unchanged motion, and the selected output's jam
    # for all seven independently actuated outputs (both fingers for gripper).
    signed_obstructions = {
        actuator: {**check_signed_obstruction(ROOT / "artifacts/evidence", actuator),
                   "evidence_path": f"artifacts/evidence/blocked_{actuator}.cbor"}
        for actuator in ACTUATORS
    }
    paused = check_recorded_run(ROOT / "artifacts/evidence", "paused")
    if paused["verdict"] != "NOT_PROVEN":
        raise ValueError("Paused physics evidence incorrectly proves movement")
    image = inspect_png(IMAGE)
    capture = json.loads(METADATA.read_text())
    if (capture.get("status") != "CAPTURED" or capture["image"] != image
            or capture["model_manifest_sha256"] != sha256((ROOT / "artifacts/model_manifest.json").read_bytes()).hexdigest()
            or capture["observed_outputs"] != 8 or capture["rigid_bodies"] != 10):
        raise ValueError("Full model capture is missing or inconsistent")
    attacks = json.loads((ROOT / "artifacts/attack_matrix.json").read_text())
    if any(attacks.get(name) != "PASS" for name in SCENARIOS):
        raise ValueError("Required observed attack scenarios are incomplete")
    for name, entry in attacks["cases"].items():
        if entry["status"] != "PASS":
            raise ValueError(f"Attack record is missing or changed: {name}")
        if "record" in entry:
            if sha256((ROOT / entry["record"]).read_bytes()).hexdigest() != entry["record_sha256"]:
                raise ValueError(f"Attack record hash changed: {name}")
        elif not entry.get("cases") or any(attacks["cases"][child]["status"] != "PASS" for child in entry["cases"]):
            raise ValueError(f"Attack case group is incomplete: {name}")
    hashes = source_hashes()
    for path, digest in attacks["source_sha256"].items():
        if hashes.get(path) != digest:
            raise ValueError(f"Stale attack source: {path}")
    for name in ("normal", "blocked", "paused", *(f"blocked_{a}" for a in ACTUATORS)):
        context = json.loads((ROOT / f"artifacts/evidence/{name}.context.json").read_text())
        for path, digest in context["metadata"]["source_sha256"].items():
            if hashes.get(path) != digest:
                raise ValueError(f"Stale signed-run source: {path}")
    physics = json.loads((DIRECTORY / "physics_summary.json").read_text())
    for run in physics["runs"].values():
        if sha256((ROOT / run["evidence_path"]).read_bytes()).hexdigest() != run["evidence_sha256"]:
            raise ValueError("Retained physical-obstruction artifact changed")
    for actuator in ACTUATORS:
        if physics["runs"][f"obstructed_{actuator}"]["status"] != "OBSTRUCTED_MOTION":
            raise ValueError("Independent actuator obstruction missing")
    if not (ROOT / "README.md").is_file():
        raise ValueError("Missing project README with physical hardware boundary")
    return {"signed_runs": checked, "signed_obstructions": signed_obstructions,
            "paused": paused, "capture": image,
            "attack_run_id": attacks["run_id"], "source_sha256": hashes}


def finish(state, phases, collected, exitstatus):
    for suite, nodes in collected.items():
        entry = state["suites"][suite]
        entry.update(suite_result(suite, [p for p in phases if p["nodeid"] in nodes], nodes))
        if exitstatus:
            entry["status"] = "FAIL"
    if source_hashes() != state["source_sha256"]:
        raise ValueError("Source/configuration changed during S6 run")
    write_json(STATE, state)
    if "test_physics.py" in collected and state["suites"]["test_physics.py"]["status"] == "PASS":
        preserve_physics()
    complete = set(state["suites"]) == set(REQUIRED) and all(v["status"] == "PASS" for v in state["suites"].values())
    if complete:
        result = validate_artifacts()
        result.update(run_id=state["run_id"], status="OBSERVED_FUNCTIONAL_RESULTS", acceptance="EXTERNAL_SUPERVISOR_PENDING")
        write_json(DIRECTORY / "release_observations.json", result)
        write_json(ROOT / "artifacts/checker_summary.json", result["signed_runs"])
        write_json(MATRIX, {f"A{i}": "FUNCTIONAL_ONLY" if i in (4, 7, 8) else "PASS" for i in range(1, 9)})

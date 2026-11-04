"""Publication accounting only. These unit records are not physics evidence."""

import json

import pytest

from tools import functional_release as release


def model_phases():
    nodes = [f"tests/acceptance/test_model.py::{name}" for name in release.REQUIRED["test_model.py"]]
    phases = [{"nodeid": node, "phase": phase, "outcome": "passed"}
              for node in nodes for phase in ("setup", "call", "teardown")]
    return nodes, phases


@pytest.mark.parametrize("fault", ["missing_case", "missing_teardown", "skipped", "failed", "setup_error", "unreported_collected"])
def test_incomplete_reports_cannot_publish_pass(fault):
    nodes, phases = model_phases()
    if fault == "missing_case":
        nodes = nodes[:1]
        phases = phases[:3]
    elif fault == "missing_teardown":
        phases.pop()
    elif fault in ("skipped", "failed"):
        phases[1]["outcome"] = fault
    elif fault == "setup_error":
        phases[0]["outcome"] = "failed"
        phases.pop(1)
    else:
        nodes.append("tests/acceptance/test_model.py::unreported")
    assert release.suite_result("test_model.py", phases, nodes)["status"] == "FAIL"


def test_complete_phase_accounting():
    nodes, phases = model_phases()
    assert release.suite_result("test_model.py", phases, nodes)["status"] == "PASS"
    assert release.suite_result("test_model.py", [], [])["status"] == "FAIL"


def test_safety_note_changes_invalidate_source_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    note = tmp_path / "README.md"
    note.write_text("Physical safety requirements\n")
    before = release.source_hashes()
    assert "README.md" in before
    note.write_text("Changed physical safety requirements\n")
    assert release.source_hashes()["README.md"] != before["README.md"]


@pytest.fixture
def isolated_records(monkeypatch, tmp_path):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "DIRECTORY", tmp_path / "artifacts/s6")
    monkeypatch.setattr(release, "STATE", tmp_path / "artifacts/s6/observed_results.json")
    monkeypatch.setattr(release, "MATRIX", tmp_path / "artifacts/functional_release_matrix.json")
    monkeypatch.setattr(release, "source_hashes", lambda: {"fixture": "unit-only"})
    return tmp_path


def test_model_rerun_invalidates_old_results_and_image(isolated_records):
    first = release.begin(["test_controller.py"], "unit-test", None)
    image = isolated_records / "artifacts/demo/full_arm_gripper.png"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"unit-only placeholder")
    new = release.begin(["test_model.py"], "unit-test", None)
    assert new["run_id"] != first["run_id"]
    assert set(new["suites"]) == {"test_model.py"}
    assert not image.exists()
    assert set(json.loads(release.MATRIX.read_text()).values()) == {"NOT_RUN"}


def test_source_change_invalidates_prior_success(isolated_records, monkeypatch):
    old = release.begin(["test_model.py"], "unit-test", None)
    monkeypatch.setattr(release, "source_hashes", lambda: {"fixture": "changed-unit-only"})
    new = release.begin(["test_controller.py"], "unit-test", None)
    assert new["run_id"] != old["run_id"]
    assert "test_model.py" not in new["suites"]


def test_partial_rerun_removes_old_release_claim(isolated_records):
    release.begin(["test_model.py"], "unit-test", None)
    success = release.DIRECTORY / "release_observations.json"
    error = release.DIRECTORY / "publication_error.json"
    success.write_text('{"status":"OBSERVED_FUNCTIONAL_RESULTS"}')
    error.write_text('{"traceback":"old error"}')
    release.begin(["test_controller.py"], "unit-test", None)
    assert not success.exists() and not error.exists()
    assert set(json.loads(release.MATRIX.read_text()).values()) == {"NOT_RUN"}


def test_failing_session_blocks_otherwise_passing_reports(isolated_records):
    nodes, phases = model_phases()
    state = release.begin(["test_model.py"], "unit-test", None)
    release.finish(state, phases, {"test_model.py": nodes}, 2)
    assert json.loads(release.STATE.read_text())["suites"]["test_model.py"]["status"] == "FAIL"
    assert set(json.loads(release.MATRIX.read_text()).values()) == {"NOT_RUN"}


def integrated_phases():
    names = [*release.REQUIRED["test_integrated.py"], *sorted(release.SIGNED_OBSTRUCTION_CASES)]
    nodes = [f"tests/acceptance/test_integrated.py::{name}" for name in names]
    phases = [{"nodeid": node, "phase": phase, "outcome": "passed"}
              for node in nodes for phase in ("setup", "call", "teardown")]
    return nodes, phases


def test_original_integrated_cases_alone_cannot_publish_a3():
    nodes, phases = integrated_phases()
    original = nodes[:len(release.REQUIRED["test_integrated.py"])]
    reports = [phase for phase in phases if phase["nodeid"] in original]
    assert release.suite_result("test_integrated.py", reports, original)["status"] == "FAIL"
    assert release.suite_result("test_integrated.py", phases, nodes)["status"] == "PASS"


@pytest.mark.parametrize("actuator", release.ACTUATORS)
def test_every_signed_obstruction_must_complete_before_publication(actuator):
    # Phase failures are covered by test_incomplete_reports_cannot_publish_pass;
    # here each required actuator must independently be present.
    nodes, phases = integrated_phases()
    node = f"tests/acceptance/test_integrated.py::test_each_actuator_signed_obstruction_verified_failure[{actuator}]"
    nodes.remove(node)
    phases = [phase for phase in phases if phase["nodeid"] != node]
    assert release.suite_result("test_integrated.py", phases, nodes)["status"] == "FAIL"


def suite_phases(suite):
    """Synthetic accounting fixtures only; never written as physics evidence."""
    names = list(release.REQUIRED[suite])
    if suite == "test_integrated.py":
        names.extend(sorted(release.SIGNED_OBSTRUCTION_CASES))
    nodes = [f"tests/acceptance/{suite}::{name}" for name in names]
    return nodes, [{"nodeid": node, "phase": phase, "outcome": "passed"}
                   for node in nodes for phase in ("setup", "call", "teardown")]


@pytest.mark.parametrize("order", [
    ("test_model.py", "test_physics.py", "test_controller.py", "test_integrated.py", "test_attacks.py"),
    ("test_integrated.py", "test_model.py", "test_physics.py", "test_controller.py", "test_attacks.py"),
    ("test_attacks.py", "test_integrated.py", "test_controller.py", "test_physics.py", "test_model.py"),
    ("test_model.py", "test_controller.py", "test_attacks.py", "test_integrated.py", "test_physics.py"),
], ids=["physics-before-signed", "historical-signed-overwrite", "model-last", "physics-last"])
def test_suite_order_cannot_lose_observations_or_signed_summary(isolated_records, monkeypatch, order):
    # Exercise each distinct publication ordering: unsigned/signed summary
    # ordering, the exact historical failure, model last, and physics last.
    # Only the artifact validator is stubbed: this test proves bookkeeping,
    # not signatures, physics, or a real functional acceptance result.
    calls = []
    signed = {"normal": {"verdict": "VERIFIED_SUCCESS", "evidence_sha256": "unit-only-normal"},
              "blocked": {"verdict": "VERIFIED_FAILURE", "evidence_sha256": "unit-only-blocked"}}

    def validate():
        calls.append("validated")
        return {"signed_runs": signed}

    monkeypatch.setattr(release, "validate_artifacts", validate)
    monkeypatch.setattr(release, "preserve_physics", lambda: None)
    summary = isolated_records / "artifacts/checker_summary.json"
    run_id = None
    for index, suite in enumerate(order):
        state = release.begin([suite], "unit-test-only", None)
        run_id = run_id or state["run_id"]
        assert state["run_id"] == run_id
        assert set(state["suites"]) == set(order[:index + 1])
        if suite == "test_physics.py":
            release.write_json(summary, {"stage": "S2", "entries": {"normal": {"verdict": "NOT_PROVEN"}}})
        elif suite == "test_integrated.py":
            release.write_json(summary, signed)
        nodes, phases = suite_phases(suite)
        release.finish(state, phases, {suite: nodes}, 0)
        if index < len(order) - 1:
            assert not calls
            assert set(json.loads(release.MATRIX.read_text()).values()) == {"NOT_RUN"}

    assert calls == ["validated"]
    assert json.loads(summary.read_text()) == signed
    assert json.loads(release.MATRIX.read_text()) == {
        "A1": "PASS", "A2": "PASS", "A3": "PASS", "A4": "FUNCTIONAL_ONLY",
        "A5": "PASS", "A6": "PASS", "A7": "FUNCTIONAL_ONLY", "A8": "FUNCTIONAL_ONLY"}


def test_repeated_suite_starts_fresh_cycle_even_when_model_was_not_first(isolated_records):
    state = release.begin(["test_integrated.py"], "unit-test-only", None)
    nodes, phases = suite_phases("test_integrated.py")
    release.finish(state, phases, {"test_integrated.py": nodes}, 0)
    state = release.begin(["test_model.py"], "unit-test-only", None)
    assert "test_integrated.py" in state["suites"]
    nodes, phases = suite_phases("test_model.py")
    release.finish(state, phases, {"test_model.py": nodes}, 0)
    next_cycle = release.begin(["test_integrated.py"], "unit-test-only", None)
    assert next_cycle["run_id"] != state["run_id"]
    assert set(next_cycle["suites"]) == {"test_integrated.py"}


def test_failed_artifact_validation_cannot_publish_a_repaired_summary(isolated_records, monkeypatch):
    state = release.begin(release.REQUIRED, "unit-test-only", None)
    for entry in state["suites"].values():
        entry["status"] = "PASS"  # Accounting fixture only.
    summary = isolated_records / "artifacts/checker_summary.json"
    unsigned = {"stage": "S2", "entries": {}}
    release.write_json(summary, unsigned)

    def invalid_bundle():
        raise ValueError("raw bundle verification failed")

    monkeypatch.setattr(release, "validate_artifacts", invalid_bundle)
    with pytest.raises(ValueError, match="raw bundle verification failed"):
        release.finish(state, [], {}, 0)
    assert json.loads(summary.read_text()) == unsigned
    assert set(json.loads(release.MATRIX.read_text()).values()) == {"NOT_RUN"}
    assert not (release.DIRECTORY / "release_observations.json").exists()

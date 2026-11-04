"""S4 artifact/checker UNIT tests. These scripted readings are never Isaac evidence."""

from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from protected_robot_controller.protocol import Rejected
from tools.integrated_fixture import MAX_CONTEXT_BYTES, check_recorded_run, record_run


# Reuse the established, explicitly synthetic S3 rig without importing any
# simulator fixture or changing an accepted test. No artifact leaves tmp_path.
_spec = importlib.util.spec_from_file_location(
    "s3_scripted_unit_fixture", Path(__file__).parents[1] / "acceptance/test_controller.py")
_unit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_unit)


def _run_unit(*, blocked=False, fail_at=None, disturbed_hold=False):
    rig = _unit.Rig(blocked=blocked)
    rig.command["trajectory"] = [
        [base + step * (1000 if channel < 6 else 100)
         for channel, base in enumerate(_unit.INITIAL[:7])]
        for step in range(1, 101)
    ]
    # The sensor script deliberately lags the command and is not populated by
    # drive(). It includes every hold sample and exceeds S4 displacement bounds.
    rig.backend.frames = [
        tuple((base + (0 if blocked else min(step, 100) * (900 if channel < 6 else 90)))
              / 1_000_000 for channel, base in enumerate(_unit.INITIAL))
        for step in range(113)
    ]
    if disturbed_hold:
        row = list(rig.backend.frames[-2])
        row[0] += 0.1
        rig.backend.frames[-2] = tuple(row)
    rig.backend.fail_at = fail_at
    observations = []
    read = rig.backend._read

    def observe():
        sample = read()
        row = asdict(sample)
        row["positions"] = list(row["positions"])
        row["valid"] = list(row["valid"])
        observations.append(row)
        return sample

    rig.backend._read = observe
    command, bundle, _ = rig.run()
    return rig, command, bundle, observations


def _record(tmp_path, run):
    rig, command, bundle, observations = run
    return record_run(tmp_path, "unit", command, bundle, rig.authority.public_key(),
                      rig.evidence_key.public_key(), observations=observations,
                      metadata={"scope": "UNIT ONLY; scripted backend, no physics",
                                "runtime": "unit", "source_revision": "unit"})


@pytest.mark.parametrize("blocked, verdict", [
    (False, "VERIFIED_SUCCESS"), (True, "VERIFIED_FAILURE"),
])
def test_unit_signed_trace_replays_without_private_keys(tmp_path, blocked, verdict):
    run = _run_unit(blocked=blocked)
    result = _record(tmp_path, run)
    assert result == {"verdict": verdict, "evidence_sha256": sha256(run[2]).hexdigest()}
    assert check_recorded_run(tmp_path, "unit") == result
    assert (tmp_path / "unit.cbor").read_bytes() == run[2]
    assert (tmp_path / "unit.command.cbor").read_bytes() == run[1]
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "unit.cbor", "unit.command.cbor", "unit.context.json", "unit.observations.json",
    ]


def test_unit_fault_preserves_authentic_partial_raw_trace(tmp_path):
    run = _run_unit(fail_at=3)
    result = _record(tmp_path, run)
    assert result["verdict"] == "NOT_PROVEN"
    assert len(run[3]) == 3
    assert (tmp_path / "unit.cbor").read_bytes() == run[2]
    assert check_recorded_run(tmp_path, "unit") == result


def test_unit_signed_final_hold_deviation_is_verified_failure(tmp_path):
    result = _record(tmp_path, _run_unit(disturbed_hold=True))
    assert result["verdict"] == "VERIFIED_FAILURE"
    assert check_recorded_run(tmp_path, "unit") == result


@pytest.mark.parametrize("change", ["position", "clock", "counter", "valid", "missing_hold"])
def test_unit_observer_comparison_includes_entire_final_hold(tmp_path, change):
    run = _run_unit()
    observation = run[3][-2]
    if change == "position":
        observation["positions"][7] += 0.001
    elif change == "clock":
        observation["monotonic_time_ns"] += 1
    elif change == "counter":
        observation["counter"] += 1
    elif change == "valid":
        observation["valid"][0] = False
    else:
        run[3].pop(-2)
    with pytest.raises(ValueError):
        _record(tmp_path, run)
    assert (tmp_path / "unit.cbor").read_bytes() == run[2]
    assert not (tmp_path / "unit.context.json").exists()


@pytest.mark.parametrize("field, value", [
    ("check_tolerance", [1_000_000] * 8),
    ("minimum_displacement", [1] * 8),
    ("verdict", "VERIFIED_FAILURE"),
    ("command_sha256", "00" * 32),
    ("evidence_sha256", "00" * 32),
    ("observations_sha256", "00" * 32),
    ("config_digest_hex", "00" * 32),
    ("model_manifest_sha256", "00" * 32),
    ("expected_context_cbor_hex", "a0"),
    ("metadata_sha256", "00" * 32),
])
def test_unit_replay_rejects_changed_retained_context(tmp_path, field, value):
    _record(tmp_path, _run_unit())
    path = tmp_path / "unit.context.json"
    context = json.loads(path.read_text())
    context[field] = value
    path.write_text(json.dumps(context))
    with pytest.raises(ValueError, match="Retained context"):
        check_recorded_run(tmp_path, "unit")


@pytest.mark.parametrize("filename", ["unit.cbor", "unit.command.cbor"])
def test_unit_replay_rejects_changed_signed_bytes(tmp_path, filename):
    _record(tmp_path, _run_unit())
    path = tmp_path / filename
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises((Rejected, InvalidSignature)):
        check_recorded_run(tmp_path, "unit")


def test_unit_replay_bounds_context_before_json_decode(tmp_path):
    (tmp_path / "unit.context.json").write_bytes(b" " * (MAX_CONTEXT_BYTES + 1))
    with pytest.raises(ValueError, match="byte bound"):
        check_recorded_run(tmp_path, "unit")


def test_unit_failed_overwrite_removes_stale_success_context(tmp_path):
    _record(tmp_path, _run_unit())
    run = _run_unit()
    run[3][-1]["physics_step"] += 1
    with pytest.raises(ValueError):
        _record(tmp_path, run)
    assert (tmp_path / "unit.cbor").read_bytes() == run[2]
    assert not (tmp_path / "unit.context.json").exists()

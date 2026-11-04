"""S6-02: run only in the pinned Isaac container, never on the host.

One real persistent normal scene supplies all four cases. Corruption fixtures
are separate retained copies; the original run and all failed attempts survive.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4

import pytest

# Load the unchanged provisioned crypto/byte stack before SimulationApp starts.
from tools.scene_fixture import ROOT, OUTPUT, run_calibration
from tools.scene_evidence import PUBLIC_FIELDS, operation_plan, verify_run
from tools.controller_fixture import development_keys, authenticated_evidence
from protected_robot_controller import limits as L
from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode, public_bytes, strict_decode, verify_sign1


def load(path):
    return json.loads(Path(path).read_text())


@pytest.fixture(scope="module")
def signed_run(scene_simulation_app):
    keys = development_keys()
    run = run_calibration(signed=True, keys=keys)
    # Keys stay in this process. Only independent PUBLIC pins enter replay.
    pins = {"authority_public_der_hex": public_bytes(keys[0].public_key()).hex(),
            "evidence_public_der_hex": public_bytes(keys[1].public_key()).hex()}
    pins["expected_runtime"] = run["runtime_image"] if run["runtime_identity"]["kind"] == "container" else "native"
    directory = OUTPUT / "signed" / run["run_id"]
    return run, directory / "run.json", pins


def altered_run(signed_run, label, mutate):
    """Copy-on-write corruption fixtures, without touching measured run bytes."""
    original, manifest, _ = signed_run
    target = OUTPUT / "signed-mutations" / (label + "-" + uuid4().hex)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Hardlinks save space for large unmodified object traces. Every edit below
    # uses atomic replacement to break its link; originals are never opened for write.
    shutil.copytree(manifest.parent, target, copy_function=os.link)
    old_prefix, new_prefix = str(manifest.parent.relative_to(ROOT)), str(target.relative_to(ROOT))

    def remap(value):
        if type(value) is str:
            return value.replace(old_prefix + "/", new_prefix + "/")
        if type(value) is dict:
            return {remap(k): remap(v) for k, v in value.items()}
        if type(value) is list:
            return [remap(v) for v in value]
        return value

    run = remap(deepcopy(original))

    def replace(relative, raw):
        path = ROOT / relative
        scratch = path.with_name(path.name + ".replacement")
        scratch.write_bytes(raw)
        scratch.replace(path)
        run["files"][relative] = sha256(raw).hexdigest()

    mutate(run, replace)
    path = target / "run.json"
    scratch = target / "manifest.replacement"
    scratch.write_text(json.dumps(run, indent=2) + "\n")
    scratch.replace(path)
    (target / "mutation.json").write_text(json.dumps({"kind": "OFFLINE_CORRUPTION_FIXTURE_NOT_EXECUTION",
                                                    "label": label, "original_manifest": str(manifest.relative_to(ROOT)),
                                                    "original_manifest_sha256": sha256(manifest.read_bytes()).hexdigest()}) + "\n")
    return path


def test_every_segment_has_original_signed_command_and_report(signed_run):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from tools.integrated_fixture import _compare_observations
    run, manifest, pins = signed_run
    replay = verify_run(manifest, **pins)
    assert replay["operation_coverage_complete"] is True
    authority = load_der_public_key(bytes.fromhex(pins["authority_public_der_hex"]))
    public = load_der_public_key(bytes.fromhex(pins["evidence_public_der_hex"]))
    for operation in run["operations"]:
        assert operation["evidence_validation"] == "VALID"
        for seg in operation["segments"]:
            command, report = (ROOT / seg["command"]).read_bytes(), (ROOT / seg["report"]).read_bytes()
            request = strict_decode((ROOT / seg["request"]).read_bytes(), MAX_REQUEST_BYTES)
            response = strict_decode((ROOT / seg["response"]).read_bytes(), MAX_RESPONSE_BYTES)
            assert request == {"version": 1, "type": "EXECUTE", "command": command}
            assert response == {"version": 1, "type": "EVIDENCE", "evidence": report}
            c, e = verify_sign1(command, authority), authenticated_evidence(report, public)
            assert e["command_digest"] == sha256(command).digest()
            assert e["execution_id"] == c["execution_id"]
            assert len(command) == seg["command_bytes"] <= 65_536
            assert len(report) == seg["report_bytes"] <= 1_048_576
            assert seg["execution_seconds"] > 0 and seg["checking_seconds"] > 0
            assert seg["units"] == ["urad"] * 6 + ["um"] * 2
            assert e["sample_count"] == e["expected_sample_count"] == 1 + len(c["trajectory"]) + c["hold_steps"]
            _compare_observations(e, load(ROOT / seg["joint_observations"]))
            # Measured lag remains visible; no reference-to-sensor substitution.
            assert any(row[5] != target + [target[-1]] for row, target in zip(e["samples"][1:], c["trajectory"]))
    # Hash-consistent mutations must still fail original-signature/binding checks.
    for field in ("command", "report"):
        def corrupt(record, replace, field=field):
            seg = record["operations"][0]["segments"][0]
            raw = (ROOT / seg[field]).read_bytes()
            changed = raw[:-1] + bytes([raw[-1] ^ 1])
            replace(seg[field], changed)
            seg[field + "_sha256"] = sha256(changed).hexdigest()
            ctx = load(ROOT / seg["public_context"])
            ctx[field + "_sha256"] = seg[field + "_sha256"]
            replace(seg["public_context"], json.dumps(ctx).encode())
            wrapper = "request" if field == "command" else "response"
            payload = {"version": 1, "type": "EXECUTE", "command": changed} if field == "command" else {
                "version": 1, "type": "EVIDENCE", "evidence": changed}
            replace(seg[wrapper], encode(payload))
        with pytest.raises(Exception):
            verify_run(altered_run(signed_run, "changed-" + field, corrupt), **pins)


def test_operation_segments_complete_ordered_and_distinct(signed_run):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from tools.scene_calibration_check import in_destination
    run, manifest, pins = signed_run
    result = verify_run(manifest, **pins)
    assert result["operation_coverage_complete"] is True
    assert all(row["evidence_validation"] == "VALID" and row["motion_verdict"] is None
               and row["object_verdict"] is None for row in result["segments"])
    assert [(op["object_id"], op["destination"]) for op in run["operations"]] == [("R1", "A"), ("B1", "B")]
    program = load(ROOT / run["public_inputs"]["program"])
    assert run["required_operations"] == operation_plan(program)
    segments = [op["segments"][0] for op in run["operations"]]
    assert len({s["execution_id"] for s in segments}) == 2
    assert len({s["command_sha256"] for s in segments}) == len({s["report_sha256"] for s in segments}) == 2
    assert len({s["boot_id"] for s in segments}) == 1
    assert [s["sequence"] for s in segments] == [1, 2]
    public = load_der_public_key(bytes.fromhex(pins["evidence_public_der_hex"]))
    reports = [authenticated_evidence((ROOT / s["report"]).read_bytes(), public) for s in segments]
    assert reports[0]["samples"][-1][1:4] == reports[1]["samples"][0][1:4]
    assert reports[0]["samples"][-1][5:] == reports[1]["samples"][0][5:]
    assert run["geometry"]["setup_calls"] == run["geometry_after"]["setup_calls"] == 1
    assert run["execution_guard"]["forbidden_calls"] == []
    assert run["physics_steps_measured"] == run["requested_drive_writes"] == sum(len(e["samples"]) - 1 for e in reports)
    profile = load(ROOT / run["public_inputs"]["profile"])
    second_objects = load(ROOT / segments[1]["object_observations"])
    assert run["persistence_observed"] is True
    assert run["persistence_samples"] == len(second_objects)
    assert all(in_destination(row, "R1", "A", profile) for row in second_objects)
    for seg in segments:
        assert {"approach", "grasp", "lift", "transport", "release", "retreat", "settle"} <= {p["name"] for p in seg["phases"]}
        assert seg["phases"][0]["first_row"] == 1
        assert seg["phases"][-1]["last_row"] + 1 == seg["expected_sample_count"]
        assert all(a["last_row"] + 1 == b["first_row"] for a, b in zip(seg["phases"], seg["phases"][1:]))

    def missing_op(r, _):
        r["operations"].pop()
    def reordered(r, _):
        r["operations"].reverse()
    def missing_segment(r, _):
        r["operations"][0]["segments"].clear()
    def duplicate(r, _):
        r["operations"][1]["segments"] = deepcopy(r["operations"][0]["segments"])
    def wrong_plan(r, _):
        r["required_operations"][0]["segments"][0]["phases"].pop()
    for label, mutation in (("missing-operation", missing_op), ("reordered", reordered),
                            ("missing-segment", missing_segment), ("duplicate-segment", duplicate), ("missing-phase", wrong_plan)):
        with pytest.raises(ValueError):
            verify_run(altered_run(signed_run, label, mutation), **pins)
    # The mutation fixtures did not modify any original signed/context byte.
    assert verify_run(manifest, **pins)["operation_coverage_complete"] is True


def test_scene_authorization_and_freshness_remain_active(signed_run):
    run, _, pins = signed_run
    probes = run["authorization_probes"]
    assert len(probes) == 14
    expected = {"altered_signature": "SIGNATURE", "wrong_key": "HEADERS", "wrong_robot": "CONTEXT",
                "wrong_config": "CONTEXT", "wrong_boot": "BOOT", "expired": "EXPIRED",
                "replaced_challenge": "REPLAY", "over_limit": "LIMIT", "replay_original": "REPLAY",
                "reused_sequence": "REPLAY", "reused_execution_id": "REPLAY"}
    assert {p["case"] for p in probes} == set(expected)
    for probe in probes:
        raw = (ROOT / probe["response_file"]).read_bytes()
        response = strict_decode(raw, MAX_RESPONSE_BYTES)
        assert response == probe["response"] == {"version": 1, "type": "REJECTED", "reason": expected[probe["case"]]}
        assert probe["before"] == probe["after"]
        assert probe["after"]["backend_target_writes"] == 0
        assert "evidence" not in response
        wire = (ROOT / probe["command"]).read_bytes()
        request = strict_decode((ROOT / probe["request"]).read_bytes(), MAX_REQUEST_BYTES)
        assert request == {"version": 1, "type": "EXECUTE", "command": wire}
        assert len(wire) == probe["command_bytes"] and len(raw) == probe["response_bytes"]
        assert probe["execution_seconds"] >= 0
    # Positive controls on the same actual backend: rejected calls did not
    # consume either sequence or disable subsequent authorized execution.
    segments = [op["segments"][0] for op in run["operations"]]
    assert [s["sequence"] for s in segments] == [1, 2]
    assert all(s["terminal_state"] == "COMPLETE" and s["partial"] is False for s in segments)
    assert probes[8]["before"]["drive_writes"] > 0
    assert probes[11]["before"]["drive_writes"] > probes[8]["before"]["drive_writes"]
    assert run["requested_drive_writes"] == probes[-1]["after"]["drive_writes"]
    # Original accepted bytes are replayed verbatim, not regenerated signatures.
    replays = [p for p in probes if p["case"] == "replay_original"]
    assert [(ROOT / p["command"]).read_bytes() for p in replays] == [(ROOT / s["command"]).read_bytes() for s in segments]


def test_retained_context_contains_public_keys_only(signed_run):
    from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key
    run, manifest, pins = signed_run
    assert pins["authority_public_der_hex"] != pins["evidence_public_der_hex"]
    key_pins = {k: v for k, v in pins.items() if k.endswith("_public_der_hex")}
    for field, expected in key_pins.items():
        assert run[field] == expected
        raw = bytes.fromhex(expected)
        assert public_bytes(load_der_public_key(raw)) == raw
        with pytest.raises(ValueError):
            load_der_private_key(raw, password=None)
    for operation in run["operations"]:
        seg = operation["segments"][0]
        ctx = load(ROOT / seg["public_context"])
        assert ctx.keys() == PUBLIC_FIELDS
        assert all(ctx[key] == value for key, value in key_pins.items())
        config = bytes.fromhex(ctx["config_cbor_hex"])
        assert config == encode(L.configuration())
        assert sha256(config).hexdigest() == ctx["config_digest_hex"] == run["config_digest_hex"]
        assert ctx["binding"]["schema_version"] == 3
        assert ctx["binding"]["security_config_sha256"] == run["security_config_sha256"]
        assert "source_fingerprint" not in ctx["binding"]
        assert ctx["binding"]["runtime_metadata_sha256"] == run["runtime_metadata_sha256"]
        assert len(run["source_fingerprint"]) == len(run["runtime_metadata_sha256"]) == 64
    if "PRC_SCENE_SOURCE_FINGERPRINT" in os.environ:
        assert run["source_fingerprint"] == os.environ["PRC_SCENE_SOURCE_FINGERPRINT"]
        assert run["source_fingerprint_origin"] == "external_supervisor"
    # Scan actual retained public artifacts, not just a self-reported flag.
    def no_private_fields(value):
        if isinstance(value, dict):
            assert not any(any(token in k.lower() for token in ("private_key", "private_der", "private_pem", "secret_scalar")) for k in value)
            for child in value.values():
                no_private_fields(child)
        elif isinstance(value, list):
            for child in value:
                no_private_fields(child)
    no_private_fields(run)
    for relative, expected in run["files"].items():
        path = ROOT / relative
        assert not path.is_symlink()
        raw = path.read_bytes()
        assert sha256(raw).hexdigest() == expected
        assert b"PRIVATE KEY" not in raw
        if path.suffix == ".json":
            no_private_fields(json.loads(raw))
    # Fresh offline process has only files/public pins, no SimulationApp or
    # original key objects. This command is executed inside the gate container.
    script = (
        "import json,sys; from tools.scene_evidence import verify_run; "
        "r=verify_run(sys.argv[1],authority_public_der_hex=sys.argv[2],evidence_public_der_hex=sys.argv[3],expected_runtime=sys.argv[4]); "
        "assert not any(n=='isaacsim' or n.startswith(('isaacsim.','omni.')) for n in sys.modules); "
        "print(json.dumps(r))"
    )
    completed = subprocess.run([sys.executable, "-c", script, str(manifest),
                                pins["authority_public_der_hex"], pins["evidence_public_der_hex"], pins["expected_runtime"]],
                               cwd=ROOT, capture_output=True, text=True, timeout=60)
    log = OUTPUT / "offline-checks" / (uuid4().hex + ".json")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(json.dumps({"command": completed.args, "returncode": completed.returncode,
                               "stdout": completed.stdout, "stderr": completed.stderr}) + "\n")
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["operation_coverage_complete"] is True
    # A changed public context is rejected even with an updated unsigned file hash.
    def extra_secret(r, replace):
        path = r["operations"][0]["segments"][0]["public_context"]
        ctx = load(ROOT / path)
        ctx["private_key"] = "FORBIDDEN_TEST_SENTINEL_NOT_A_KEY"
        replace(path, json.dumps(ctx).encode())
    with pytest.raises(ValueError, match="context fields"):
        verify_run(altered_run(signed_run, "unexpected-context-field", extra_secret), **pins)
    with pytest.raises(ValueError, match="identity"):
        verify_run(manifest, authority_public_der_hex=pins["evidence_public_der_hex"], expected_runtime=pins["expected_runtime"])

@pytest.mark.parametrize("kind", ["native", "container", "legacy"])
def test_runtime_relabel_rejects_signed_archive(signed_run, kind):
    """Rehash every edited public file; existing signed bytes must not be relabeled."""
    from tools.scene_evidence import segment_binding
    run, _, pins = signed_run
    profile = load(ROOT / run["public_inputs"]["profile"])
    image = "sha256:" + "a" * 64
    expected = "native" if kind == "native" else image
    if kind == "legacy":
        expected = profile["runtime_image"]

    def mutate(record, replace):
        runtime = load(ROOT / record["public_inputs"]["runtime"])
        if kind == "legacy":
            runtime.pop("runtime_identity", None)
            record.pop("runtime_identity", None)
            runtime["runtime_image"] = record["runtime_image"] = expected
        else:
            identity = {"schema_version": 1, "kind": kind,
                        "image_id": None if kind == "native" else image,
                        "identity_source": "local_process" if kind == "native" else "trusted_launcher",
                        "python_executable": "/different/runtime/python"}
            runtime["runtime_identity"] = record["runtime_identity"] = identity
            runtime["runtime_image"] = record["runtime_image"] = identity["image_id"]
        runtime_raw = json.dumps(runtime).encode()
        replace(record["public_inputs"]["runtime"], runtime_raw)
        record["runtime_metadata_sha256"] = sha256(runtime_raw).hexdigest()
        for index, operation in enumerate(record["operations"]):
            segment = operation["segments"][0]
            context = load(ROOT / segment["public_context"])
            context["binding"] = segment_binding(record, index)
            replace(segment["public_context"], json.dumps(context).encode())

    altered = altered_run(signed_run, "runtime-relabel-" + kind, mutate)
    with pytest.raises(ValueError, match="binding"):
        verify_run(altered, **{**pins, "expected_runtime": expected})
    from tools.scene_check import replay_run
    replay = replay_run(altered, **{**pins, "expected_runtime": expected})
    assert replay["evidence_validation"] == "REJECTED_EVIDENCE"

"""S6-02 public segment records and byte-interface rejection probes.

No simulator imports, private-key persistence, new messages, or motion/object
policy. The authored program currently uses one bounded segment per operation.
The retained plan is bound through the existing opaque authorization digest.
Public replay checks provenance/coverage; it cannot attest the host or sensors.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
import time
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_der_public_key

from protected_robot_controller import limits as L
from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import (
    MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, encode, key_id, public_bytes,
    strict_decode, verify_sign1,
)
from tools.prc_security import security_config_digest
from tools.source_inventory import source_inventory
from tools.controller_fixture import (
    EvidenceChecker, authenticated_evidence, command_for, sign_command,
)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FIELDS = frozenset({
    "schema_version", "authority_public_der_hex", "evidence_public_der_hex",
    "authority_key_id", "evidence_key_id", "config_cbor_hex", "config_digest_hex",
    "profile_sha256", "trajectory_sha256", "command_sha256", "report_sha256",
    "candidate_tolerance", "phases", "binding", "outputs", "units",
})


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def operation_plan(program):
    """Full coverage is predetermined, never inferred from completed segments."""
    result = []
    for index, operation in enumerate(program["operations"]):
        first, phases = 1, []
        for phase in operation["phases"]:
            last = first + phase["steps"] - 1
            phases.append({"name": phase["name"], "first_row": first, "last_row": last})
            first = last + 1
        phases.append({"name": "settle", "first_row": first,
                       "last_row": first + program["hold_steps"] - 1})
        result.append({"operation_index": index, "object_id": operation["object_id"],
                       "destination": operation["destination"], "required_segment_count": 1,
                       "segments": [{"segment_index": 0, "global_segment_index": index,
                                     "trajectory_rows": first - 1, "hold_steps": program["hold_steps"],
                                     "expected_sample_count": first + program["hold_steps"],
                                     "phases": phases}]})
    return result


def scenario_operation_plan(program, scenario):
    """Select fixed required coverage without changing any authored trajectory.

    The persistent normal fixture executes both operations. Each controlled
    fault fixture executes the same original R1->A operation only. A scenario
    is an unsigned experiment label until the existing authorization-context
    digest binds this complete plan into the signed command. It never selects
    a motion tolerance or determines an evidence/object verdict.
    """
    require(type(scenario) is str and scenario in ("normal", "missed_grasp", "obstructed", "incomplete"),
            "Unsupported scene scenario")
    plan = operation_plan(program)
    require([(p["object_id"], p["destination"]) for p in plan] == [("R1", "A"), ("B1", "B")],
            "Scene program requires the fixed ordered R1->A, B1->B operations")
    return plan if scenario == "normal" else plan[:1]


def prepare_run(store, program, authority_public, evidence_public):
    """Snapshot public inputs before authorization; accept public key objects only."""
    authority_der, evidence_der = public_bytes(authority_public), public_bytes(evidence_public)
    require(authority_der != evidence_der, "Separate command and evidence keys required")
    record, directory = store.record, store.directory
    source_files = source_inventory(ROOT)
    profile = json.loads((ROOT / "scenes/manipulation/profile.json").read_bytes())
    assessment_policy = json.loads((ROOT / "scenes/manipulation/evidence_policy.json").read_bytes())
    record["security_config_sha256"] = security_config_digest(profile, assessment_policy)
    source_hash = sha256(encode(source_files)).hexdigest()
    external = record["source_fingerprint"]
    record.update(source_fingerprint=external if external is not None else source_hash,
                  source_fingerprint_origin=record.get("source_fingerprint_origin") or (
                      "external_supervisor" if external is not None else "local_source_files"),
                  source_files_sha256=source_hash, config_digest_hex=L.CONFIG_DIGEST.hex(),
                  authority_public_der_hex=authority_der.hex(), evidence_public_der_hex=evidence_der.hex(),
                  required_operations=scenario_operation_plan(program, record["scenario"]))
    runtime = {"runtime_image": record["runtime_image"], "isaac_version": record["isaac_version"],
               "python": sys.version.split()[0], "protocol_runtime": record["protocol_runtime"]}
    if "runtime_identity" in record:
        runtime["runtime_identity"] = record["runtime_identity"]
    if "visual_runtime" in record:
        runtime["visual_runtime"] = record["visual_runtime"]
    snapshots = {"profile": ROOT / "scenes/manipulation/profile.json",
                 "program": ROOT / "scenes/manipulation/trajectories.json",
                 "model": ROOT / "artifacts/model_manifest.json",
                 "assessment_policy": ROOT / "scenes/manipulation/evidence_policy.json"}
    record["public_inputs"] = {}
    for name, source in snapshots.items():
        target = directory / (name + ".snapshot.json")
        target.write_bytes(source.read_bytes())
        record["public_inputs"][name] = str(target.relative_to(ROOT))
    for name, data in (("source_files", source_files), ("runtime", runtime),
                       ("operation_plan", record["required_operations"])):
        target = directory / (name + ".json")
        write_json(target, data)
        record["public_inputs"][name] = str(target.relative_to(ROOT))
    record["runtime_metadata_sha256"] = digest(directory / "runtime.json")
    record["operation_plan_sha256"] = sha256(encode(record["required_operations"])).hexdigest()
    record["authorization_probes"] = []


def segment_binding(record, operation_index):
    """Build historical v2 or runtime-bound v3 authorization context."""
    require(type(operation_index) is int and type(record.get("required_operations")) is list
            and 0 <= operation_index < len(record["required_operations"]), "Invalid operation index")
    require(type(record.get("run_id")) is str and bool(record["run_id"]), "Invalid run ID")
    require(record.get("scenario") in ("normal", "missed_grasp", "obstructed", "incomplete"), "Invalid scenario")
    for field in ("security_config_sha256", "model_sha256", "operation_plan_sha256"):
        require(type(record.get(field)) is str and re.fullmatch(r"[0-9a-f]{64}", record[field]) is not None
                and record[field] != "0" * 64,
                "Invalid binding digest: " + field)
    operation = record["required_operations"][operation_index]
    require(type(operation) is dict and operation.get("operation_index") == operation_index
            and type(operation.get("operation_index")) is int
            and type(operation.get("required_segment_count")) is int
            and operation["required_segment_count"] == 1
            and type(operation.get("object_id")) is str and type(operation.get("destination")) is str,
            "Invalid trusted operation")
    binding = {"schema_version": 2, "run_id": record["run_id"], "scenario": record["scenario"],
            "security_config_sha256": record["security_config_sha256"], "model_sha256": record["model_sha256"],
            "operation_plan_sha256": record["operation_plan_sha256"],
            "operation_count": len(record["required_operations"]), "operation_index": operation_index,
            "object_id": operation["object_id"], "destination": operation["destination"],
            "segment_index": 0, "segment_count": operation["required_segment_count"],
            "global_segment_index": operation_index}
    if "runtime_identity" in record:
        runtime_digest = record.get("runtime_metadata_sha256")
        require(type(runtime_digest) is str and re.fullmatch(r"[0-9a-f]{64}", runtime_digest) is not None
                and runtime_digest != "0" * 64, "Invalid runtime metadata digest")
        binding.update(schema_version=3, runtime_metadata_sha256=runtime_digest)
    return binding


def complete_segment(store, index, name, segment, context, wire, bundle, command, evidence):
    """Persist public metadata even if subsequent motion/object checking fails."""
    context.update(schema_version=1, authority_key_id=sha256(bytes.fromhex(context["authority_public_der_hex"])).hexdigest(),
                   evidence_key_id=sha256(bytes.fromhex(context["evidence_public_der_hex"])).hexdigest(),
                   config_digest_hex=command["config_digest"].hex(),
                   report_sha256=sha256(bundle).hexdigest(), binding=segment_binding(store.record, index),
                   outputs=list(command["outputs"]), units=list(command["units"]))
    require(context.keys() == PUBLIC_FIELDS, "Public context has unexpected fields")
    write_json(store.directory / (name + ".public.json"), context)
    segment.update(operation_index=index, segment_index=0, global_segment_index=index,
                   required_segment_count=1, command_sha256=sha256(wire).hexdigest(),
                   report_sha256=sha256(bundle).hexdigest(),
                   config_digest_hex=command["config_digest"].hex(), units=list(command["units"]),
                   outputs=list(command["outputs"]), expected_sample_count=evidence["expected_sample_count"],
                   captured_sample_count=evidence["sample_count"], terminal_state=evidence["terminal_state"],
                   partial=evidence["partial"], termination_reason=evidence["reason"],
                   physics_dt=command["physics_dt"], sample_every_steps=command["sample_every_steps"],
                   simulated_seconds=(len(command["trajectory"]) + command["hold_steps"]) / L.HZ,
                   timing_clock="time.perf_counter wall seconds; signed sample times are nanoseconds",
                   **{field: str((store.directory / (name + "." + suffix)).relative_to(ROOT))
                      for field, suffix in (("hello", "hello.cbor"), ("request", "request.cbor"),
                                            ("response", "response.cbor"))})
    # Separate receipt survives later assessment failures; exact bytes precede it.
    write_json(store.directory / (name + ".segment.json"), segment)


def authorization_probes(store, interface, observed, authority, program, *, accepted=None):
    """Real byte-interface refusals; same controller/backend, no injected clock.

    Expiry uses an already elapsed signed deadline. Every probe retains raw
    traffic and checks zero requested drives, steps and acquisitions. An
    unexpected execution is retained and terminates this run immediately.
    """
    def snapshot():
        return {"drive_writes": observed.drive_writes, "physics_steps": observed.backend._steps,
                "joint_observations": len(observed.joints), "object_observations": len(observed.objects)}

    cases = [("replay_original", "REPLAY"), ("reused_sequence", "REPLAY"), ("reused_execution_id", "REPLAY")] if accepted else [
        ("altered_signature", "SIGNATURE"), ("wrong_key", "HEADERS"), ("wrong_robot", "CONTEXT"),
        ("wrong_config", "CONTEXT"), ("wrong_boot", "BOOT"), ("expired", "EXPIRED"),
        ("replaced_challenge", "REPLAY"), ("over_limit", "LIMIT")]
    for case, expected in cases:
        name = f"probe-{len(store.record['authorization_probes']):02d}-{case}"
        hello_raw = interface.handle(encode({"version": 1, "type": "HELLO"}))
        (store.directory / (name + ".hello.cbor")).write_bytes(hello_raw)
        hello = strict_decode(hello_raw, MAX_RESPONSE_BYTES)
        command = command_for(hello, program["initial_target"] + [program["initial_target"][-1]],
                              [program["initial_target"]])
        if accepted:
            previous = verify_sign1(accepted, authority.public_key())
            if case == "reused_sequence":
                command["sequence"] = previous["sequence"]
            elif case == "reused_execution_id":
                command["execution_id"] = previous["execution_id"]
        elif case == "wrong_robot":
            command["robot_id"] = "different-robot"
        elif case == "wrong_config":
            command["config_digest"] = bytes(32)
        elif case == "wrong_boot":
            command["boot_id"] = bytes(32)
        elif case == "expired":
            command["expires_ns"] = 0
        elif case == "replaced_challenge":
            raw = interface.handle(encode({"version": 1, "type": "HELLO"}))
            (store.directory / (name + ".replacement-hello.cbor")).write_bytes(raw)
        elif case == "over_limit":
            command["effort_limits"][0] += 1
        wire = accepted if case == "replay_original" else sign_command(command, authority)
        if case == "altered_signature":
            wire = wire[:-1] + bytes([wire[-1] ^ 1])
        elif case == "wrong_key":
            from cryptography.hazmat.primitives.asymmetric import ec
            wrong_key = ec.generate_private_key(ec.SECP256R1())
            wire = sign_command(command, wrong_key)
        request = encode({"version": 1, "type": "EXECUTE", "command": wire})
        for suffix, raw in (("command.cbor", wire), ("request.cbor", request)):
            (store.directory / (name + "." + suffix)).write_bytes(raw)
        before = snapshot()
        before["backend_target_writes"] = 0
        started = time.perf_counter()
        # Observation only: the real target writer is called unchanged if the
        # controller unexpectedly reaches it. Never mock physics or samples.
        with patch.object(observed.backend, "_write_targets", wraps=observed.backend._write_targets) as writes:
            raw = interface.handle(request)
            after = snapshot()
            after["backend_target_writes"] = writes.call_count
        elapsed = time.perf_counter() - started
        (store.directory / (name + ".response.cbor")).write_bytes(raw)
        response = strict_decode(raw, MAX_RESPONSE_BYTES)
        result = {"case": case, "expected_reason": expected, "response": response,
                  "before": before, "after": after, "execution_seconds": elapsed,
                  "command_bytes": len(wire), "response_bytes": len(raw),
                  **{field: str((store.directory / (name + "." + suffix)).relative_to(ROOT))
                     for field, suffix in (("command", "command.cbor"), ("request", "request.cbor"),
                                           ("response_file", "response.cbor"), ("hello", "hello.cbor"))}}
        store.record["authorization_probes"].append(result)
        write_json(store.directory / (name + ".json"), result)
        require(response == {"version": 1, "type": "REJECTED", "reason": expected} and before == after,
                f"Authorization probe {case} failed; original bytes and observed side effects retained")


def verify_run(manifest, *, authority_public_der_hex=None, evidence_public_der_hex=None,
               expected_runtime=None, root=ROOT):
    """Offline structural/authenticity replay, separate from task verdicts.

    Optional public pins come from the caller's trusted setup. Without pins this
    verifies only consistency under the retained development identities. The
    unsigned manifest/HELLO is not an attestation or a live freshness claim.
    Raises on missing, mixed, reordered, repeated or unauthenticated segments.
    """
    root, manifest = Path(root).resolve(), Path(manifest).absolute()
    require(not manifest.is_symlink(), "Symlink manifest")
    run = json.loads(manifest.read_text())
    directory = manifest.parent
    require(directory.is_relative_to(root / "artifacts/scene-work"), "Run outside scene-work")

    def read(relative):
        path = PurePosixPath(relative)
        require(not path.is_absolute() and ".." not in path.parts, "Unsafe retained path")
        target = root / path
        require(target.is_relative_to(directory), "Retained path outside this run")
        require(all(not p.is_symlink() for p in (target, *target.parents)), "Symlink retained path")
        raw = target.read_bytes()
        require(sha256(raw).hexdigest() == run["files"].get(relative), "Retained file digest mismatch")
        return raw

    def load(relative):
        return json.loads(read(relative))

    for relative in run["files"]:
        read(relative)
    inputs = run["public_inputs"]
    program, profile = load(inputs["program"]), load(inputs["profile"])
    require(security_config_digest(profile, load(inputs["assessment_policy"])) == run["security_config_sha256"],
            "Wrong semantic security configuration")
    for field, name in (("profile_sha256", "profile"), ("trajectory_sha256", "program"), ("model_sha256", "model"),
                        ("runtime_metadata_sha256", "runtime")):
        require(sha256(read(inputs[name])).hexdigest() == run[field], f"Wrong {field}")
    sources = load(inputs["source_files"])
    require(sha256(encode(sources)).hexdigest() == run["source_files_sha256"], "Wrong source hash")
    require(isinstance(run["source_fingerprint"], str) and len(run["source_fingerprint"]) == 64,
            "Missing source fingerprint")
    runtime = load(inputs["runtime"])
    from tools.runtime_provenance import validate_runtime
    require(validate_runtime(runtime, run, profile, expected_runtime=expected_runtime), "Wrong runtime provenance")
    require(runtime["isaac_version"][0].split("-")[0].split("+")[0] == "6.0.0", "Wrong Isaac runtime")
    plan = scenario_operation_plan(program, run["scenario"])
    require(run["required_operations"] == load(inputs["operation_plan"]) == plan, "Operation plan changed")
    require(sha256(encode(plan)).hexdigest() == run["operation_plan_sha256"], "Wrong operation plan hash")
    require(len(run["operations"]) == len(plan), "Missing or extra operation")
    authority_hex, evidence_hex = run["authority_public_der_hex"], run["evidence_public_der_hex"]
    require(authority_hex != evidence_hex, "Command/evidence keys are not separate")
    require(authority_public_der_hex in (None, authority_hex) and evidence_public_der_hex in (None, evidence_hex),
            "Unexpected public verification identity")
    authority, public = (load_der_public_key(bytes.fromhex(k)) for k in (authority_hex, evidence_hex))
    public_bytes(authority), public_bytes(public)  # Explicit P-256 public-only validation.
    checker = EvidenceChecker(authority, public)
    seen, previous, results = set(), None, []
    for index, (operation, required) in enumerate(zip(run["operations"], plan)):
        require((operation["object_id"], operation["destination"]) == (required["object_id"], required["destination"]),
                "Reordered/wrong operation")
        require(len(operation["segments"]) == required["required_segment_count"], "Missing or extra segment")
        segment = operation["segments"][0]
        require(segment["operation_index"] == segment["global_segment_index"] == index
                and segment["segment_index"] == 0 and segment["required_segment_count"] == 1, "Wrong segment ordering")
        wire, bundle = read(segment["command"]), read(segment["report"])
        context = load(segment["public_context"])
        require(context.keys() == PUBLIC_FIELDS, "Unexpected public context fields")
        require(context["authority_public_der_hex"] == authority_hex and context["evidence_public_der_hex"] == evidence_hex,
                "Segment key substitution")
        require(context["authority_key_id"] == key_id(authority).hex() and context["evidence_key_id"] == key_id(public).hex(),
                "Wrong public key identity")
        command = verify_sign1(wire, authority)
        evidence = authenticated_evidence(bundle, public)
        checked = checker.check(bundle, wire)
        require(checked != "REJECTED", "Original signature/context/replay check failed")
        config = bytes.fromhex(context["config_cbor_hex"])
        require(config == encode(L.configuration()) and sha256(config).digest() == command["config_digest"] == L.CONFIG_DIGEST,
                "Wrong controller configuration")
        require(context["config_digest_hex"] == segment["config_digest_hex"] == run["config_digest_hex"] == L.CONFIG_DIGEST.hex(),
                "Wrong configuration digest metadata")
        binding = segment_binding(run, index)
        require(context["binding"] == binding and sha256(encode(binding)).digest() == command["authorization_context_digest"],
                "Wrong signed operation/segment binding")
        require(context["profile_sha256"] == run["profile_sha256"] and context["trajectory_sha256"] == run["trajectory_sha256"],
                "Wrong public profile/trajectory hashes")
        require(context["candidate_tolerance"] == profile["candidate_policy"]["tracking_tolerance"], "Policy metadata changed")
        for field, raw in (("command", wire), ("report", bundle)):
            require(sha256(raw).hexdigest() == segment[field + "_sha256"] == context[field + "_sha256"], "Wrong raw hash")
            require(len(raw) == segment[field + "_bytes"], "Wrong raw size")
        require(len(wire) <= MAX_COMMAND_BYTES and len(bundle) <= MAX_EVIDENCE_BYTES, "Wire size limit")
        require(strict_decode(read(segment["request"]), MAX_REQUEST_BYTES) == {"version": 1, "type": "EXECUTE", "command": wire},
                "Original request does not contain original command")
        require(strict_decode(read(segment["response"]), MAX_RESPONSE_BYTES) == {"version": 1, "type": "EVIDENCE", "evidence": bundle},
                "Original response does not contain original report")
        hello = strict_decode(read(segment["hello"]), MAX_RESPONSE_BYTES)
        for field in ("boot_id", "challenge", "config_digest", "robot_id", "controller_id", "profile"):
            require(hello[field] == command[field], "HELLO/command mismatch")
        require(hello["type"] == "HELLO" and hello["version"] == 1 and hello["evidence_key_id"] == key_id(public)
                and command["sequence"] == hello["sequence_floor"] + 1
                and 0 < command["expires_ns"] <= hello["expires_ns"], "Wrong readiness context")
        require(segment["boot_id"] == command["boot_id"].hex() and segment["execution_id"] == command["execution_id"].hex()
                and segment["sequence"] == command["sequence"], "Wrong execution metadata")
        require(command["execution_id"] not in seen, "Reused execution ID")
        seen.add(command["execution_id"])
        require(command["outputs"] == context["outputs"] == segment["outputs"] == list(L.OUTPUTS)
                and command["units"] == context["units"] == segment["units"] == list(L.UNITS)
                and command["actuators"] == list(L.ACTUATORS), "Wrong channel/units coverage")
        require(segment["physics_dt"] == command["physics_dt"] == [1, L.HZ]
                and segment["sample_every_steps"] == command["sample_every_steps"] == 1, "Wrong sampling schedule")
        reference = load(segment["reference"])
        expected = required["segments"][0]
        # Recompute the authored deterministic program without loading Isaac.
        rows, old = [], list(program["initial_target"])
        for phase in program["operations"][index]["phases"]:
            for step in range(1, phase["steps"] + 1):
                u = step / phase["steps"]
                alpha = u * u * (3 - 2 * u)
                rows.append([round(a + (b-a)*alpha) for a, b in zip(old, phase["target"])])
            old = phase["target"]
        require(reference == {"trajectory": rows, "phases": expected["phases"], "hold_steps": program["hold_steps"],
                              "initial_target": program["initial_target"]}, "Wrong full reference coverage")
        require(command["trajectory"] == rows and command["hold_steps"] == expected["hold_steps"]
                and len(rows) == expected["trajectory_rows"]
                and command["initial_positions"] == program["initial_target"] + [program["initial_target"][-1]]
                and command["initial_tolerance"] == program["initial_tolerance"], "Command does not cover authored operation")
        require(segment["phases"] == context["phases"] == expected["phases"]
                and segment["reference_trajectory_sha256"] == sha256(encode(rows)).hexdigest(), "Wrong phase coverage")
        require(segment["expected_sample_count"] == evidence["expected_sample_count"] == expected["expected_sample_count"]
                and segment["captured_sample_count"] == evidence["sample_count"] == len(evidence["samples"]), "Wrong sample counts")
        require(segment["terminal_state"] == evidence["terminal_state"] and segment["partial"] == evidence["partial"]
                and segment["termination_reason"] == evidence["reason"], "Wrong terminal metadata")
        # This tests capture structure/timing only. No tracking tolerance or
        # task verdict is selected here (S6-03 owns the independent predicates).
        # Both legacy movement outcomes require full capture; neither is used
        # as a scene motion verdict. No tolerance is changed for this check.
        complete = checked != "NOT_PROVEN"
        for field in ("execution_seconds", "checking_seconds"):
            require(type(segment[field]) in (int, float) and math.isfinite(segment[field]) and segment[field] >= 0,
                    "Invalid wall timing")
        require(segment["simulated_seconds"] == (expected["expected_sample_count"] - 1) / L.HZ, "Wrong simulation duration")
        if previous is not None:
            old_command, old_evidence = previous
            require(command["boot_id"] == old_command["boot_id"] and command["sequence"] == old_command["sequence"] + 1
                    and command["challenge"] != old_command["challenge"], "Broken persistent controller sequence")
            require(old_evidence["samples"] and evidence["samples"] and
                    old_evidence["samples"][-1][1:4] == evidence["samples"][0][1:4] and
                    old_evidence["samples"][-1][5:] == evidence["samples"][0][5:], "Scene reset/gap at operation boundary")
        previous = command, evidence
        results.append({"operation_index": index, "segment_index": 0, "execution_id": command["execution_id"].hex(),
                        "evidence_validation": "VALID", "capture_complete": complete,
                        "motion_verdict": None, "object_verdict": None,
                        "reason": "Exact signed command/report and required operation coverage verified; no task verdict computed"})
    return {"run_id": run["run_id"], "segments": results,
            "operation_coverage_complete": len(results) == len(plan) and all(r["capture_complete"] for r in results),
            "identity_scope": "caller-pinned public keys" if authority_public_der_hex and evidence_public_der_hex else "retained development public keys"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="Offline run.json; no simulator required")
    parser.add_argument("--authority-public-der-hex")
    parser.add_argument("--evidence-public-der-hex")
    parser.add_argument("--expected-runtime", help="For new archives: native or the full expected container image ID")
    args = parser.parse_args()
    print(json.dumps(verify_run(args.manifest, authority_public_der_hex=args.authority_public_der_hex,
                               evidence_public_der_hex=args.evidence_public_der_hex,
                               expected_runtime=args.expected_runtime), indent=2))


if __name__ == "__main__":
    main()

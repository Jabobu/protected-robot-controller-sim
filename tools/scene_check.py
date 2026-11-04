"""S6-03 offline task assessment. No simulator, private keys, or task controller.

The caller trusts the policy, reference plan and public identities. Retained
development keys provide consistency only unless independently pinned. Replaying
an archive is not live freshness or physical sensor authentication.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.serialization import load_der_public_key

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import PROFILE, encode, key_id, public_bytes, strict_decode, verify_sign1
from tools.controller_fixture import EvidenceChecker, authenticated_evidence
from tools.scene_evidence import PUBLIC_FIELDS, operation_plan, scenario_operation_plan, segment_binding, require
from tools.scene_objects import assess_objects
from tools.prc_security import security_config_digest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "scenes/manipulation/evidence_policy.json"


def load_policy(path=POLICY):
    """Local verifier policy is a trusted input, never selected by report fields."""
    policy = json.loads(Path(path).read_bytes())
    motion = policy["motion"]
    require(policy["schema_version"] == 1 and policy["policy_id"] == "B601-SCENE-ASSESSMENT-1",
            "Unsupported assessment policy")
    require(motion["outputs"] == list(L.OUTPUTS) and motion["units"] == list(L.UNITS)
            and motion["physics_hz"] == L.HZ and motion["simulation_time_tolerance_ns"] == 5
            and motion["minimum_endpoint_displacement"] == 0 and motion["incomplete_verdict"] == "UNKNOWN",
            "Wrong fixed sampling/channel policy")
    tolerance = motion["tracking_tolerance"]
    require(type(tolerance) is list and len(tolerance) == 8
            and all(type(v) is int and v >= 0 for v in tolerance), "Invalid tracking tolerance")
    return policy


def expected_segment(program, operation_index, binding, hello, *, segment_index=0):
    """Expand a trusted deterministic reference independently of simulator code.

    S6-02 uses one bounded segment per operation. assess_operation also accepts
    multiple explicit expectations for callers with an authored segmented plan.
    Never derive the list of required expectations from received segments.
    """
    rows, old = [], program["initial_target"]
    for phase in program["operations"][operation_index]["phases"]:
        require(type(phase["steps"]) is int and phase["steps"] > 0, "Invalid phase duration")
        for step in range(1, phase["steps"] + 1):
            u = step / phase["steps"]
            alpha = u * u * (3 - 2 * u)
            rows.append([round(a + (b - a) * alpha) for a, b in zip(old, phase["target"])])
        old = phase["target"]
    fields = {
        "version": 1, "type": "EXECUTE", "profile": PROFILE,
        "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
        "config_digest": L.CONFIG_DIGEST, "authorization_context_digest": sha256(encode(binding)).digest(),
        "actuators": list(L.ACTUATORS), "outputs": list(L.OUTPUTS), "units": list(L.UNITS),
        "physics_dt": [1, L.HZ], "sample_every_steps": 1, "start_behavior": "IMMEDIATE_IF_MATCH",
        "velocity_limits": list(L.VELOCITY), "effort_limits": list(L.EFFORT),
        "initial_positions": program["initial_target"] + [program["initial_target"][-1]],
        "initial_tolerance": program["initial_tolerance"], "trajectory": rows,
        "hold_steps": program["hold_steps"],
    }
    return {"segment_index": segment_index, "command_fields": fields, "hello": hello,
            "phases": operation_plan(program)[operation_index]["segments"][0]["phases"]}


def _result(validation, motion, reasons, **diagnostics):
    return {"evidence_validation": validation, "motion_verdict": motion,
            "reasons": reasons, **diagnostics}


def _motion(evidence, command, tolerance, phases):
    """Every valid row is compared; partial prefixes retain deviation diagnostics."""
    rows = evidence["samples"]
    count = 1 + len(command["trajectory"]) + command["hold_steps"]
    valid_indices, errors, first_deviation = [], [0] * 8, None
    previous = None
    timing_valid = type(rows) is list and bool(rows)
    for index, row in enumerate(rows if type(rows) is list else []):
        if (type(row) is not list or len(row) != 7
                or any(type(v) is not int or v < 0 for v in row[:5])
                or row[0] != index or index >= count
                or type(row[5]) is not list or len(row[5]) != 8
                or any(type(v) is not int or not -(2**31) <= v < 2**31 for v in row[5])
                or type(row[6]) is not list or len(row[6]) != 8
                or any(v is not True for v in row[6])
                or row[4] > L.MAX_RUN_NS or (index == 0 and row[4] > L.MAX_STEP_NS)):
            timing_valid = False
            break
        if previous is not None and (row[1] != previous[1] + 1 or row[2] != previous[2] + 1
                or abs((row[3] - previous[3]) * L.HZ - 1_000_000_000) > 5 * L.HZ
                or not previous[4] <= row[4] <= previous[4] + L.MAX_STEP_NS):
            timing_valid = False
            break
        if index == 0:
            target, thresholds = command["initial_positions"], command["initial_tolerance"]
        else:
            actuator_row = command["trajectory"][min(index - 1, len(command["trajectory"]) - 1)]
            target, thresholds = actuator_row + [actuator_row[6]], tolerance
        difference = [abs(q - t) for q, t in zip(row[5], target)]
        errors = [max(a, b) for a, b in zip(errors, difference)]
        if first_deviation is None and any(v > t for v, t in zip(difference, thresholds)):
            first_deviation = {"sample_index": index, "errors": difference, "thresholds": list(thresholds)}
        valid_indices.append(index)
        previous = row
    # Reuse S6's complete timing/count predicate, with no endpoint displacement
    # requirement. A COMPLETE flag alone cannot yield conformance.
    checked = EvidenceChecker._motion(evidence, command, tolerance, (0,) * 8)
    verdict = {"VERIFIED_SUCCESS": "CONFORMANT", "VERIFIED_FAILURE": "DEVIATED",
               "NOT_PROVEN": "UNKNOWN"}[checked]
    if not timing_valid:
        verdict = "UNKNOWN"
    phase_coverage = [{**p, "expected_samples": p["last_row"] - p["first_row"] + 1,
                       "valid_samples": sum(p["first_row"] <= i <= p["last_row"] for i in valid_indices)}
                      for p in phases]
    reasons = {"CONFORMANT": "Every initial, trajectory and hold observation meets the frozen policy",
               "DEVIATED": "Authentic complete observations exceed the frozen motion tolerance",
               "UNKNOWN": "Incomplete, invalid, mistimed or aborted capture cannot establish complete motion"}
    return _result("VALID", verdict, [reasons[verdict]],
                   captured_tracking_deviation=first_deviation is not None, first_deviation=first_deviation,
                   max_error=errors if valid_indices else None, max_error_units=list(L.UNITS),
                   coverage={"expected_samples": count, "captured_samples": len(rows) if type(rows) is list else 0,
                             "reported_expected_samples": evidence["expected_sample_count"],
                             "reported_captured_samples": evidence["sample_count"], "valid_prefix_samples": len(valid_indices),
                             "timing_and_channels_valid": timing_valid, "phases": phase_coverage,
                             "terminal_state": evidence["terminal_state"], "partial": evidence["partial"],
                             "termination_reason": evidence["reason"]})


class SceneChecker:
    """One replay session retains execution/challenge/sequence uniqueness.

    This ledger detects archive reuse, not current controller liveness. HELLO is
    unsigned: expiry is checked for consistency, not retrospectively attested.
    """
    def __init__(self, authority_public_key, evidence_public_key, policy):
        require(public_bytes(authority_public_key) != public_bytes(evidence_public_key), "Separate keys required")
        self.authority, self.public = authority_public_key, evidence_public_key
        self.tolerance = tuple(policy["motion"]["tracking_tolerance"])
        require(len(self.tolerance) == 8 and all(type(v) is int and v >= 0 for v in self.tolerance),
                "Trusted tolerance must cover every output")
        self.checker = EvidenceChecker(authority_public_key, evidence_public_key)
        self.executions, self.challenges, self.sequences = set(), set(), {}
        self.boot = None
        self.previous = None

    def assess_segment(self, command_bytes, evidence_bytes, expected):
        try:
            command = verify_sign1(command_bytes, self.authority)
            fields = expected["command_fields"]
            dynamic = {"boot_id", "challenge", "execution_id", "sequence", "expires_ns"}
            require(type(command) is dict and command.keys() == fields.keys() | dynamic, "Wrong command schema")
            require(all(encode(command[k]) == encode(v) for k, v in fields.items()),
                    "Wrong command reference, configuration, channels or operation binding")
            for name, size in (("boot_id", 32), ("challenge", 32), ("execution_id", 16)):
                require(type(command[name]) is bytes and len(command[name]) == size, "Wrong freshness identity")
            for name in ("sequence", "expires_ns"):
                require(type(command[name]) is int and 0 < command[name] < 2**63, "Wrong freshness integer")
            hello = expected["hello"]
            require(hello["type"] == "HELLO" and type(hello["version"]) is int and hello["version"] == 1
                    and hello["evidence_key_id"] == key_id(self.public), "Wrong readiness identity")
            for field in ("profile", "robot_id", "controller_id", "boot_id", "challenge", "config_digest"):
                require(encode(hello[field]) == encode(command[field]), "HELLO/command binding mismatch")
            require(type(hello["sequence_floor"]) is int and type(hello["expires_ns"]) is int
                    and command["sequence"] == hello["sequence_floor"] + 1
                    and command["expires_ns"] <= hello["expires_ns"], "Wrong readiness freshness")
            identity = command["boot_id"], command["execution_id"]
            challenge = command["boot_id"], command["challenge"]
            require(self.boot in (None, command["boot_id"]), "Unexpected controller restart within replay session")
            self.boot = command["boot_id"]
            require(identity not in self.executions
                    and challenge not in self.challenges
                    and command["sequence"] > self.sequences.get(command["boot_id"], 0), "Reused/reordered execution")
            self.executions.add(identity)
            self.challenges.add(challenge)
            self.sequences[command["boot_id"]] = command["sequence"]
            if evidence_bytes is None:
                self.previous = None
                return _result("VALID", "UNKNOWN", ["Authenticated command; required signed report is missing"])
            checked = self.checker.check(evidence_bytes, command_bytes)
            require(checked != "REJECTED", "Original report signature, command digest, schema or replay check failed")
            evidence = authenticated_evidence(evidence_bytes, self.public)
            result = _motion(evidence, command, self.tolerance, expected["phases"])
            if self.previous is not None:
                old_command, old_evidence = self.previous
                require(command["boot_id"] == old_command["boot_id"], "Unexpected controller restart in persistent operation")
                # Check continuity only across complete adjacent captures. Missing
                # coverage cannot prove a gap or reset, so remains UNKNOWN.
                if result["motion_verdict"] != "UNKNOWN" and old_evidence["terminal_state"] == "COMPLETE" and old_evidence["samples"]:
                    a, b = old_evidence["samples"][-1], evidence["samples"][0]
                    require(a[1:4] == b[1:4] and a[5:] == b[5:], "Signed segment boundary is discontinuous")
            self.previous = (command, evidence) if result["motion_verdict"] != "UNKNOWN" else None
            return result
        except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
            self.previous = None
            return _result("REJECTED_EVIDENCE", None, [str(error) or type(error).__name__])

    def assess_operation(self, segments, required):
        """Missing coverage is UNKNOWN; all present segments still authenticate."""
        results, missing, supplied = [], [], {}
        if type(segments) is not list or any(type(s) is not dict or not {"segment_index", "command", "report"} <= s.keys() for s in segments):
            return _result("REJECTED_EVIDENCE", None, ["Malformed segment record"], segments=[])
        indices = [s["segment_index"] for s in segments]
        if (any(type(i) is not int for i in indices) or indices != sorted(set(indices))
                or any(i not in [p["segment_index"] for p in required] for i in indices)):
            return _result("REJECTED_EVIDENCE", None, ["Extra, duplicate or reordered segment"], segments=[])
        supplied = {s["segment_index"]: s for s in segments}
        require(required and [p["segment_index"] for p in required] == list(range(len(required))),
                "Trusted required segment plan must be contiguous and nonempty")
        for expectation in required:
            index = expectation["segment_index"]
            if index not in supplied:
                missing.append(index)
                self.previous = None
                continue
            segment = supplied[index]
            result = self.assess_segment(segment["command"], segment["report"], expectation)
            results.append({"segment_index": index, **result})
        rejected = any(r["evidence_validation"] == "REJECTED_EVIDENCE" for r in results)
        verdict = None if rejected else (
            "UNKNOWN" if missing or any(r["motion_verdict"] == "UNKNOWN" for r in results) else
            "DEVIATED" if any(r["motion_verdict"] == "DEVIATED" for r in results) else "CONFORMANT")
        reasons = [reason for r in results for reason in r["reasons"]]
        if missing:
            reasons.append(f"Required segments missing: {missing}")
        return _result("REJECTED_EVIDENCE" if rejected else "VALID", verdict, reasons, segments=results,
                       coverage={"required_segments": len(required), "present_segments": len(segments),
                                 "missing_segments": missing},
                       captured_tracking_deviation=any(r.get("captured_tracking_deviation", False) for r in results))


class _Archive:
    def __init__(self, manifest, root):
        self.root, self.manifest = Path(root).resolve(), Path(manifest).absolute()
        require(".." not in self.manifest.parts, "Unsafe manifest path")
        require(self.manifest.is_relative_to(self.root / "artifacts/scene-work"), "Archive outside scene-work")
        require(all(not p.is_symlink() for p in (self.manifest, *self.manifest.parents)), "Symlink archive")
        self.run = json.loads(self.manifest.read_bytes())
        require(type(self.run) is dict and type(self.run.get("files")) is dict, "Malformed archive file index")

    def read(self, relative, *, optional=False):
        path = PurePosixPath(relative)
        require(not path.is_absolute() and ".." not in path.parts, "Unsafe archive path")
        target = self.root / path
        require(target.is_relative_to(self.manifest.parent)
                and all(not p.is_symlink() for p in (target, *target.parents)), "Path outside archive or symlink")
        if optional and not target.exists():
            return None
        raw = target.read_bytes()
        require(sha256(raw).hexdigest() == self.run["files"].get(relative), "Retained file digest mismatch")
        return raw

    def load(self, relative):
        return json.loads(self.read(relative))


def _replay_run(manifest, *, policy_path=POLICY, authority_public_der_hex=None,
                evidence_public_der_hex=None, expected_runtime=None, root=ROOT):
    """Replay scene archives, keeping object failure independent of signed motion.

    Missing operations/segments/reports are coverage gaps; present altered bytes
    or incorrect associations are rejection. Old stored verdicts are ignored.
    """
    policy = load_policy(policy_path)
    archive = _Archive(manifest, root)
    run = archive.run
    output = {"schema_version": 1, "run_id": run["run_id"], "policy_id": policy["policy_id"],
              "policy_sha256": sha256(Path(policy_path).read_bytes()).hexdigest(),
              "manifest_sha256": sha256(Path(manifest).read_bytes()).hexdigest(),
              "sensor_authenticated": False,
              "identity_scope": "caller-pinned public keys" if authority_public_der_hex and evidence_public_der_hex
                                else "retained development public keys",
              "limitations": ["Object replay is not sensor authentication", "Offline replay is not live freshness"],
              "operations": []}
    # A metadata error rejects motion but must not become a delivered-object assertion.
    try:
        profile, program = (archive.load(run["public_inputs"][k]) for k in ("profile", "program"))
        require(security_config_digest(profile, policy) == run["security_config_sha256"],
                "Wrong semantic security configuration")
        for field, name in (("profile_sha256", "profile"), ("trajectory_sha256", "program")):
            require(sha256(archive.read(run["public_inputs"][name])).hexdigest() == run[field] == policy[field],
                    "Archive differs from frozen profile/program")
        require(sha256(archive.read(run["public_inputs"]["model"])).hexdigest()
                == run["model_sha256"] == L.MODEL_MANIFEST_SHA256, "Wrong model provenance")
        from tools.runtime_provenance import validate_runtime
        require(sha256(archive.read(run["public_inputs"]["runtime"])).hexdigest() == run["runtime_metadata_sha256"]
                and validate_runtime(archive.load(run["public_inputs"]["runtime"]), run, profile,
                                         expected_runtime=expected_runtime),
                "Wrong runtime provenance")
        runtime = archive.load(run["public_inputs"]["runtime"])
        if "runtime_identity" in runtime:
            require(type(runtime.get("isaac_version")) is list and bool(runtime["isaac_version"])
                    and type(runtime["isaac_version"][0]) is str
                    and runtime["isaac_version"][0].split("-")[0].split("+")[0] == "6.0.0",
                    "Wrong Isaac runtime")
        require(sha256(encode(archive.load(run["public_inputs"]["source_files"]))).hexdigest()
                == run["source_files_sha256"], "Wrong source provenance")
        require(program["interpolation"] == policy["motion"]["interpolation"], "Wrong interpolation policy")
        plan = scenario_operation_plan(program, run["scenario"])
        require(run["required_operations"] == archive.load(run["public_inputs"]["operation_plan"]) == plan
                and sha256(encode(plan)).hexdigest() == run["operation_plan_sha256"], "Changed required operation coverage")
        authority_hex, evidence_hex = run["authority_public_der_hex"], run["evidence_public_der_hex"]
        require(authority_public_der_hex in (None, authority_hex) and evidence_public_der_hex in (None, evidence_hex),
                "Unexpected public verification identity")
        authority, public = (load_der_public_key(bytes.fromhex(k)) for k in (authority_hex, evidence_hex))
        checker = SceneChecker(authority, public, policy)
        expected_order = [(p["object_id"], p["destination"]) for p in plan]
        actual_order = [(o["object_id"], o["destination"]) for o in run["operations"]]
        require(len(actual_order) == len(set(actual_order))
                and all(o in expected_order for o in actual_order)
                and actual_order == sorted(actual_order, key=expected_order.index), "Extra, duplicated or reordered operation")
    except (ValueError, KeyError, TypeError, OSError) as error:
        return {**output, **_result("REJECTED_EVIDENCE", None, [str(error)]), "object_verdict": "UNKNOWN"}
    by_identity = {(o["object_id"], o["destination"]): o for o in run["operations"]}
    for index, requirement in enumerate(plan):
        operation = by_identity.get((requirement["object_id"], requirement["destination"]), {"segments": []})
        raw_segments, expectations = [], []
        object_result = {"object_verdict": "UNKNOWN", "sensor_authenticated": False,
                         "reasons": ["Required operation/object observations missing"]}
        # Object observations have their own integrity/coverage outcome. Their
        # absence or corruption cannot invalidate an otherwise valid signature.
        if operation["segments"]:
            try:
                segment = operation["segments"][-1]
                observations = archive.load(segment["object_observations"])
                end_step = segment["physics_step_last"]
                endpoint = next(r for r in reversed(observations) if r["physics_step"] == end_step)
                object_result = assess_objects(observations, requirement["object_id"], requirement["destination"],
                                               profile, policy, end_step=end_step,
                                               end_time_ns=endpoint["simulation_time_ns"])
                object_result["endpoint_source"] = "retained independent object endpoint (unsigned)"
            except (ValueError, KeyError, TypeError, OSError, StopIteration) as error:
                object_result["reasons"] = [f"Object data unavailable or invalid: {error}"]
        try:
            binding = segment_binding(run, index)
            require(len(operation["segments"]) <= 1, "Extra or duplicated segment")
            # One required segment even when none arrived. No implicit success
            # from an empty received list. HELLO is only needed for present data.
            hello = None
            for segment in operation["segments"]:
                require(segment["operation_index"] == segment["global_segment_index"] == index
                        and segment["segment_index"] == 0 and segment["required_segment_count"] == 1, "Wrong segment ordering")
                context = archive.load(segment["public_context"])
                require(type(context) is dict and context.keys() == PUBLIC_FIELDS
                        and context["binding"] == binding, "Wrong public segment binding")
                require(context["authority_public_der_hex"] == authority_hex and context["evidence_public_der_hex"] == evidence_hex
                        and context["authority_key_id"] == key_id(authority).hex()
                        and context["evidence_key_id"] == key_id(public).hex(), "Wrong segment identity")
                require(bytes.fromhex(context["config_cbor_hex"]) == encode(L.configuration())
                        and context["config_digest_hex"] == L.CONFIG_DIGEST.hex(), "Wrong configuration context")
                require(context["outputs"] == list(L.OUTPUTS) and context["units"] == list(L.UNITS), "Wrong public channels")
                require(context["profile_sha256"] == run["profile_sha256"]
                        and context["trajectory_sha256"] == run["trajectory_sha256"], "Wrong public profile binding")
                require(context["candidate_tolerance"] == policy["motion"]["tracking_tolerance"],
                        "Public tolerance metadata differs from frozen policy")
                hello = strict_decode(archive.read(segment["hello"]), 1_049_600)
                raw = {"segment_index": 0, "command": archive.read(segment["command"]),
                       "report": archive.read(segment["report"], optional=True)}
                for field in ("command", "report"):
                    if raw[field] is not None:
                        require(sha256(raw[field]).hexdigest() == context[field + "_sha256"] == segment[field + "_sha256"]
                                and len(raw[field]) == segment[field + "_bytes"], "Wrong raw byte identity/size")
                command = verify_sign1(raw["command"], authority)
                require(type(command) is dict, "Wrong command schema")
                require(type(command["boot_id"]) is bytes and type(command["execution_id"]) is bytes,
                        "Wrong execution identity schema")
                require(segment["boot_id"] == command["boot_id"].hex()
                        and segment["execution_id"] == command["execution_id"].hex()
                        and segment["sequence"] == command["sequence"], "Wrong execution identity metadata")
                require(segment["outputs"] == context["outputs"] and segment["units"] == context["units"]
                        and segment["config_digest_hex"] == run["config_digest_hex"] == L.CONFIG_DIGEST.hex(),
                        "Wrong segment configuration metadata")
                raw_segments.append(raw)
            expectations.append(expected_segment(program, index, binding, hello))
            if raw_segments:
                fields, phases = expectations[0]["command_fields"], expectations[0]["phases"]
                reference = {"trajectory": fields["trajectory"], "phases": phases,
                             "hold_steps": fields["hold_steps"], "initial_target": program["initial_target"]}
                require(archive.load(segment["reference"]) == reference
                        and context["phases"] == segment["phases"] == phases, "Wrong reference/phase coverage")
                require(segment["reference_trajectory_sha256"] == sha256(encode(fields["trajectory"])).hexdigest(),
                        "Wrong reference hash")
            motion = checker.assess_operation(raw_segments, expectations)
        except (ValueError, KeyError, TypeError, OSError) as error:
            checker.previous = None
            motion = _result("REJECTED_EVIDENCE", None, [str(error)])
        # When a complete authentic trace exists, its final physics step/time
        # anchors the object window too. This binds interval association, not
        # object sensor truth. Partial/rejected motion leaves the independently
        # retained object endpoint available and explicitly unsigned.
        if (motion["evidence_validation"] == "VALID" and motion["motion_verdict"] != "UNKNOWN"
                and raw_segments and raw_segments[-1]["report"] is not None):
            try:
                report = authenticated_evidence(raw_segments[-1]["report"], public)
                endpoint = report["samples"][-1]
                observations = archive.load(operation["segments"][-1]["object_observations"])
                object_result = assess_objects(observations, requirement["object_id"], requirement["destination"],
                                               profile, policy, end_step=endpoint[2], end_time_ns=endpoint[3])
                object_result["endpoint_source"] = "complete signed joint trace; object values remain unsigned"
            except (ValueError, KeyError, TypeError, OSError) as error:
                object_result = {"object_verdict": "UNKNOWN", "sensor_authenticated": False,
                                 "reasons": [f"Object interval association unavailable: {error}"]}
        output["operations"].append({"operation_index": index, "object_id": requirement["object_id"],
                                     "destination": requirement["destination"], **motion,
                                     "object_verdict": object_result["object_verdict"], "objects": object_result})
    rejected = any(o["evidence_validation"] == "REJECTED_EVIDENCE" for o in output["operations"])
    verdict = None if rejected else (
        "UNKNOWN" if any(o["motion_verdict"] == "UNKNOWN" for o in output["operations"]) else
        "DEVIATED" if any(o["motion_verdict"] == "DEVIATED" for o in output["operations"]) else "CONFORMANT")
    return {**output, "evidence_validation": "REJECTED_EVIDENCE" if rejected else "VALID", "motion_verdict": verdict}


def replay_run(manifest, *, policy_path=POLICY, authority_public_der_hex=None,
               evidence_public_der_hex=None, expected_runtime=None, root=ROOT):
    """Structured fail-closed archive entry point; see _replay_run for scope."""
    try:
        return _replay_run(manifest, policy_path=policy_path,
                           authority_public_der_hex=authority_public_der_hex,
                           evidence_public_der_hex=evidence_public_der_hex, expected_runtime=expected_runtime, root=root)
    except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
        return {"schema_version": 1, **_result("REJECTED_EVIDENCE", None, [str(error)]),
                "object_verdict": "UNKNOWN", "sensor_authenticated": False, "operations": []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--authority-public-der-hex")
    parser.add_argument("--evidence-public-der-hex")
    parser.add_argument("--expected-runtime", help="For new archives: native or the full expected container image ID")
    args = parser.parse_args()
    result = replay_run(args.manifest, policy_path=args.policy,
                        authority_public_der_hex=args.authority_public_der_hex,
                        evidence_public_der_hex=args.evidence_public_der_hex,
                        expected_runtime=args.expected_runtime)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 2 if result["evidence_validation"] == "REJECTED_EVIDENCE" else 0


if __name__ == "__main__":
    raise SystemExit(main())

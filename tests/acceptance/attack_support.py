"""Trusted S5 test instrumentation. Never imported by controller code.

Every PASS uses a live B601 backend. Denial counters observe both the controller
backend calls and the actual articulation/tensor write boundary, independently
of any response text. These are trusted-host tests, not OS isolation evidence.
"""

from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import secrets
import shlex
import sys

import pytest

from physics_support import HOLD_STEPS, RAMP_STEPS, measured_backend, trajectory
from protected_robot_controller import limits as L
from protected_robot_controller.controller import Controller
from protected_robot_controller.interface import ControllerInterface, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode, public_bytes, strict_decode
from protected_robot_controller.simulation.model import MANIFEST_PATH, ROOT
from tools.controller_fixture import (
    EvidenceChecker, authenticated_evidence, command_for, sign_command,
)
from tools.integrated_fixture import CHECK_TOLERANCE, MIN_DISPLACEMENT

REQUIRED = {
    "forged_command": ["test_wrong_key_and_address_no_motor_writes",
                       "test_invalid_signature_no_motor_writes",
                       "test_unsafe_limits_no_motor_writes",
                       "test_malformed_requests_no_motor_writes"],
    "replayed_command": ["test_expired_and_replayed_no_motor_writes",
                         "test_restart_invalidates_boot_commands"],
    "altered_evidence": ["test_modified_evidence_is_rejected"],
    "sensor_injection": ["test_untrusted_sensor_injection_denied"],
    "direct_motor_bypass": ["test_untrusted_motor_bypass_denied"],
    "invalid_acquisition": ["test_sensor_failure_not_proven",
                            "test_simulation_pause_does_not_extend_deadline",
                            "test_backend_connection_failure_not_proven",
                            "test_complete_obstructed_trace_is_verified_failure"],
    "connection_loss": ["test_connection_loss_stop_behavior"],
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


class AttackRecords:
    def __init__(self, config, keys):
        self.keys = keys
        self.run_id = secrets.token_hex(12)
        self.directory = ROOT / "artifacts/s5/runs" / self.run_id
        self.matrix = {
            "stage": "S5", "run_id": self.run_id,
            "scope": "Live B601 PhysX and real byte-interface denials on trusted host; no guest-root or physical-security claim",
            "stage_acceptance": "PENDING_EXTERNAL_SUPERVISOR",
            "command": shlex.join([sys.executable, "-m", "pytest", *map(str, config.invocation_params.args)]),
            "rerun": "/isaac-sim/python.sh -m pytest -q tests/acceptance/test_attacks.py --junitxml=/reports/s5-attacks.xml",
            "scenarios": {name: "NOT_RUN" for name in REQUIRED},
            "required_cases": REQUIRED, "cases": {},
            "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                "tests/acceptance/test_attacks.py", "tests/acceptance/attack_support.py",
                "protected_robot_controller/controller.py", "protected_robot_controller/interface.py",
                "protected_robot_controller/protocol.py", "protected_robot_controller/simulation/_backend.py",
                "tools/controller_fixture.py")},
        }
        self.flush()

    def flush(self):
        for scenario, names in REQUIRED.items():
            statuses = [self.matrix["cases"].get(name, {}).get("status", "NOT_RUN") for name in names]
            status = (
                "FAIL" if "FAIL" in statuses else "PASS" if all(s == "PASS" for s in statuses) else "NOT_RUN")
            # The stage artifact contract exposes scenario IDs at the root.
            # Keep the detailed view in sync, including resets and failures.
            self.matrix[scenario] = self.matrix["scenarios"][scenario] = status
        for path in (ROOT / "artifacts/attack_matrix.json", self.directory / "attack_matrix.json"):
            write_json(path, self.matrix)

    @contextmanager
    def case(self, name):
        """Record PASS only after assertions AND real backend cleanup return."""
        from isaacsim.core.version import get_version

        directory = self.directory / name
        directory.mkdir(parents=True, exist_ok=True)
        record = {"status": "RUNNING", "events": [], "isaac_version": list(get_version()),
                  "model_manifest_sha256": sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
                  "authority_public_der_hex": public_bytes(self.keys[0].public_key()).hex(),
                  "evidence_public_der_hex": public_bytes(self.keys[1].public_key()).hex()}
        self.matrix["cases"][name] = {"status": "RUNNING", "record": str((directory / "record.json").relative_to(ROOT))}
        self.flush()
        try:
            assert record["model_manifest_sha256"] == L.MODEL_MANIFEST_SHA256
            with pytest.MonkeyPatch.context() as patch, measured_backend(patch) as backend:
                rig = AttackRig(backend, patch, self.keys, directory, record)
                yield rig
            record["status"] = "PASS"
        except BaseException as error:
            record.update(status="FAIL", error=repr(error))
            raise
        finally:
            write_json(directory / "record.json", record)
            self.matrix["cases"][name].update(
                status=record["status"], record_sha256=sha256((directory / "record.json").read_bytes()).hexdigest())
            self.flush()


class AttackRig:
    def __init__(self, backend, patch, keys, directory, record):
        self.backend, self.patch = backend, patch
        self.authority, self.evidence_key = keys
        self.directory, self.record = directory, record
        self.counts = dict(drive=0, action=0, position_targets=0, velocity_targets=0,
                           efforts=0, stop=0, capture=0)
        self.observations = []
        self.first_drive = lambda: None
        self.writes, self.stops = [], []

        original_drive = backend.drive
        def drive(targets, **limits):
            self.counts["drive"] += 1
            self.writes.append({"targets": list(targets), **{k: list(v) for k, v in limits.items()}})
            if self.counts["drive"] == 1:
                self.first_drive()
            return original_drive(targets, **limits)
        patch.setattr(backend, "drive", drive)

        # Observe below the controller/backend drive function. Positive controls
        # require these counters to move, so an inert spy cannot prove denial.
        view = backend._robot._articulation_view._physics_view
        for obj, method, counter in (
            (backend._robot, "apply_action", "action"),
            (view, "set_dof_position_targets", "position_targets"),
            (view, "set_dof_velocity_targets", "velocity_targets"),
            (view, "set_dof_actuation_forces", "efforts"),
        ):
            original = getattr(obj, method)
            def observe(*args, _original=original, _counter=counter, **kwargs):
                self.counts[_counter] += 1
                return _original(*args, **kwargs)
            patch.setattr(obj, method, observe)

        original_stop = backend.stop_or_hold
        def stop(reason=None):
            self.counts["stop"] += 1
            self.stops.append(reason)
            return original_stop(reason)
        patch.setattr(backend, "stop_or_hold", stop)

        original_capture = backend._capture
        def capture():
            import numpy as np

            self.counts["capture"] += 1
            sample = original_capture()
            raw = np.array(backend._robot.get_joint_positions(), dtype=float, copy=True)
            actual = tuple(float(raw[i]) for i in backend._indices)
            assert sample.positions == actual
            self.observations.append({"counter": sample.counter, "physics_step": sample.physics_step,
                                      "simulation_time_ns": sample.simulation_time_ns,
                                      "monotonic_time_ns": sample.monotonic_time_ns,
                                      "positions": list(actual), "valid": list(sample.valid)})
            return sample
        patch.setattr(backend, "_capture", capture)
        self.restart()
        self.command = self.new_command()

    def restart(self):
        self.controller = Controller(self.authority.public_key(), self.evidence_key, self.backend)
        self.interface = ControllerInterface(self.controller)

    def new_command(self):
        hello = self.request("hello", {"version": 1, "type": "HELLO"})
        assert hello["type"] == "HELLO"
        self.hello = hello
        initial = [round(q * 1_000_000) for q in self.backend._read_vector(self.backend._robot.get_joint_positions)]
        ramp = [[round(q * 1_000_000) for q in target] for target in trajectory()[:RAMP_STEPS]]
        command = command_for(hello, initial, ramp, hold_steps=HOLD_STEPS)
        command["authorization_context_digest"] = sha256(b"S5 trusted adverse fixture").digest()
        return command

    def save(self, name, raw):
        path = self.directory / name
        path.write_bytes(raw)
        return {"path": str(path.relative_to(ROOT)), "sha256": sha256(raw).hexdigest(), "bytes": len(raw)}

    def request(self, label, message=None, *, raw=None):
        wire = encode(message) if raw is None else raw
        index = len(self.record["events"])
        event = {"label": label, "request": self.save(f"{index:03d}.request.cbor", wire),
                 "before": self.counts.copy()}
        self.record["events"].append(event)
        response = self.interface.handle(wire)
        event.update(response=self.save(f"{index:03d}.response.cbor", response), after=self.counts.copy())
        decoded = strict_decode(response, MAX_RESPONSE_BYTES)
        event["response_type"] = decoded["type"]
        if "reason" in decoded:
            event["reason"] = decoded["reason"]
        return decoded

    def reject(self, label, command=None, *, message=None, raw=None, reason=None):
        before = self.counts.copy()
        if command is not None:
            message = {"version": 1, "type": "EXECUTE", "command": command}
        result = self.request(label, message, raw=raw)
        assert result["type"] == "REJECTED", result
        assert set(result) == {"version", "type", "reason"}
        if reason is not None:
            assert result["reason"] == reason
        assert self.counts == before, (label, before, self.counts)
        self.record["events"][-1]["observed_zero_requested_writes"] = True
        return result

    def signed(self, command=None):
        return sign_command(self.command if command is None else command, self.authority)

    def checker(self):
        return EvidenceChecker(self.authority.public_key(), self.evidence_key.public_key())

    def check(self, bundle, command):
        return self.checker().check(bundle, command, tolerance=CHECK_TOLERANCE,
                                    minimum_displacement=MIN_DISPLACEMENT)

    def execute(self, *, command=None, label="execute"):
        wire = self.signed() if command is None else command
        result = self.request(label, {"version": 1, "type": "EXECUTE", "command": wire})
        assert result["type"] == "EVIDENCE", result
        bundle = result["evidence"]
        evidence = authenticated_evidence(bundle, self.evidence_key.public_key())
        event = self.record["events"][-1]
        event.update(command=self.save(label + ".command.cbor", wire),
                     evidence=self.save(label + ".evidence.cbor", bundle),
                     verdict=self.check(bundle, wire), terminal=evidence["terminal_state"],
                     sample_count=evidence["sample_count"], reason=evidence["reason"])
        self.record.update(observations=self.observations, drive_calls=self.writes, stops=self.stops)
        return wire, bundle, evidence

    def positive_control(self):
        wire, bundle, evidence = self.execute(label="positive-control")
        assert self.check(bundle, wire) == "VERIFIED_SUCCESS"
        assert evidence["terminal_state"] == "COMPLETE" and not evidence["partial"]
        assert evidence["sample_count"] == 361
        assert self.counts["drive"] == 360
        assert self.counts["action"] == self.counts["position_targets"] == 361
        assert self.counts["velocity_targets"] == 361
        assert self.counts["efforts"] == 0
        assert self.stops == ["NONE"]
        for row, observation in zip(evidence["samples"], self.observations):
            assert row[5] == [round(q * 1_000_000) for q in observation["positions"]]
        return wire, bundle, evidence

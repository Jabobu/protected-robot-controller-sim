"""S5 adversarial acceptance: real controller, real B601, observed denials.

The provisioned Python and Isaac entry points are both /isaac-sim/python.sh.
These tests deliberately require SimulationApp: a synthetic backend cannot
produce a PASS attack matrix. No earlier acceptance test is modified.
"""

from copy import deepcopy
from dataclasses import replace
import socket
import time

import cbor2
import pytest
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message

from attack_support import AttackRecords
from physics_support import obstruct
from protected_robot_controller import limits as L
from protected_robot_controller.interface import MAX_REQUEST_BYTES
from protected_robot_controller.protocol import (
    MAX_COMMAND_BYTES, cose_private, encode, key_id,
)
from tools.controller_fixture import development_keys, sign_command


@pytest.fixture(scope="session", autouse=True)
def attack_records(pytestconfig):
    # Reset all scenario statuses before attempting to start Isaac. A failed
    # runtime setup cannot retain a previous attempt's PASS entries.
    return AttackRecords(pytestconfig, development_keys())


@pytest.fixture
def attack_case(attack_records, simulation_app, request):
    return lambda: attack_records.case(request.node.name)


def test_wrong_key_and_address_no_motor_writes(attack_case):
    with attack_case() as rig:
        other, _ = development_keys()
        rig.reject("wrong-key", sign_command(rig.command, other), reason="HEADERS")
        # A forged KID must reach and fail cryptographic verification itself.
        spoofed = Sign1Message(phdr={Algorithm: Es256, KID: key_id(rig.authority.public_key())},
                               payload=encode(rig.command), key=cose_private(other)).encode(tag=True)
        rig.reject("wrong-key-correct-kid", spoofed, reason="SIGNATURE")
        for field, value in (("controller_id", "other-controller"), ("robot_id", "other-robot"),
                             ("config_digest", b"x" * 32), ("outputs", list(reversed(L.OUTPUTS))),
                             ("units", ["rad"] * 8), ("profile", "different-profile")):
            command = deepcopy(rig.command)
            command[field] = value
            rig.reject(field, rig.signed(command), reason="CONTEXT")
        rig.positive_control()


def test_invalid_signature_no_motor_writes(attack_case):
    with attack_case() as rig:
        wire = rig.signed()
        rig.reject("signature-bit-flip", wire[:-1] + bytes([wire[-1] ^ 1]), reason="SIGNATURE")
        envelope = cbor2.loads(wire)
        parts = list(envelope.value)
        changed = deepcopy(rig.command)
        changed["trajectory"][1][0] += 1
        parts[2] = encode(changed)
        rig.reject("signed-target-altered", encode(cbor2.CBORTag(18, parts)), reason="SIGNATURE")
        rig.positive_control()


def test_unsafe_limits_no_motor_writes(attack_case):
    with attack_case() as rig:
        for channel in range(7):
            for violation in ("position", "speed", "effort", "velocity-cap"):
                command = deepcopy(rig.command)
                if violation == "position":
                    command["trajectory"][0][channel] = L.UPPER[channel] + 1
                elif violation == "speed":
                    command["trajectory"][0][channel] = command["initial_positions"][channel] + L.VELOCITY[channel] // L.HZ + 1
                elif violation == "effort":
                    command["effort_limits"][channel] += 1
                else:
                    command["velocity_limits"][channel] += 1
                rig.reject(f"{channel}-{violation}", rig.signed(command), reason="LIMIT")
        for field, value in (("hold_steps", L.MAX_HOLD_STEPS + 1),
                             ("initial_tolerance", [10**9] * 8), ("trajectory", [])):
            command = deepcopy(rig.command)
            command[field] = value
            rig.reject("unsafe-" + field, rig.signed(command), reason="LIMIT")
        # Compact zero-valued integers keep this genuine duration violation
        # below 64 KiB, so it exercises the duration bound, not just framing.
        command = deepcopy(rig.command)
        command.update(initial_positions=[0] * 8, trajectory=[[0] * 7] * (L.MAX_DURATION_STEPS + 1))
        rig.reject("duration", rig.signed(command), reason="LIMIT")
        for value in (float("nan"), float("inf")):
            command = deepcopy(rig.command)
            command["trajectory"][0][0] = value
            rig.reject("nonfinite-position", rig.signed(command), reason="MALFORMED")
        rig.positive_control()


def test_malformed_requests_no_motor_writes(attack_case):
    with attack_case() as rig:
        for index, raw in enumerate((b"", b"x" * (MAX_REQUEST_BYTES + 1), b"\xbf\xff",
                                      b"\xa2\x64type\x65HELLO\x64type\x65HELLO",
                                      encode({"version": 1, "type": "HELLO"}) + b"\x00")):
            rig.reject(f"framing-{index}", raw=raw)
        for label, value in (("empty", b""), ("oversize", b"x" * (MAX_COMMAND_BYTES + 1)),
                             ("wrong-type", [])):
            rig.reject(label, message={"version": 1, "type": "EXECUTE", "command": value})
        rig.positive_control()


def test_expired_and_replayed_no_motor_writes(attack_case):
    with attack_case() as rig:
        expired = deepcopy(rig.command)
        expired["expires_ns"] = time.monotonic_ns() - 1
        rig.reject("expired", rig.signed(expired), reason="EXPIRED")
        stale = rig.signed()
        rig.command = rig.new_command()
        rig.reject("superseded-challenge", stale, reason="REPLAY")
        wire, _, _ = rig.positive_control()
        rig.reject("exact-command-replay", wire, reason="REPLAY")
        # Replacing just the relay/interface preserves controller replay state.
        rig.interface = type(rig.interface)(rig.controller)
        rig.reject("relay-restart-replay", wire, reason="REPLAY")
        old = deepcopy(rig.command)
        fresh = rig.new_command()
        for field in ("sequence", "execution_id"):
            command = deepcopy(fresh)
            command[field] = old[field]
            rig.reject("fresh-challenge-old-" + field, rig.signed(command), reason="REPLAY")


def test_restart_invalidates_boot_commands(attack_case):
    with attack_case() as rig:
        # Pending but unused authorizations are invalid after a trusted restart.
        old_boot = rig.command["boot_id"]
        pending = rig.signed()
        rig.restart()  # Same provisioned authority/evidence keys and real backend.
        rig.command = rig.new_command()
        assert rig.command["boot_id"] != old_boot
        rig.reject("old-unused-boot", pending, reason="BOOT")
        consumed, _, _ = rig.positive_control()
        accepted_boot = rig.command["boot_id"]
        rig.restart()
        fresh = rig.new_command()
        assert fresh["boot_id"] not in (old_boot, accepted_boot)
        rig.reject("old-consumed-boot", consumed, reason="BOOT")
        rig.reject("old-snapshot-boot", pending, reason="BOOT")
        # Boot, challenge and sequence reset are independent of a guest's cache.
        assert fresh["sequence"] == 1


def test_modified_evidence_is_rejected(attack_case):
    with attack_case() as rig:
        wire, bundle, evidence = rig.positive_control()
        mutations = {
            "sample-value": lambda e: e["samples"][1][5].__setitem__(0, 123456),
            "sample-order": lambda e: e["samples"].reverse(),
            "sample-count": lambda e: e.update(sample_count=1),
            "sample-missing": lambda e: e["samples"].pop(2),
            "validity": lambda e: e["samples"][1][6].__setitem__(0, False),
            "units": lambda e: e.update(units=["rad"] * 8),
            "terminal": lambda e: e.update(terminal_state="ABORTED", partial=True),
            "context": lambda e: e.update(authorization_context_digest=b"x" * 32),
            "boot": lambda e: e.update(boot_id=b"x" * 32),
            "challenge": lambda e: e.update(challenge=b"x" * 32),
            "command-digest": lambda e: e.update(command_digest=b"x" * 32),
        }
        for label, mutation in mutations.items():
            changed = deepcopy(evidence)
            mutation(changed)
            parts = list(cbor2.loads(bundle).value)
            parts[2] = encode(changed)  # Retain original signature, never re-sign.
            altered = encode(cbor2.CBORTag(18, parts))
            observed = rig.check(altered, wire)
            rig.record["events"].append({"label": label, "altered_evidence": rig.save(label + ".cbor", altered),
                                         "verdict": observed})
            assert observed == "REJECTED"
        # Authentic evidence cannot be substituted for a different retained
        # execution or authorization context, even with valid command signatures.
        for field, value in (("authorization_context_digest", b"y" * 32),
                             ("execution_id", b"y" * 16), ("challenge", b"y" * 32)):
            expected = deepcopy(rig.command)
            expected[field] = value
            other_wire = rig.signed(expected)
            verdict = rig.check(bundle, other_wire)
            rig.record["events"].append({"label": "retained-" + field,
                                         "expected_command": rig.save(field + ".command.cbor", other_wire),
                                         "verdict": verdict})
            assert verdict == "REJECTED"
        checker = rig.checker()
        # Default strict tolerances may yield failure, but authenticity must hold.
        assert checker.check(bundle, wire) in ("VERIFIED_SUCCESS", "VERIFIED_FAILURE")
        replay_verdict = checker.check(bundle, wire)
        assert replay_verdict == "REJECTED"
        rig.record["events"].append({"label": "evidence-replay", "verdict": replay_verdict})


def test_untrusted_sensor_injection_denied(attack_case):
    with attack_case() as rig:
        wire = rig.signed()
        for kind in ("SAMPLE", "SENSOR", "FEEDBACK", "SIGN", "SIGN_EVIDENCE"):
            rig.reject(kind, message={"version": 1, "type": kind, "positions": [999] * 8,
                                      "valid": [True] * 8, "payload": b"arbitrary"}, reason="REQUEST")
        for field, value in (("samples", [[999] * 8]), ("valid", [True] * 8),
                             ("sensor_source", "guest"), ("evidence", b"forged")):
            rig.reject("outer-" + field, message={"version": 1, "type": "EXECUTE", "command": wire,
                                                 field: value}, reason="REQUEST")
            command = deepcopy(rig.command)
            command[field] = value
            rig.reject("signed-" + field, rig.signed(command), reason="SCHEMA")
        _, _, evidence = rig.positive_control()
        assert all(999 not in row[5] for row in evidence["samples"])


def test_untrusted_motor_bypass_denied(attack_case):
    with attack_case() as rig:
        for kind in ("DRIVE", "ENABLE", "RESET", "CALIBRATE", "CONFIGURE", "SET_JOINT_POSITIONS",
                     "APPLY_ACTION", "SET_EFFORT", "STOP_OR_HOLD"):
            rig.reject(kind, message={"version": 1, "type": kind, "targets": [0] * 7}, reason="REQUEST")
        for field in ("targets", "backend", "effort_limits", "reset", "calibrate"):
            rig.reject("execute-extra-" + field,
                       message={"version": 1, "type": "EXECUTE", "command": rig.signed(), field: [0] * 7},
                       reason="REQUEST")
        rig.positive_control()


def test_sensor_failure_not_proven(attack_records, simulation_app):
    # Each fault uses fresh physics and fresh keys' challenges; no reset can
    # revive an aborted controller. Individual outcomes are retained, but the
    # required scenario stays NOT_RUN until the entire named test succeeds.
    kinds = ("missing", "invalid", "counter", "physics-step", "simulation-time", "wall-time", "nonfinite")
    for kind in kinds:
        with attack_records.case("test_sensor_failure_not_proven-" + kind) as rig:
            original_sample = rig.backend.sample_outputs
            def sample():
                reading = original_sample()
                if reading.counter != 3:
                    return reading
                if kind == "missing":
                    raise OSError("Trusted test: acquisition channel unavailable")
                changes = {
                    "invalid": {"valid": (False,) + (True,) * 7},
                    "counter": {"counter": reading.counter + 1},
                    "physics-step": {"physics_step": reading.physics_step + 1},
                    "simulation-time": {"simulation_time_ns": reading.simulation_time_ns - 1_000_000},
                    "wall-time": {"monotonic_time_ns": reading.monotonic_time_ns + L.MAX_STEP_NS},
                    "nonfinite": {"positions": (float("nan"),) + reading.positions[1:]},
                }
                return replace(reading, **changes[kind])
            rig.patch.setattr(rig.backend, "sample_outputs", sample)
            wire, bundle, evidence = rig.execute()
            rig.record["trusted_fault"] = kind
            assert evidence["terminal_state"] == "ABORTED" and evidence["partial"] is True
            assert evidence["sample_count"] == (4 if kind == "invalid" else 3)
            assert evidence["expected_sample_count"] == 361
            assert rig.check(bundle, wire) == "NOT_PROVEN"
            assert rig.counts["drive"] == 3
            assert rig.counts["action"] == rig.counts["position_targets"] == 4
            assert len(rig.stops) == 1 and rig.backend._faulted
            if kind == "invalid":
                assert evidence["samples"][-1][6][0] is False
            rig.reject("fault-replay", wire, reason="FAULT")
            rig.reject("fault-hello", message={"version": 1, "type": "HELLO"}, reason="FAULT")
    # Aggregate only observed child records, never a stubbed result.
    children = ["test_sensor_failure_not_proven-" + kind for kind in kinds]
    assert all(attack_records.matrix["cases"][name]["status"] == "PASS" for name in children)
    attack_records.matrix["cases"]["test_sensor_failure_not_proven"] = {"status": "PASS", "cases": children}
    attack_records.flush()


def test_simulation_pause_does_not_extend_deadline(attack_records, simulation_app):
    name = "test_simulation_pause_does_not_extend_deadline"
    with attack_records.case(name + "-start-expiry") as rig:
        # Pause the actual World. Its simulation time stays fixed while the
        # trusted monotonic start window expires; the clock is never replaced.
        rig.backend._world.pause()
        frozen = (int(rig.backend._world.current_time_step_index), float(rig.backend._world.current_time))
        expiring = deepcopy(rig.command)
        expiring["expires_ns"] = time.monotonic_ns() + 50_000_000
        old = rig.signed(expiring)
        remaining = (expiring["expires_ns"] - time.monotonic_ns()) / 1e9
        if remaining > 0:
            time.sleep(remaining + 0.01)
        rig.reject("paused-start-expiry", old, reason="EXPIRED")
        assert frozen == (int(rig.backend._world.current_time_step_index), float(rig.backend._world.current_time))
        rig.record["pause"] = {"frozen_before_start": frozen, "signed_expiry_ns": expiring["expires_ns"],
                               "observed_monotonic_ns": time.monotonic_ns()}
    # Resume can itself dispatch a physics tick. Use a fresh scene rather than
    # resetting the backend clock or resynchronizing away an unobserved step.
    with attack_records.case(name + "-running") as rig:
        original_step = rig.backend.step_physics
        pause = {}
        def step(*, deadline_ns):
            if rig.backend._steps == 5:
                rig.backend._world.pause()
                pause.update(step=int(rig.backend._world.current_time_step_index), deadline_ns=deadline_ns,
                             started_ns=time.monotonic_ns())
                assert pause["started_ns"] < deadline_ns
            return original_step(deadline_ns=deadline_ns)
        rig.patch.setattr(rig.backend, "step_physics", step)
        wire, bundle, evidence = rig.execute()
        ended = time.monotonic_ns()
        assert pause and ended < pause["deadline_ns"]
        assert int(rig.backend._world.current_time_step_index) == pause["step"]
        assert evidence["terminal_state"] == "ABORTED" and evidence["partial"]
        assert evidence["sample_count"] == 6 and evidence["reason"] == "BACKEND"
        assert rig.counts["drive"] == 6
        assert rig.backend._faulted and rig.stops[-1] == "BACKEND"
        assert rig.check(bundle, wire) == "NOT_PROVEN"
        rig.record["pause"] = {**pause, "ended_ns": ended}
        rig.reject("paused-retry", wire, reason="FAULT")
    children = [name + "-start-expiry", name + "-running"]
    assert all(attack_records.matrix["cases"][child]["status"] == "PASS" for child in children)
    attack_records.matrix["cases"][name] = {"status": "PASS", "cases": children}
    attack_records.flush()


def test_connection_loss_stop_behavior(attack_case):
    with attack_case() as rig:
        # Real disconnected socket, while all PhysX operations stay on the
        # main thread. This is a TEST relay, not another controller transport.
        peer, relay = socket.socketpair()
        relay.settimeout(1)
        disconnect = {}
        def close_peer():
            peer.close()
            assert relay.recv(1) == b""
            disconnect.update(at_requested_write=rig.counts["drive"], time_ns=time.monotonic_ns())
        rig.first_drive = close_peer
        try:
            wire, bundle, evidence = rig.positive_control()
            assert disconnect["at_requested_write"] == 1
            with pytest.raises(BrokenPipeError) as denied:
                relay.sendall(bundle)
            rig.record["delivery_denial"] = {**disconnect, "error": type(denied.value).__name__,
                                             "errno": denied.value.errno}
            assert rig.checker().check(None, wire) == "NOT_PROVEN"
            assert evidence["terminal_state"] == "COMPLETE"
            assert rig.stops == ["NONE"] and rig.backend._pending_drive is False
            # A replacement relay cannot repeat an already accepted trajectory.
            rig.interface = type(rig.interface)(rig.controller)
            rig.reject("reconnect-replay", wire, reason="REPLAY")
        finally:
            peer.close()
            relay.close()


def test_backend_connection_failure_not_proven(attack_case):
    with attack_case() as rig:
        original_step = rig.backend.step_physics
        def disconnected(*, deadline_ns):
            if rig.backend._steps == 3:
                raise ConnectionError("Trusted fault: protected backend communication lost")
            return original_step(deadline_ns=deadline_ns)
        rig.patch.setattr(rig.backend, "step_physics", disconnected)
        wire, bundle, evidence = rig.execute()
        assert evidence["terminal_state"] == "ABORTED" and evidence["partial"]
        assert evidence["reason"] == "BACKEND" and evidence["sample_count"] == 4
        assert evidence["expected_sample_count"] == 361
        assert rig.check(bundle, wire) == "NOT_PROVEN"
        assert rig.counts["drive"] == 4 and rig.counts["action"] == 5
        assert rig.stops == ["BACKEND"] and rig.backend._faulted
        rig.record["trusted_fault"] = "Protected backend connection exception after three real steps"
        rig.reject("failed-backend-retry", wire, reason="FAULT")


def test_complete_obstructed_trace_is_verified_failure(attack_case):
    with attack_case() as rig:
        # A complete, authentic failed movement must remain distinguishable
        # from acquisition failure. Lock the gripper leader in actual PhysX;
        # both coupled outputs must report the obstruction, without sensor edits.
        constraint = obstruct(rig.backend, "gripper")
        wire, bundle, evidence = rig.execute()
        rig.record["constraint"] = constraint
        assert evidence["terminal_state"] == "COMPLETE" and evidence["partial"] is False
        assert evidence["reason"] == "NONE" and evidence["sample_count"] == 361
        assert rig.check(bundle, wire) == "VERIFIED_FAILURE"
        assert rig.counts["drive"] == 360
        assert rig.counts["action"] == rig.counts["position_targets"] == 361
        assert rig.stops == ["NONE"]
        rows = evidence["samples"]
        assert len(rig.observations) == len(rows)
        for row, observed in zip(rows, rig.observations):
            assert row[5] == [round(q * 1_000_000) for q in observed["positions"]]
            assert row[6] == [True] * 8
        for output in (6, 7):
            assert max(abs(row[5][output] - rows[0][5][output]) for row in rows) < 100
            assert abs(rows[-1][5][output] - rig.command["trajectory"][-1][6]) > 8000
        assert all(abs(rows[-1][5][j] - rows[0][5][j]) > 50_000 for j in range(6))

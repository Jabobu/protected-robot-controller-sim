"""S3 crypto/state-machine UNIT tests. No mock result counts as Isaac physics.

The eight supervisor-required names are real tests below. Sample data is fixed
by trusted test setup and is intentionally different from commanded targets.
No test imports Isaac, changes the model, or accesses a supervisor directory.
"""

from dataclasses import replace
from hashlib import sha256
import importlib.metadata
import json
from pathlib import Path
import threading

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message

from protected_robot_controller import limits as L
from protected_robot_controller.backend import Observation
from protected_robot_controller.controller import Controller, EvidenceUnavailable
from protected_robot_controller.protocol import (
    MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, Rejected, cose_private, encode, key_id, verify_sign1,
)
from tools.controller_fixture import (
    EvidenceChecker, authenticated_evidence, command_for, development_keys, record_vector, sign_command,
)

INITIAL = (0, -700_000, -1_100_000, 0, 0, 0, 20_000, 20_000)


class UnitClock:
    def __init__(self):
        self.now = 1_000_000_000

    def __call__(self):
        return self.now


class ScriptedUnitBackend:
    """Unit double only: a preloaded sensor script, never target feedback."""

    def __init__(self, clock, *, blocked=False):
        self.clock = clock
        self.frames = [tuple((base + (0 if blocked else min(i, 10) * (900 if j < 6 else 90)))
                             / 1_000_000 for j, base in enumerate(INITIAL)) for i in range(23)]
        self.steps = 0
        self.writes = []
        self.stops = []
        self.fail_at = None
        self.modify = lambda sample: sample
        self.on_drive = lambda: None
        self.fail_stop = False

    def _read(self):
        if self.steps == self.fail_at:
            raise RuntimeError("test sensor failure")
        sample = Observation(self.steps, 100 + self.steps,
                             round((100 + self.steps) * 1_000_000_000 / 120),
                             self.clock(), self.frames[self.steps], (True,) * 8)
        return self.modify(sample)

    def read_initial(self):
        return self._read()

    def drive(self, targets, *, velocity_limits, effort_limits):
        self.writes.append((targets, velocity_limits, effort_limits))
        self.on_drive()

    def step_physics(self, *, deadline_ns):
        self.steps += 1
        self.clock.now += 8_333_333

    def sample_outputs(self):
        return self._read()

    def stop_or_hold(self, reason):
        self.stops.append(reason)
        if self.fail_stop:
            raise RuntimeError("test stop failure")


class Rig:
    def __init__(self, *, blocked=False):
        self.authority, self.evidence_key = development_keys()
        self.clock = UnitClock()
        self.backend = ScriptedUnitBackend(self.clock, blocked=blocked)
        self.controller = Controller(self.authority.public_key(), self.evidence_key, self.backend,
                                     monotonic_ns=self.clock)
        self.hello = self.controller.hello()
        targets = [[base + step * (1000 if j < 6 else 100)
                    for j, base in enumerate(INITIAL[:7])] for step in range(1, 11)]
        self.command = command_for(self.hello, INITIAL, targets)

    def signed(self):
        return sign_command(self.command, self.authority)

    def run(self):
        command = self.signed()
        bundle = self.controller.execute(command)
        return command, bundle, authenticated_evidence(bundle, self.evidence_key.public_key())

    def checker(self):
        return EvidenceChecker(self.authority.public_key(), self.evidence_key.public_key())


@pytest.fixture
def rig():
    return Rig()


@pytest.fixture
def s3_reports(pytestconfig):
    xml = pytestconfig.getoption("xmlpath", default=None)
    folder = (Path(xml).resolve().parent if xml else Path("output").resolve()) / "s3"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def assert_rejected(rig, wire, code=None):
    before = len(rig.backend.writes)
    with pytest.raises(Rejected) as error:
        rig.controller.execute(wire)
    if code is not None:
        assert error.value.code == code
    assert len(rig.backend.writes) == before, "Rejected command requested actuation"
    return error.value.code


def test_valid_signed_command_executes(rig, s3_reports):
    command, bundle, evidence = rig.run()
    assert rig.controller.state == "COMPLETE"
    assert len(rig.backend.writes) == 22
    assert rig.backend.stops == ["NONE"]
    assert evidence["sample_count"] == 23
    assert evidence["terminal_state"] == "COMPLETE"
    assert evidence["partial"] is False
    assert rig.checker().check(bundle, command) == "VERIFIED_SUCCESS"
    assert len(bundle) < MAX_EVIDENCE_BYTES
    record_vector(s3_reports, "unit_normal", command, bundle,
                  rig.authority.public_key(), rig.evidence_key.public_key())
    (s3_reports / "runtime.json").write_text(json.dumps({
        "scope": "UNIT ONLY; no Isaac execution", "versions": {
            package: importlib.metadata.version(package)
            for package in ("cryptography", "cbor2", "pycose", "pytest")}}, indent=2) + "\n")


def test_rejects_invalid_signature(rig):
    wire = rig.signed()
    assert_rejected(rig, wire[:-1] + bytes([wire[-1] ^ 1]), "SIGNATURE")


def test_rejects_wrong_controller(rig):
    rig.command["controller_id"] = "other-controller"
    assert_rejected(rig, rig.signed(), "CONTEXT")


def test_rejects_expired_command(rig):
    wire = rig.signed()
    rig.clock.now = rig.hello["expires_ns"]
    assert_rejected(rig, wire, "EXPIRED")


def test_rejects_replay(rig):
    wire = rig.signed()
    rig.controller.execute(wire)
    assert_rejected(rig, wire, "REPLAY")


def _assert_actuator_limit_rejected(rig, channel, violation):
    if violation == "position":
        rig.command["trajectory"][0][channel] = L.UPPER[channel] + 1
    elif violation == "speed":
        rig.command["trajectory"][0][channel] = INITIAL[channel] + L.VELOCITY[channel] // L.HZ + 1
    else:
        rig.command["effort_limits"][channel] += 1
    assert_rejected(rig, rig.signed(), "LIMIT")


def test_enforces_actuator_limits():
    # Keep every channel/violation once under the required acceptance name.
    # Each authority-signed unsafe command must cause zero requested writes.
    for channel in range(7):
        for violation in ("position", "speed", "effort"):
            _assert_actuator_limit_rejected(Rig(), channel, violation)


def test_signed_evidence_binds_command(rig):
    command, bundle, evidence = rig.run()
    assert evidence["command_digest"] == sha256(command).digest()
    for field in ("challenge", "boot_id", "sequence", "execution_id", "authorization_context_digest"):
        assert evidence[field] == rig.command[field]
    checker = rig.checker()
    assert checker.check(bundle, command) == "VERIFIED_SUCCESS"
    assert checker.check(bundle, command) == "REJECTED"
    rig.command["authorization_context_digest"] = b"x" * 32
    assert rig.checker().check(bundle, rig.signed()) == "REJECTED"
    # Verify command's original Sig_structure independently of controller/pycose.
    protected, _, payload, signature = cbor2.loads(command).value
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                     int.from_bytes(signature[32:], "big"))
    rig.authority.public_key().verify(der, encode(["Signature1", protected, b"", payload]),
                                      ec.ECDSA(hashes.SHA256()))


def test_controller_fault_stop(rig, s3_reports):
    rig.backend.fail_at = 3
    command, bundle, evidence = rig.run()
    assert rig.controller.state == "ABORTED"
    assert rig.backend.stops == ["BACKEND"]
    assert evidence["terminal_state"] == "ABORTED" and evidence["partial"] is True
    assert evidence["sample_count"] == 3
    assert evidence["samples"][-1][0] == 2
    assert rig.checker().check(bundle, command) == "NOT_PROVEN"
    assert_rejected(rig, command, "FAULT")
    with pytest.raises(Rejected, match="FAULT"):
        rig.controller.hello()
    record_vector(s3_reports, "unit_aborted", command, bundle,
                  rig.authority.public_key(), rig.evidence_key.public_key())


def test_signed_stationary_samples_are_failure_not_target_echo(s3_reports):
    rig = Rig(blocked=True)
    command, bundle, evidence = rig.run()
    assert len(rig.backend.writes) == 22
    assert all(row[5] == list(INITIAL) for row in evidence["samples"])
    assert rig.checker().check(bundle, command) == "VERIFIED_FAILURE"
    record_vector(s3_reports, "unit_stationary", command, bundle,
                  rig.authority.public_key(), rig.evidence_key.public_key())


def test_sample_trace_comes_only_from_backend(rig):
    _, _, evidence = rig.run()
    assert evidence["samples"][1][5][0] == 900
    assert rig.command["trajectory"][0][0] == 1000
    assert evidence["samples"][1][5][0] != rig.command["trajectory"][0][0]
    rig.backend.frames[1] = (100.0,) * 8
    assert evidence["samples"][1][5][0] == 900
    assert all(row[6] == [True] * 8 for row in evidence["samples"])


@pytest.mark.parametrize("field,value", [
    ("robot_id", "wrong-robot"), ("config_digest", b"x" * 32),
    ("boot_id", b"x" * 32), ("challenge", b"x" * 32),
    ("version", True), ("version", 2), ("sequence", True), ("sequence", 0),
    ("profile", "production"), ("type", "SIGN"), ("execution_id", b"short"),
    ("actuators", ["unknown"]), ("outputs", list(L.OUTPUTS[:-1])),
    ("units", ["rad"] * 8), ("physics_dt", [True, 120]), ("sample_every_steps", 2),
    ("start_behavior", "IGNORE_INITIAL"), ("initial_tolerance", [10**9] * 8),
    ("hold_steps", 0), ("hold_steps", 241), ("trajectory", []),
])
def test_rejects_bad_authenticated_context(rig, field, value):
    rig.command[field] = value
    assert_rejected(rig, rig.signed())


def test_rejects_wrong_authority_even_with_valid_es256(rig):
    other, _ = development_keys()
    assert_rejected(rig, sign_command(rig.command, other), "HEADERS")


def test_separate_keys_required(rig):
    with pytest.raises(ValueError, match="separate"):
        Controller(rig.authority.public_key(), rig.authority, rig.backend)


def test_only_p256_keys_allowed(rig):
    other = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="P-256"):
        Controller(other.public_key(), rig.evidence_key, rig.backend)


def test_renewed_challenge_invalidates_previous(rig):
    wire = rig.signed()
    renewed = rig.controller.hello()
    assert renewed["challenge"] != rig.hello["challenge"]
    assert_rejected(rig, wire, "REPLAY")


def test_controller_restart_rejects_old_boot(rig):
    wire = rig.signed()
    rig.controller = Controller(rig.authority.public_key(), rig.evidence_key, rig.backend,
                                monotonic_ns=rig.clock)
    assert rig.controller.hello()["boot_id"] != rig.hello["boot_id"]
    assert_rejected(rig, wire, "BOOT")


@pytest.mark.parametrize("reuse", ["sequence", "execution_id"])
def test_fresh_challenge_does_not_allow_old_sequence_or_execution(rig, reuse):
    rig.run()
    hello = rig.controller.hello()
    old = rig.command[reuse]
    rig.command = command_for(hello, INITIAL, rig.command["trajectory"])
    rig.command[reuse] = old
    assert_rejected(rig, rig.signed(), "REPLAY")


def test_single_active_execution(rig):
    entered, release = threading.Event(), threading.Event()
    def pause():
        entered.set()
        assert release.wait(3)
    rig.backend.on_drive = pause
    wire = rig.signed()
    results = []
    def run():
        try:
            results.append(rig.controller.execute(wire))
        except BaseException as error:
            results.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert entered.wait(3)
        assert_rejected(rig, wire, "BUSY")
        with pytest.raises(Rejected, match="BUSY"):
            rig.controller.hello()
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    assert len(results) == 1 and type(results[0]) is bytes
    assert len(rig.backend.writes) == 22


def test_initial_mismatch_consumes_authorization_without_drive(rig):
    rig.command["initial_positions"][0] = 100
    wire, _, evidence = rig.run()
    assert rig.backend.writes == []
    assert evidence["reason"] == "INITIAL_STATE"
    assert evidence["sample_count"] == 1
    assert rig.backend.stops == ["INITIAL_STATE"]
    assert_rejected(rig, wire, "FAULT")


@pytest.mark.parametrize("kind", ["invalid_flag", "nan", "counter", "step", "sim_time", "wall_time", "limit"])
def test_invalid_acquisition_is_partial_and_stopped(rig, kind):
    def broken(sample):
        if sample.counter != 2:
            return sample
        return replace(sample, **{
            "invalid_flag": {"valid": (False,) + (True,) * 7},
            "nan": {"positions": (float("nan"),) + sample.positions[1:]},
            "counter": {"counter": 50}, "step": {"physics_step": 900},
            "sim_time": {"simulation_time_ns": 1}, "wall_time": {"monotonic_time_ns": 1},
            "limit": {"positions": (10.0,) + sample.positions[1:]},
        }[kind])
    rig.backend.modify = broken
    command, bundle, evidence = rig.run()
    assert evidence["terminal_state"] == "ABORTED" and evidence["partial"]
    assert 2 <= evidence["sample_count"] <= 3
    assert len(rig.backend.stops) == 1
    assert len(rig.backend.writes) == 2
    assert rig.checker().check(bundle, command) == "NOT_PROVEN"
    if kind == "invalid_flag":
        assert evidence["samples"][-1][6][0] is False
    if kind == "limit":
        assert evidence["samples"][-1][5][0] == 10_000_000


def test_step_overrun_stops_without_filling_missing_sample(rig):
    rig.backend.on_drive = lambda: setattr(rig.clock, "now", rig.clock.now + L.MAX_STEP_NS + 1)
    _, _, evidence = rig.run()
    assert evidence["reason"] == "OVERRUN"
    assert evidence["sample_count"] == 1
    assert rig.backend.stops == ["OVERRUN"]


def test_start_expiry_rechecked_after_initial_acquisition(rig):
    def delay(sample):
        rig.clock.now = rig.command["expires_ns"]
        return replace(sample, monotonic_time_ns=rig.clock.now)
    rig.command["expires_ns"] = rig.clock.now + 1_000_000
    rig.backend.modify = delay
    _, _, evidence = rig.run()
    assert evidence["reason"] == "START_EXPIRED"
    assert rig.backend.writes == []


def test_expiry_at_first_drive_check_prevents_actuation(rig):
    calls = 0
    def delayed_clock():
        nonlocal calls
        calls += 1
        if calls == 5:
            rig.clock.now = rig.command["expires_ns"]
        return rig.clock.now
    rig.controller = Controller(rig.authority.public_key(), rig.evidence_key, rig.backend,
                                monotonic_ns=delayed_clock)
    hello = rig.controller.hello()
    rig.command = command_for(hello, INITIAL, rig.command["trajectory"])
    calls = 0
    _, _, evidence = rig.run()
    assert evidence["reason"] == "START_EXPIRED"
    assert rig.backend.writes == []


def test_drive_step_and_capture_share_one_deadline(rig):
    rig.backend.on_drive = lambda: setattr(rig.clock, "now", rig.clock.now + 1_100_000_000)
    def slow_read(sample):
        if sample.counter:
            rig.clock.now += 1_100_000_000
        return replace(sample, monotonic_time_ns=rig.clock.now)
    rig.backend.modify = slow_read
    _, _, evidence = rig.run()
    assert evidence["reason"] == "OVERRUN"
    assert evidence["sample_count"] == 1
    assert len(rig.backend.writes) == 1


def test_stop_failure_is_not_complete(rig):
    rig.backend.fail_stop = True
    command, bundle, evidence = rig.run()
    assert evidence["reason"] == "STOP_FAILED"
    assert evidence["terminal_state"] == "ABORTED"
    assert rig.controller.state == "FAULT"
    assert rig.checker().check(bundle, command) == "NOT_PROVEN"


def test_clock_rollback_rejected_before_drive(rig):
    rig.clock.now -= 1
    assert_rejected(rig, rig.signed(), "CLOCK")
    assert rig.controller.state == "FAULT"


def test_no_signing_sensor_or_drive_operations_on_message_interface(rig):
    wire = rig.signed()
    with pytest.raises(TypeError):
        rig.controller.execute(wire, measurements=[1] * 8)
    for name in ("sign", "sign_evidence", "drive", "sample_outputs", "reset", "calibrate", "backend"):
        assert not hasattr(rig.controller, name)
    rig.command["samples"] = [[1] * 8]
    assert_rejected(rig, rig.signed(), "SCHEMA")


def _sign_raw_payload(rig, payload):
    return Sign1Message(phdr={Algorithm: Es256, KID: key_id(rig.authority.public_key())},
                        payload=payload, key=cose_private(rig.authority)).encode(tag=True)


@pytest.mark.parametrize("payload", [
    b"\xa2\x61a\x01\x61a\x02",  # duplicate map key
    b"\xbf\x61a\x01\xff",  # indefinite map
    b"\xa1\x61a\x18\x01",  # nonminimal integer
    b"\xa2\x61b\x01\x61a\x02",  # map order
    b"\xa0\x00", b"\x81" * 20 + b"\x00", b"\xd8\x1c\x81\xd8\x1d\x00",
    b"\xa1\x61a\xf9\x7e\x00", b"\xa1\x61a\xf9\x7c\x00", b"\xa1\x61a\xf6",
    b"\xa1\x01\x01", b"\xa1\x61a\xc2\x41\x01", b"\xa1\x61a\x61\xff",
])
def test_strict_cbor_rejects_signed_malformed_payload(rig, payload):
    assert_rejected(rig, _sign_raw_payload(rig, payload), "MALFORMED")


@pytest.mark.parametrize("mutation", ["trailing", "untagged", "header", "unprotected", "detached", "short_signature"])
def test_cose_shape_and_headers_are_fixed(rig, mutation):
    wire = rig.signed()
    envelope = list(cbor2.loads(wire).value)
    if mutation == "trailing":
        wire += b"\x00"
    elif mutation == "untagged":
        wire = wire[1:]
    else:
        if mutation == "header":
            envelope[0] = encode({1: -35, 4: key_id(rig.authority.public_key())})
        elif mutation == "unprotected":
            envelope[1] = {"data": "ignored?"}
        elif mutation == "detached":
            envelope[2] = None
        elif mutation == "short_signature":
            envelope[3] = b"x" * 63
        wire = b"\xd2" + encode(envelope)
    assert_rejected(rig, wire)


def test_rejects_duration_and_byte_bounds(rig):
    # Resource bound is independently exercised using a compact in-envelope payload.
    rig.command["trajectory"] = [[0, 0, 0, 0, 0, 0, 0]] * 3601
    rig.command["initial_positions"] = [0] * 8
    assert_rejected(rig, rig.signed(), "LIMIT")
    assert_rejected(rig, b"x" * (MAX_COMMAND_BYTES + 1), "SIZE")


def test_checker_rejects_evidence_tampering(rig):
    command, bundle, evidence = rig.run()
    envelope = list(cbor2.loads(bundle).value)
    # An unsigned payload change fails authentication before field semantics.
    evidence["samples"] = "tampered"
    envelope[2] = encode(evidence)
    altered = b"\xd2" + encode(envelope)
    assert rig.checker().check(altered, command) == "REJECTED"


def test_checker_checks_entire_trace_and_hold(rig):
    # Still authentic controller evidence: one real unit-source deviation at
    # an intermediate row, and separately during the hold, with final pose good.
    for index in (4, 18):
        case = Rig()
        case.backend.frames[index] = tuple(q + (0.03 if j == 0 else 0)
                                            for j, q in enumerate(case.backend.frames[index]))
        command, bundle, evidence = case.run()
        assert evidence["terminal_state"] == "COMPLETE"
        assert case.checker().check(bundle, command) == "VERIFIED_FAILURE"


def test_checker_rejects_motion_that_stalls_after_nonzero_displacement(rig):
    rig.backend.frames[4:] = [rig.backend.frames[3]] * 19
    command, bundle, evidence = rig.run()
    assert evidence["terminal_state"] == "COMPLETE"
    assert evidence["samples"][-1][5][0] > INITIAL[0] + 1000
    assert rig.checker().check(bundle, command) == "VERIFIED_FAILURE"


def test_signing_failure_is_not_a_preexecution_rejection(rig, monkeypatch):
    wire = rig.signed()
    def unavailable(*args, **kwargs):
        raise RuntimeError("test evidence-key failure")
    monkeypatch.setattr(Sign1Message, "encode", unavailable)
    with pytest.raises(EvidenceUnavailable):
        rig.controller.execute(wire)
    assert len(rig.backend.writes) == 22
    assert rig.backend.stops == ["NONE"]
    assert rig.controller.state == "FAULT"


def test_mutable_or_nonbyte_inputs_rejected(rig):
    assert_rejected(rig, bytearray(rig.signed()), "SIZE")
    assert_rejected(rig, {"samples": []}, "SIZE")


def test_fresh_second_execution_uses_new_acquisition(rig):
    rig.run()
    hello = rig.controller.hello()
    actual = tuple(round(q * 1e6) for q in rig.backend.frames[-1])
    rig.command = command_for(hello, actual, [list(actual[:7])])
    # Extend only the unit-source script; counters/time continue across executions.
    rig.backend.frames += [rig.backend.frames[-1]] * 13
    _, _, evidence = rig.run()
    assert evidence["terminal_state"] == "COMPLETE"
    assert evidence["samples"][0][1] == 22
    assert evidence["samples"][0][5] == list(actual)
    assert evidence["sample_count"] == 14


def test_protocol_imports_do_not_load_simulator():
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-c", "import sys; import protected_robot_controller.controller; "
                             "assert not any(m.startswith(('isaacsim', 'omni', 'pxr')) for m in sys.modules)"],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_limits_pin_existing_model_manifest():
    path = Path(__file__).resolve().parents[2] / "artifacts/model_manifest.json"
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == L.MODEL_MANIFEST_SHA256
    model = json.loads(raw)
    assert model["output_order"] == list(L.OUTPUTS)
    assert model["actuator_order"] == list(L.ACTUATORS)
    for i, channel in enumerate(model["channels"]):
        assert L.LOWER[i] / 1e6 >= channel["position_limits"][0]
        assert L.UPPER[i] / 1e6 <= channel["position_limits"][1]
        if i < 7:
            assert L.VELOCITY[i] / 1e6 <= channel["max_velocity"]
            assert L.EFFORT[i] / 1000 <= channel["max_effort"]


@pytest.mark.parametrize("clock_change", [L.MAX_STEP_NS + 1, -1])
def test_terminal_stop_checks_deadline_and_clock(rig, clock_change):
    stop = rig.backend.stop_or_hold
    def delayed_stop(reason):
        stop(reason)
        rig.clock.now += clock_change
    rig.backend.stop_or_hold = delayed_stop
    command, bundle, evidence = rig.run()
    assert evidence["reason"] == ("STOP_OVERRUN" if clock_change > 0 else "CLOCK")
    assert evidence["terminal_state"] == "ABORTED" and evidence["partial"] is True
    assert evidence["sample_count"] == 23  # Honest full capture, failed terminal stop.
    assert rig.backend.stops == ["NONE"]
    assert rig.controller.state == "FAULT"
    assert rig.checker().check(bundle, command) == "NOT_PROVEN"
    assert_rejected(rig, command, "FAULT")


def test_terminal_stop_included_in_total_run_deadline(rig):
    rig.command["trajectory"] += [rig.command["trajectory"][-1]] * 50
    rig.backend.frames += [rig.backend.frames[-1]] * 50
    def slow_step(*, deadline_ns):
        rig.backend.steps += 1
        rig.clock.now += 1_650_000_000
        assert rig.clock.now <= deadline_ns
    rig.backend.step_physics = slow_step
    stop = rig.backend.stop_or_hold
    def slow_stop(reason):
        stop(reason)
        rig.clock.now += 1_300_000_000  # Within per-operation bound, exceeds total.
    rig.backend.stop_or_hold = slow_stop
    command, bundle, evidence = rig.run()
    assert evidence["sample_count"] == 73
    assert evidence["reason"] == "STOP_OVERRUN"
    assert evidence["terminal_state"] == "ABORTED" and evidence["partial"] is True
    assert rig.controller.state == "FAULT"
    assert rig.checker().check(bundle, command) == "NOT_PROVEN"


def test_public_vector_roundtrip_and_tamper_detection(rig, tmp_path):
    from tools.controller_fixture import check_recorded_vector

    command, bundle, _ = rig.run()
    name = "unit_roundtrip"
    record_vector(tmp_path, name, command, bundle,
                  rig.authority.public_key(), rig.evidence_key.public_key())
    assert (tmp_path / f"{name}.command.cbor").read_bytes() == command
    assert (tmp_path / f"{name}.evidence.cbor").read_bytes() == bundle
    assert (tmp_path / f"{name}.vector.json").is_file()
    path = tmp_path / f"{name}.vector.json"
    result = check_recorded_vector(path)
    assert result["verdict"] == "VERIFIED_SUCCESS"
    assert result["command_sha256"] == sha256(command).hexdigest()
    assert result["evidence_sha256"] == sha256(bundle).hexdigest()
    original = path.read_text()
    recorded = json.loads(original)
    recorded["evidence_sha256"] = "00" * 32
    path.write_text(json.dumps(recorded))
    with pytest.raises(ValueError, match="does not match"):
        check_recorded_vector(path)
    path.write_text(original)
    (tmp_path / f"{name}.evidence.cbor").write_bytes(bundle[:-1] + bytes([bundle[-1] ^ 1]))
    with pytest.raises(ValueError, match="unauthenticated"):
        check_recorded_vector(path)

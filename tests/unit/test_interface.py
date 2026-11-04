"""Wire boundary tests using the explicitly synthetic S3 unit rig, never PhysX."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "acceptance"))
from test_controller import Rig

from protected_robot_controller.interface import (
    ControllerInterface, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
)
from protected_robot_controller.protocol import MAX_COMMAND_BYTES, encode, strict_decode
from tools.controller_fixture import authenticated_evidence, sign_command


@pytest.fixture
def wire_rig():
    rig = Rig()
    return rig, ControllerInterface(rig.controller)


def response(interface, value):
    return strict_decode(interface.handle(encode(value)), MAX_RESPONSE_BYTES)


def test_wire_signed_execution_and_replay(wire_rig):
    rig, interface = wire_rig
    hello = response(interface, {"version": 1, "type": "HELLO"})
    rig.command.update(boot_id=hello["boot_id"], challenge=hello["challenge"], expires_ns=hello["expires_ns"])
    command = sign_command(rig.command, rig.authority)
    result = response(interface, {"version": 1, "type": "EXECUTE", "command": command})
    assert result.keys() == {"version", "type", "evidence"}
    assert result["type"] == "EVIDENCE"
    payload = authenticated_evidence(result["evidence"], rig.evidence_key.public_key())
    assert payload["sample_count"] == 23
    assert "verdict" not in payload and "success" not in payload
    assert rig.checker().check(result["evidence"], command) == "VERIFIED_SUCCESS"
    writes = len(rig.backend.writes)
    assert response(interface, {"version": 1, "type": "EXECUTE", "command": command}) == {
        "version": 1, "type": "REJECTED", "reason": "REPLAY"}
    assert len(rig.backend.writes) == writes


@pytest.mark.parametrize("message", [
    {"version": 1, "type": "SIGN", "payload": b"arbitrary"},
    {"version": 1, "type": "SAMPLE", "positions": [0] * 8},
    {"version": 1, "type": "DRIVE", "targets": [0] * 7},
    {"version": True, "type": "HELLO"},
    {"version": 2, "type": "HELLO"},
    {"version": 1, "type": "HELLO", "backend": "peer"},
    {"version": 1, "type": "EXECUTE", "command": {}, "valid": [True] * 8},
    {"version": 1, "type": "EXECUTE", "command": b"", "evidence_key": b"peer"},
    {"version": 1, "type": "EXECUTE", "command": b""},
    {"version": 1, "type": "EXECUTE", "command": b"x" * (MAX_COMMAND_BYTES + 1)},
    [],
])
def test_wire_rejects_extra_authority_before_backend(wire_rig, message):
    rig, interface = wire_rig
    result = response(interface, message)
    assert result["type"] == "REJECTED"
    assert not rig.backend.writes and not rig.backend.stops and rig.backend.steps == 0


@pytest.mark.parametrize("raw", [b"", b"x" * (MAX_REQUEST_BYTES + 1),
                                 b"\xa2\x64type\x65HELLO\x64type\x65HELLO"])
def test_wire_framing_is_bounded(wire_rig, raw):
    rig, interface = wire_rig
    result = strict_decode(interface.handle(raw), MAX_RESPONSE_BYTES)
    assert result["type"] == "REJECTED"
    assert not rig.backend.writes and not rig.backend.stops


def test_wire_invalid_signature_has_no_actuation(wire_rig):
    rig, interface = wire_rig
    command = rig.signed()
    damaged = command[:-1] + bytes([command[-1] ^ 1])
    assert response(interface, {"version": 1, "type": "EXECUTE", "command": damaged}) == {
        "version": 1, "type": "REJECTED", "reason": "SIGNATURE"}
    assert not rig.backend.writes and not rig.backend.stops


def test_wire_fault_returns_authentic_partial_bundle(wire_rig):
    rig, interface = wire_rig
    rig.backend.fail_at = 3
    command = rig.signed()
    result = response(interface, {"version": 1, "type": "EXECUTE", "command": command})
    payload = authenticated_evidence(result["evidence"], rig.evidence_key.public_key())
    assert payload["partial"] is True and payload["terminal_state"] == "ABORTED"
    assert payload["sample_count"] == 3 and rig.backend.stops == ["BACKEND"]
    assert rig.checker().check(result["evidence"], command) == "NOT_PROVEN"

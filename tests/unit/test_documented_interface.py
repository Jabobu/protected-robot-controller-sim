"""The public API documentation must match the real wire-neutral adapter."""
import json
from pathlib import Path
import re

from protected_robot_controller import limits as L
from protected_robot_controller.controller import EvidenceUnavailable
from protected_robot_controller.interface import ControllerInterface, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, PROFILE, encode, strict_decode

ROOT = Path(__file__).resolve().parents[2]


def test_documented_interface_matches_existing_byte_api():
    document = (ROOT / "docs/SCENE_INTERFACE.md").read_text()
    marker = "<!-- controller-interface-contract-v1 -->"
    assert document.count(marker) == 1
    match = re.search(r"```json\s*(.*?)\s*```", document.split(marker, 1)[1], flags=re.S)
    assert match
    contract = json.loads(match.group(1))
    assert contract == {
        "implementation": "protected_robot_controller.interface.ControllerInterface",
        "entry_point": "handle(request: bytes) -> bytes", "request_types": ["HELLO", "EXECUTE"],
        "response_types": ["HELLO", "EVIDENCE", "REJECTED", "UNAVAILABLE"], "retrieve_supported": False,
        "max_command_bytes": MAX_COMMAND_BYTES, "max_evidence_bytes": MAX_EVIDENCE_BYTES,
        "max_request_bytes": MAX_REQUEST_BYTES, "max_response_bytes": MAX_RESPONSE_BYTES,
        "profile": PROFILE, "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
        "actuators": list(L.ACTUATORS), "outputs": list(L.OUTPUTS), "units": list(L.UNITS),
        "physics_dt": [1, L.HZ], "sample_every_steps": 1,
    }
    # WIRE_ADAPTER_VECTOR_NOT_EXECUTION: exercise only adapter forwarding and
    # request shape. No backend, sensor readings, signed proof or physics claim.
    class AdapterProbe:
        def __init__(self):
            self.received = []
            self.unavailable = False

        def hello(self):
            return {"version": 1, "type": "HELLO"}

        def execute(self, command):
            self.received.append(command)
            if self.unavailable:
                raise EvidenceUnavailable()
            return b"adapter-response-vector"

    probe = AdapterProbe()
    interface = ControllerInterface(probe)
    decode = lambda raw: strict_decode(raw, MAX_RESPONSE_BYTES)
    assert decode(interface.handle(encode({"version": 1, "type": "HELLO"})))["type"] == "HELLO"
    wire = b"adapter-command-vector"
    assert decode(interface.handle(encode({"version": 1, "type": "EXECUTE", "command": wire}))) == {
        "version": 1, "type": "EVIDENCE", "evidence": b"adapter-response-vector"}
    assert probe.received == [wire]
    assert decode(interface.handle(encode({"version": 1, "type": "RETRIEVE"}))) == {
        "version": 1, "type": "REJECTED", "reason": "REQUEST"}
    assert not hasattr(interface, "retrieve") and probe.received == [wire]
    probe.unavailable = True
    assert decode(interface.handle(encode({"version": 1, "type": "EXECUTE", "command": wire}))) == {
        "version": 1, "type": "UNAVAILABLE", "reason": "EVIDENCE_UNAVAILABLE"}


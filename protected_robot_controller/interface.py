"""Bounded, wire-neutral byte requests. No transport, simulator or test imports.

Trusted setup supplies the controller. A peer gets only handle(bytes)->bytes;
it cannot supply keys, backend callbacks, sensor values or configuration. This
in-process adapter does not establish compromised-OS isolation.
"""

from .controller import EvidenceUnavailable
from .protocol import MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, Rejected, encode, strict_decode

# The signed command and evidence retain their original, tighter ceilings.
MAX_REQUEST_BYTES = MAX_COMMAND_BYTES + 128
MAX_RESPONSE_BYTES = MAX_EVIDENCE_BYTES + 128


class ControllerInterface:
    def __init__(self, controller):
        self.__controller = controller

    def handle(self, request):
        """Exactly one bounded CBOR response; no task-success verdict exists here."""
        try:
            message = strict_decode(request, MAX_REQUEST_BYTES)
            if (type(message) is not dict or type(message.get("version")) is not int
                    or message["version"] != 1):
                raise Rejected("REQUEST")
            if message.keys() == {"version", "type"} and message["type"] == "HELLO":
                response = self.__controller.hello()
            elif message.keys() == {"version", "type", "command"} and message["type"] == "EXECUTE":
                command = message["command"]
                if type(command) is not bytes or not 0 < len(command) <= MAX_COMMAND_BYTES:
                    raise Rejected("SIZE")
                response = {"version": 1, "type": "EVIDENCE",
                            "evidence": self.__controller.execute(command)}
            else:
                raise Rejected("REQUEST")
        except Rejected as error:
            response = {"version": 1, "type": "REJECTED", "reason": error.code}
        except EvidenceUnavailable:
            response = {"version": 1, "type": "UNAVAILABLE", "reason": "EVIDENCE_UNAVAILABLE"}
        raw = encode(response)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("Internal response ceiling exceeded")
        return raw

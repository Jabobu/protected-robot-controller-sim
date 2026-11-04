"""Test-only A3 replay: a signed, stationary failure for each actual actuator.

Callers establish real PhysX provenance with completed acceptance cases. These
checks bind their retained public records; they do not attest a physical sensor.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_der_public_key

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import verify_sign1
from tools.controller_fixture import authenticated_evidence
from tools.integrated_fixture import check_recorded_run


def check_signed_obstruction(directory, actuator):
    if actuator not in L.ACTUATORS:
        raise ValueError("Unknown independently actuated output")
    directory = Path(directory)
    name = f"blocked_{actuator}"
    normal = check_recorded_run(directory, "normal")
    checked = check_recorded_run(directory, name)
    if normal["verdict"] != "VERIFIED_SUCCESS" or checked["verdict"] != "VERIFIED_FAILURE":
        raise ValueError(f"Signed normal/obstruction verdict missing: {actuator}")
    # check_recorded_run bounded and authenticated these same retained files,
    # including the independent observation array and fixed checker tolerances.
    context = json.loads((directory / f"{name}.context.json").read_text())
    normal_context = json.loads((directory / "normal.context.json").read_text())
    for field in ("authority_public_der_hex", "evidence_public_der_hex"):
        if context[field] != normal_context[field]:
            raise ValueError("Obstruction is not from the normal run's development key set")
    authority = load_der_public_key(bytes.fromhex(context["authority_public_der_hex"]))
    evidence_key = load_der_public_key(bytes.fromhex(context["evidence_public_der_hex"]))
    command = verify_sign1((directory / f"{name}.command.cbor").read_bytes(), authority)
    reference = verify_sign1((directory / "normal.command.cbor").read_bytes(), authority)
    # Fresh authorizations and fresh measured starts must differ between runs;
    # no trajectory, limits, schedule, units or other policy change is allowed.
    fresh = {"boot_id", "challenge", "execution_id", "sequence", "expires_ns", "initial_positions"}
    if ({k: v for k, v in command.items() if k not in fresh}
            != {k: v for k, v in reference.items() if k not in fresh}):
        raise ValueError("Obstruction changed the signed motion program")
    if command["execution_id"] == reference["execution_id"]:
        raise ValueError("Obstruction reused the normal execution")
    evidence = authenticated_evidence((directory / f"{name}.cbor").read_bytes(), evidence_key)
    if evidence["terminal_state"] != "COMPLETE" or evidence["partial"] or evidence["reason"] != "NONE":
        raise ValueError("Obstruction must have a complete valid capture")
    index = L.ACTUATORS.index(actuator)
    constraint = context["metadata"].get("constraint") or {}
    if (constraint.get("method") != "PhysX articulation DOF hard limits"
            or constraint.get("actuator") != actuator
            or constraint.get("output_index") != index
            or constraint.get("output") != L.OUTPUTS[index]
            or constraint.get("units") != ("rad" if index < 6 else "m")):
        raise ValueError("Obstruction constraint does not identify the required output")
    rows = evidence["samples"]
    for output in ([index] if index < 6 else [6, 7]):
        # Scaled signed readings; these are the unchanged S2 stall/error bounds.
        stall = 1000 if output < 6 else 100
        final_error = 100_000 if output < 6 else 8000
        if max(abs(row[5][output] - rows[0][5][output]) for row in rows) >= stall:
            raise ValueError(f"Required output was not stationary: {L.OUTPUTS[output]}")
        goal = command["trajectory"][-1][min(output, 6)]
        if abs(rows[-1][5][output] - goal) <= final_error:
            raise ValueError("Required output did not exhibit the commanded movement failure")
    for other in range(7):
        if other != index and abs(rows[-1][5][other] - rows[0][5][other]) <= (50_000 if other < 6 else 6000):
            raise ValueError("An unconstrained independent actuator did not move")
    return checked

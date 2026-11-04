"""TEST-ONLY recording/replay of S4 public evidence and independent observations.

The trusted fixture supplies copied backend readings, never requested targets.
Replay checks the retained public context; it does not independently establish
where a sensor ran or make a physical-attestation/hostile-OS claim. Unit tests of
this helper remain unit tests, irrespective of their signature verification.
"""

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_der_public_key

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import (
    MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, MAX_ROWS, PROFILE, encode, public_bytes,
    verify_sign1,
)
from tools.controller_fixture import EvidenceChecker, authenticated_evidence

CHECK_TOLERANCE = (25_000, 30_000, 30_000, 30_000, 40_000, 25_000, 1_000, 1_000)
MIN_DISPLACEMENT = (80_000,) * 6 + (8_000, 8_000)
MAX_CONTEXT_BYTES = 65_536
MAX_OBSERVATIONS_BYTES = 4_194_304
_OBSERVATION_FIELDS = frozenset({
    "counter", "physics_step", "simulation_time_ns", "monotonic_time_ns", "positions", "valid",
})
_CONTEXT_FIELDS = (
    "profile", "robot_id", "controller_id", "boot_id", "challenge", "execution_id",
    "sequence", "expires_ns", "config_digest", "authorization_context_digest",
    "actuators", "outputs", "units", "physics_dt", "sample_every_steps", "hold_steps",
    "initial_positions", "initial_tolerance", "start_behavior", "velocity_limits", "effort_limits",
)


def _paths(directory, name):
    if type(name) is not str or not name or Path(name).name != name or name in (".", ".."):
        raise ValueError("Run name must be a basename")
    root = Path(directory)
    return {"command": root / f"{name}.command.cbor", "evidence": root / f"{name}.cbor",
            "observations": root / f"{name}.observations.json",
            "context": root / f"{name}.context.json"}


def _bounded_bytes(value, limit):
    if type(value) is not bytes or not 0 < len(value) <= limit:
        raise ValueError("Artifact exceeds its byte bound or is empty")
    return value


def _read(path, limit):
    # Bound the read itself, before JSON/CBOR parsing and irrespective of stat races.
    with path.open("rb") as stream:
        return _bounded_bytes(stream.read(limit + 1), limit)


def _json_bytes(value, limit):
    return _bounded_bytes((json.dumps(value, indent=2, sort_keys=True, allow_nan=False)
                           + "\n").encode("utf-8"), limit)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _json_read(raw):
    def reject_constant(value):
        raise ValueError(f"Non-finite JSON value: {value}")

    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=reject_constant)


def _compare_observations(evidence, observations):
    rows = evidence.get("samples")
    if (type(rows) is not list or len(rows) > MAX_ROWS
            or type(observations) is not list or len(observations) > MAX_ROWS
            or len(observations) < len(rows)):
        raise ValueError("Observation coverage does not match signed trace")
    # A fault may occur after a backend reading but before the controller accepts
    # that reading. Retain such trailing observations, but never omit a signed row.
    if evidence.get("terminal_state") == "COMPLETE" and len(rows) != len(observations):
        raise ValueError("Complete trace must cover every independent observation")
    offset = None
    for index, observation in enumerate(observations):
        if (type(observation) is not dict or observation.keys() != _OBSERVATION_FIELDS
                or any(type(observation[k]) is not int or not 0 <= observation[k] < 2**63
                       for k in ("counter", "physics_step", "simulation_time_ns", "monotonic_time_ns"))
                or type(observation["positions"]) is not list or len(observation["positions"]) != 8
                or any(type(q) not in (int, float) or not math.isfinite(q) or abs(q) > 2148
                       for q in observation["positions"])
                or type(observation["valid"]) is not list or len(observation["valid"]) != 8
                or any(type(v) is not bool for v in observation["valid"])):
            raise ValueError("Malformed independent observation")
        if index >= len(rows):
            continue
        row = rows[index]
        if (type(row) is not list or len(row) != 7
                or any(type(v) is not int or v < 0 for v in row[:5])
                or row[:4] != [index, observation["counter"], observation["physics_step"],
                               observation["simulation_time_ns"]]
                or row[5] != [round(q * 1_000_000) for q in observation["positions"]]
                or row[6] != observation["valid"]):
            raise ValueError("Signed sample differs from independent observation")
        current_offset = observation["monotonic_time_ns"] - row[4]
        if current_offset < 0 or (offset is not None and current_offset != offset):
            raise ValueError("Signed elapsed clock differs from independent observation")
        offset = current_offset


def _context(name, command, bundle, authority, evidence_key, observations_raw, metadata):
    if type(metadata) is not dict:
        raise ValueError("Trusted run metadata must be a JSON object")
    expected = verify_sign1(command, authority)
    constants = {"profile": PROFILE, "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
                 "config_digest": L.CONFIG_DIGEST, "actuators": list(L.ACTUATORS),
                 "outputs": list(L.OUTPUTS), "units": list(L.UNITS), "physics_dt": [1, L.HZ]}
    if any(encode(expected.get(field)) != encode(value) for field, value in constants.items()):
        raise ValueError("Retained command does not use the fixed model/configuration")
    evidence = authenticated_evidence(bundle, evidence_key)
    verdict = EvidenceChecker(authority, evidence_key).check(
        bundle, command, tolerance=CHECK_TOLERANCE, minimum_displacement=MIN_DISPLACEMENT)
    if verdict == "REJECTED":
        raise ValueError("Evidence signature or retained command context was rejected")
    _compare_observations(evidence, _json_read(observations_raw))
    return {
        "version": 1, "stage": "S4", "name": name, "verdict": verdict,
        "authority_public_der_hex": public_bytes(authority).hex(),
        "evidence_public_der_hex": public_bytes(evidence_key).hex(),
        "command_sha256": sha256(command).hexdigest(),
        "evidence_sha256": sha256(bundle).hexdigest(),
        "observations_sha256": sha256(observations_raw).hexdigest(),
        "config_cbor_hex": encode(L.configuration()).hex(),
        "config_digest_hex": L.CONFIG_DIGEST.hex(),
        "model_manifest_sha256": L.MODEL_MANIFEST_SHA256,
        "expected_context_cbor_hex": encode({field: expected[field] for field in _CONTEXT_FIELDS}).hex(),
        "check_tolerance": list(CHECK_TOLERANCE), "minimum_displacement": list(MIN_DISPLACEMENT),
        "metadata_sha256": sha256(_json_bytes(metadata, MAX_CONTEXT_BYTES)).hexdigest(),
        "metadata": metadata,
    }


def record_run(directory, name, command, bundle, authority_public_key, evidence_public_key,
               *, observations, metadata):
    """Preserve raw public run artifacts and independently check the entire trace.

    Keys must be public. No private key is serialized. Raw bytes are written
    before checking so an authentic failure/partial run remains available even
    if an assertion fails. Only callers with real physics observations may
    describe the resulting record as an Isaac execution.
    """
    paths = _paths(directory, name)
    command = _bounded_bytes(command, MAX_COMMAND_BYTES)
    bundle = _bounded_bytes(bundle, MAX_EVIDENCE_BYTES)
    public_bytes(authority_public_key)
    public_bytes(evidence_public_key)
    paths["command"].parent.mkdir(parents=True, exist_ok=True)
    paths["command"].write_bytes(command)
    paths["evidence"].write_bytes(bundle)
    # Never leave an old successful context beside raw bytes from a failed run.
    paths["context"].unlink(missing_ok=True)
    paths["observations"].unlink(missing_ok=True)
    observations_raw = _json_bytes(observations, MAX_OBSERVATIONS_BYTES)
    paths["observations"].write_bytes(observations_raw)
    context = _context(name, command, bundle, authority_public_key, evidence_public_key,
                       observations_raw, metadata)
    paths["context"].write_bytes(_json_bytes(context, MAX_CONTEXT_BYTES))
    return {field: context[field] for field in ("verdict", "evidence_sha256")}


def check_recorded_run(directory, name):
    """Recheck bounded retained files without simulator, process state, or secrets."""
    paths = _paths(directory, name)
    recorded = _json_read(_read(paths["context"], MAX_CONTEXT_BYTES))
    if type(recorded) is not dict:
        raise ValueError("Malformed retained context")
    command = _read(paths["command"], MAX_COMMAND_BYTES)
    bundle = _read(paths["evidence"], MAX_EVIDENCE_BYTES)
    observations_raw = _read(paths["observations"], MAX_OBSERVATIONS_BYTES)
    authority = load_der_public_key(bytes.fromhex(recorded["authority_public_der_hex"]))
    evidence_key = load_der_public_key(bytes.fromhex(recorded["evidence_public_der_hex"]))
    actual = _context(name, command, bundle, authority, evidence_key, observations_raw,
                      recorded["metadata"])
    if _json_bytes(recorded, MAX_CONTEXT_BYTES) != _json_bytes(actual, MAX_CONTEXT_BYTES):
        raise ValueError("Retained context differs from checked raw artifacts")
    return {field: actual[field] for field in ("verdict", "evidence_sha256")}


def main():
    parser = argparse.ArgumentParser(description="Replay public S4 normal and blocked measured traces")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps({name: check_recorded_run(args.directory, name)
                      for name in ("normal", "blocked")}, indent=2))


if __name__ == "__main__":
    main()

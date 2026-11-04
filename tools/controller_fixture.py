"""Small trusted TEST signer/checker. Never imported by controller code.

Keys are ephemeral and remain in memory. This is not OP-TEE or a production
verifier. A unit-backend verdict is not an Isaac physics acceptance result.
"""

import importlib.metadata
import json
import secrets
import sys
from hashlib import sha256
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec, utils
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import (
    PROFILE, MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, MAX_ROWS, Rejected,
    encode, strict_decode, verify_sign1, key_id, public_bytes, cose_private,
)


def development_keys():
    return ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())


def command_for(hello, initial, trajectory, *, sequence=None, hold_steps=L.MIN_HOLD_STEPS):
    return {
        "version": 1, "type": "EXECUTE", "profile": PROFILE,
        "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
        "boot_id": hello["boot_id"], "challenge": hello["challenge"],
        "execution_id": secrets.token_bytes(16),
        "sequence": hello["sequence_floor"] + 1 if sequence is None else sequence,
        "expires_ns": hello["expires_ns"], "config_digest": L.CONFIG_DIGEST,
        "authorization_context_digest": sha256(b"S3 development test context").digest(),
        "actuators": list(L.ACTUATORS), "outputs": list(L.OUTPUTS), "units": list(L.UNITS),
        "physics_dt": [1, L.HZ], "sample_every_steps": 1,
        "initial_positions": list(initial), "initial_tolerance": [0] * 8,
        "trajectory": [list(row) for row in trajectory], "hold_steps": hold_steps,
        "start_behavior": "IMMEDIATE_IF_MATCH", "velocity_limits": list(L.VELOCITY),
        "effort_limits": list(L.EFFORT),
    }


def sign_command(command, authority_private_key):
    payload = encode(command)
    message = Sign1Message(phdr={Algorithm: Es256, KID: key_id(authority_private_key.public_key())},
                           uhdr={}, payload=payload, key=cose_private(authority_private_key))
    wire = message.encode(tag=True)
    if len(wire) > MAX_COMMAND_BYTES:
        raise ValueError("command ceiling")
    return wire


def authenticated_evidence(raw, evidence_public_key):
    """Independent ES256 check using cryptography, without pycose verification."""
    if type(raw) is not bytes or len(raw) > MAX_EVIDENCE_BYTES or raw[:1] != b"\xd2":
        raise Rejected("EVIDENCE_FORMAT")
    envelope = strict_decode(raw[1:], MAX_EVIDENCE_BYTES)
    if (type(envelope) is not list or len(envelope) != 4
            or envelope[0] != encode({1: -7, 4: key_id(evidence_public_key)})
            or type(envelope[1]) is not dict or envelope[1]
            or type(envelope[2]) is not bytes or type(envelope[3]) is not bytes
            or len(envelope[3]) != 64):
        raise Rejected("EVIDENCE_FORMAT")
    protected, _, payload, signature = envelope
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                     int.from_bytes(signature[32:], "big"))
    evidence_public_key.verify(der, encode(["Signature1", protected, b"", payload]),
                               ec.ECDSA(hashes.SHA256()))
    return strict_decode(payload, MAX_EVIDENCE_BYTES)


_CONTEXT_FIELDS = (
    "profile", "robot_id", "controller_id", "boot_id", "challenge", "execution_id", "sequence",
    "config_digest", "authorization_context_digest", "outputs", "units", "physics_dt",
    "sample_every_steps", "hold_steps",
)
_EVIDENCE_FIELDS = frozenset(_CONTEXT_FIELDS) | {
    "version", "type", "evidence_key_id", "command_digest", "samples", "sample_count",
    "expected_sample_count", "terminal_state", "partial", "reason",
}


class EvidenceChecker:
    """One trusted runner keeps the expected original command and replay ledger."""

    def __init__(self, authority_public_key, evidence_public_key):
        self._authority = authority_public_key
        self._evidence = evidence_public_key
        self._consumed = set()

    def check(self, bundle, expected_command, *, tolerance=(2_000,) * 6 + (200, 200),
              minimum_displacement=(1000,) * 6 + (100, 100)):
        if bundle is None:
            return "NOT_PROVEN"
        if (len(tolerance) != 8 or len(minimum_displacement) != 8
                or any(type(v) is not int or v < 0 for v in tolerance)
                or any(type(v) is not int or v <= 0 for v in minimum_displacement)):
            raise ValueError("Trusted checker thresholds must cover every output")
        try:
            expected = verify_sign1(expected_command, self._authority)
            evidence = authenticated_evidence(bundle, self._evidence)
            if (type(evidence) is not dict or evidence.keys() != _EVIDENCE_FIELDS
                    or type(evidence["version"]) is not int or evidence["version"] != 1
                    or evidence["type"] != "EVIDENCE"
                    or evidence["evidence_key_id"] != key_id(self._evidence)
                    or evidence["command_digest"] != sha256(expected_command).digest()
                    or any(encode(evidence[k]) != encode(expected[k]) for k in _CONTEXT_FIELDS)):
                return "REJECTED"
            context = (evidence["boot_id"], evidence["challenge"])
            if context in self._consumed:
                return "REJECTED"
            self._consumed.add(context)
            return self._motion(evidence, expected, tolerance, minimum_displacement)
        except Exception:
            return "REJECTED"

    @staticmethod
    def _motion(evidence, expected, tolerance, displacement):
        rows = evidence["samples"]
        count = 1 + len(expected["trajectory"]) + expected["hold_steps"]
        if (type(rows) is not list or not 1 <= len(rows) <= MAX_ROWS
                or type(evidence["sample_count"]) is not int or evidence["sample_count"] != len(rows)
                or type(evidence["expected_sample_count"]) is not int
                or evidence["expected_sample_count"] != count
                or evidence["terminal_state"] != "COMPLETE" or evidence["partial"] is not False
                or evidence["reason"] != "NONE" or len(rows) != count):
            return "NOT_PROVEN"
        for index, row in enumerate(rows):
            if (type(row) is not list or len(row) != 7
                    or any(type(n) is not int or n < 0 for n in row[:5])
                    or row[0] != index or type(row[5]) is not list or len(row[5]) != 8
                    or any(type(q) is not int or not -(2**31) <= q < 2**31 for q in row[5])
                    or type(row[6]) is not list or len(row[6]) != 8
                    or any(v is not True for v in row[6]) or row[4] > L.MAX_RUN_NS):
                return "NOT_PROVEN"
            if index:
                previous = rows[index - 1]
                if (row[1] != previous[1] + 1 or row[2] != previous[2] + 1
                        or abs((row[3] - previous[3]) * L.HZ - 1_000_000_000) > 5 * L.HZ
                        or not previous[4] <= row[4] <= previous[4] + L.MAX_STEP_NS):
                    return "NOT_PROVEN"
        if any(abs(q - wanted) > t for q, wanted, t in zip(
                rows[0][5], expected["initial_positions"], expected["initial_tolerance"])):
            return "VERIFIED_FAILURE"
        targets = expected["trajectory"] + [expected["trajectory"][-1]] * expected["hold_steps"]
        # Every row, including the entire final hold, is compared; no last-pose shortcut.
        for row, target in zip(rows[1:], targets):
            outputs = target + [target[6]]
            if any(abs(q - wanted) > t for q, wanted, t in zip(row[5], outputs, tolerance)):
                return "VERIFIED_FAILURE"
        if any(abs(end - start) < minimum for start, end, minimum in zip(
                rows[0][5], rows[-1][5], displacement)):
            return "VERIFIED_FAILURE"
        return "VERIFIED_SUCCESS"


def _vector(name, command, bundle, authority_public_key, evidence_public_key):
    verdict = EvidenceChecker(authority_public_key, evidence_public_key).check(bundle, command)
    if verdict == "REJECTED":
        raise ValueError("Cannot record an unauthenticated verification vector")
    vector = {"scope": "S3 UNIT BACKEND ONLY; not Isaac physics evidence", "name": name,
              "verdict": verdict,
              "authority_public_der_hex": public_bytes(authority_public_key).hex(),
              "evidence_public_der_hex": public_bytes(evidence_public_key).hex(),
              "config_cbor_hex": encode(L.configuration()).hex(),
              "config_digest_hex": L.CONFIG_DIGEST.hex(),
              "command_sha256": sha256(command).hexdigest(),
              "evidence_sha256": sha256(bundle).hexdigest()}
    for label, wire in (("command", command), ("evidence", bundle)):
        protected, _, payload, signature = cbor2.loads(wire).value
        vector[label + "_protected_hex"] = protected.hex()
        vector[label + "_payload_hex"] = payload.hex()
        vector[label + "_signature_hex"] = signature.hex()
        vector[label + "_sig_structure_hex"] = encode(["Signature1", protected, b"", payload]).hex()
    return vector


def record_vector(directory, name, command, bundle, authority_public_key, evidence_public_key):
    """Retain public unit vectors in the caller's output directory only."""
    if not name or Path(name).name != name or name in (".", ".."):
        raise ValueError("Vector name must be a basename")
    vector = _vector(name, command, bundle, authority_public_key, evidence_public_key)
    vector["runtime"] = {"python": sys.version.split()[0], "packages": {
        package: importlib.metadata.version(package)
        for package in ("cryptography", "cbor2", "pycose", "pytest")}}
    destination = Path(directory).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    (destination / f"{name}.command.cbor").write_bytes(command)
    (destination / f"{name}.evidence.cbor").write_bytes(bundle)
    (destination / f"{name}.vector.json").write_text(json.dumps(vector, indent=2) + "\n")


def check_recorded_vector(path):
    """Reverify raw public files without a backend, original process or private key."""
    path = Path(path)
    name = path.name.removesuffix(".vector.json")
    recorded = json.loads(path.read_text())
    command = path.with_name(f"{name}.command.cbor").read_bytes()
    bundle = path.with_name(f"{name}.evidence.cbor").read_bytes()
    authority = load_der_public_key(bytes.fromhex(recorded["authority_public_der_hex"]))
    evidence = load_der_public_key(bytes.fromhex(recorded["evidence_public_der_hex"]))
    actual = _vector(name, command, bundle, authority, evidence)
    if any(recorded.get(field) != value for field, value in actual.items()):
        raise ValueError("Recorded vector does not match authenticated raw bundles")
    return {"name": name, "verdict": actual["verdict"],
            "command_sha256": actual["command_sha256"],
            "evidence_sha256": actual["evidence_sha256"]}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Recheck public S3 UNIT vectors; not physics acceptance")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    paths = sorted(args.directory.glob("*.vector.json"))
    if not paths:
        parser.error("No recorded vectors; run the S3 acceptance unit tests first")
    results = [check_recorded_vector(path) for path in paths]
    print(json.dumps({"scope": "S3 UNIT ONLY", "vectors": results}, indent=2))


if __name__ == "__main__":
    main()

"""Fixed wire format and verification; no signing service or simulator imports."""

from hashlib import sha256

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

from ._framing import preflight as _preflight

MAX_COMMAND_BYTES = 65_536
MAX_EVIDENCE_BYTES = 1_048_576
MAX_ROWS = 4097
PROFILE = "PRC-B601-SIM-1"


class Rejected(ValueError):
    """A bounded protocol error, never an execution or motion verdict."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def encode(value):
    return cbor2.dumps(value, canonical=True)


def strict_decode(raw, ceiling):
    """Bound decoding before schema validation, then require exact canonical bytes.

    No float/simple/tag types, aliases, duplicate keys, indefinite containers,
    nonminimal integers, trailing data, cycles, or excessive nesting survive.
    Text-only map keys also avoid attacker-chosen integer hash collisions.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= ceiling:
        raise Rejected("SIZE")
    try:
        _preflight(raw)
        value = cbor2.loads(raw, max_depth=8, allow_indefinite=False,
                            allow_duplicate_keys=False)
        if encode(value) != raw:
            raise ValueError("not deterministic CBOR")
        return value
    except Exception as error:
        raise Rejected("MALFORMED") from error


def public_bytes(key):
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("One P-256 public key is required")
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(key):
    return sha256(public_bytes(key)).digest()


def cose_public(key):
    public_bytes(key)  # Enforce the curve before converting the provisioned key.
    return CoseKey.from_pem_public_key(key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())


def cose_private(key):
    # Trusted setup only; never called with data from the message interface.
    public_bytes(key.public_key())
    return CoseKey.from_pem_private_key(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode())


def verify_sign1(raw, public_key, ceiling=MAX_COMMAND_BYTES):
    """Authenticate original payload/header bytes with exactly one trusted key."""
    if type(raw) is not bytes or not 0 < len(raw) <= ceiling:
        raise Rejected("SIZE")
    if raw[:1] != b"\xd2":  # Required, minimally encoded COSE_Sign1 tag 18.
        raise Rejected("MALFORMED")
    envelope = strict_decode(raw[1:], ceiling)
    if (type(envelope) is not list or len(envelope) != 4
            or envelope[0] != encode({1: -7, 4: key_id(public_key)})
            or type(envelope[1]) is not dict or envelope[1]
            or type(envelope[2]) is not bytes
            or type(envelope[3]) is not bytes or len(envelope[3]) != 64):
        raise Rejected("HEADERS")
    try:
        # cbor2 6.x decodes tagged arrays as tuples; pycose 1.1.0's generic
        # decode() requires a list. We already checked the tag and strictly
        # decoded/validated this envelope. Parse a copy (pycose pops fields),
        # retaining its exact protected-header and payload byte strings.
        message = Sign1Message.from_cose_obj(list(envelope), allow_unknown_attributes=False)
        message.key = cose_public(public_key)
        if (message.payload != envelope[2] or message.phdr_encoded != envelope[0]
                or not message.verify_signature()):
            raise ValueError("signature")
    except Exception as error:
        raise Rejected("SIGNATURE") from error
    return strict_decode(envelope[2], ceiling)

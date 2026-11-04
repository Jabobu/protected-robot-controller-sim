"""Direct wire-boundary checks; do not require or simulate crypto/Isaac."""

import random

import pytest

from protected_robot_controller._framing import preflight


@pytest.mark.parametrize("wire", [
    b"\x00", b"\x20", b"\x18\x18", b"\x19\x01\x00", b"\x1a\x00\x01\x00\x00",
    b"\x1b\x7f\xff\xff\xff\xff\xff\xff\xff",
    b"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff",
    b"\xf4", b"\xf5", b"\x80", b"\xa0", b"\x40", b"\x60",
    b"\xa2\x61a\x01\x61b\x02", b"\x84\x41\xd2\xa0\x41\xff\x41\xf9",
    b"\x81" * 8 + b"\x00",
])
def test_framing_accepts_supported_bounded_encodings(wire):
    preflight(wire)


@pytest.mark.parametrize("wire", [
    b"", b"\x00\x00", b"\x18", b"\x18\x01", b"\x19\x00\xff",
    b"\x1a\x00\x00\xff\xff", b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff",
    b"\x1b\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x3b\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x81" * 9 + b"\x00", b"\x82\x01", b"\x42\x01", b"\x62\x61",
    b"\x9f\x00\xff", b"\x1c", b"\xff",
    b"\xa2\x61a\x01\x61a\x02", b"\xa2\x61b\x01\x61a\x02",
    b"\xa1\x00\x01",
    b"\xd8\x1c\x81\xd8\x1d\x00",
    b"\xf6", b"\xf9\x7e\x00",
    b"\x9b" + b"\xff" * 8, b"\x5b" + b"\xff" * 8,
])
def test_framing_rejects_ambiguous_or_unsafe_encodings(wire):
    with pytest.raises(ValueError):
        preflight(wire)


def test_framing_bounds_total_work():
    # A valid definite array of 100,000 one-byte items exceeds total-node budget.
    wire = b"\x9a\x00\x01\x86\xa0" + b"\x00" * 100_000
    with pytest.raises(ValueError):
        preflight(wire)


def test_arbitrary_bounded_bytes_cannot_escape_as_index_or_recursion_errors():
    rng = random.Random(601)
    for _ in range(10_000):
        wire = rng.randbytes(rng.randrange(0, 128))
        try:
            preflight(wire)
        except ValueError:
            pass

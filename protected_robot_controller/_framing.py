"""Bounded wire framing only; value decoding remains in cbor2."""


def preflight(raw):
    """Non-decoding framing guard before cbor2 6.1.5 sees untrusted bytes.

    Disallow ALL semantic tags/references and non-text map keys before library
    allocation/hashing. The pinned release predates strict_hashable_types.
    cbor2 remains the value decoder and canonical encoder.
    """
    remaining = 100_000

    def item(offset, depth=0, map_key=False):
        nonlocal remaining
        remaining -= 1
        if offset >= len(raw) or depth > 8 or remaining < 0:
            raise ValueError("framing bound")
        lead = raw[offset]
        major, argument = lead >> 5, lead & 31
        offset += 1
        if map_key and major != 3:
            raise ValueError("text map key required")
        if major == 6 or (major == 7 and argument not in (20, 21)):
            raise ValueError("tags/floats/simple values forbidden")
        if argument >= 24:
            if argument > 27:
                raise ValueError("indefinite/reserved length")
            width = 1 << (argument - 24)
            if offset + width > len(raw):
                raise ValueError("truncated argument")
            value = int.from_bytes(raw[offset:offset + width], "big")
            if value < (24, 256, 65536, 4294967296)[argument - 24]:
                raise ValueError("nonminimal argument")
            offset += width
        else:
            value = argument
        if major in (0, 1):
            if value >= 2**63:
                raise ValueError("integer range")
        elif major in (2, 3):
            if value > len(raw) - offset:
                raise ValueError("string length")
            offset += value
        elif major in (4, 5):
            if value * (2 if major == 5 else 1) > min(remaining, len(raw) - offset):
                raise ValueError("container length")
            previous_key = None
            for _ in range(value):
                if major == 5:
                    start = offset
                    offset = item(offset, depth + 1, map_key=True)
                    order = (offset - start, raw[start:offset])
                    if previous_key is not None and order <= previous_key:
                        raise ValueError("duplicate or unordered key")
                    previous_key = order
                offset = item(offset, depth + 1)
        return offset

    if item(0) != len(raw):
        raise ValueError("trailing bytes")

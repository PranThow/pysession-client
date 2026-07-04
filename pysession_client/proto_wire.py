"""Minimal hand-rolled protobuf wire-format encoder.

Avoids requiring a `protoc` install for the handful of fields pysession needs
(Envelope / Content / DataMessage from Session's SessionProtos.proto).
"""

WIRETYPE_VARINT = 0
WIRETYPE_LEN = 2


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field_number: int, wiretype: int) -> bytes:
    return _varint((field_number << 3) | wiretype)


def varint_field(field_number: int, value: int) -> bytes:
    return tag(field_number, WIRETYPE_VARINT) + _varint(value)


def bytes_field(field_number: int, value: bytes) -> bytes:
    return tag(field_number, WIRETYPE_LEN) + _varint(len(value)) + value


def string_field(field_number: int, value: str) -> bytes:
    return bytes_field(field_number, value.encode("utf-8"))


def message_field(field_number: int, submessage_bytes: bytes) -> bytes:
    return bytes_field(field_number, submessage_bytes)

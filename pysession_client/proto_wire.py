"""Minimal hand-rolled protobuf wire-format encoder.

Avoids requiring a `protoc` install for the handful of fields pysession needs
(Envelope / Content / DataMessage from Session's SessionProtos.proto).
"""

WIRETYPE_VARINT = 0
WIRETYPE_FIXED64 = 1
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


def fixed64_field(field_number: int, value: int) -> bytes:
    return tag(field_number, WIRETYPE_FIXED64) + value.to_bytes(8, "little")


def bytes_field(field_number: int, value: bytes) -> bytes:
    return tag(field_number, WIRETYPE_LEN) + _varint(len(value)) + value


def string_field(field_number: int, value: str) -> bytes:
    return bytes_field(field_number, value.encode("utf-8"))


def message_field(field_number: int, submessage_bytes: bytes) -> bytes:
    return bytes_field(field_number, submessage_bytes)


def _read_varint(data: bytes, i: int):
    val, shift = 0, 0
    while True:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def parse_message(data: bytes) -> dict:
    """Decode top-level fields into {field_number: [values, ...]} (int for varint
    fields, raw bytes for length-delimited ones) — every occurrence is kept in
    order, so repeated fields (e.g. DataMessage.attachments) aren't lost like a
    last-value-wins dict would. Fixed64 fields aren't decoded (not needed by any
    caller — AttachmentPointer.deprecated_id is write-only, always 0)."""
    i = 0
    fields = {}
    while i < len(data):
        key, i = _read_varint(data, i)
        field_num, wiretype = key >> 3, key & 7
        if wiretype == WIRETYPE_VARINT:
            val, i = _read_varint(data, i)
        elif wiretype == WIRETYPE_LEN:
            length, i = _read_varint(data, i)
            val = data[i:i + length]
            i += length
        elif wiretype == WIRETYPE_FIXED64:
            val = data[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported wiretype {wiretype}")
        fields.setdefault(field_num, []).append(val)
    return fields

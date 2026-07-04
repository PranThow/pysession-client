"""Local self-consistency tests for the crypto layer (no network calls).

Run: python -m pysession_client._selftest
"""
import nacl.bindings as sodium

from . import envelope, keys, mnemonic


def test_mnemonic_roundtrip():
    import os
    for _ in range(20):
        seed = os.urandom(16)
        phrase = mnemonic.encode(seed)
        assert mnemonic.decode(phrase) == seed
    print("mnemonic roundtrip: OK")


def test_key_derivation_deterministic():
    seed = b"\x01" * 16
    kp1 = keys.from_seed(seed)
    kp2 = keys.from_seed(seed)
    assert kp1.session_id == kp2.session_id
    assert kp1.session_id.startswith("05")
    assert len(bytes.fromhex(kp1.session_id)) == 33
    print("key derivation deterministic + well-formed:", kp1.session_id)


def test_envelope_roundtrip():
    alice = keys.from_seed(b"\x11" * 16)
    bob = keys.from_seed(b"\x22" * 16)

    env_bytes = envelope.build_encrypted_envelope(alice, bob.x25519_pk, "hello bob")

    # Minimal manual protobuf parse to pull out field 8 (Envelope.content).
    def read_varint(data, i):
        val = 0
        shift = 0
        while True:
            b = data[i]
            i += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                return val, i
            shift += 7

    def parse_top_level(data):
        i = 0
        fields = {}
        while i < len(data):
            key, i = read_varint(data, i)
            field_num, wiretype = key >> 3, key & 7
            if wiretype == 0:
                val, i = read_varint(data, i)
            elif wiretype == 2:
                length, i = read_varint(data, i)
                val = data[i:i + length]
                i += length
            else:
                raise ValueError("unexpected wiretype")
            fields[field_num] = val
        return fields

    # build_encrypted_envelope wraps the Envelope in a WebSocketMessage shell
    # (see envelope._wrap_websocket_message) - unwrap it before reading Envelope fields.
    ws_request = parse_top_level(env_bytes)[2]
    envelope_bytes = parse_top_level(ws_request)[3]
    ciphertext = parse_top_level(envelope_bytes)[8]
    decrypted = sodium.crypto_box_seal_open(ciphertext, bob.x25519_pk, bob.x25519_sk)

    sig = decrypted[-64:]
    sender_pk = decrypted[-96:-64]
    padded_content = decrypted[:-96]
    assert sender_pk == alice.ed25519_pk

    verification_data = padded_content + sender_pk + bob.x25519_pk
    assert envelope._verify_detached(sig, verification_data, sender_pk)

    trimmed = padded_content.rstrip(b"\x00")
    assert trimmed[-1:] == b"\x80"
    content = trimmed[:-1]

    content_fields = parse_top_level(content)
    dm_fields = parse_top_level(content_fields[1])
    body = dm_fields[1].decode("utf-8")
    assert body == "hello bob"
    print("envelope build + decrypt + verify + parse roundtrip: OK, body =", repr(body))


if __name__ == "__main__":
    test_mnemonic_roundtrip()
    test_key_derivation_deterministic()
    test_envelope_roundtrip()
    print("All self-tests passed.")

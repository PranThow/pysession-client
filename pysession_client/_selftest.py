"""Local self-consistency tests for the crypto layer (no network calls).

Run: python -m pysession_client._selftest
"""
import nacl.bindings as sodium

from . import attachments, envelope, keys, mnemonic, proto_wire as pw, retrieve


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

    # build_encrypted_envelope wraps the Envelope in a WebSocketMessage shell
    # (see envelope._wrap_websocket_message) - unwrap it before reading Envelope fields.
    ws_request = pw.parse_message(env_bytes)[2][0]
    envelope_bytes = pw.parse_message(ws_request)[3][0]
    ciphertext = pw.parse_message(envelope_bytes)[8][0]
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

    content_fields = pw.parse_message(content)
    dm_fields = pw.parse_message(content_fields[1][0])
    body = dm_fields[1][0].decode("utf-8")
    assert body == "hello bob"
    print("envelope build + decrypt + verify + parse roundtrip: OK, body =", repr(body))


def test_disappearing_message_roundtrip():
    alice = keys.from_seed(b"\x33" * 16)
    bob = keys.from_seed(b"\x44" * 16)

    env_bytes = envelope.build_encrypted_envelope(
        alice, bob.x25519_pk, "gone in 30",
        expiration_type=envelope.EXPIRATION_TYPE_DELETE_AFTER_READ,
        expiration_seconds=30,
    )
    _, body, _, expire_seconds, expire_after_read = retrieve.decrypt_envelope(
        env_bytes, bob.x25519_pk, bob.x25519_sk
    )
    assert body == "gone in 30"
    assert expire_seconds == 30
    assert expire_after_read is True

    # A message with no timer set should decode as "no expiration", not 0/False-by-accident.
    plain_env_bytes = envelope.build_encrypted_envelope(alice, bob.x25519_pk, "sticks around")
    _, _, _, no_expire_seconds, _ = retrieve.decrypt_envelope(
        plain_env_bytes, bob.x25519_pk, bob.x25519_sk
    )
    assert no_expire_seconds is None
    print("disappearing-message envelope roundtrip: OK, expire_seconds =", expire_seconds)


def test_attachment_crypto_and_pointer_roundtrip():
    import os
    plaintext = os.urandom(5000)
    encrypted_blob, key, digest = attachments.encrypt_attachment(plaintext)
    assert attachments.decrypt_attachment(encrypted_blob, key, digest) == plaintext

    pointer_bytes = attachments.build_pointer(
        "image/png", len(plaintext), "cat.png", key, digest,
        "http://filev2.getsession.org/file/123", caption="a cat", width=10, height=20,
    )
    parsed = attachments.parse_pointer(pointer_bytes)
    assert parsed["content_type"] == "image/png"
    assert parsed["file_name"] == "cat.png"
    assert parsed["size"] == len(plaintext)
    assert parsed["key"] == key
    assert parsed["digest"] == digest
    assert parsed["url"] == "http://filev2.getsession.org/file/123"
    assert parsed["caption"] == "a cat"
    assert parsed["width"] == 10 and parsed["height"] == 20
    print("attachment encrypt/decrypt + pointer build/parse roundtrip: OK")


if __name__ == "__main__":
    test_mnemonic_roundtrip()
    test_key_derivation_deterministic()
    test_envelope_roundtrip()
    test_disappearing_message_roundtrip()
    test_attachment_crypto_and_pointer_roundtrip()
    print("All self-tests passed.")

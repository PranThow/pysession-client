"""Retrieve + decrypt messages for a Session ID from its swarm."""
import base64
import time

import nacl.bindings as sodium

from . import network

DEFAULT_NAMESPACE = 0


def _snode_signature(method: str, ed25519_sk: bytes, namespace: int, timestamp_ms: int) -> bytes:
    """Ported from session-desktop's SnodeSignature.getSnodeSignatureParams:
    signed string is `{method}{timestamp}` when namespace == 0, otherwise
    `{method}{namespace}{timestamp}` — namespace 0 is deliberately omitted."""
    to_sign = f"{method}{timestamp_ms}" if namespace == 0 else f"{method}{namespace}{timestamp_ms}"
    signed = sodium.crypto_sign(to_sign.encode("utf-8"), ed25519_sk)
    return signed[:64]  # detached signature (crypto_sign prepends sig to the message)


def retrieve_raw(pool, swarm, session_id_hex: str, ed25519_sk: bytes, last_hash: str = "",
                  namespace: int = DEFAULT_NAMESPACE) -> list:
    """Fetch raw stored messages for a Session ID. Retrieval requires a signature
    proving ownership of the account (unlike store, which anyone can do)."""
    target = swarm[0]
    timestamp_ms = int(time.time() * 1000)

    signature = _snode_signature("retrieve", ed25519_sk, namespace, timestamp_ms)
    ed25519_pk = sodium.crypto_sign_ed25519_sk_to_pk(ed25519_sk)

    params = {
        "pubkey": session_id_hex,
        "namespace": namespace,
        "timestamp": timestamp_ms,
        "signature": base64.b64encode(signature).decode("ascii"),
        "pubkey_ed25519": ed25519_pk.hex(),
    }
    if last_hash:
        params["last_hash"] = last_hash

    result = network._post_onion_request(
        pool[0], [pool[0], pool[1]], target, {"method": "retrieve", "params": params}
    )
    return result.get("messages", [])


def decrypt_envelope(envelope_bytes: bytes, my_x25519_pk: bytes, my_x25519_sk: bytes):
    """Parse+decrypt a stored Envelope protobuf, returning (sender_ed25519_pk, body_text)."""
    def read_varint(data, i):
        val, shift = 0, 0
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

    ws_fields = parse_top_level(envelope_bytes)
    request_fields = parse_top_level(ws_fields[2])
    envelope_fields = parse_top_level(request_fields[3])
    ciphertext = envelope_fields[8]

    decrypted = sodium.crypto_box_seal_open(ciphertext, my_x25519_pk, my_x25519_sk)
    sig = decrypted[-64:]
    sender_pk = decrypted[-96:-64]
    padded_content = decrypted[:-96]

    verification_data = padded_content + sender_pk + my_x25519_pk
    sodium.crypto_sign_open(sig + verification_data, sender_pk)  # raises if invalid

    trimmed = padded_content.rstrip(b"\x00")
    content = trimmed[:-1]  # strip the 0x80 delimiter

    content_fields = parse_top_level(content)
    dm_fields = parse_top_level(content_fields[1])
    body = dm_fields[1].decode("utf-8")
    return sender_pk, body

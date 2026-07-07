"""Retrieve + decrypt messages for a Session ID from its swarm."""
import base64
import time

import nacl.bindings as sodium

from . import attachments as attachments_mod
from . import network
from . import proto_wire as pw

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

    result = network.post_onion_request(
        pool[0], [pool[0], pool[1]], target, {"method": "retrieve", "params": params}
    )
    return result.get("messages", [])


def decrypt_envelope(envelope_bytes: bytes, my_x25519_pk: bytes, my_x25519_sk: bytes):
    """Parse+decrypt a stored Envelope protobuf, returning (sender_ed25519_pk, body_text,
    attachments) — attachments is a list of parsed AttachmentPointer dicts (see
    attachments.parse_pointer), empty if the message carried none."""
    ws_fields = pw.parse_message(envelope_bytes)
    request_fields = pw.parse_message(ws_fields[2][0])
    envelope_fields = pw.parse_message(request_fields[3][0])
    ciphertext = envelope_fields[8][0]

    decrypted = sodium.crypto_box_seal_open(ciphertext, my_x25519_pk, my_x25519_sk)
    sig = decrypted[-64:]
    sender_pk = decrypted[-96:-64]
    padded_content = decrypted[:-96]

    verification_data = padded_content + sender_pk + my_x25519_pk
    sodium.crypto_sign_open(sig + verification_data, sender_pk)  # raises if invalid

    trimmed = padded_content.rstrip(b"\x00")
    content = trimmed[:-1]  # strip the 0x80 delimiter

    content_fields = pw.parse_message(content)
    dm_fields = pw.parse_message(content_fields[1][0])
    body = dm_fields[1][0].decode("utf-8") if 1 in dm_fields else ""
    attachment_list = [attachments_mod.parse_pointer(p) for p in dm_fields.get(2, [])]
    return sender_pk, body, attachment_list

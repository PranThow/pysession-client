"""Onion-request encryption for routing requests through Session's service node network.

Per-hop symmetric crypto confirmed from oxen-storage-server's own decryption code
(oxenss/crypto/channel_encryption.cpp):
  shared_secret = X25519_scalarmult(my_seckey, their_pubkey)
  aes_key       = HMAC-SHA256(key=b"LOKI", msg=shared_secret)
  ciphertext    = 12-byte random IV || AES-256-GCM(aes_key, iv, plaintext) with a 16-byte tag appended

Onion nesting (from session-desktop's onions.ts, built destination-outward to the guard node):
  - Each layer's plaintext is: int32-LE(len(inner_ciphertext)) || inner_ciphertext || json(routing_info)
  - routing_info for all but the innermost layer: {"destination": <next hop's ed25519 pubkey hex>,
    "ephemeral_key": <hex of this layer's ephemeral X25519 pubkey>}
  - The innermost (destination) layer's plaintext is just the actual request JSON
    (e.g. {"method": "store", "params": {...}}), no routing wrapper.
  - The final (outermost / guard-facing) payload sent over HTTP is:
    int32-LE(len(guard_ciphertext)) || guard_ciphertext || json({"ephemeral_key": hex(guard_ephemeral_pk)})
"""
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from typing import List

import nacl.bindings as sodium
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_LOKI_SALT = b"LOKI"


@dataclass
class SnodeInfo:
    ip: str
    port: int
    x25519_pk_hex: str
    ed25519_pk_hex: str


def _derive_aes_key(shared_secret: bytes) -> bytes:
    return hmac.new(_LOKI_SALT, shared_secret, hashlib.sha256).digest()


def encrypt_for_pubkey(their_x25519_pk: bytes, plaintext: bytes, ephemeral_keypair=None):
    """Generate an ephemeral X25519 keypair, encrypt plaintext for their_x25519_pk.

    Returns (ciphertext, ephemeral_pk) — ephemeral_pk must be sent alongside the
    ciphertext so the recipient can rederive the same shared secret.
    """
    if ephemeral_keypair is None:
        ephemeral_pk, ephemeral_sk = sodium.crypto_box_keypair()
    else:
        ephemeral_pk, ephemeral_sk = ephemeral_keypair
    shared_secret = sodium.crypto_scalarmult(ephemeral_sk, their_x25519_pk)
    aes_key = _derive_aes_key(shared_secret)

    iv = os.urandom(12)
    ct_and_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)
    ciphertext = iv + ct_and_tag
    return ciphertext, ephemeral_pk


def decrypt_from_pubkey(my_x25519_sk: bytes, their_ephemeral_pk: bytes, wire_bytes: bytes) -> bytes:
    shared_secret = sodium.crypto_scalarmult(my_x25519_sk, their_ephemeral_pk)
    aes_key = _derive_aes_key(shared_secret)
    iv, ct_and_tag = wire_bytes[:12], wire_bytes[12:]
    return AESGCM(aes_key).decrypt(iv, ct_and_tag, None)


def _encode_ciphertext_plus_json(ciphertext: bytes, obj: dict) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("<i", len(ciphertext)) + ciphertext + body


def build_onion_request(path: List[SnodeInfo], destination: SnodeInfo, request_body_bytes: bytes):
    """Build the raw bytes to POST to path[0] (the guard/entry node).

    `path` is the ordered list of relay hops (guard first); `destination` is the
    actual target snode (e.g. a member of the recipient's swarm); `request_body_bytes`
    is the raw request body (e.g. utf-8 JSON-RPC text like b'{"method":"get_swarm",...}')
    to deliver to the destination.

    Per oxen-storage-server's process_inner_request (oxenss/rpc/onion_processing.cpp):
    every hop's decrypted plaintext is itself a combined-payload structure
    [4B len][inner][trailing json]. The destination is marked by the trailing json
    containing a "headers" key (deliberately near-empty — this is literally how the
    server tells "this is the final hop" apart from a relay, per its own source
    comment) — the "ciphertext" slot at that point is the raw body, not further
    AES-GCM ciphertext.

    Returns (wire_bytes, response_shared_secret) — the shared secret is needed to
    decrypt the destination's response (it replies encrypted with the same
    symmetric key derived for our destination-layer ephemeral keypair).
    """
    dest_pk = bytes.fromhex(destination.x25519_pk_hex)

    dest_ephemeral_pk, dest_ephemeral_sk = sodium.crypto_box_keypair()
    response_shared_secret = sodium.crypto_scalarmult(dest_ephemeral_sk, dest_pk)

    final_combined_payload = _encode_ciphertext_plus_json(request_body_bytes, {"headers": {}})
    ciphertext, ephemeral_pk = encrypt_for_pubkey(dest_pk, final_combined_payload,
                                                   ephemeral_keypair=(dest_ephemeral_pk, dest_ephemeral_sk))

    # Walk from the last relay hop back to the guard node, each layer wrapping the previous.
    next_hop_ed25519_hex = destination.ed25519_pk_hex
    for hop in reversed(path):
        routing_info = {
            "destination": next_hop_ed25519_hex,
            "ephemeral_key": ephemeral_pk.hex(),
        }
        layer_plaintext = _encode_ciphertext_plus_json(ciphertext, routing_info)
        hop_pk = bytes.fromhex(hop.x25519_pk_hex)
        ciphertext, ephemeral_pk = encrypt_for_pubkey(hop_pk, layer_plaintext)
        next_hop_ed25519_hex = hop.ed25519_pk_hex

    wire_bytes = struct.pack("<i", len(ciphertext)) + ciphertext + json.dumps(
        {"ephemeral_key": ephemeral_pk.hex()}
    ).encode("utf-8")
    return wire_bytes, response_shared_secret


def decrypt_response(response_shared_secret: bytes, wire_bytes: bytes) -> bytes:
    aes_key = _derive_aes_key(response_shared_secret)
    iv, ct_and_tag = wire_bytes[:12], wire_bytes[12:]
    return AESGCM(aes_key).decrypt(iv, ct_and_tag, None)

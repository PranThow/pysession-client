"""Session key derivation: mnemonic seed -> Ed25519 keypair -> X25519 keypair -> Session ID.

Recipe (per Session's technical blog + Signal/Session-derived client behavior):
  1. 16-byte seed from mnemonic, zero-padded to 32 bytes.
  2. libsodium crypto_sign_seed_keypair(seed32) -> Ed25519 keypair.
  3. Convert Ed25519 keys to X25519 via crypto_sign_ed25519_*_to_curve25519.
  4. Session ID = 0x05 || X25519 pubkey, hex-encoded (66 chars).
"""
from dataclasses import dataclass

import nacl.bindings as sodium

from . import mnemonic as mnemonic_mod

SESSION_ID_PREFIX = b"\x05"


@dataclass
class Keypair:
    seed16: bytes
    ed25519_pk: bytes
    ed25519_sk: bytes  # libsodium convention: 64 bytes (seed || pubkey internally derived)
    x25519_pk: bytes
    x25519_sk: bytes
    session_id: str  # hex, includes 05 prefix


def from_mnemonic(phrase: str) -> Keypair:
    seed16 = mnemonic_mod.decode(phrase)
    return from_seed(seed16)


def from_seed(seed16: bytes) -> Keypair:
    if len(seed16) != 16:
        raise ValueError("seed must be 16 bytes")

    seed32 = seed16 + b"\x00" * 16
    ed_pk, ed_sk = sodium.crypto_sign_seed_keypair(seed32)

    x_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(ed_pk)
    x_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(ed_sk)

    session_id = (SESSION_ID_PREFIX + x_pk).hex()

    return Keypair(
        seed16=seed16,
        ed25519_pk=ed_pk,
        ed25519_sk=ed_sk,
        x25519_pk=x_pk,
        x25519_sk=x_sk,
        session_id=session_id,
    )


def session_id_to_x25519_pubkey(session_id: str) -> bytes:
    """Strip the 05 prefix from a hex Session ID and return the raw 32-byte X25519 pubkey."""
    raw = bytes.fromhex(session_id)
    if len(raw) != 33 or raw[0] != 0x05:
        raise ValueError("Not a standard (05-prefixed) Session ID")
    return raw[1:]


def ed25519_pk_to_session_id(ed25519_pk: bytes) -> str:
    """Convert a sender's Ed25519 pubkey (as recovered from a decrypted envelope's
    signature metadata) into their hex Session ID."""
    x25519_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)
    return (SESSION_ID_PREFIX + x25519_pk).hex()

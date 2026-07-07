"""Build a Session Envelope protobuf for a plain-text 1:1 DM and encrypt it.

Field numbers confirmed against libsession-util's SessionProtos.proto:
  Envelope: type=1, source=2, sourceDevice=7, timestamp=5, content=8, serverTimestamp=10
  Content:  dataMessage=1, expirationType=12, expirationTimer=13
  DataMessage: body=1, flags=4, timestamp=7 (Flags.EXPIRATION_TIMER_UPDATE=2)

Disappearing messages live on Content (not DataMessage) in Session's current
protocol — expirationType/expirationTimer ride along on every message while a
timer is active. flags=EXPIRATION_TIMER_UPDATE marks a dedicated empty-body
message announcing a timer change (what real clients send when you tap the
timer), same as session-desktop.

Padding: Session pads plaintext to 160-byte blocks before crypto_box_seal —
0x80 delimiter byte followed by zero-fill to the next 160-byte boundary.
(Recipient strips trailing zeros then the last 0x80 byte on decode.)
"""
import time

import nacl.bindings as sodium

from . import proto_wire as pw
from .keys import Keypair

ENVELOPE_TYPE_SESSION_MESSAGE = 6
PAD_BLOCK_SIZE = 160

EXPIRATION_TYPE_DELETE_AFTER_READ = 1
EXPIRATION_TYPE_DELETE_AFTER_SEND = 2
DATA_MESSAGE_FLAG_EXPIRATION_TIMER_UPDATE = 2


def _build_data_message(body: str, timestamp_ms: int, attachment_pointers=(), flags: int = 0) -> bytes:
    out = b""
    if body:
        out += pw.string_field(1, body)
    for pointer_bytes in attachment_pointers:
        out += pw.message_field(2, pointer_bytes)
    if flags:
        out += pw.varint_field(4, flags)
    out += pw.varint_field(7, timestamp_ms)
    return out


def _build_content(body: str, timestamp_ms: int, attachment_pointers=(), flags: int = 0,
                    expiration_type: int = None, expiration_seconds: int = None) -> bytes:
    data_message = _build_data_message(body, timestamp_ms, attachment_pointers, flags)
    out = pw.message_field(1, data_message)
    if expiration_type is not None:
        out += pw.varint_field(12, expiration_type)
    if expiration_seconds is not None:
        out += pw.varint_field(13, expiration_seconds)
    return out


def _build_envelope(content_ciphertext: bytes, timestamp_ms: int) -> bytes:
    out = b""
    out += pw.varint_field(1, ENVELOPE_TYPE_SESSION_MESSAGE)
    out += pw.varint_field(5, timestamp_ms)
    out += pw.bytes_field(8, content_ciphertext)
    return out


def _pad(data: bytes) -> bytes:
    padded_len = ((len(data) // PAD_BLOCK_SIZE) + 1) * PAD_BLOCK_SIZE
    return data + b"\x80" + b"\x00" * (padded_len - len(data) - 1)


def _sign_detached(message: bytes, ed25519_sk: bytes) -> bytes:
    # nacl.bindings has no crypto_sign_detached; crypto_sign returns sig(64B) || message.
    signed = sodium.crypto_sign(message, ed25519_sk)
    return signed[:64]


def _verify_detached(signature: bytes, message: bytes, ed25519_pk: bytes) -> bool:
    try:
        sodium.crypto_sign_open(signature + message, ed25519_pk)
        return True
    except Exception:
        return False


def _sign_and_seal(plaintext: bytes, sender: Keypair, recipient_x25519_pk: bytes) -> bytes:
    verification_data = plaintext + sender.ed25519_pk + recipient_x25519_pk
    signature = _sign_detached(verification_data, sender.ed25519_sk)
    plaintext_with_metadata = plaintext + sender.ed25519_pk + signature
    return sodium.crypto_box_seal(plaintext_with_metadata, recipient_x25519_pk)


def _wrap_websocket_message(envelope_bytes: bytes) -> bytes:
    """Real Session clients store/expect the Envelope nested inside a
    WebSocketMessage{type=REQUEST(1), request=WebSocketRequestMessage{verb="",
    path="", body=<Envelope>}} shell (confirmed against a real client's stored bytes)."""
    request = pw.string_field(1, "") + pw.string_field(2, "") + pw.bytes_field(3, envelope_bytes)
    return pw.varint_field(1, 1) + pw.message_field(2, request)


def seal_content(sender: Keypair, recipient_x25519_pk: bytes, content_bytes: bytes,
                  timestamp_ms: int = None) -> bytes:
    """Pad, sign, seal, and envelope-wrap already-built Content protobuf bytes.

    This is the shared pipeline any Content type funnels through — text bodies
    today (via build_encrypted_envelope), attachments or a typingMessage Content
    later just need their own builder feeding in here."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    padded_content = _pad(content_bytes)
    ciphertext = _sign_and_seal(padded_content, sender, recipient_x25519_pk)
    envelope_bytes = _build_envelope(ciphertext, timestamp_ms)
    return _wrap_websocket_message(envelope_bytes)


def build_encrypted_envelope(sender: Keypair, recipient_x25519_pk: bytes, body: str,
                              timestamp_ms: int = None, attachment_pointers=(), flags: int = 0,
                              expiration_type: int = None, expiration_seconds: int = None) -> bytes:
    """Returns the serialized WebSocketMessage-wrapped Envelope bytes, ready to base64 and `store`.

    `attachment_pointers` is a list of already-built AttachmentPointer protobuf
    bytes (see attachments.py) to include as DataMessage.attachments.

    `expiration_type`/`expiration_seconds` set Session's disappearing-message
    timer (EXPIRATION_TYPE_DELETE_AFTER_READ/_SEND above) — carried on every
    message while a timer is active, same as real Session clients."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    content = _build_content(body, timestamp_ms, attachment_pointers, flags,
                              expiration_type, expiration_seconds)
    return seal_content(sender, recipient_x25519_pk, content, timestamp_ms)

"""Attachment encryption + upload/download via Session's file server, and the
AttachmentPointer protobuf that references one from a DataMessage.

AttachmentPointer field numbers confirmed against session-desktop's
protos/SignalService.proto (dev branch): deprecated_id=1 (fixed64, always 0 —
required by the proto but unused by any modern client), contentType=2, key=3,
size=4, digest=6, fileName=7, width=9, height=10, caption=11, url=101.

Attachment encryption (AES-256-CBC + HMAC-SHA256, "encrypt-then-MAC") confirmed
against ts/util/crypto/attachmentsEncrypter.ts: key is a random 64 bytes (first
32 = AES key, last 32 = HMAC key), iv is a random 16 bytes, and
digest = SHA256(iv || ciphertext || mac). This client doesn't apply Session's
extra size-bucket padding before encrypting (ts/session/crypto/BufferPadding.ts)
since receivers already tolerate an exact-size (unpadded) attachment.

Upload/download go through network.post_onion_request_to_file_server, which
onion-routes an HTTP request to the file server per session-desktop's
FileServerApi.ts + onions.ts (see onion.build_onion_request_to_host).
"""
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from . import network
from . import proto_wire as pw

FILE_ENDPOINT = "/file"


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_attachment(plaintext: bytes):
    """Returns (encrypted_blob, key, digest). `key` (64 bytes) and `digest` (32
    bytes) go in the AttachmentPointer; `encrypted_blob` is what gets uploaded."""
    key = os.urandom(64)
    iv = os.urandom(16)
    aes_key, mac_key = key[:32], key[32:]

    iv_and_ciphertext = iv + _aes_cbc_encrypt(aes_key, iv, plaintext)
    mac = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()
    encrypted_blob = iv_and_ciphertext + mac
    digest = hashlib.sha256(encrypted_blob).digest()
    return encrypted_blob, key, digest


def decrypt_attachment(encrypted_blob: bytes, key: bytes, digest: bytes) -> bytes:
    if len(key) != 64:
        raise ValueError("attachment key must be 64 bytes")
    if len(encrypted_blob) < 16 + 32:
        raise ValueError("attachment blob too short")
    if not hmac.compare_digest(hashlib.sha256(encrypted_blob).digest(), digest):
        raise ValueError("attachment digest mismatch")

    aes_key, mac_key = key[:32], key[32:]
    iv, ciphertext, mac = encrypted_blob[:16], encrypted_blob[16:-32], encrypted_blob[-32:]
    expected_mac = hmac.new(mac_key, encrypted_blob[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("attachment MAC mismatch")

    return _aes_cbc_decrypt(aes_key, iv, ciphertext)


def build_pointer(content_type: str, size: int, file_name: str, key: bytes, digest: bytes,
                   url: str, caption: str = None, width: int = None, height: int = None) -> bytes:
    out = pw.fixed64_field(1, 0)  # deprecated_id
    if content_type:
        out += pw.string_field(2, content_type)
    out += pw.bytes_field(3, key)
    out += pw.varint_field(4, size)
    out += pw.bytes_field(6, digest)
    if file_name:
        out += pw.string_field(7, file_name)
    if width:
        out += pw.varint_field(9, width)
    if height:
        out += pw.varint_field(10, height)
    if caption:
        out += pw.string_field(11, caption)
    out += pw.string_field(101, url)
    return out


def parse_pointer(pointer_bytes: bytes) -> dict:
    fields = pw.parse_message(pointer_bytes)

    def s(n):
        return fields[n][0].decode("utf-8") if n in fields else None

    return {
        "content_type": s(2),
        "key": fields[3][0] if 3 in fields else None,
        "size": fields[4][0] if 4 in fields else None,
        "digest": fields[6][0] if 6 in fields else None,
        "file_name": s(7),
        "width": fields[9][0] if 9 in fields else None,
        "height": fields[10][0] if 10 in fields else None,
        "caption": s(11),
        "url": s(101),
    }


def upload(pool, file_bytes: bytes, content_type: str = None, file_name: str = None) -> dict:
    """Encrypt and upload `file_bytes`. Returns {"pointer_bytes", "url", "key", "digest"}."""
    encrypted_blob, key, digest = encrypt_attachment(file_bytes)

    _metadata, body = network.post_onion_request_to_file_server(
        pool, "POST", FILE_ENDPOINT, body=encrypted_blob,
    )
    file_id = body and json.loads(body).get("id")
    if not file_id:
        raise network.SessionNetworkError(f"File server upload did not return an id: {body!r}")

    url = f"http://{network.FILE_SERVER_HOST}{FILE_ENDPOINT}/{file_id}"
    pointer_bytes = build_pointer(content_type, len(file_bytes), file_name, key, digest, url)
    return {"pointer_bytes": pointer_bytes, "url": url, "key": key, "digest": digest}


def download(pool, url: str, key: bytes, digest: bytes) -> bytes:
    """Fetch and decrypt an attachment given its pointer's url/key/digest."""
    file_id = url.rstrip("/").rsplit("/", 1)[-1]
    _metadata, encrypted_blob = network.post_onion_request_to_file_server(
        pool, "GET", f"{FILE_ENDPOINT}/{file_id}",
    )
    return decrypt_attachment(encrypted_blob, key, digest)

"""High-level pysession.Client API.

    from pysession import Client
    client = Client("13 word recovery phrase ...")
    client.send("05...recipient session id...", "hello")

    for msg in client.receive():
        print(msg["sender_session_id"], msg["body"])

Verified end-to-end against the live production Session network.
"""
import base64

from . import attachments as attachments_mod
from . import envelope as envelope_mod
from . import keys as keys_mod
from . import network
from . import retrieve as retrieve_mod


class Client:
    def __init__(self, mnemonic: str):
        self.keypair = keys_mod.from_mnemonic(mnemonic)
        self._pool = None

    @property
    def session_id(self) -> str:
        return self.keypair.session_id

    def _get_pool(self):
        if self._pool is None:
            self._pool = network.get_snode_pool()
        return self._pool

    def _get_swarm_or_raise(self, session_id: str):
        pool = self._get_pool()
        swarm = network.get_swarm(pool, session_id)
        if not swarm:
            raise network.SessionNetworkError(f"Empty swarm for {session_id}")
        return pool, swarm

    def _store(self, session_id: str, envelope_bytes: bytes) -> dict:
        """Store already-sealed envelope bytes in `session_id`'s swarm — the shared
        send path any message type (text today, attachments/typing later) funnels
        through once envelope.py has built the bytes."""
        pool, swarm = self._get_swarm_or_raise(session_id)
        return network.store_message(pool, swarm, session_id, envelope_bytes)

    def send(self, session_id: str, text: str) -> dict:
        """Encrypt `text` for `session_id` and store it in their swarm. Returns the
        storage server's raw JSON response."""
        recipient_x25519_pk = keys_mod.session_id_to_x25519_pubkey(session_id)
        envelope_bytes = envelope_mod.build_encrypted_envelope(
            self.keypair, recipient_x25519_pk, text
        )
        return self._store(session_id, envelope_bytes)

    def send_attachment(self, session_id: str, file_bytes: bytes, content_type: str = None,
                         file_name: str = None, caption: str = "") -> dict:
        """Upload `file_bytes` to Session's file server, then send an envelope
        referencing it (with optional `caption` text as the message body)."""
        uploaded = attachments_mod.upload(self._get_pool(), file_bytes,
                                           content_type=content_type, file_name=file_name)

        recipient_x25519_pk = keys_mod.session_id_to_x25519_pubkey(session_id)
        envelope_bytes = envelope_mod.build_encrypted_envelope(
            self.keypair, recipient_x25519_pk, caption,
            attachment_pointers=[uploaded["pointer_bytes"]],
        )
        return self._store(session_id, envelope_bytes)

    def download_attachment(self, attachment: dict) -> bytes:
        """Fetch and decrypt an attachment dict as returned in receive()'s
        "attachments" list (needs its "url", "key", and "digest")."""
        return attachments_mod.download(self._get_pool(), attachment["url"],
                                         attachment["key"], attachment["digest"])

    def receive(self, last_hash: str = "") -> list:
        """Fetch and decrypt messages waiting in this account's own swarm.

        Returns a list of {"sender_session_id", "body", "hash", "attachments"}
        — "attachments" is a list of pointer dicts (see attachments.parse_pointer),
        empty if the message carried none; pass one to download_attachment() to
        fetch its data."""
        pool, swarm = self._get_swarm_or_raise(self.session_id)
        raw_messages = retrieve_mod.retrieve_raw(
            pool, swarm, self.session_id, self.keypair.ed25519_sk, last_hash=last_hash
        )

        out = []
        for m in raw_messages:
            try:
                envelope_bytes = base64.b64decode(m["data"])
                sender_ed25519_pk, body, attachment_list = retrieve_mod.decrypt_envelope(
                    envelope_bytes, self.keypair.x25519_pk, self.keypair.x25519_sk
                )
                sender_session_id = keys_mod.ed25519_pk_to_session_id(sender_ed25519_pk)
            except Exception:
                continue  # skip anything we can't decrypt (not for us / malformed)
            out.append({
                "sender_session_id": sender_session_id,
                "body": body,
                "hash": m.get("hash"),
                "attachments": attachment_list,
            })
        return out

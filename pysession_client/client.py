"""High-level pysession.Client API.

    from pysession import Client
    client = Client("13 word recovery phrase ...")
    client.send("05...recipient session id...", "hello")

    for msg in client.receive():
        print(msg["sender_session_id"], msg["body"])

Verified end-to-end against the live production Session network.
"""
import base64

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

    def _get_own_swarm(self):
        pool = self._get_pool()
        swarm = network.get_swarm(pool, self.session_id)
        if not swarm:
            raise network.SessionNetworkError(f"Empty swarm for {self.session_id}")
        return pool, swarm

    def send(self, session_id: str, text: str) -> dict:
        """Encrypt `text` for `session_id` and store it in their swarm. Returns the
        storage server's raw JSON response."""
        recipient_x25519_pk = keys_mod.session_id_to_x25519_pubkey(session_id)
        envelope_bytes = envelope_mod.build_encrypted_envelope(
            self.keypair, recipient_x25519_pk, text
        )

        pool = self._get_pool()
        swarm = network.get_swarm(pool, session_id)
        if not swarm:
            raise network.SessionNetworkError(f"Empty swarm for {session_id}")

        return network.store_message(pool, swarm, session_id, envelope_bytes)

    def receive(self, last_hash: str = "") -> list:
        """Fetch and decrypt messages waiting in this account's own swarm.

        Returns a list of {"sender_session_id": str, "body": str, "hash": str}."""
        pool, swarm = self._get_own_swarm()
        raw_messages = retrieve_mod.retrieve_raw(
            pool, swarm, self.session_id, self.keypair.ed25519_sk, last_hash=last_hash
        )

        out = []
        for m in raw_messages:
            try:
                envelope_bytes = base64.b64decode(m["data"])
                sender_ed25519_pk, body = retrieve_mod.decrypt_envelope(
                    envelope_bytes, self.keypair.x25519_pk, self.keypair.x25519_sk
                )
                sender_session_id = keys_mod.ed25519_pk_to_session_id(sender_ed25519_pk)
            except Exception:
                continue  # skip anything we can't decrypt (not for us / malformed)
            out.append({"sender_session_id": sender_session_id, "body": body, "hash": m.get("hash")})
        return out

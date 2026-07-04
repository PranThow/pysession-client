"""Bootstrapping and swarm/store RPC calls against the Session service node network.

SEED_NODES, ONION_REQUEST_PATH, and the onion-request wire format have all been
verified against the live production Session network (real seed node responses,
real snode pool, real get_swarm/store round trips returning valid signed data).
"""
import base64
import json
import random
import time
from typing import List

import requests
import urllib3

from . import onion
from .onion import SnodeInfo

# Session's storage-server/seed-node TLS certs are self-signed (identity is
# established via the ed25519/x25519 snode pubkeys, not the CA system), so
# standard cert verification is expected to fail — this is normal, not a MITM
# signal, for this particular decentralized network.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEED_NODES = [
    "https://seed1.getsession.org:4443",
    "https://seed2.getsession.org:4443",
    "https://seed3.getsession.org:4443",
]

ONION_REQUEST_PATH = "/onion_req/v2"

DEFAULT_NAMESPACE = 0  # regular 1:1 DM namespace, confirmed via SnodeNamespaces research
DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000  # 14 days


class SessionNetworkError(RuntimeError):
    pass


def _rpc_via_seednode(seed_url: str, method: str, params: dict) -> dict:
    """Seed nodes expose a plain (non-onion) JSON-RPC endpoint used only for bootstrapping
    the initial node pool — this is NOT how normal traffic (store/retrieve/get_swarm for
    arbitrary users) is expected to work once you have real snodes to onion-route through.
    """
    resp = requests.post(
        f"{seed_url}/json_rpc",
        json={"method": method, "params": params},
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()


def get_snode_pool() -> List[SnodeInfo]:
    """Fetch an initial pool of service nodes from a random seed node."""
    last_error = None
    for seed_url in random.sample(SEED_NODES, len(SEED_NODES)):
        try:
            data = _rpc_via_seednode(seed_url, "get_n_service_nodes", {
                "active_only": True,
                "fields": {"public_ip": True, "storage_port": True,
                           "pubkey_x25519": True, "pubkey_ed25519": True},
            })
            nodes = data.get("result", {}).get("service_node_states", [])
            pool = [
                SnodeInfo(
                    ip=n["public_ip"],
                    port=n["storage_port"],
                    x25519_pk_hex=n["pubkey_x25519"],
                    ed25519_pk_hex=n["pubkey_ed25519"],
                )
                for n in nodes
                if n.get("public_ip") not in (None, "0.0.0.0")
            ]
            if pool:
                return pool
        except Exception as e:  # noqa: BLE001 - try next seed node
            last_error = e
            continue
    raise SessionNetworkError(f"Could not reach any seed node: {last_error}")


def _post_onion_request(entry_node: SnodeInfo, path: List[SnodeInfo], destination: SnodeInfo,
                         rpc_body: dict) -> dict:
    """rpc_body is the plain JSON-RPC dict (e.g. {"method": "get_swarm", "params": {...}}),
    delivered raw to the destination snode's storage_rpc dispatcher (confirmed against
    oxen-storage-server's onion_processing.cpp: the destination layer is just the raw
    request body wrapped in a combined-payload structure with a {"headers": {}} marker)."""
    request_body_bytes = json.dumps(rpc_body).encode("utf-8")
    payload, response_shared_secret = onion.build_onion_request(path, destination, request_body_bytes)
    url = f"https://{entry_node.ip}:{entry_node.port}{ONION_REQUEST_PATH}"
    resp = requests.post(url, data=payload,
                          headers={"Content-Type": "application/octet-stream"},
                          timeout=15, verify=False)
    resp.raise_for_status()

    raw = resp.content
    try:
        # Response body is base64 of an AES-GCM blob encrypted back to us with the
        # same shared secret we used for the destination layer; plaintext inside is
        # {"body": "<json-encoded RPC response string>", "status": <http status>}.
        decoded = base64.b64decode(raw)
        plaintext = onion.decrypt_response(response_shared_secret, decoded)
        envelope = json.loads(plaintext)
    except Exception as e:
        raise SessionNetworkError(
            f"Could not decrypt/parse onion response (status {resp.status_code}) from {url}: "
            f"{raw[:300]!r}"
        ) from e

    status = envelope.get("status")
    if status and status >= 400:
        raise SessionNetworkError(f"Destination snode returned error: {envelope}")

    body = envelope.get("body")
    return json.loads(body) if isinstance(body, str) else body


def _pick_path_and_target(pool: List[SnodeInfo], target: SnodeInfo = None):
    """Pick a 2-hop relay path (guard + 1 relay) plus a destination snode.
    If `target` isn't given, a random pool member is used as the destination."""
    guard, relay, random_target = random.sample(pool, 3)
    return guard, [guard, relay], (target or random_target)


def get_swarm(pool: List[SnodeInfo], session_id_hex: str) -> List[SnodeInfo]:
    """Look up the swarm (service nodes responsible for storing) for a Session ID."""
    guard, path, target = _pick_path_and_target(pool)

    result = _post_onion_request(
        guard, path, target,
        {"method": "get_swarm", "params": {"pubkey": session_id_hex}},
    )
    snodes = result.get("snodes", [])
    return [
        SnodeInfo(
            ip=n["ip"], port=int(n["port"]),
            x25519_pk_hex=n["pubkey_x25519"], ed25519_pk_hex=n.get("pubkey_ed25519", ""),
        )
        for n in snodes
        if n.get("ip") not in (None, "0.0.0.0")
    ]


def store_message(pool: List[SnodeInfo], swarm: List[SnodeInfo], session_id_hex: str,
                   envelope_bytes: bytes, ttl_ms: int = DEFAULT_TTL_MS,
                   namespace: int = DEFAULT_NAMESPACE) -> dict:
    """Onion-route a `store` call to a random node in the recipient's swarm."""
    guard, path, target = _pick_path_and_target(pool, target=random.choice(swarm))

    params = {
        "pubkey": session_id_hex,
        "ttl": ttl_ms,
        "timestamp": int(time.time() * 1000),
        "data": base64.b64encode(envelope_bytes).decode("ascii"),
        "namespace": namespace,
    }

    return _post_onion_request(guard, path, target, {"method": "store", "params": params})

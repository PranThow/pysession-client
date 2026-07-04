# pysession-client

A pure-Python client for sending and receiving 1:1 direct messages on the
[Session](https://getsession.org) messenger network, given your 13-word recovery
phrase and a recipient's Session ID.

Reimplements the parts of Session's protocol needed for this from scratch
(Ed25519/X25519 key derivation, message encryption, and onion-routed swarm
storage) and has been verified end-to-end against the live production network.

## Install

```
pip install -r requirements.txt
```

Dependencies: `pynacl` (libsodium bindings), `cryptography` (AES-GCM),
`requests` (HTTP), `protobuf` (unused directly — the wire format is hand-encoded
in `proto_wire.py`, no `protoc` required).

## Quick start

```python
from pysession-client import Client

client = Client("your thirdteen word recovery phrase goes here")
print(client.session_id)  # your own Session ID, derived from the phrase

# Send a message as yourself
client.send("<recipient session id hex>", "Hello world!")

# Check your own swarm for new messages
for msg in client.receive():
    print(msg["sender_session_id"], "says:", msg["body"])
```

`receive()` takes an optional `last_hash` to only fetch messages newer than a
previously-seen one (pass the `"hash"` field from a prior message to page
forward); without it, it returns everything currently stored in your swarm
(Session's default message TTL is 14 days).

## API reference

### `pysession.Client(mnemonic: str)`

- **`.session_id`** — your Session ID (`str`, hex, `05`-prefixed).
- **`.send(session_id: str, text: str) -> dict`** — encrypts `text` for the given
  recipient and stores it in their swarm. Returns the storage server's raw
  `store` response (contains a message `hash`, per-node `signature`s, and
  `expiry` timestamp).
- **`.receive(last_hash: str = "") -> list[dict]`** — fetches and decrypts
  messages waiting in your own swarm. Each result is
  `{"sender_session_id": str, "body": str, "hash": str}`. Messages that fail to
  decrypt (not addressed to you, corrupt, etc.) are silently skipped.

Lower-level building blocks (`keys`, `mnemonic`, `envelope`, `onion`, `network`,
`retrieve`) are all importable directly if you need more control — see
"Module walkthrough" below.

## Implemented features

- Recovery phrase (13-word mnemonic) → Session ID derivation.
- Sending plain-text 1:1 direct messages (`Client.send`).
- Receiving/decrypting messages from your own swarm, with `last_hash` paging
  (`Client.receive`).
- Full onion-routed swarm transport: seed-node bootstrap, swarm lookup,
  `store`, and signed `retrieve`.
- Offline self-test covering mnemonic, key derivation, and the envelope
  build/seal/decrypt round trip.

## Features to be implemented

- Attachments (images, files, voice messages).
- Group / closed-group messaging (only 1:1 DMs are supported today).
- Disappearing messages, typing indicators, read receipts.
- Local persistence — no conversation history or seen-message tracking is
  kept; callers must manage `hash`/`last_hash` themselves.

## Known limitations

- TLS certificate verification is disabled for service-node connections. This
  is expected/necessary for this network (see "Network transport" above), but
  worth knowing if you're auditing this code.

## Self-test (no network required)

```
python -m pysession._selftest
```

Exercises mnemonic encode/decode, key derivation determinism, and the full
envelope build → seal → decrypt → signature-verify → parse round trip locally,
without touching the network.

## Module walkthrough

| Module | Responsibility |
|---|---|
| `mnemonic.py` | 13-word recovery phrase ↔ 16-byte seed |
| `keys.py` | seed → Ed25519 keypair → X25519 keypair → Session ID |
| `proto_wire.py` | minimal hand-rolled protobuf wire-format encoder |
| `envelope.py` | builds + pads + signs + seals a `DataMessage` into ciphertext |
| `onion.py` | per-hop AES-GCM crypto + onion-nesting for routing requests |
| `network.py` | seed-node bootstrap, swarm lookup, `store` |
| `retrieve.py` | signed `retrieve` calls + decrypting fetched envelopes |
| `client.py` | the public `Client` class tying everything together |

## How it works

Session has no central server: messages are end-to-end encrypted, then stored
on a decentralized network of **service nodes** run by the Oxen/Session
Foundation network. Nodes are grouped into **swarms** — every Session ID maps
deterministically to one swarm (typically 5+ nodes) that holds its messages
until the recipient polls for them or the TTL expires. Requests are routed
through the network via 3-hop **onion routing**, similar in spirit to Tor, so
no single node sees both sender and recipient.

### 1. Identity: recovery phrase → Session ID (`mnemonic.py`, `keys.py`)

Session's 13-word "recovery password" is a Monero/Electrum-style mnemonic: 12
data words plus 1 CRC32 checksum word, matched on a 3-character prefix against
a fixed 1626-word list (bundled as `wordlist_english.json`). Decoding it yields
a 16-byte seed.

That seed is zero-padded to 32 bytes and fed to libsodium's
`crypto_sign_seed_keypair` to derive an **Ed25519 keypair** (used for signing
messages). The Ed25519 keys are then converted to an **X25519 keypair** (used
for encryption) via `crypto_sign_ed25519_*_to_curve25519`. Your Session ID is
simply `0x05` followed by the X25519 public key, hex-encoded.

Because the real entropy is only 16 bytes (zero-padded, not real random data,
to fit libsodium's 32-byte seed requirement), this is Session's documented
"128-bit, not 256-bit" security trade-off in exchange for a shorter recovery
phrase.

### 2. Message construction (`envelope.py`, `proto_wire.py`)

A plaintext message is wrapped in a minimal hand-encoded protobuf structure
(field numbers taken from libsession-util's `SessionProtos.proto` — no
`protoc` needed, since only a handful of fields are used):

```
Envelope { type=SESSION_MESSAGE, timestamp, content=<encrypted Content bytes> }
Content { dataMessage: DataMessage { body: "hello", timestamp } }
```

Before encryption, the serialized `Content` is padded to a 160-byte boundary
(a `0x80` delimiter byte followed by zero-fill — this hides the exact message
length from anyone who can see ciphertext size). The sender then:

1. Signs `padded_content || sender_ed25519_pubkey || recipient_x25519_pubkey`
   with their Ed25519 key (proves authorship without an unencrypted "from"
   field).
2. Appends the sender's Ed25519 pubkey and the signature to the padded
   content.
3. Encrypts the whole thing with libsodium's `crypto_box_seal` — an anonymous
   sealed box using an ephemeral keypair, so the ciphertext itself reveals no
   sender information; authentication comes entirely from the signature
   inside.

The result becomes the `Envelope.content` field, and the serialized `Envelope`
is what gets base64'd and sent to the network.

### 3. Network transport (`network.py`, `onion.py`)

To deliver a message, a client needs to:

1. **Bootstrap** — fetch an initial pool of live service nodes from one of
   Session's public seed nodes (`seed1/2/3.getsession.org:4443`), via a plain
   (non-onion) `get_n_service_nodes` JSON-RPC call. These seed nodes use
   self-signed TLS certificates — Session authenticates node identity via each
   node's ed25519/x25519 keys at the protocol layer, not via the CA/TLS
   system, so certificate verification is intentionally disabled for these
   connections (see the note in `network.py`).
2. **Find the recipient's swarm** — send a `get_swarm` RPC call, onion-routed
   through 2 random relay nodes to a 3rd destination node, asking which nodes
   are responsible for the recipient's Session ID.
3. **Store the message** — send a `store` RPC call (recipient pubkey, TTL,
   timestamp, base64 envelope data, namespace `0` for regular 1:1 DMs),
   onion-routed the same way, to a random node in the recipient's swarm.
4. **Retrieve messages** — send a `retrieve` RPC call to a node in *your own*
   swarm. Unlike `store` (which anyone can call — that's how strangers can
   message you), `retrieve` requires proving you own the account: the request
   is signed with your Ed25519 key over the string `"retrieve" + timestamp`
   (or `"retrieve" + namespace + timestamp` for any namespace other than the
   default `0`).

#### Onion request format

Each onion "hop" is encrypted independently. The per-hop symmetric crypto
(confirmed directly from `oxen-storage-server`'s own C++ decryption source,
`oxenss/crypto/channel_encryption.cpp`) is:

```
shared_secret = X25519_scalarmult(my_ephemeral_seckey, their_static_pubkey)
aes_key       = HMAC-SHA256(key="LOKI", msg=shared_secret)
wire_bytes    = 12-byte random IV || AES-256-GCM(aes_key, iv, plaintext)   # 16-byte tag appended
```

Layers are nested from the destination outward to the entry ("guard") node.
Each layer's plaintext is itself a small framed structure (confirmed from
`oxen-storage-server`'s `onion_processing.cpp`):

```
[4-byte little-endian length N][N bytes: inner data][remaining bytes: routing JSON]
```

The routing JSON tells a hop what to do with the inner data:
- `{"destination": <next hop's ed25519 pubkey>, "ephemeral_key": <hex>}` — relay
  further to another node.
- `{"headers": {}}` — this hop is the final destination; the "inner data" at
  this layer is the raw request body (JSON-RPC text) to hand to the storage
  server's own RPC dispatcher, not further ciphertext.

The whole nested structure is POSTed as raw bytes to
`https://<guard-ip>:<guard-port>/onion_req/v2`. The response comes back
encrypted with the same shared secret used for the destination layer, as
`{"body": "<json string>", "status": <http status>}`.
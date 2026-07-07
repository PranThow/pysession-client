# Architecture

Technical companion to [README.md](README.md): how Session's protocol works,
how this client reimplements it, and what every module/function does. Read
this if you're extending the client, auditing the crypto, or just curious.

## How it works

Session has no central server: messages are end-to-end encrypted, then stored
on a decentralized network of **service nodes** ("snodes") run by the
Oxen/Session Foundation network. Nodes are grouped into **swarms** — every
Session ID maps deterministically to one swarm (typically 5+ nodes) that holds
its messages until the recipient polls for them or the TTL expires. Requests
are routed through the network via 3-hop **onion routing**, similar in spirit
to Tor, so no single node sees both sender and recipient.

## Module map

| Module | Responsibility |
|---|---|
| `mnemonic.py` | 13-word recovery phrase ↔ 16-byte seed |
| `keys.py` | seed → Ed25519 keypair → X25519 keypair → Session ID |
| `proto_wire.py` | minimal hand-rolled protobuf wire-format encoder/decoder |
| `envelope.py` | builds `Envelope`/`Content`/`DataMessage`, then pads + signs + seals via `seal_content` |
| `onion.py` | per-hop AES-GCM crypto + onion-nesting, for both snode and non-snode (file server) destinations |
| `network.py` | seed-node bootstrap, swarm lookup, `store`/`retrieve` RPCs, file-server request path |
| `attachments.py` | attachment encryption, `AttachmentPointer` build/parse, file-server upload/download |
| `retrieve.py` | signed `retrieve` calls + decrypting fetched envelopes |
| `client.py` | the public `Client` class tying everything together |

## 1. Identity: recovery phrase → Session ID

**Files: `mnemonic.py`, `keys.py`**

Session's 13-word "recovery password" is a Monero/Electrum-style mnemonic: 12
data words plus 1 CRC32 checksum word, matched on a 3-character prefix against
a fixed 1626-word list (bundled as `wordlist_english.json`). Decoding it
yields a 16-byte seed.

That seed is zero-padded to 32 bytes and fed to libsodium's
`crypto_sign_seed_keypair` to derive an **Ed25519 keypair** (used for signing
messages). The Ed25519 keys are then converted to an **X25519 keypair** (used
for encryption) via `crypto_sign_ed25519_*_to_curve25519`. Your Session ID is
simply `0x05` followed by the X25519 public key, hex-encoded.

Because the real entropy is only 16 bytes (zero-padded, not real random data,
to fit libsodium's 32-byte seed requirement), this is Session's documented
"128-bit, not 256-bit" security trade-off in exchange for a shorter recovery
phrase.

### `mnemonic.py`

| Function | Does |
|---|---|
| `decode(phrase) -> bytes` | 13-word phrase → 16-byte seed. Validates the checksum word (index = `crc32(joined 3-char prefixes) % word_count`) and that each data-word triplet's arithmetic checks out; raises `MnemonicError` otherwise. |
| `encode(seed) -> bytes` | Inverse of `decode` — seed → 13-word phrase. Used for round-trip testing; not needed to use an existing recovery phrase. |
| `_word_index(word)` | Looks up a word's index via its 3-char prefix (first-match, mirrors JS `Array.indexOf` semantics for prefix collisions). |
| `_checksum_index(words)` | `crc32` of the joined 3-char prefixes, mod word count — picks which word gets repeated as the checksum. |
| `_swap_endian_4byte(hex)` | Byte-swaps a 4-byte hex chunk; the mnemonic encoding operates on little-endian 4-byte words internally. |

### `keys.py`

| Function | Does |
|---|---|
| `from_mnemonic(phrase) -> Keypair` | `mnemonic.decode` + `from_seed` in one call — the normal entry point. |
| `from_seed(seed16) -> Keypair` | Zero-pads to 32 bytes, derives Ed25519 via `crypto_sign_seed_keypair`, converts to X25519, builds the `05`-prefixed Session ID. |
| `session_id_to_x25519_pubkey(session_id) -> bytes` | Strips the `05` prefix from a hex Session ID, returns the raw 32-byte X25519 public key (needed to encrypt *to* someone). |
| `ed25519_pk_to_session_id(ed25519_pk) -> str` | Converts a sender's Ed25519 pubkey (recovered from a decrypted envelope's signature metadata) into their Session ID — used by `retrieve.decrypt_envelope` to identify who sent an incoming message. |

`Keypair` is a plain dataclass: `seed16`, `ed25519_pk`/`ed25519_sk`,
`x25519_pk`/`x25519_sk`, `session_id`.

## 2. Wire format and message construction

**Files: `proto_wire.py`, `envelope.py`**

Session's messages are Protocol Buffers, but only a handful of fields are
ever touched, so this client hand-encodes/decodes them instead of requiring
a `protoc` build step.

### `proto_wire.py`

| Function | Does |
|---|---|
| `tag(field_number, wiretype) -> bytes` | Encodes a protobuf field key (`(field_number << 3) \| wiretype`) as a varint. |
| `varint_field(n, value)` | Tag + varint-encoded value (wiretype 0) — ints, enums, bools. |
| `fixed64_field(n, value)` | Tag + 8 little-endian bytes (wiretype 1) — only used for `AttachmentPointer.deprecated_id`. |
| `bytes_field(n, value)` | Tag + varint length + raw bytes (wiretype 2). |
| `string_field(n, value)` | `bytes_field` with the string UTF-8 encoded. |
| `message_field(n, submessage_bytes)` | `bytes_field` for an already-serialized nested message. |
| `parse_message(data) -> dict` | Decodes *any* top-level fields into `{field_number: [values, ...]}` — every occurrence is kept (so repeated fields like `DataMessage.attachments` survive), values are `int` for varint fields or raw `bytes` for length-delimited ones. Fixed64 values are returned as raw bytes, undecoded (nothing currently reads one). |
| `_varint(n)` / `_read_varint(data, i)` | Internal varint encode/decode. |

### `envelope.py`

Builds the plaintext structure and runs it through Session's pad → sign →
seal → wrap pipeline.

```
WebSocketMessage { type=REQUEST, request: WebSocketRequestMessage { body: Envelope } }
Envelope         { type=SESSION_MESSAGE, timestamp, content: <sealed Content ciphertext> }
Content          { dataMessage: DataMessage, expirationType?, expirationTimer? }
DataMessage      { body, attachments[], flags?, timestamp }
```

| Function | Does |
|---|---|
| `_build_data_message(body, timestamp_ms, attachment_pointers, flags)` | Serializes a `DataMessage`: body text, attachment pointers, `flags` (only written if nonzero — see [Reference: types and flags](README.md#reference-types-and-flags)), timestamp. |
| `_build_content(body, timestamp_ms, attachment_pointers, flags, expiration_type, expiration_seconds)` | Wraps the `DataMessage` as `Content.dataMessage`, and — if given — writes `Content.expirationType`/`expirationTimer` for disappearing messages. |
| `_build_envelope(content_ciphertext, timestamp_ms)` | Wraps already-sealed `Content` ciphertext as `Envelope.content`, plus `type`/`timestamp`. |
| `_pad(data) -> bytes` | Pads to the next 160-byte boundary: a `0x80` delimiter byte, then zero-fill. Hides the exact plaintext length from anyone who can only see ciphertext size. |
| `_sign_detached(message, ed25519_sk) -> bytes` | `crypto_sign` returns `signature(64B) \|\| message`; this slices off just the 64-byte detached signature (`nacl.bindings` has no detached-sign primitive). |
| `_verify_detached(signature, message, ed25519_pk) -> bool` | Reassembles `signature + message` and calls `crypto_sign_open`; `True`/`False` instead of raising. |
| `_sign_and_seal(plaintext, sender, recipient_x25519_pk) -> bytes` | Signs `plaintext \|\| sender_ed25519_pk \|\| recipient_x25519_pk`, appends the sender's pubkey + signature to the plaintext, then anonymously seals the whole thing with `crypto_box_seal` (see [Message encryption](#message-encryption) below). |
| `_wrap_websocket_message(envelope_bytes) -> bytes` | Nests the `Envelope` inside the `WebSocketMessage`/`WebSocketRequestMessage` shell real Session clients expect in swarm storage (confirmed against a real client's stored bytes; `verb`/`path` are always empty strings). |
| `seal_content(sender, recipient_x25519_pk, content_bytes, timestamp_ms=None) -> bytes` | The shared pipeline: pad → sign+seal → envelope-wrap → websocket-wrap. Any `Content` type (text today; a future `typingMessage` or reaction) funnels through this once its bytes are built. |
| `build_encrypted_envelope(sender, recipient_x25519_pk, body, timestamp_ms=None, attachment_pointers=(), flags=0, expiration_type=None, expiration_seconds=None) -> bytes` | The full text-message builder: `_build_content` + `seal_content`. What `Client.send`/`send_attachment`/`set_disappearing_timer` call. |

## 3. Message encryption

Before encryption, the serialized `Content` is padded (see `_pad` above).
The sender then:

1. Signs `padded_content \|\| sender_ed25519_pubkey \|\| recipient_x25519_pubkey`
   with their Ed25519 key (proves authorship without an unencrypted "from"
   field).
2. Appends the sender's Ed25519 pubkey and the signature to the padded
   content.
3. Encrypts the whole thing with libsodium's `crypto_box_seal` — an anonymous
   sealed box using an ephemeral keypair, so the ciphertext itself reveals no
   sender information; authentication comes entirely from the signature
   inside.

The result becomes `Envelope.content`. On decrypt (`retrieve.decrypt_envelope`),
the recipient opens the sealed box with their own X25519 keys, splits off the
trailing signature + sender pubkey, verifies the signature, strips the
padding, then parses `Content`/`DataMessage` fields.

## 4. Network transport

**Files: `network.py`, `onion.py`**

To deliver a message, a client needs to:

1. **Bootstrap** — fetch an initial pool of live service nodes from one of
   Session's public seed nodes (`seed1/2/3.getsession.org:4443`), via a plain
   (non-onion) `get_n_service_nodes` JSON-RPC call. These seed nodes use
   self-signed TLS certificates — Session authenticates node identity via each
   node's ed25519/x25519 keys at the protocol layer, not via the CA/TLS
   system, so certificate verification is intentionally disabled for these
   connections (`network.VERIFY_TLS`).
2. **Find the recipient's swarm** — send a `get_swarm` RPC call, onion-routed
   through 2 random relay nodes to a 3rd destination node, asking which nodes
   are responsible for the recipient's Session ID.
3. **Store the message** — send a `store` RPC call (recipient pubkey, TTL,
   timestamp, base64 envelope data, namespace `0` for regular 1:1 DMs),
   onion-routed the same way, to a random node in the recipient's swarm.
   Anyone can call `store` for anyone — that's how strangers can message you.
4. **Retrieve messages** — send a `retrieve` RPC call to a node in *your own*
   swarm. Unlike `store`, `retrieve` requires proving you own the account:
   signed with your Ed25519 key over the string `"retrieve" + timestamp` (or
   `"retrieve" + namespace + timestamp` for any namespace other than the
   default `0`).

### `network.py`

| Function | Does |
|---|---|
| `get_snode_pool() -> list[SnodeInfo]` | Tries each seed node (random order) until one returns a usable node pool. |
| `_rpc_via_seednode(seed_url, method, params)` | Plain (non-onion) JSON-RPC POST to a seed node — bootstrapping only, never used for real traffic. |
| `post_onion_request(entry_node, path, destination, rpc_body) -> dict` | Builds and sends an onion request via `onion.build_onion_request`, decrypts the response, and unwraps the JSON-RPC result. Shared by `get_swarm`, `store_message`, and `retrieve.retrieve_raw`. |
| `post_onion_request_to_file_server(pool, method, endpoint, body=None, headers=None)` | Same idea, but targets the non-snode file server via `onion.build_onion_request_to_host` and the V4 bencode-ish framing (`onion.encode_v4_request`/`decode_v4_response`). |
| `get_swarm(pool, session_id_hex) -> list[SnodeInfo]` | `get_swarm` RPC — which nodes are responsible for storing a given Session ID's messages. |
| `store_message(pool, swarm, session_id_hex, envelope_bytes, ttl_ms=..., namespace=0) -> dict` | `store` RPC to a random swarm member. |
| `_pick_path_and_target(pool, target=None)` | Picks a 2-hop relay path (guard + 1 relay) plus a destination snode (random pool member if not given). |
| `_pick_path(pool)` | Picks a 2-hop relay path with no snode destination — for non-snode targets (file server), where the relay itself proxies onward over HTTP. |

`VERIFY_TLS`, `SEED_NODES`, `ONION_REQUEST_PATH`, `DEFAULT_NAMESPACE`,
`DEFAULT_TTL_MS` (14 days), `FILE_SERVER_HOST`, `FILE_SERVER_X25519_PK`, and
`LSRPC_PATH` (`/oxen/v4/lsrpc`) are the fixed network parameters, confirmed
against session-desktop's `FileServerTarget.ts`/`SERVER_HOSTS`.

### Onion request format (`onion.py`)

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
- `{"headers": {}}` — this hop is the final destination (snode case); the
  "inner data" at this layer is the raw request body (JSON-RPC text) to hand
  to the storage server's own RPC dispatcher, not further ciphertext.
- `{"host", "target": "/oxen/v4/lsrpc", "method": "POST"[, "protocol", "port"]}` —
  this hop is adjacent to a **non-snode** destination (file server); it
  proxies the still-opaque ciphertext over plain HTTP(S) instead of relaying
  further into the onion network.

The whole nested structure is POSTed as raw bytes to
`https://<guard-ip>:<guard-port>/onion_req/v2`. The response comes back
encrypted with the same shared secret used for the destination layer, as
`{"body": "<json string>", "status": <http status>}` for snode targets, or
raw AES-GCM ciphertext (no base64/JSON envelope) framed with the V4
bencode-ish format for the file server.

| Function | Does |
|---|---|
| `encrypt_for_pubkey(their_x25519_pk, plaintext, ephemeral_keypair=None) -> (ciphertext, ephemeral_pk)` | One layer's encryption: generates (or reuses) an ephemeral X25519 keypair, derives the shared secret, AES-GCM encrypts. |
| `decrypt_from_pubkey(my_x25519_sk, their_ephemeral_pk, wire_bytes) -> bytes` | Inverse — used to decrypt an incoming onion layer (not currently exercised by this client, which only relays outbound). |
| `_encode_ciphertext_plus_json(ciphertext, obj) -> bytes` | The `[4B len][inner][routing JSON]` framing shared by every layer. |
| `_nest_through_path(path, ciphertext, ephemeral_pk, first_layer_extra)` | Wraps `ciphertext` back through `path`, last hop first, building up the nested onion from the destination outward to the guard. |
| `build_onion_request(path, destination, request_body_bytes) -> (wire_bytes, response_shared_secret)` | Full onion build for a snode destination — wraps `request_body_bytes` with the `{"headers": {}}` destination marker, then nests through `path`. |
| `build_onion_request_to_host(path, destination_x25519_pk_hex, host, lsrpc_path, request_bytes, protocol="https", port=None)` | Same, but for a non-snode HTTP(S) destination (the file server) — no `{"headers": {}}` wrapper; the relay is told to proxy instead. |
| `decrypt_response(response_shared_secret, wire_bytes) -> bytes` | Decrypts a destination's reply using the shared secret derived during the request build. |
| `encode_v4_request(endpoint, method, headers, body=None) -> bytes` | Bencode-ish framing (`l<len>:<json metadata>[<bodylen>:<body>]e`) non-snode destinations expect. |
| `decode_v4_response(data) -> (metadata, body)` | Inverse framing for the response. |

## 5. Attachments

**Files: `attachments.py`**

Attachments are uploaded to Session's file server (`filev2.getsession.org`)
rather than a swarm, and referenced from the message as an
`AttachmentPointer` appended to `DataMessage.attachments`.

**Encryption** (confirmed against session-desktop's
`ts/util/crypto/attachmentsEncrypter.ts`) is separate from the onion-transport
crypto above — it's what protects the file at rest on the file server, which
isn't part of the swarm's end-to-end-encrypted path:

```
key = 64 random bytes (aesKey = key[:32], macKey = key[32:])
iv  = 16 random bytes
ciphertext   = AES-256-CBC(aesKey, iv, plaintext)
mac          = HMAC-SHA256(macKey, iv || ciphertext)
encryptedBin = iv || ciphertext || mac
digest       = SHA256(encryptedBin)
```

`key` and `digest` go in the `AttachmentPointer` so the recipient can decrypt
and verify; `encryptedBin` is the file uploaded to the server. This client
skips Session's extra size-bucket padding step before encrypting — receivers
already tolerate an attachment whose downloaded size exactly matches the
pointer's `size` field, so omitting it costs nothing but the
size-obfuscation privacy benefit.

**Upload/download** — the file server is not a service node, so it can't be
reached the same way as `get_swarm`/`store`/`retrieve`. Session instead
onion-routes an HTTP(S) request to it (confirmed against session-desktop's
`FileServerApi.ts` and `onions.ts`): see "non-snode destination" in the onion
request format above.

| Function | Does |
|---|---|
| `encrypt_attachment(plaintext) -> (encrypted_blob, key, digest)` | Generates the random key+IV, runs the encrypt-then-MAC scheme above. |
| `decrypt_attachment(encrypted_blob, key, digest) -> bytes` | Verifies `digest` then the MAC (both via `hmac.compare_digest`, constant-time) before decrypting — fails closed on any mismatch. |
| `_aes_cbc_encrypt`/`_aes_cbc_decrypt` | PKCS7-padded AES-256-CBC, via the `cryptography` package. |
| `build_pointer(content_type, size, file_name, key, digest, url, caption=None, width=None, height=None) -> bytes` | Serializes an `AttachmentPointer` (see field table below). `deprecated_id` is always written as `0` — required by the proto but unused by any modern client. |
| `parse_pointer(pointer_bytes) -> dict` | Inverse of `build_pointer` — used by `retrieve.decrypt_envelope` to turn incoming `DataMessage.attachments` entries into plain dicts. |
| `upload(pool, file_bytes, content_type=None, file_name=None) -> dict` | Encrypts, POSTs to the file server, and builds the pointer from the returned file ID. Returns `{"pointer_bytes", "url", "key", "digest"}`. |
| `download(pool, url, key, digest) -> bytes` | Extracts the file ID from `url`, GETs the encrypted blob, decrypts it. |

## 6. Retrieval

**Files: `retrieve.py`**

| Function | Does |
|---|---|
| `_snode_signature(method, ed25519_sk, namespace, timestamp_ms) -> bytes` | Signs `"retrieve" + timestamp` (or `+ namespace +` if not the default namespace `0`) — proves account ownership for the `retrieve` RPC, which anyone-can't call unlike `store`. |
| `retrieve_raw(pool, swarm, session_id_hex, ed25519_sk, last_hash="", namespace=0) -> list[dict]` | Signed `retrieve` RPC against `swarm[0]`; `last_hash` pages forward past a previously-seen message. Returns the raw stored-message dicts (`{"data": base64, "hash": str, ...}`) as-is from the snode. |
| `decrypt_envelope(envelope_bytes, my_x25519_pk, my_x25519_sk) -> (sender_pk, body, attachment_list, expire_seconds, expire_after_read)` | Unwraps `WebSocketMessage` → `Envelope`, opens the sealed box, verifies the signature, strips padding, then parses `Content`/`DataMessage` fields — including `expirationType`/`expirationTimer` (fields 12/13 on `Content`) if present. `expire_seconds` is `None` when the message carries no timer. |

## 7. Client

**Files: `client.py`**

The public façade. Every send path funnels through `_store` (already-sealed
bytes → swarm) so `send`, `send_attachment`, and `set_disappearing_timer`
don't each duplicate the swarm-lookup/store-call logic.

| Function | Does |
|---|---|
| `_expiration_type(expire_seconds, expire_after_read)` (module-level) | `None` if `expire_seconds` is falsy, else the `EXPIRATION_TYPE_DELETE_AFTER_READ`/`_SEND` constant — shared by `send`, `send_attachment`, `set_disappearing_timer` so the "which enum value" logic lives in one place. |
| `Client.__init__(mnemonic)` | Derives the keypair; the snode pool is fetched lazily (`_pool` starts `None`). |
| `_get_pool()` | Fetches (once, memoized) the initial snode pool. |
| `_get_swarm_or_raise(session_id)` | Pool + `get_swarm`, raising if the swarm comes back empty. |
| `_store(session_id, envelope_bytes)` | Shared send path: swarm lookup + `store_message`. |
| `send(session_id, text, expire_seconds=None, expire_after_read=False)` | Builds and stores a text envelope, optionally with a disappearing timer. |
| `send_attachment(session_id, file_bytes, content_type=None, file_name=None, caption="", expire_seconds=None, expire_after_read=False)` | Uploads the file, then builds and stores an envelope referencing it. |
| `set_disappearing_timer(session_id, expire_seconds, expire_after_read=False)` | Sends the empty-body `EXPIRATION_TIMER_UPDATE`-flagged control message. |
| `download_attachment(attachment)` | `attachments.download` using the `url`/`key`/`digest` from a `.receive()` attachment dict. |
| `receive(last_hash="")` | Fetches raw messages, decrypts each (skipping any that fail — not addressed to you, corrupt, etc.), and returns the public dict shape described in [README.md](README.md#api-reference). |

## Protocol field reference

Field numbers below are confirmed against `libsession-util`'s
`SessionProtos.proto` and session-desktop's `protos/SignalService.proto` (see
each module's docstring for the specific source). Only fields this client
reads or writes are listed; see the linked proto files for the full message
definitions.

### `WebSocketMessage` (the storage envelope shell)

| Field | # | Type | Notes |
|---|---|---|---|
| `type` | 1 | varint | Always `1` (REQUEST) |
| `request` | 2 | `WebSocketRequestMessage` | `{verb: "", path: "", body: <Envelope bytes>}` |

### `Envelope`

| Field | # | Type | Notes |
|---|---|---|---|
| `type` | 1 | varint (`Envelope.Type`) | See [types table](README.md#envelope-types) |
| `timestamp` | 5 | varint (ms) | |
| `content` | 8 | bytes | Sealed `Content` ciphertext |
| `source` | 2 | string | Unused (sender identity comes from the signature inside `content`, not this field) |
| `sourceDevice` | 7 | varint | Unused |
| `serverTimestamp` | 10 | varint | Unused |

### `Content`

| Field | # | Type | Notes |
|---|---|---|---|
| `dataMessage` | 1 | `DataMessage` | |
| `expirationType` | 12 | varint enum | See [disappearing-message types](README.md#disappearing-message-types-contentexpirationtype) |
| `expirationTimer` | 13 | varint (seconds) | |

### `DataMessage`

| Field | # | Type | Notes |
|---|---|---|---|
| `body` | 1 | string | Omitted entirely if empty |
| `attachments` | 2 | repeated `AttachmentPointer` | |
| `flags` | 4 | varint (`DataMessage.Flags`) | See [message flags](README.md#message-flags-datamessageflags) |
| `timestamp` | 7 | varint (ms) | |

### `AttachmentPointer`

| Field | # | Type | Notes |
|---|---|---|---|
| `deprecated_id` | 1 | fixed64 | Required by the proto, always written as `0`, unused by any modern client |
| `contentType` | 2 | string | Freeform MIME type — see [README](README.md#attachments-and-content-types) |
| `key` | 3 | bytes | 64-byte encrypt/HMAC key |
| `size` | 4 | varint | Plaintext byte size |
| `digest` | 6 | bytes | `SHA256(encrypted_blob)` |
| `fileName` | 7 | string | |
| `flags` | 8 | varint (`AttachmentPointer.Flags`) | Not currently written by `build_pointer` — see [attachment flags](README.md#attachment-flags-attachmentpointerflags) |
| `width` | 9 | varint | |
| `height` | 10 | varint | |
| `caption` | 11 | string | |
| `url` | 101 | string | Full download URL, filled in by `attachments.upload()` after the file server assigns an ID |

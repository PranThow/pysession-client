# pysession-client

A pure-Python client for sending and receiving 1:1 direct messages on the
[Session](https://getsession.org) messenger network, given your 13-word
recovery phrase and a recipient's Session ID.

Reimplements the parts of Session's protocol needed for this from scratch —
no `libsession-util` bindings, no Electron/Node — and has been verified
end-to-end against the live production network.

For how any of this actually works under the hood (cryptography, onion
routing, wire formats), see **[ARCHITECTURE.md](ARCHITECTURE.md)**. This
README just covers using the library.

## Installation

```
pip install -r requirements.txt
```

| Package | Version | Used for |
|---|---|---|
| `pynacl` | >=1.5.0 | libsodium bindings — Ed25519/X25519 keys, signing, sealed-box encryption |
| `cryptography` | >=41.0.0 | AES-256-GCM (onion transport), AES-256-CBC+HMAC (attachment encryption) |
| `requests` | >=2.31.0 | HTTP to seed nodes and onion-routed service nodes |
| `protobuf` | >=4.25.0 | Declared but unused directly — the protobuf wire format is hand-encoded in `proto_wire.py`, so no `protoc` install is required |

Requires Python 3.9+.

## Quick start

```python
from pysession_client import Client

client = Client("your thirteen word recovery phrase goes here")
print(client.session_id)  # your own Session ID, derived from the phrase

# Send a message as yourself
client.send("<recipient session id hex>", "Hello world!")

# Send a message that disappears 30 seconds after the recipient reads it
client.send("<recipient session id hex>", "self-destructing", expire_seconds=30, expire_after_read=True)

# Send a file
with open("cat.png", "rb") as f:
    client.send_attachment("<recipient session id hex>", f.read(),
                            content_type="image/png", file_name="cat.png",
                            caption="look at this cat")

# Check your own swarm for new messages
for msg in client.receive():
    print(msg["sender_session_id"], "says:", msg["body"])
    for attachment in msg["attachments"]:
        data = client.download_attachment(attachment)
        print("  attachment:", attachment["file_name"], len(data), "bytes")
```

`receive()` takes an optional `last_hash` to only fetch messages newer than a
previously-seen one (pass the `"hash"` field from a prior message to page
forward); without it, it returns everything currently stored in your swarm
(Session's default message TTL is 14 days).

## Included features

| Feature | Client method(s) |
|---|---|
| Recovery phrase → Session ID derivation | `Client(mnemonic)`, `.session_id` |
| Sending plain-text 1:1 direct messages | `.send()` |
| Sending / receiving file attachments | `.send_attachment()`, `.download_attachment()` |
| Receiving & decrypting your own swarm, with paging | `.receive(last_hash=...)` |
| Disappearing messages (delete-after-send / delete-after-read) | `.send()`, `.send_attachment()`, `.set_disappearing_timer()` |
| Full onion-routed swarm transport (bootstrap, swarm lookup, store, signed retrieve) | used internally by all of the above |
| Offline self-test (mnemonic, keys, envelope crypto, attachments, disappearing messages) | `python -m pysession_client._selftest` |

## Upcoming features

| Feature | Notes |
|---|---|
| Group / closed-group messaging | Only 1:1 DMs are supported today |
| Typing indicators, read receipts | Protocol messages exist (`TypingMessage`, `ReceiptMessage`) but aren't built by this client yet |
| Voice-message attachment flag | `AttachmentPointer.flags` (`VOICE_MESSAGE`) isn't exposed by `send_attachment()` yet — see [Attachment flags](#attachment-flags) |
| Local persistence | No conversation history or seen-message tracking; callers manage `hash`/`last_hash` themselves |
| Local expiry enforcement | See [Disappearing messages](#disappearing-messages) — this library reports timers, it doesn't run a background deleter |

## Known limitations

- **TLS certificate verification is disabled** for service-node connections
  (`network.VERIFY_TLS`). This is expected/necessary for this network — Session
  authenticates nodes by their ed25519/x25519 keys at the protocol layer, not
  via the CA system — but worth knowing if you're auditing this code.
- **No local storage.** `pysession-client` is a stateless transport client. It
  doesn't track which messages you've seen, doesn't delete expired messages,
  and doesn't persist anything between calls — build that layer yourself on
  top of `.receive()`'s return values.

## API reference

### `Client(mnemonic: str)`

| Member | Signature | Description |
|---|---|---|
| `.session_id` | `str` | Your Session ID (hex, `05`-prefixed) |
| `.send()` | `(session_id, text, expire_seconds=None, expire_after_read=False) -> dict` | Encrypt `text` and store it in `session_id`'s swarm |
| `.send_attachment()` | `(session_id, file_bytes, content_type=None, file_name=None, caption="", expire_seconds=None, expire_after_read=False) -> dict` | Upload `file_bytes` to Session's file server, then send an envelope referencing it |
| `.set_disappearing_timer()` | `(session_id, expire_seconds, expire_after_read=False) -> dict` | Announce a disappearing-messages timer change (or turn it off with `expire_seconds=0`) |
| `.receive()` | `(last_hash="") -> list[dict]` | Fetch and decrypt messages waiting in your own swarm |
| `.download_attachment()` | `(attachment: dict) -> bytes` | Fetch and decrypt an attachment dict from `.receive()` |

`.send()` / `.send_attachment()` return the storage server's raw `store`
response (message `hash`, per-node `signature`s, `expiry` timestamp).

`.receive()` returns a list of:

```python
{
    "sender_session_id": str,
    "body": str,
    "hash": str,
    "attachments": list[dict],       # see Attachments below, [] if none
    "expire_seconds": int | None,    # see Disappearing messages below
    "expire_after_read": bool,       # only meaningful if expire_seconds is set
}
```

Messages that fail to decrypt (not addressed to you, corrupt, etc.) are
silently skipped.

Lower-level building blocks (`keys`, `mnemonic`, `envelope`, `onion`,
`network`, `retrieve`, `attachments`) are all importable directly if you need
more control — see [ARCHITECTURE.md](ARCHITECTURE.md) for what each one does.

## Disappearing messages

Session's disappearing-message timer isn't a per-message flag bolted onto the
text — it's carried on every message's `Content` (see
[Reference: types and flags](#reference-types-and-flags) below) while a timer
is active for the conversation, so a recipient's client can apply it even to
messages that aren't the one that changed the setting.

| Parameter | Meaning |
|---|---|
| `expire_seconds` | How many seconds after the trigger point the message should be deleted. `None` (default) = no timer — the message just lives until the swarm's normal TTL (14 days). |
| `expire_after_read` | Chooses the trigger point. `False` (default) = **delete after send** — same expiry instant for both sides. `True` = **delete after read** — the clock starts when the recipient opens it, so each side may see it disappear at a different time. Ignored if `expire_seconds` isn't set. |

```python
# Delete 30 seconds after send (both sides expire at the same instant)
client.send(recipient, "self-destructing", expire_seconds=30)

# Delete 5 minutes after the recipient reads it
client.send(recipient, "read this quick", expire_seconds=300, expire_after_read=True)
```

`set_disappearing_timer(session_id, expire_seconds, expire_after_read=False)`
sends the dedicated "timer changed" control message real Session clients
generate when you tap the clock icon in a conversation — an empty-body
message flagged `EXPIRATION_TIMER_UPDATE` (see below) that recipient apps show
as a system notice ("X set messages to disappear after..."). It doesn't
delete anything by itself, and it doesn't set future `.send()` calls to
auto-apply the timer — each `.send()`/`.send_attachment()` call still needs
its own `expire_seconds`/`expire_after_read`. Pass `expire_seconds=0` to
announce the timer being turned off.

**pysession-client does not delete anything itself.** `expire_seconds` /
`expire_after_read` on a received message just tell you what the sender
intended — actually hiding/deleting it once expired is up to whatever you
build on top of `.receive()`.

## Attachments and content types

`content_type` (on `send_attachment()`) and the `"content_type"` key (from
`.receive()`'s attachment dicts) is a plain MIME-type string, written verbatim
into `AttachmentPointer.contentType`. Session's protocol doesn't validate or
restrict it — it's caller-supplied metadata that receiving clients use to
decide how to render the file. `pysession-client` doesn't sniff or check it
against the actual bytes either, so it's on you to pass something accurate.

Common values real Session clients use:

| Content type | Rendered as |
|---|---|
| `image/jpeg`, `image/png`, `image/gif`, `image/webp` | Inline image preview |
| `video/mp4`, `video/quicktime` | Inline video player |
| `audio/aac`, `audio/mp4`, `audio/mpeg` | Audio player (voice notes also set `AttachmentPointer.flags = VOICE_MESSAGE`, see below) |
| `application/pdf` | Document icon |
| anything else / omitted | Falls back to a generic file icon + file name |

## Reference: types and flags

### Envelope types

Every message on the wire is wrapped in an `Envelope` with a `type`. This
client only ever sends/expects `SESSION_MESSAGE`.

| Type | Value | Meaning |
|---|---|---|
| `SESSION_MESSAGE` | 6 | Standard 1:1 direct message |
| `CLOSED_GROUP_MESSAGE` | 7 | Legacy closed-group message — not supported by this client |

### Disappearing-message types (`Content.expirationType`)

| Type | Value | Meaning |
|---|---|---|
| *(unset)* | – | No disappearing timer on this message |
| `DELETE_AFTER_READ` | 1 | Deleted `expirationTimer` seconds after the recipient reads it |
| `DELETE_AFTER_SEND` | 2 | Deleted `expirationTimer` seconds after it was sent |

Maps directly to the `expire_after_read` argument above (`True`/`False`
respectively).

### Message flags (`DataMessage.flags`)

| Flag | Value | Meaning |
|---|---|---|
| `EXPIRATION_TIMER_UPDATE` | 2 | Marks an empty-body message as a "disappearing timer changed" announcement rather than a real message. Set automatically by `.set_disappearing_timer()`. |

### Attachment flags (`AttachmentPointer.flags`)

<a id="attachment-flags"></a>

| Flag | Value | Meaning |
|---|---|---|
| `VOICE_MESSAGE` | 1 | Marks an attachment as a recorded voice note so receiving clients show a waveform/voice player instead of a generic file. **Not currently settable via `send_attachment()`** — see [Upcoming features](#upcoming-features). |

## Self-test (no network required)

```
python -m pysession_client._selftest
```

Exercises mnemonic encode/decode, key derivation determinism, the full
envelope build → seal → decrypt → signature-verify → parse round trip,
disappearing-message field round-tripping, and attachment encryption +
`AttachmentPointer` build/parse — all locally, without touching the network.

## License

GPLv3 — see [LICENSE](LICENSE).

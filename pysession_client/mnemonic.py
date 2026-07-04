"""Session's 13-word recovery phrase (Monero/Electrum-style mnemonic, prefixLen=3).

Ported from session-desktop's ts/session/crypto/mnemonic.ts.
"""
import json
import zlib
from pathlib import Path

_PREFIX_LEN = 3
_WORDLIST_PATH = Path(__file__).parent / "wordlist_english.json"

with open(_WORDLIST_PATH, "r", encoding="utf-8") as f:
    WORDLIST = json.load(f)

N = len(WORDLIST)  # 1626

# first-match prefix -> index, built in list order (matches JS Array.indexOf semantics)
_PREFIX_TO_INDEX = {}
for _i, _w in enumerate(WORDLIST):
    _p = _w[:_PREFIX_LEN]
    if _p not in _PREFIX_TO_INDEX:
        _PREFIX_TO_INDEX[_p] = _i


class MnemonicError(ValueError):
    pass


def _swap_endian_4byte(hex_chunk: str) -> str:
    return hex_chunk[6:8] + hex_chunk[4:6] + hex_chunk[2:4] + hex_chunk[0:2]


def _word_index(word: str) -> int:
    prefix = word[:_PREFIX_LEN]
    if prefix not in _PREFIX_TO_INDEX:
        raise MnemonicError(f"Unknown mnemonic word: {word!r}")
    return _PREFIX_TO_INDEX[prefix]


def _checksum_index(words: list) -> int:
    trimmed = "".join(w[:_PREFIX_LEN] for w in words)
    checksum = zlib.crc32(trimmed.encode("utf-8")) & 0xFFFFFFFF
    return checksum % len(words)


def decode(phrase: str) -> bytes:
    """Decode a 13-word Session recovery phrase into its 16-byte seed."""
    words = phrase.split()
    if len(words) != 13:
        raise MnemonicError(f"Expected 13 words, got {len(words)}")

    data_words = words[:12]
    checksum_word = words[12]

    expected_index = _checksum_index(data_words)
    expected_prefix = data_words[expected_index][:_PREFIX_LEN]
    if checksum_word[:_PREFIX_LEN] != expected_prefix:
        raise MnemonicError("Checksum word does not match — phrase is invalid or mistyped")

    hex_out = ""
    for i in range(0, 12, 3):
        w1 = _word_index(data_words[i])
        w2 = _word_index(data_words[i + 1])
        w3 = _word_index(data_words[i + 2])

        x = w1 + N * ((N - w1 + w2) % N) + N * N * ((N - w2 + w3) % N)
        if x % N != w1:
            raise MnemonicError("Invalid mnemonic word triplet")

        chunk = format(x, "08x")
        hex_out += _swap_endian_4byte(chunk)

    return bytes.fromhex(hex_out)


def encode(seed: bytes) -> str:
    """Encode a 16-byte seed into a 13-word Session recovery phrase (for testing/round-trip)."""
    if len(seed) != 16:
        raise MnemonicError("Seed must be 16 bytes")

    seed_hex = seed.hex()
    swapped_hex = "".join(
        _swap_endian_4byte(seed_hex[i:i + 8]) for i in range(0, len(seed_hex), 8)
    )

    words = []
    for i in range(0, len(swapped_hex), 8):
        x = int(swapped_hex[i:i + 8], 16)
        w1 = x % N
        w2 = (x // N + w1) % N
        w3 = (x // N // N + w2) % N
        words.extend([WORDLIST[w1], WORDLIST[w2], WORDLIST[w3]])

    checksum_word = words[_checksum_index(words)]
    words.append(checksum_word)
    return " ".join(words)

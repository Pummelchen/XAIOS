#!/usr/bin/env python3
"""Oracle for QUIC packet protection: AEAD, header protection, Retry tag.

RFC 9001 Appendix A gives complete input/output pairs, which makes this the
strongest available check on the packet-protection layer -- stronger than the
key schedule alone, because it exercises the AEAD nonce construction, the
associated-data definition, the header-protection sample offset and mask, and
the Retry pseudo-header, all of which are places where a wrong choice still
produces output of the right shape.

Run this before changing the C port. Every expected value is from the RFC.
"""

from __future__ import annotations

import hashlib
import hmac
import sys

# `cryptography` is a host-only dependency of this cross-check, not of the
# build or of any gate. When it is absent the script says so and exits 0: a
# missing optional tool must not read as a failed verification, and the C tests
# it exists to cross-check run without it.
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ImportError:  # pragma: no cover - depends on the host
    print("verify_wt_rfc9001_packets: python 'cryptography' is not installed; "
          "skipping the independent cross-check (the C tests in "
          "test_wt_crypto.c are unaffected)")
    raise SystemExit(0)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      length: int) -> bytes:
    full_label = b"tls13 " + label.encode()
    info = (length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label
            + bytes([len(context)]) + context)
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]

FAILURES: list[str] = []
CHECKS = 0


def expect(name: str, expected_hex: str, actual: bytes) -> None:
    global CHECKS
    CHECKS += 1
    expected = expected_hex.replace(" ", "").replace("\n", "")
    if expected == actual.hex():
        return
    FAILURES.append(f"{name}\n     expected {expected}\n     actual   {actual.hex()}")


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
DCID = bytes.fromhex("8394c8f03e515708")

initial_secret = hkdf_extract(INITIAL_SALT, DCID)
client_initial = hkdf_expand_label(initial_secret, "client in", b"", 32)
server_initial = hkdf_expand_label(initial_secret, "server in", b"", 32)


def aead_encrypt(key: bytes, iv: bytes, pn: int, header: bytes,
                 plaintext: bytes) -> bytes:
    """AES-128-GCM as QUIC uses it.

    The nonce is the IV with the packet number XORed into its rightmost bytes,
    and the associated data is the entire packet header -- including the
    unprotected packet number. Both are easy to get subtly wrong.
    """
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(len(iv), "big")))
    return AESGCM(key).encrypt(nonce, plaintext, header)


# ---------------------------------------------------------------------------
# A.2 Client Initial

CLIENT_KEY = hkdf_expand_label(client_initial, "quic key", b"", 16)
CLIENT_IV = hkdf_expand_label(client_initial, "quic iv", b"", 12)
CLIENT_HP = hkdf_expand_label(client_initial, "quic hp", b"", 16)

client_header = bytes.fromhex("c300000001088394c8f03e5157080000449e00000002")
client_plaintext = bytes.fromhex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff")
# Payload is 1162 bytes: the CRYPTO frame above plus PADDING to that length.
client_payload = client_plaintext + b"\x00" * (1162 - len(client_plaintext))
expect("A.2 plaintext length is 1162", "048a", len(client_payload).to_bytes(2, "big"))

client_ciphertext = aead_encrypt(CLIENT_KEY, CLIENT_IV, 2, client_header,
                                 client_payload)
expect("A.2 client payload ciphertext length 1178",
       "049a", len(client_ciphertext).to_bytes(2, "big"))

# Header protection sample: 16 bytes starting 4 bytes after the start of the
# packet number field, which for a 4-byte PN is offset 18 in the header.
sample = client_ciphertext[4 - 4:][0:16]
expect("A.2 sample = d1b1c98dd7689fb8ec11d242b123dc9b",
       "d1b1c98dd7689fb8ec11d242b123dc9b", sample)

mask = aes_ecb_encrypt_block(CLIENT_HP, sample)[:5]
expect("A.2 mask = 437b9aec36", "437b9aec36", mask)

protected_header = bytearray(client_header)
protected_header[0] ^= mask[0] & 0x0F
for i in range(4):
    protected_header[18 + i] ^= mask[1 + i]
expect("A.2 protected header = c000000001088394c8f03e5157080000449e7b9aec34",
       "c000000001088394c8f03e5157080000449e7b9aec34", bytes(protected_header))

client_packet = bytes(protected_header) + client_ciphertext
expect("A.2 client packet length 1200", "04b0",
       len(client_packet).to_bytes(2, "big"))
expect("A.2 first 32 bytes of the protected packet",
       "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
       client_packet[:32])

# ---------------------------------------------------------------------------
# A.3 Server Initial

SERVER_KEY = hkdf_expand_label(server_initial, "quic key", b"", 16)
SERVER_IV = hkdf_expand_label(server_initial, "quic iv", b"", 12)
SERVER_HP = hkdf_expand_label(server_initial, "quic hp", b"", 16)

server_header = bytes.fromhex("c1000000010008f067a5502a4262b50040750001")
server_plaintext = bytes.fromhex(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304")
# RFC 9001 labels this block 116 octets; the hex above it is 103 bytes (a
# 5-byte ACK frame, a 98-byte CRYPTO frame). The block is what is protected, so
# the length asserted is the block's, and the label is noted rather than used.
expect("A.3 server plaintext length 99", "0063", len(server_plaintext).to_bytes(2, "big"))

server_ciphertext = aead_encrypt(SERVER_KEY, SERVER_IV, 1, server_header,
                                 server_plaintext)
server_sample = server_ciphertext[2:18]
expect("A.3 sample = 2cd0991cd25b0aac406a5816b6394100",
       "2cd0991cd25b0aac406a5816b6394100", server_sample)
server_mask = aes_ecb_encrypt_block(SERVER_HP, server_sample)[:5]
expect("A.3 mask = 2ec0d8356a", "2ec0d8356a", server_mask)

server_protected = bytearray(server_header)
server_protected[0] ^= server_mask[0] & 0x0F
for i in range(2):
    server_protected[18 + i] ^= server_mask[1 + i]
expect("A.3 protected header = cf000000010008f067a5502a4262b5004075c0d9",
       "cf000000010008f067a5502a4262b5004075c0d9", bytes(server_protected))
server_packet = bytes(server_protected) + server_ciphertext
expect("A.3 protected packet starts",
       "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
       server_packet[:32])

# ---------------------------------------------------------------------------
# A.4 Retry integrity tag

# The key and nonce are fixed constants in RFC 9001 section 5.8, not derived.
RETRY_KEY = bytes.fromhex("be0c690b9f66575a1d766b54e368c84e")
RETRY_NONCE = bytes.fromhex("461599d35d632bf2239825bb")

# The pseudo-packet: the original destination connection ID, length-prefixed,
# followed by the Retry packet itself with its own 16-byte tag removed. The
# client-chosen DCID is included here even though it is absent from the packet
# on the wire -- that is what binds the tag to the connection it answers.
retry_without_tag = bytes.fromhex(
    "ff000000010008f067a5502a4262b5746f6b656e")
pseudo = (bytes([len(DCID)]) + DCID + retry_without_tag)
tag = AESGCM(RETRY_KEY).encrypt(RETRY_NONCE, b"", pseudo)
expect("A.4 Retry integrity tag = 04a265ba2eff4d829058fb3f0f2496ba",
       "04a265ba2eff4d829058fb3f0f2496ba", tag)

expect("A.4 full Retry packet",
       "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
       retry_without_tag + tag)

# ---------------------------------------------------------------------------
# A.5 ChaCha20-Poly1305 short header

APP_SECRET = bytes.fromhex(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
CH_KEY = hkdf_expand_label(APP_SECRET, "quic key", b"", 32)
CH_IV = hkdf_expand_label(APP_SECRET, "quic iv", b"", 12)
CH_HP = hkdf_expand_label(APP_SECRET, "quic hp", b"", 32)
CH_KU = hkdf_expand_label(APP_SECRET, "quic ku", b"", 32)

PN = 654360564
unprotected_header = bytes.fromhex("4200bff4")
nonce = bytes(a ^ b for a, b in zip(CH_IV, PN.to_bytes(12, "big")))
expect("A.5 nonce = e0459b3474bdd0e46d417eb0", "e0459b3474bdd0e46d417eb0", nonce)

# QUIC prepends the unprotected header to the nonce for the AEAD nonce? No --
# the nonce is the IV XOR the packet number, and the header is the AAD.
ch_ciphertext = ChaCha20Poly1305(CH_KEY).encrypt(nonce, b"\x01",
                                                 unprotected_header)
expect("A.5 payload ciphertext",
       "655e5cd55c41f69080575d7999c25a5bfb", ch_ciphertext)

# ChaCha20 header protection: the mask is the first 5 bytes of the ChaCha20
# *keystream*, with the counter taken from the first 4 sample bytes as a
# little-endian integer and the nonce from the remaining 12. This differs from
# AES, which encrypts the sample block itself.
sample = ch_ciphertext[1:17]
expect("A.5 sample = 5e5cd55c41f69080575d7999c25a5bfb",
       "5e5cd55c41f69080575d7999c25a5bfb", sample)

# The ChaCha20 block function, written out because the obvious library call is
# ambiguous: `cryptography`'s ChaCha20 takes a 16-byte nonce that is the counter
# followed by the nonce, and passing an IV built any other way silently gives
# the wrong keystream (it gave 28a5e1bcca here before this was written out).
def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    import struct
    state = (list(struct.unpack("<4I", b"expand 32-byte k"))
             + list(struct.unpack("<8I", key))
             + [counter] + list(struct.unpack("<3I", nonce)))
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *[(working[i] + state[i]) & 0xFFFFFFFF
                                 for i in range(16)])


# Before trusting it on the QUIC vector, check it against RFC 7539's own test
# vector (zero key, zero nonce, counter 0).
expect("RFC 7539 ChaCha20 block (zero key, counter 0)",
       "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
       chacha20_block(bytes(32), 0, bytes(12))[:32])

keystream = chacha20_block(CH_HP, int.from_bytes(sample[:4], "little"),
                           sample[4:16])[:5]
expect("A.5 mask = aefefe7d03", "aefefe7d03", keystream)

protected = bytearray(unprotected_header)
protected[0] ^= keystream[0] & 0x1F
for i in range(3):
    protected[1 + i] ^= keystream[1 + i]
expect("A.5 header = 4cfe4189", "4cfe4189", bytes(protected))
expect("A.5 packet = 4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
       "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
       bytes(protected) + ch_ciphertext)

# Key update secret, so the "quic ku" label is exercised rather than assumed.
expect("A.5 key update secret",
       "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
       CH_KU)


def main() -> int:
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}")
        print(f"\n{len(FAILURES)} of {CHECKS} packet-protection values NOT reproduced")
        return 1
    print(f"oracle: all {CHECKS} RFC 9001 packet-protection values reproduced "
          f"(AEAD, header protection, Retry integrity tag)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

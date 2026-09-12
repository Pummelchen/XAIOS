#!/usr/bin/env python3
"""Oracle for the TLS 1.3 key schedule and QUIC packet protection.

Every expected value here is transcribed from an RFC. Run this before writing
or changing the C port: if the oracle cannot reproduce the published vectors
then the understanding behind it is wrong, and a C implementation written to
the same misunderstanding would be wrong in the same way and would pass its own
tests.

Sources:
  RFC 8448  Example Handshake Traces for TLS 1.3
  RFC 9001  Using TLS to Secure QUIC, Appendix A

Only values whose inputs the RFC states are checked here. The three RFC 8448
entries that need a transcript hash assembled from bytes in RFC 8448's own
hex dumps are deliberately absent: transcribing several hundred hex bytes by
hand is the one thing in this document that cannot be got right by reading, and
an oracle with a mistyped vector is worse than no oracle -- it fails a correct
implementation. Transcript hashing is checked separately, in C, against the
QUIC Initial sample, where RFC 9001 gives the exact packet bytes.
"""

from __future__ import annotations

import hashlib
import hmac

SHA256 = "sha256"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      length: int) -> bytes:
    """HKDF-Expand-Label (RFC 8446 section 7.1).

    HkdfLabel is a structure, not a concatenation:
        uint16 length;
        opaque label<7..255>;    one length byte, then "tls13 " + label
        opaque context<0..255>;  one length byte, then the context
    Getting the length prefixes wrong still produces plausible output, which is
    why this is checked against published vectors rather than reviewed.
    """
    full_label = b"tls13 " + label.encode()
    assert len(full_label) <= 255, "label too long"
    assert len(context) <= 255, "context too long"
    info = (length.to_bytes(2, "big")
            + bytes([len(full_label)]) + full_label
            + bytes([len(context)]) + context)
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_secret(secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, 32)


EMPTY_HASH = hashlib.sha256(b"").digest()

CHECKS: list[tuple[str, str, bytes]] = []


def check(name: str, expected_hex: str, actual: bytes) -> None:
    CHECKS.append((name, expected_hex.replace(" ", "").replace("\n", ""),
                   actual))


# ---------------------------------------------------------------------------
# RFC 8448 section 3 -- the key schedule as far as it is determined by values
# the RFC states outright.

EARLY = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
check("rfc8448 early_secret",
      "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", EARLY)

DERIVED_EARLY = derive_secret(EARLY, "derived", EMPTY_HASH)
check("rfc8448 derived_from_early_secret",
      "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
      DERIVED_EARLY)

# The ECDHE input the RFC names for this trace.
HANDSHAKE_SECRET = hkdf_extract(DERIVED_EARLY, bytes.fromhex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"))
check("rfc8448 handshake_secret",
      "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
      HANDSHAKE_SECRET)

DERIVED_HANDSHAKE = derive_secret(HANDSHAKE_SECRET, "derived", EMPTY_HASH)
check("rfc8448 derived_from_handshake_secret",
      "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4",
      DERIVED_HANDSHAKE)

MASTER = hkdf_extract(DERIVED_HANDSHAKE, b"\x00" * 32)
check("rfc8448 master_secret",
      "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919", MASTER)

# RFC 8448 states this traffic secret and the transcript it came from, so the
# derive_secret path can be checked against the RFC's own transcript hash
# without assembling any handshake bytes.
TH_SH = bytes.fromhex(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
C_HS = derive_secret(HANDSHAKE_SECRET, "c hs traffic", TH_SH)
check("rfc8448 client_handshake_traffic_secret",
      "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21", C_HS)

S_HS = derive_secret(HANDSHAKE_SECRET, "s hs traffic", TH_SH)
check("rfc8448 server_handshake_traffic_secret",
      "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38", S_HS)

check("rfc8448 server_handshake_key",
      "3fce516009c21727d0f2e4e86ee403bc",
      hkdf_expand_label(S_HS, "key", b"", 16))
check("rfc8448 server_handshake_iv",
      "5d313eb2671276ee13000b30",
      hkdf_expand_label(S_HS, "iv", b"", 12))
check("rfc8448 server_finished_key",
      "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8",
      hkdf_expand_label(S_HS, "finished", b"", 32))

TH_AP = bytes.fromhex(
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
check("rfc8448 client_application_traffic_secret",
      "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
      derive_secret(MASTER, "c ap traffic", TH_AP))
check("rfc8448 exporter_master_secret",
      "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50",
      derive_secret(MASTER, "exp master", TH_AP))


# ---------------------------------------------------------------------------
# RFC 9001 Appendix A.1 -- QUIC Initial secrets from a connection ID.

INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
CLIENT_DCID = bytes.fromhex("8394c8f03e515708")

initial_secret = hkdf_extract(INITIAL_SALT, CLIENT_DCID)
check("rfc9001 initial_secret",
      "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
      initial_secret)

client_initial = hkdf_expand_label(initial_secret, "client in", b"", 32)
check("rfc9001 client_initial_secret",
      "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
      client_initial)
check("rfc9001 client_initial_key",
      "1f369613dd76d5467730efcbe3b1a22d",
      hkdf_expand_label(client_initial, "quic key", b"", 16))
check("rfc9001 client_initial_iv",
      "fa044b2f42a3fd3b46fb255c",
      hkdf_expand_label(client_initial, "quic iv", b"", 12))
check("rfc9001 client_initial_hp",
      "9f50449e04a0e810283a1e9933adedd2",
      hkdf_expand_label(client_initial, "quic hp", b"", 16))

server_initial = hkdf_expand_label(initial_secret, "server in", b"", 32)
check("rfc9001 server_initial_secret",
      "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
      server_initial)
check("rfc9001 server_initial_key",
      "cf3a5331653c364c88f0f379b6067e37",
      hkdf_expand_label(server_initial, "quic key", b"", 16))
check("rfc9001 server_initial_iv",
      "0ac1493ca1905853b0bba03e",
      hkdf_expand_label(server_initial, "quic iv", b"", 12))
check("rfc9001 server_initial_hp",
      "c206b8d9b9f0f37644430b490eeaa314",
      hkdf_expand_label(server_initial, "quic hp", b"", 16))

# The labels themselves, as RFC 9001 Appendix A.1 prints them, byte for byte.
# A wrong length prefix, a missing "tls13 " or a wrong length in the uint16
# still yields plausible output, so the encoded HkdfLabel is compared directly
# for the "client in" case, which is the one the RFC prints in full here.
#
# The remaining labels are exercised through the secrets above: the derived
# keys below agree with the RFC only if every label is encoded exactly right.
def _hkdf_label_bytes(label: str, length: int, context: bytes) -> bytes:
    full = b"tls13 " + label.encode()
    return (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)

check("rfc9001 client_in_hkdf_label_encoding",
      "00200f746c73313320636c69656e7420696e00",
      _hkdf_label_bytes("client in", 32, b""))

# RFC 9001 Appendix A.5 -- a short-header packet under ChaCha20-Poly1305.
APP_SECRET = bytes.fromhex(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
check("rfc9001 chacha20_key",
      "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
      hkdf_expand_label(APP_SECRET, "quic key", b"", 32))
check("rfc9001 chacha20_iv",
      "e0459b3474bdd0e44a41c144",
      hkdf_expand_label(APP_SECRET, "quic iv", b"", 12))
check("rfc9001 chacha20_hp",
      "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
      hkdf_expand_label(APP_SECRET, "quic hp", b"", 32))
check("rfc9001 chacha20_key_update",
      "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
      hkdf_expand_label(APP_SECRET, "quic ku", b"", 32))

# The nonce construction for that packet: iv XOR the packet number, left
# padded to the iv length. This is checked because it is a place where "XOR the
# number in" can be written four subtly different ways.
PN = 654360564
IV = bytes.fromhex("e0459b3474bdd0e44a41c144")
nonce = bytes(a ^ b for a, b in zip(IV, PN.to_bytes(12, "big")))
check("rfc9001 chacha20_nonce", "e0459b3474bdd0e46d417eb0", nonce)


def main() -> int:
    failures = 0
    for name, expected, actual in CHECKS:
        if expected == actual.hex():
            continue
        failures += 1
        print(f"FAIL {name}\n     expected {expected}\n     actual   {actual.hex()}")
    total = len(CHECKS)
    if failures:
        print(f"\n{failures} of {total} published values NOT reproduced")
        return 1
    print(f"oracle: all {total} published RFC values reproduced "
          f"(RFC 8448 key schedule, RFC 9001 QUIC Initial secrets and "
          f"ChaCha20 labels)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

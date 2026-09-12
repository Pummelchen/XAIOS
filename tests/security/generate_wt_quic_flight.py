#!/usr/bin/env python3
"""Generate and self-verify a complete TLS 1.3 QUIC server flight.
The QUIC client in userspace/wt/ must be driven to completion by a flight it did
not compute itself, or the test only checks that the C agrees with the C. This
builds the whole server flight -- and the client-auth variant of it -- with
Python and `cryptography`, an implementation independent of the C, and emits it
as a C header with the secrets and MACs derived from the same transcripts.

    python3 tests/security/generate_wt_quic_flight.py          # re-verify
    python3 tests/security/generate_wt_quic_flight.py --force  # rewrite

Only the CertificateVerify signature is not reproducible (RSA-PSS uses a random
salt), so the default run refuses to rewrite and instead re-derives every value
from the fixed inputs, reporting exactly what disagrees with the committed file.
The x25519 scalars are RFC 7748 section 6.1's Alice and Bob keys, both randoms
are counters, and the certificate is signed by a hardcoded RSA test key that
protects nothing. A CertificateRequest changes the transcript, so the second
variant re-signs and re-MACs everything after it; the client answers it with an
empty Certificate, and its own Finished covers that message (RFC 8446 section
4.4.1, and build_client_flight absorbs it before computing verify_data).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import re
import sys
from pathlib import Path
# Fixed inputs. These are the whole of what makes the fixture reproducible.
CLIENT_PRIVATE = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
SERVER_PRIVATE = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
CLIENT_RANDOM, SERVER_RANDOM = bytes(range(0x20)), bytes(range(0x20, 0x40))
SERVER_TRANSPORT_PARAMETERS, ALPN = bytes.fromhex("0a0b0c0d0e0f"), b"h3"
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"
CIPHER_SUITE, GROUP_X25519, SIG_RSA_PSS_RSAE_SHA256 = 0x1301, 0x001D, 0x0804
# A test RSA-2048 key, pasted as its two primes (the rest is derived, which is
# exact for RSA). It protects nothing: the fixture must verify offline.
RSA_E = 0x10001
RSA_P = int("fa2a55074d8c214394ed7d4c4d8e5c8e707324bc47bebff52f2d47431f544ec18d4a63d4426a3cfd80b71616fd0a34ce7a56279a6fb7acce47b16d11c25ccf951a7d2924583311b01978621e21c5d4dca72efea1783382a4c8e3ac6e970c1783792c87a7823ce6b53b76764b52fa3b4423465e6c9e97b58492a7d0593146e2b7", 16)
RSA_Q = int("d0e54bef4d54abb8bb8188982ef80ffcca1ca1de3e5b4321c2e03b3937bfe29d115f8cfcdc9c9e8852d4016da318738ec085f4fd8c4e7f2ff3f997b615eaf4ae25fd38540db36ec76d79f3bc5d9efb8f56f2e5aacde3a9e7aef3ebe773cb337f2291c1072d0c6dd15b7401f8990b1cfe8538fce6188f307df26bc01a8c813b9f", 16)
RSA_N = RSA_P * RSA_Q
RSA_D = pow(RSA_E, -1, (RSA_P - 1) * (RSA_Q - 1) // __import__("math").gcd(
    RSA_P - 1, RSA_Q - 1))
DEFAULT_OUT = (Path(__file__).resolve().parents[2]
               / "userspace/wt/include/wt_quic_flight_vectors.h")  # committed
# HKDF, copied from the other generators; this script imports none of them.
def h(data): return hashlib.sha256(data).digest()
def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand_label(secret, label, context, length):
    # HkdfLabel is length-prefixed three ways (RFC 8446 section 7.1); a wrong
    full = b"tls13 " + label.encode()
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm, counter = okm + block, counter + 1
    return okm[:length]
def derive_secret(secret, label, th): return hkdf_expand_label(secret, label, th, 32)
def finished_mac(secret, th):
    return hmac.new(hkdf_expand_label(secret, "finished", b"", 32), th,
                    hashlib.sha256).digest()
# x25519 via `cryptography`, which clamps the scalar as RFC 7748 section 5
# requires. The C reverses it for BearSSL and gets the RFC's published keys.
def x25519_public(private):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def x25519_shared(private, peer):
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    return X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(peer))
# Message encoders, mirroring build_extensions in wt_tls_handshake.c byte for
# byte, extension order included; the C test compares the two ClientHellos.
def be(v, w): return v.to_bytes(w, "big")
def vec(d, w): return be(len(d), w) + d
def ext(t, b): return be(t, 2) + vec(b, 2)
def build_client_hello(cp):
    e = ext(0x0000, vec(b"\x00" + vec(b"server", 2), 2))  # server_name
    e += ext(0x000A, vec(be(GROUP_X25519, 2), 2)); e += ext(0x000D, vec(be(0x0804, 2), 2))
    e += ext(0x0010, vec(vec(ALPN, 1), 2)); e += ext(0x002B, b"\x02" + be(0x0304, 2))
    e += ext(0x0033, vec(be(GROUP_X25519, 2) + vec(cp, 2), 2))
    e += ext(0x0039, bytes.fromhex("01020304"))
    b = (be(0x0303, 2) + CLIENT_RANDOM + b"\x00" + vec(be(CIPHER_SUITE, 2), 2)
         + b"\x01\x00" + vec(e, 2))
    return b"\x01" + be(len(b), 3) + b
def build_server_hello(sp):
    e = ext(0x002B, be(0x0304, 2)) + ext(0x0033, be(GROUP_X25519, 2) + vec(sp, 2))
    return b"\x02" + be(40 + len(e), 3) + (be(0x0303, 2) + SERVER_RANDOM
        + b"\x00" + be(CIPHER_SUITE, 2) + b"\x00" + vec(e, 2))
def build_encrypted_extensions():
    # RFC 7301 section 3.1: the server's extension_data is structured exactly
    # like the client's -- a ProtocolNameList -- except that the list contains
    # exactly one name. So it is a two-byte list length around a
    # length-prefixed name, NOT a bare name. The first version of this emitted
    # the bare form, because that is what the C parser of the day accepted; a
    # fixture written to agree with the code under test cannot disagree with
    # it, and that is the one thing this file exists to be able to do.
    e = ext(0x0010, vec(vec(ALPN, 1), 2)) + ext(0x0039, SERVER_TRANSPORT_PARAMETERS)
    return b"\x08" + be(2 + len(e), 3) + vec(e, 2)
def build_certificate(der):
    entries = vec(der, 3) + vec(b"", 2)
    return b"\x0b" + be(4 + len(entries), 3) + b"\x00" + vec(entries, 3)
# The client's answer to a CertificateRequest when it has none.
EMPTY_CERTIFICATE = b"\x0b" + be(6, 3) + b"\x00" + vec(b"", 3) + vec(b"", 2)
# An empty certificate_request_context, so 0d 00 00 03 00 00 00.
CLIENT_AUTH_REQUEST = b"\x0d" + be(3, 3) + b"\x00" + vec(b"", 2)
def build_certificate_verify(sig):
    return b"\x0f" + be(4 + len(sig), 3) + be(SIG_RSA_PSS_RSAE_SHA256, 2) + vec(sig, 2)
def build_finished(mac): return b"\x14" + be(len(mac), 3) + mac
# RFC 8446 section 4.4.3: 64 spaces, the context, a 0x00, the hash.
def verify_content(th): return b"\x20" * 64 + CV_CONTEXT + b"\x00" + th
def rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.RSAPrivateNumbers(
        RSA_P, RSA_Q, RSA_D, RSA_D % (RSA_P - 1), RSA_D % (RSA_Q - 1),
        pow(RSA_Q, -1, RSA_P), rsa.RSAPublicNumbers(RSA_E, RSA_N)).private_key()
def pss():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
def build_leaf_der():
    # Deterministic: X.509 signatures are RSA PKCS#1 v1.5, not randomised.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    key = rsa_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webtransport-test")])
    utc = datetime.timezone.utc
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=utc))
            .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=utc))
            .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.DER)
def sign_transcript(th):
    from cryptography.hazmat.primitives import hashes
    return rsa_key().sign(verify_content(th), pss(), hashes.SHA256())
def key_schedule(ecdhe, t_sh, t_sf):
    early = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
    hs = hkdf_extract(derive_secret(early, "derived", h(b"")), ecdhe)
    master = hkdf_extract(derive_secret(hs, "derived", h(b"")), b"\x00" * 32)
    return {"c_hs": derive_secret(hs, "c hs traffic", t_sh),
            "s_hs": derive_secret(hs, "s hs traffic", t_sh),
            "c_ap": derive_secret(master, "c ap traffic", t_sf),
            "s_ap": derive_secret(master, "s ap traffic", t_sf)}
# `entry` is the CertificateRequest for the client-auth variant, or b"" for the
# plain flight. The client's Finished covers its own Certificate when present.
def build_variant(entry):
    ch = build_client_hello(x25519_public(CLIENT_PRIVATE))
    sh = build_server_hello(x25519_public(SERVER_PRIVATE))
    ee, cert = build_encrypted_extensions(), build_certificate(build_leaf_der())
    ecdhe = x25519_shared(CLIENT_PRIVATE, x25519_public(SERVER_PRIVATE))
    prefix, flight = ch + sh + ee + entry, (EMPTY_CERTIFICATE if entry else b"")
    cv = build_certificate_verify(sign_transcript(h(prefix + cert)))
    fin = build_finished(finished_mac(
        key_schedule(ecdhe, h(ch + sh), b"")["s_hs"], h(prefix + cert + cv)))
    body = prefix + cert + cv + fin
    t_sf = h(body)
    s = key_schedule(ecdhe, h(ch + sh), t_sf)
    # The client's Finished covers the transcript through the server's Finished, plus its own Certificate, not the digest hashed again.
    value = finished_mac(s["c_hs"], h(body + flight) if flight else t_sf)
    return {"CLIENT_PUBLIC": x25519_public(CLIENT_PRIVATE),
            "SERVER_PUBLIC": x25519_public(SERVER_PRIVATE),
            "CLIENT_HELLO": ch, "SERVER_HELLO": sh, "ENCRYPTED_EXTENSIONS": ee,
            "CERTIFICATE": cert, "CERTIFICATE_VERIFY": cv, "FINISHED": fin,
            "CLIENT_FINISHED": value,
            "CLIENT_AUTH_FLIGHT": flight + build_finished(value),
            "CLIENT_HANDSHAKE_SECRET": s["c_hs"],
            "SERVER_HANDSHAKE_SECRET": s["s_hs"],
            "CLIENT_APPLICATION_SECRET": s["c_ap"],
            "SERVER_APPLICATION_SECRET": s["s_ap"]}
def build_values():
    v, auth = build_variant(b""), build_variant(CLIENT_AUTH_REQUEST)
    v.update({"CLIENT_PRIVATE": CLIENT_PRIVATE, "SERVER_PRIVATE": SERVER_PRIVATE,
              "CLIENT_AUTH_REQUEST": CLIENT_AUTH_REQUEST,
              "CLIENT_AUTH_CERTIFICATE_VERIFY": auth["CERTIFICATE_VERIFY"],
              "CLIENT_AUTH_FINISHED": auth["FINISHED"],
              "CLIENT_AUTH_FINISHED_VALUE": auth["CLIENT_FINISHED"],
              "CLIENT_AUTH_FLIGHT": auth["CLIENT_AUTH_FLIGHT"],
              "SERVER_TRANSPORT_PARAMETERS": SERVER_TRANSPORT_PARAMETERS,
              "SERVER_ALPN": ALPN, "CERT_MODULUS_HEX": format(RSA_N, "x")})
    return v
# (name, fixed length or None, comment) in file order, shared by both users.
BLOCKS = [
    ("CLIENT_PRIVATE", 32, "The client x25519 private key, RFC 7748 section 6.1's Alice scalar, which wt_tls_client_start clamps in the ladder."), ("CLIENT_PUBLIC", 32, "The public key derived from it, used as the ClientHello key share."),
    ("SERVER_PRIVATE", 32, "The server x25519 private key, RFC 7748 section 6.1's Bob scalar; the ECDHE secret is over this pair."), ("SERVER_PUBLIC", 32, "The public key derived from it; ServerHello's key_share must carry these bytes, which re-verification checks."),
    ("CLIENT_HELLO", None, "The complete ClientHello this client's builder produces, type || uint24 length || body: random 00..1f, empty legacy_session_id, cipher suite 0x1301, group 0x001d, signature algorithm 0x0804, ALPN h3 and the client key share."), ("SERVER_HELLO", None, "The complete ServerHello: random 20..3f, cipher suite 0x1301, an empty legacy_session_id echo, supported_versions 0x0304 and the server key share."),
    ("ENCRYPTED_EXTENSIONS", None, "The complete EncryptedExtensions, carrying ALPN h3 and the server's QUIC transport parameters and nothing else."), ("CERTIFICATE", None, "The complete Certificate: an empty certificate_request_context, one CertificateEntry holding the self-signed leaf DER and an empty extension block. The client takes entry one as the leaf."),
    ("CERTIFICATE_VERIFY", None, "The complete CertificateVerify, scheme 0x0804 (rsa_pss_rsae_sha256), over 64 spaces || \"TLS 1.3, server CertificateVerify\" || 0x00 || hash through Certificate."), ("CLIENT_AUTH_REQUEST", None, "The complete CertificateRequest for the client-auth variant: empty context and empty extensions, so 0d 00 00 03 00 00 00. It changes the transcript after it."),
    ("CLIENT_AUTH_CERTIFICATE_VERIFY", None, "The same certificate re-signing the transcript that now includes the CertificateRequest."), ("FINISHED", None, "The complete server Finished for the plain flight: the 32-byte MAC inside a Finished message."),
    ("CLIENT_AUTH_FINISHED", None, "The complete server Finished for the client-auth variant, over the transcript that includes the CertificateRequest."), ("CLIENT_FINISHED", 32, "The verify_data the CLIENT must produce for the plain flight: an HMAC with the client handshake traffic secret over the transcript through the server's Finished. Not a message."),
    ("CLIENT_AUTH_FINISHED_VALUE", 32, "The client's verify_data for the client-auth variant; it additionally covers the client's own empty Certificate, which build_client_flight absorbs before MACing."), ("CLIENT_AUTH_FLIGHT", None, "The complete 46-byte flight the client sends in the client-auth variant: the empty Certificate (zero-length context, empty certificate_list, empty extensions) then the Finished 14 00 00 20 || the value above."),
    ("CLIENT_HANDSHAKE_SECRET", 32, "RFC 8446 c hs traffic, over the transcript through ServerHello."), ("SERVER_HANDSHAKE_SECRET", 32, "RFC 8446 s hs traffic, over the transcript through ServerHello."),
    ("CLIENT_APPLICATION_SECRET", 32, "RFC 8446 c ap traffic, over the transcript through the server's Finished."), ("SERVER_APPLICATION_SECRET", 32, "RFC 8446 s ap traffic, over the transcript through the server's Finished."),
    ("SERVER_TRANSPORT_PARAMETERS", 6, "The bytes the server's quic_transport_parameters extension carries, so a test can compare what wt_tls_client_peer_transport_parameters reports."), ("SERVER_ALPN", 2, "The ALPN protocol the server selected, so a test can compare what wt_tls_client_alpn reports."),
]
PREAMBLE = '''/* Generated by tests/security/generate_wt_quic_flight.py -- do not edit.
 *
 * A complete TLS 1.3 server flight for the QUIC client in userspace/wt/, with
 * the secrets and MACs derived from it. Every value was computed by Python and
 * the `cryptography` package, independently of the C under test.
 *
 * The CertificateVerify signature is RSA-PSS and so is not reproducible.
 * Re-verify: python3 tests/security/generate_wt_quic_flight.py
 * Rewrite:   python3 tests/security/generate_wt_quic_flight.py --force
 */
#ifndef WT_QUIC_FLIGHT_VECTORS_H
#define WT_QUIC_FLIGHT_VECTORS_H
#include <stdint.h>
'''
def block(name, data, comment, fixed):
    macro = "" if fixed else f"#define WT_QUIC_FLIGHT_{name}_LEN {len(data)}\n"
    size = f"[{fixed}]" if fixed else f"[WT_QUIC_FLIGHT_{name}_LEN]"
    body = ",\n".join("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 10])
                      for i in range(0, len(data), 10))
    return (f"/* {comment} */\n{macro}static const uint8_t WT_QUIC_FLIGHT_"
            f"{name}{size} = {{\n{body}\n}};\n\n")
def render_header(v):
    modulus = v["CERT_MODULUS_HEX"]
    return "".join([PREAMBLE] + [block(n, v[n], c, f) for n, f, c in BLOCKS] + [
        "/* The leaf certificate's RSA modulus as lowercase hex with no leading\n"
        "   zero byte, so a test can pin the key the CertificateVerify signature\n"
        "   is checked against. */\n"
        f"static const char WT_QUIC_FLIGHT_CERT_MODULUS_HEX[{len(modulus) + 1}]"
        f' = "{modulus}";\n\n#endif /* WT_QUIC_FLIGHT_VECTORS_H */\n'])

ARRAY_RE = re.compile(r"uint8_t (WT_QUIC_FLIGHT_\w+)\[\w*\] = \{(.*?)\};", re.S)
def parse_header(text):
    values = {m.group(1)[len("WT_QUIC_FLIGHT_"):]:
              bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(2)))
              for m in ARRAY_RE.finditer(text)}
    values["CERT_MODULUS_HEX"] = re.search(r'CERT_MODULUS_HEX\[\d+\] = "(\w+)"',
                                           text).group(1)
    return values
def extension_map(exts):
    out, offset = {}, 0
    while offset < len(exts):
        n = int.from_bytes(exts[offset + 2:offset + 4], "big")
        out[int.from_bytes(exts[offset:offset + 2], "big")] = exts[offset + 4:offset + 4 + n]
        offset += 4 + n
    return out

def verify(v):
    bad = []

    def eq(name, expected, actual):
        if expected != actual:
            bad.append(f"{name}: expected {expected.hex()} got {actual.hex()}")

    ch, sh, ee = v["CLIENT_HELLO"], v["SERVER_HELLO"], v["ENCRYPTED_EXTENSIONS"]
    cert, cr = v["CERTIFICATE"], v["CLIENT_AUTH_REQUEST"]
    cv, fin = v["CERTIFICATE_VERIFY"], v["FINISHED"]
    cv2, fin2 = v["CLIENT_AUTH_CERTIFICATE_VERIFY"], v["CLIENT_AUTH_FINISHED"]
    cp, sp = x25519_public(v["CLIENT_PRIVATE"]), x25519_public(v["SERVER_PRIVATE"])
    # A message is type || uint24 length || body; the length must describe it.
    for name in ("CLIENT_HELLO", "SERVER_HELLO", "ENCRYPTED_EXTENSIONS",
                 "CERTIFICATE", "CERTIFICATE_VERIFY", "CLIENT_AUTH_REQUEST",
                 "FINISHED", "CLIENT_AUTH_FINISHED"):
        if int.from_bytes(v[name][1:4], "big") != len(v[name]) - 4:
            bad.append(f"{name}: the length field does not describe the message")
    eq("CLIENT_PRIVATE", CLIENT_PRIVATE, v["CLIENT_PRIVATE"]); eq("SERVER_PRIVATE", SERVER_PRIVATE, v["SERVER_PRIVATE"])
    eq("CLIENT_PUBLIC", cp, v["CLIENT_PUBLIC"]); eq("SERVER_PUBLIC", sp, v["SERVER_PUBLIC"])
    eq("CLIENT_HELLO", build_client_hello(cp), ch); eq("SERVER_HELLO", build_server_hello(sp), sh)
    eq("ENCRYPTED_EXTENSIONS", build_encrypted_extensions(), ee); eq("CLIENT_AUTH_REQUEST", CLIENT_AUTH_REQUEST, cr)
    # The ServerHello key_share must be the committed server public key.
    at = 4 + 2 + 32
    at += 1 + sh[at] + 2 + 1 + 2
    eq("SERVER_HELLO key_share", sp,
       extension_map(sh[at:]).get(0x0033, b"\x00" * 4)[4:])
    # modulus must be the pinned hex; cryptography parses the DER on its own.
    at = 4 + 1 + cert[4] + 3
    der = cert[at + 3:at + 3 + int.from_bytes(cert[at:at + 3], "big")]
    eq("CERTIFICATE", build_certificate(build_leaf_der()), cert)
    if (v["CERT_MODULUS_HEX"] != format(RSA_N, "x")
            or len(v["CERT_MODULUS_HEX"]) % 2 or v["CERT_MODULUS_HEX"][:2] == "00"):
        bad.append("CERT_MODULUS_HEX: not the test key's modulus")
    try:
        from cryptography import x509
        leaf = x509.load_der_x509_certificate(der).public_key()
    except Exception as error:  # noqa: BLE001 - the reason is the report
        bad.append(f"CERTIFICATE DER: cryptography cannot parse it: {error}")
        return bad
    exts = extension_map(ee[6:])
    eq("SERVER_TRANSPORT_PARAMETERS", v["SERVER_TRANSPORT_PARAMETERS"],
       exts.get(0x0039, b""))
    alpn = exts.get(0x0010, b"")
    # Unwrap the ProtocolNameList by hand rather than by slicing, so a
    # malformed one is reported instead of silently compared: two bytes of
    # list length that must account for the rest, then one length-prefixed
    # name that must account for the list.
    if len(alpn) < 4 or be(int.from_bytes(alpn[0:2], "big"), 2) != alpn[0:2] \
            or int.from_bytes(alpn[0:2], "big") != len(alpn) - 2 \
            or alpn[2] != len(alpn) - 3 or alpn[2] == 0:
        bad.append(f"SERVER_ALPN: not a single-name ProtocolNameList: "
                   f"{alpn.hex()}")
    else:
        eq("SERVER_ALPN", v["SERVER_ALPN"], alpn[3:])
    t_sh, t_cert = h(ch + sh), h(ch + sh + ee + cert); t_cv = h(ch + sh + ee + cert + cv)
    body = ch + sh + ee + cert + cv + fin
    s = key_schedule(x25519_shared(v["CLIENT_PRIVATE"], v["SERVER_PUBLIC"]), t_sh,
                     h(body))
    eq("CLIENT_HANDSHAKE_SECRET", s["c_hs"], v["CLIENT_HANDSHAKE_SECRET"]); eq("SERVER_HANDSHAKE_SECRET", s["s_hs"], v["SERVER_HANDSHAKE_SECRET"])
    eq("CLIENT_APPLICATION_SECRET", s["c_ap"], v["CLIENT_APPLICATION_SECRET"]); eq("SERVER_APPLICATION_SECRET", s["s_ap"], v["SERVER_APPLICATION_SECRET"])
    eq("FINISHED", build_finished(finished_mac(s["s_hs"], t_cv)), fin); eq("CLIENT_FINISHED", finished_mac(s["c_hs"], h(body)), v["CLIENT_FINISHED"])
    # Client-auth: the CertificateRequest changes the transcript, so both MACs change.
    t2_cert, t2_cv = h(ch + sh + ee + cr + cert), h(ch + sh + ee + cr + cert + cv2)
    body2 = ch + sh + ee + cr + cert + cv2 + fin2
    eq("CLIENT_AUTH_FINISHED", build_finished(finished_mac(s["s_hs"], t2_cv)), fin2)
    auth = finished_mac(s["c_hs"], h(body2 + EMPTY_CERTIFICATE))
    eq("CLIENT_AUTH_FINISHED_VALUE", auth, v["CLIENT_AUTH_FINISHED_VALUE"])
    eq("CLIENT_AUTH_FLIGHT", EMPTY_CERTIFICATE + build_finished(auth),
       v["CLIENT_AUTH_FLIGHT"])
    if len(v["CLIENT_AUTH_FLIGHT"]) != 46:
        bad.append(f"CLIENT_AUTH_FLIGHT: {len(v['CLIENT_AUTH_FLIGHT'])} bytes, "
                   f"expected 46")
    if auth == v["CLIENT_FINISHED"]:
        bad.append("CLIENT_AUTH_FINISHED_VALUE: equals the plain client Finished, "
                   "so the client-auth transcript was not used")
    # Both signatures, verified with `cryptography`, not the C's BearSSL.
    from cryptography.hazmat.primitives import hashes
    for name, message, transcript in (("CERTIFICATE_VERIFY", cv, t_cert),
                                      ("CLIENT_AUTH_CERTIFICATE_VERIFY", cv2, t2_cert)):
        scheme = int.from_bytes(message[4:6], "big")
        sig = message[8:8 + int.from_bytes(message[6:8], "big")]
        if scheme != SIG_RSA_PSS_RSAE_SHA256:
            bad.append(f"{name} scheme: {scheme:#06x}")
        try:
            leaf.verify(sig, verify_content(transcript), pss(), hashes.SHA256())
        except Exception as error:  # noqa: BLE001 - the reason is the report
            bad.append(f"{name} signature did not verify ({type(error).__name__})")
    return bad

def main():
    parser = argparse.ArgumentParser(description="TLS 1.3 QUIC server flight")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--force", action="store_true", help="rewrite the header")
    args = parser.parse_args()
    if args.force:
        text = render_header(build_values())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"wt_quic_flight: wrote {len(text.encode('utf-8'))} bytes of fixture")
    elif not args.out.exists():
        print(f"wt_quic_flight: no fixture at {args.out}; run --force to create it",
              file=sys.stderr)
        return 1
    bad = verify(parse_header(args.out.read_text(encoding="utf-8")))
    if bad:
        for line in bad:
            print(f"wt_quic_flight: {line}", file=sys.stderr)
        print(f"wt_quic_flight: {len(bad)} disagreement(s)", file=sys.stderr)
        return 1
    print("wt_quic_flight: committed fixture re-verified (certificate, "
          "CertificateVerify, server Finished, client Finished, client-auth variant)")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())

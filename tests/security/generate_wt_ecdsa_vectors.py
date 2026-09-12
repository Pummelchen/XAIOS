#!/usr/bin/env python3
"""Generate and re-verify the ECDSA-P256 CertificateVerify fixture.

`cryptography` produces the certificate, point and signature and BearSSL checks
them, so the two sides are independent. The committed fixture is re-verified by
default and only rewritten with --force, because ECDSA signing draws a random
nonce and a rewrite gives a different but equally valid signature every run. The
private key is RFC 6979 A.2.5's published P-256 test key: it protects nothing
and must never be used for anything else.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Anchored to this file, not the caller's cwd, because the script is run by hand.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT = REPO_ROOT / "userspace" / "wt" / "include" / "wt_ecdsa_vectors.h"

# A fixed scalar is what makes the public point, and so the committed
# WT_ECDSA_POINT, reproducible across runs; only the signature is randomized.
TEST_PRIVATE_SCALAR = int(
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)

# RFC 8446 section 4.4.3: 64 spaces, the context string, 0x00, then the
# transcript hash. The hash is a placeholder ramp because both sides only have
# to agree on the bytes; a recognizable ramp reads better in a diff than 32
# opaque bytes.
CONTENT = (b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"
           + bytes(range(32)))
assert len(CONTENT) == 130, "the signed content must be exactly 130 bytes"

def c_array(data: bytes, per_line: int = 10) -> str:
    """A C initialiser for `data`, as wt_rfc8448_vectors.h lays one out."""
    return ",\n".join("    " + ", ".join(f"0x{b:02x}" for b in data[o:o + per_line])
                      for o in range(0, len(data), per_line))

def read_array(header: str, name: str) -> bytes:
    """The bytes of `NAME` from a header this script wrote.

    Deliberately dull, because the input has a shape fixed below. `NAME_LEN` is
    checked against what was read: a truncated array still parses, so it would
    otherwise pass unnoticed.
    """
    marker = "#define %s_LEN " % name
    start = header.index(marker) + len(marker)
    declared = int(header[start:header.index("\n", start)].strip())
    opens = header.index("static const uint8_t %s[%s_LEN] = {" % (name, name))
    body = header[header.index("{", opens) + 1:header.index("};", opens)]
    values = [int(token, 16) for token in body.replace(",", " ").split()]
    if len(values) != declared:
        raise ValueError("%s_LEN says %d, the array holds %d"
                         % (name, declared, len(values)))
    return bytes(values)

def build_fixture() -> "tuple[bytes, bytes, bytes, bytes]":
    """A fresh (certificate DER, point, content, signature) from `cryptography`."""
    private_key = ec.derive_private_key(TEST_PRIVATE_SCALAR, ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    point = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webtransport-test")])
    # Self-signed and a leaf: the verifier never consults a trust store, so a
    # chain would add bytes without coverage. The dates span 2020-2100.
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(private_key.public_key())
                   .serial_number(0x0102030405060708)
                   .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                   .not_valid_after(datetime(2100, 1, 1, tzinfo=timezone.utc))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                                  critical=True)
                   .sign(private_key, hashes.SHA256()))
    # `sign` hashes the content itself; it does not take a digest. BearSSL
    # expects that: it hashes these same bytes and passes the digest to
    # br_ecdsa_i31_vrfy_asn1.
    signature = private_key.sign(CONTENT, ec.ECDSA(hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)
    return der, point, CONTENT, signature

def verify_fixture(cert_der: bytes, point: bytes, content: bytes,
                   signature: bytes) -> "list[str]":
    """Complaints about it; every check runs in `cryptography`, not BearSSL."""
    try:
        public_key = x509.load_der_x509_certificate(cert_der).public_key()
    except Exception as error:  # any parse failure is a refusal, not a pass
        return ["the certificate or its public key does not parse: %s" % error]
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return ["the certificate's key is not an EC key"]
    if not isinstance(public_key.curve, ec.SECP256R1):
        return ["the curve is %s, not secp256r1" % public_key.curve.name]
    numbers = public_key.public_numbers()
    expected = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    if expected != point:
        return ["WT_ECDSA_POINT is %s, the certificate's point is %s"
                % (point.hex(), expected.hex())]
    try:
        public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return ["WT_ECDSA_SIGNATURE does not verify over WT_ECDSA_CONTENT"]
    return []

HEADER = """/* Generated by tests/security/generate_wt_ecdsa_vectors.py -- do not edit.
 *
 * An ECDSA-P256-SHA256 CertificateVerify fixture for test_wt_tls_cert.c. It is
 * NOT from any RFC: the traces this repository otherwise uses carry RSA keys,
 * so no published P-256 transcript exists to copy. The certificate, point and
 * signature were produced by the Python `cryptography` package and its output
 * is committed here, so the test runs offline.
 *
 * The committed fixture is NOT regenerated on each run, because ECDSA signing
 * draws a random nonce and every run would produce a different but equally
 * valid signature; the default invocation re-verifies these bytes and --force
 * rewrites them. That re-verification uses `cryptography`, an independent
 * implementation from the code under test (BearSSL's br_ecdsa_i31_vrfy_asn1),
 * so the fixture is cross-checked rather than confirmed by the same opinion
 * twice.
 *
 * THE PRIVATE KEY BEHIND THIS FIXTURE IS A TEST KEY. It protects nothing and
 * must never be used for anything. WT_ECDSA_CONTENT is RFC 8446 section 4.4.3's
 * signed content (64 spaces, context string, 0x00) plus a placeholder
 * transcript hash 00 01 .. 1f; the real hash comes from the handshake.
 */

#ifndef WT_ECDSA_VECTORS_H
#define WT_ECDSA_VECTORS_H

#include <stdint.h>

/* The self-signed leaf, DER, subject and issuer CN=webtransport-test. */
#define WT_ECDSA_CERT_LEN {cert_len}
static const uint8_t WT_ECDSA_CERT[WT_ECDSA_CERT_LEN] = {{
{cert}
}};
/* Exactly the 130 bytes a server CertificateVerify signs. */
#define WT_ECDSA_CONTENT_LEN {content_len}
static const uint8_t WT_ECDSA_CONTENT[WT_ECDSA_CONTENT_LEN] = {{
{content}
}};
/* The ASN.1 DER ECDSA-Sig-Value, beginning 0x30 (SEQUENCE), the form
   br_ecdsa_i31_vrfy_asn1 requires. */
#define WT_ECDSA_SIGNATURE_LEN {signature_len}
static const uint8_t WT_ECDSA_SIGNATURE[WT_ECDSA_SIGNATURE_LEN] = {{
{signature}
}};
/* The certificate's public key as RFC 5480 section 2.2 encodes it: the
   uncompressed point 0x04 || X || Y, 65 bytes for P-256. */
#define WT_ECDSA_POINT_LEN {point_len}
static const uint8_t WT_ECDSA_POINT[WT_ECDSA_POINT_LEN] = {{
{point}
}};

#endif /* WT_ECDSA_VECTORS_H */
"""

def main() -> int:
    parser = argparse.ArgumentParser(description="see the module docstring")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    generated = args.force or not args.out.exists()
    if generated:
        cert_der, point, content, signature = build_fixture()
        text = HEADER.format(cert_len=len(cert_der), cert=c_array(cert_der),
                             content_len=len(content), content=c_array(content),
                             signature_len=len(signature), signature=c_array(signature),
                             point_len=len(point), point=c_array(point))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print("wt_ecdsa_vectors: wrote %d bytes of fixture"
              % len(text.encode("utf-8")))
    # Read the file back; the re-read catches a rendering bug the first would not.
    try:
        header = args.out.read_text(encoding="utf-8")
        problems = verify_fixture(read_array(header, "WT_ECDSA_CERT"),
                                  read_array(header, "WT_ECDSA_POINT"),
                                  read_array(header, "WT_ECDSA_CONTENT"),
                                  read_array(header, "WT_ECDSA_SIGNATURE"))
    except (ValueError, IndexError) as error:
        print("wt_ecdsa_vectors: header unreadable: %s" % error, file=sys.stderr)
        return 1
    if problems:
        print("wt_ecdsa_vectors: " + "; ".join(problems), file=sys.stderr)
        return 1
    if not generated:
        print("wt_ecdsa_vectors: committed fixture re-verified (certificate, "
              "point and signature agree)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

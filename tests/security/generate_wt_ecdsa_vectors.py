#!/usr/bin/env python3
"""Generate and re-verify the ECDSA CertificateVerify fixtures.

Three curves, because the verifier has three ECDSA branches and two of them had
never seen a real certificate (B-90): a P-256 scheme answered by a P-256 key was
tested, and so was a P-384 scheme *refused* against a P-256 key, but nothing had
ever put a secp384r1 or secp521r1 certificate through
`br_ecdsa_i31_vrfy_asn1`. The branch that runs a longer curve is the one a
signature verifier must not leave untested.

`cryptography` produces the certificates, points and signatures and BearSSL
checks them, so the two sides are independent. The committed fixtures are
re-verified by default and only rewritten with --force, because ECDSA signing
draws a random nonce and a rewrite gives a different but equally valid signature
every run. The private keys are RFC 6979's published test keys for A.2.5, A.2.6
and A.2.7: they protect nothing and must never be used for anything else.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Curve:
    """One verifier branch and the published test key that exercises it."""

    prefix: str          # the C names this curve's fixture is emitted under
    label: str           # what the prose calls it
    curve: ec.EllipticCurve
    digest: hashes.HashAlgorithm
    scalar: str          # RFC 6979's x, hex
    coordinate: int      # bytes per coordinate in the uncompressed point


# A fixed scalar is what makes the public point, and so the committed points,
# reproducible across runs; only the signature is randomized.
CURVES = (
    Curve("WT_ECDSA", "P-256", ec.SECP256R1(), hashes.SHA256(),
          "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 32),
    Curve("WT_ECDSA_P384", "P-384", ec.SECP384R1(), hashes.SHA384(),
          "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
          "96D5724E4C70A825F872C9EA60D2EDF5", 48),
    Curve("WT_ECDSA_P521", "P-521", ec.SECP521R1(), hashes.SHA512(),
          # 131 hex digits, not 132: 521 bits is ceiling(521/4) digits, and
          # the value is quoted exactly as RFC 6979 A.2.7 wraps it.
          "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
          "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
          "538", 66),
)

# RFC 8446 section 4.4.3: 64 spaces, the context string, 0x00, then the
# transcript hash. The hash is the fixed ramp 00 01 .. 1f, because this fixture
# signs given bytes rather than a handshake: both sides only have to agree on
# them, and a recognizable ramp reads better in a diff than 32 opaque bytes.
# The signed content is the same 130 bytes for every curve -- only the digest
# the signature is computed over differs -- so it is emitted once.
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


def build_fixture(spec: Curve) -> "tuple[bytes, bytes, bytes, bytes]":
    """A fresh (certificate DER, point, content, signature) from `cryptography`."""
    private_key = ec.derive_private_key(int(spec.scalar, 16), spec.curve)
    numbers = private_key.public_key().public_numbers()
    point = (b"\x04" + numbers.x.to_bytes(spec.coordinate, "big")
             + numbers.y.to_bytes(spec.coordinate, "big"))
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
                   .sign(private_key, spec.digest))
    # `sign` hashes the content itself; it does not take a digest. BearSSL
    # expects that: it hashes these same bytes and passes the digest to
    # br_ecdsa_i31_vrfy_asn1. The digest differs per curve, which is the point.
    signature = private_key.sign(CONTENT, ec.ECDSA(spec.digest))
    der = certificate.public_bytes(serialization.Encoding.DER)
    return der, point, CONTENT, signature


def verify_fixture(spec: Curve, cert_der: bytes, point: bytes, content: bytes,
                   signature: bytes) -> "list[str]":
    """Complaints about it; every check runs in `cryptography`, not BearSSL."""
    try:
        public_key = x509.load_der_x509_certificate(cert_der).public_key()
    except Exception as error:  # any parse failure is a refusal, not a pass
        return ["the certificate or its public key does not parse: %s" % error]
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return ["the certificate's key is not an EC key"]
    if not isinstance(public_key.curve, type(spec.curve)):
        return ["the curve is %s, not %s" % (public_key.curve.name, spec.label)]
    numbers = public_key.public_numbers()
    expected = (b"\x04" + numbers.x.to_bytes(spec.coordinate, "big")
                + numbers.y.to_bytes(spec.coordinate, "big"))
    if expected != point:
        return ["%s_POINT is %s, the certificate's point is %s"
                % (spec.prefix, point.hex(), expected.hex())]
    try:
        public_key.verify(signature, content, ec.ECDSA(spec.digest))
    except InvalidSignature:
        return ["%s_SIGNATURE does not verify over WT_ECDSA_CONTENT" % spec.prefix]
    if content != CONTENT:
        return ["%s signs %d bytes, not the %d of WT_ECDSA_CONTENT"
                % (spec.prefix, len(content), len(CONTENT))]
    return []


PREAMBLE = """/* Generated by tests/security/generate_wt_ecdsa_vectors.py -- do not edit.
 *
 * Three ECDSA CertificateVerify fixtures for test_wt_tls_cert.c, one per curve
 * the verifier has a branch for: P-256/SHA-256, P-384/SHA-384 and
 * P-521/SHA-512. None is from any RFC: the traces this repository otherwise
 * uses carry RSA keys, so no published transcript exists to copy. The
 * certificates, points and signatures were produced by the Python
 * `cryptography` package and their output is committed here, so the tests run
 * offline.
 *
 * Two branches and why they are here. Until these existed the verifier had seen
 * a P-256 key accept a P-256 scheme and a P-256 key *refuse* a P-384 one, and
 * nothing else: no secp384r1 or secp521r1 multiplication had ever run, and an
 * untested branch in a signature verifier is the one place not to leave one
 * (B-90). The curve check that refuses a mismatched scheme is still worth
 * having, and these do not replace it -- they exercise the longer curves as
 * well as the refusal.
 *
 * The committed fixtures are NOT regenerated on each run, because ECDSA signing
 * draws a random nonce and every run would produce a different but equally
 * valid signature; the default invocation re-verifies these bytes and --force
 * rewrites them. That re-verification uses `cryptography`, an independent
 * implementation from the code under test (BearSSL's br_ecdsa_i31_vrfy_asn1),
 * so each fixture is cross-checked rather than confirmed by the same opinion
 * twice.
 *
 * THE PRIVATE KEYS BEHIND THESE FIXTURES ARE RFC 6979'S PUBLISHED TEST KEYS,
 * from A.2.5, A.2.6 and A.2.7. They protect nothing and must never be used for
 * anything. WT_ECDSA_CONTENT is RFC 8446 section 4.4.3's signed content (64
 * spaces, context string, 0x00) plus the fixed ramp 00 01 .. 1f where a
 * transcript hash goes; these fixtures sign given bytes rather than a
 * handshake, and the real hash comes from the handshake. The content is the
 * same 130 bytes for all three curves, so it is emitted once.
 */

#ifndef WT_ECDSA_VECTORS_H
#define WT_ECDSA_VECTORS_H

#include <stdint.h>

/* Exactly the 130 bytes a server CertificateVerify signs. Shared: the curves
   differ in the digest taken over these bytes, not in the bytes. */
#define WT_ECDSA_CONTENT_LEN {content_len}
static const uint8_t WT_ECDSA_CONTENT[WT_ECDSA_CONTENT_LEN] = {{
{content}
}};
"""

SECTION = """
/* {label}: {coord}-byte coordinates, {digest} digest. The self-signed leaf is
   DER, subject and issuer CN=webtransport-test. */
#define {p}_CERT_LEN {cert_len}
static const uint8_t {p}_CERT[{p}_CERT_LEN] = {{
{cert}
}};
/* The ASN.1 DER ECDSA-Sig-Value, beginning 0x30 (SEQUENCE), the form
   br_ecdsa_i31_vrfy_asn1 requires. */
#define {p}_SIGNATURE_LEN {signature_len}
static const uint8_t {p}_SIGNATURE[{p}_SIGNATURE_LEN] = {{
{signature}
}};
/* The certificate's public key as RFC 5480 section 2.2 encodes it: the
   uncompressed point 0x04 || X || Y, {point_len} bytes for {label}. */
#define {p}_POINT_LEN {point_len}
static const uint8_t {p}_POINT[{p}_POINT_LEN] = {{
{point}
}};
"""

FOOTER = """
#endif /* WT_ECDSA_VECTORS_H */
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="see the module docstring")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    generated = args.force or not args.out.exists()
    if generated:
        text = PREAMBLE.format(content_len=len(CONTENT), content=c_array(CONTENT))
        for spec in CURVES:
            cert_der, point, _content, signature = build_fixture(spec)
            text += SECTION.format(p=spec.prefix, label=spec.label,
                                   coord=spec.coordinate,
                                   digest=spec.digest.name.replace("sha", "SHA-"),
                                   cert_len=len(cert_der), cert=c_array(cert_der),
                                   signature_len=len(signature),
                                   signature=c_array(signature),
                                   point_len=len(point), point=c_array(point))
        text += FOOTER
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print("wt_ecdsa_vectors: wrote %d bytes of fixture"
              % len(text.encode("utf-8")))
    # Read the file back; the re-read catches a rendering bug the first would not.
    try:
        header = args.out.read_text(encoding="utf-8")
        problems: "list[str]" = []
        content = read_array(header, "WT_ECDSA_CONTENT")
        for spec in CURVES:
            problems += verify_fixture(spec,
                                       read_array(header, "%s_CERT" % spec.prefix),
                                       read_array(header, "%s_POINT" % spec.prefix),
                                       content,
                                       read_array(header, "%s_SIGNATURE" % spec.prefix))
    except (ValueError, IndexError) as error:
        print("wt_ecdsa_vectors: header unreadable: %s" % error, file=sys.stderr)
        return 1
    if problems:
        print("wt_ecdsa_vectors: " + "; ".join(problems), file=sys.stderr)
        return 1
    if not generated:
        print("wt_ecdsa_vectors: committed fixtures re-verified (%d curves: "
              "certificate, point and signature agree)" % len(CURVES))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

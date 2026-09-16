#!/usr/bin/env python3
"""Write the WebTransport peer's DER identity, and re-verify it.

The handshake gate needs a certificate and its private key as *DER files*,
because the peer is a C program that hands DER views straight to the library --
and, on the guest side, the client pins the certificate's SHA-256 before the
first packet, so the identity cannot be generated at run time.

The key material is the repository's existing throwaway pair from
`tests/fixtures/xapt-tls-cert.pem` and `xapt-tls-key.pem`, converted here rather
than replaced. That means no new private key enters the repository, and the
README beside them already says what they are: disposable, public, and never to
be used for anything real.

Run without arguments to re-verify what is committed. The check is that the
certificate and the key are a pair and that the DER on disk is that pair; a
fixture that had drifted from its PEM source would otherwise only be found by a
failing handshake on a booted machine.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
PEM_CERT = FIXTURES / "xapt-tls-cert.pem"
PEM_KEY = FIXTURES / "xapt-tls-key.pem"
DER_CERT = FIXTURES / "wt-peer-cert.der"
DER_KEY = FIXTURES / "wt-peer-key.der"


def load_source() -> tuple[bytes, bytes, rsa.RSAPrivateKey, bytes]:
    certificate = x509.load_pem_x509_certificate(PEM_CERT.read_bytes())
    key = serialization.load_pem_private_key(PEM_KEY.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SystemExit("tests/fixtures/xapt-tls-key.pem is not an RSA key")
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # The two halves must be a pair, or the peer would offer a certificate it
    # cannot sign for and every handshake would fail at CertificateVerify.
    cert_public = certificate.public_key().public_numbers()
    key_public = key.public_key().public_numbers()
    if cert_public != key_public:
        raise SystemExit("the PEM certificate and key are not a pair")
    return cert_der, key_der, key, cert_der


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="rewrite the DER files even if they match")
    args = parser.parse_args()

    cert_der, key_der, key, _ = load_source()

    # BearSSL's RSA signing uses the CRT parameters, so a key without them is a
    # key the peer cannot sign with. `openssl req -newkey` always emits them;
    # this is the assertion that the fixture still does.
    numbers = key.private_numbers()
    if numbers.p is None or numbers.q is None:
        raise SystemExit("the key carries no CRT parameters; it cannot sign")

    fingerprint = hashlib.sha256(cert_der).hexdigest()
    problems: list[str] = []
    if DER_CERT.exists() and not args.force:
        if DER_CERT.read_bytes() != cert_der:
            problems.append("wt-peer-cert.der does not match the PEM certificate")
    if DER_KEY.exists() and not args.force:
        if DER_KEY.read_bytes() != key_der:
            problems.append("wt-peer-key.der does not match the PEM private key")

    if problems:
        for problem in problems:
            print("error: " + problem, file=sys.stderr)
        print("rerun with --force to rewrite the fixtures", file=sys.stderr)
        return 1

    if args.force or not DER_CERT.exists() or not DER_KEY.exists():
        DER_CERT.write_bytes(cert_der)
        DER_KEY.write_bytes(key_der)
        print("wrote %s (%d bytes)" % (DER_CERT.relative_to(REPO_ROOT), len(cert_der)))
        print("wrote %s (%d bytes)" % (DER_KEY.relative_to(REPO_ROOT), len(key_der)))

    print("wt-peer-identity: certificate sha256=%s" % fingerprint)
    print("wt-peer-identity: %d-byte certificate, %d-byte PKCS#8 key, a pair"
          % (len(cert_der), len(key_der)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

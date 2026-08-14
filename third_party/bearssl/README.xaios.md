# BearSSL in XAIOS

This directory vendors BearSSL for the `xapt` TLS 1.2 client. The source is
upstream BearSSL at the revision recorded in `UPSTREAM_COMMIT`; its MIT license
is preserved in `LICENSE.txt`.

XAIOS builds the library with `scripts/build-bearssl.sh` and links only the
objects reached by `xapt`. Runtime identity verification uses an operator-set
RSA public-key pin. The certificate and private key under `tests/fixtures/`
are public, deterministic interoperability fixtures and are not production
credentials.

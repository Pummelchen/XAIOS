# WebTransport C99, vendored

This is the completed C99 WebTransport library from
[`Pummelchen/WebTransport`](https://github.com/Pummelchen/WebTransport), copied
whole so that XAIOS's WebTransport work closes against an audited upstream
implementation rather than against more in-tree protocol code (`B-131`).

- **Upstream commit:** `46937e29eb734887ca7b739abfedaf68ae565de2`
- **Vendored:** 2026-09-17
- **License:** MIT, in `LICENSE` (Copyright © 2026 André Borchert)

## What was copied, and what was not

`include/` and `src/` are the library: the core utilities, the QUIC wire core
and crypto, the TLS 1.3 handshake over CRYPTO frames, the QUIC connection
runtime, HTTP/3 and QPACK, the draft-16 WebTransport session layer, and the
public consumer API. The empty `platform/{debian,freebsd,macos26,windows11}/`
directories were **not** copied: they hold build scripts and READMEs and zero
C lines, which is the finding `docs/WEBTRANSPORT-C99-INTEGRATION.md` is built
on. Upstream's own `tests/`, `apps/`, `cmake/`, `Experiments/`, `out/` and
`scripts/` are not copied either -- the tests do not run here and CMake is not
this repository's build system.

Nothing in this directory has been edited. `MANIFEST.sha256` records the
SHA-256 of every file, and `tests/repository/check-webtransport-vendor.py`
verifies it on every `make docs-check`, so a silent local change to vendored
code is a build failure rather than a discovery. A port that needs a change
here adds a file beside the tree, not inside it.

## Where the port actually happens

`docs/WEBTRANSPORT-C99-INTEGRATION.md` is the plan and the evidence: the real
seams are `src/runtime/udp_platform.h`, `src/core/time.c` and the crypto
primitives `include/webtransport/crypto/crypto.h` declares. The XAIOS side is
`userspace/wt/`, which already carries a BearSSL backend, a pin-based TLS 1.3
client and the RFC vectors to check them, and which becomes this library's
platform and crypto backend rather than being replaced.

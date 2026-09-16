# Integrating the upstream C99 WebTransport library

Assessment of `Pummelchen/WebTransport`, release **1.4.0**, C99 subtree, into
XAIOS's freestanding userspace. Upstream pin:
commit `46937e29eb734887ca7b739abfedaf68ae565de2`.

This document is the *evidence* for `B-131`. It records what the library needs
from an operating system, which of those needs XAIOS already meets, which it
does not, and what the smallest honest integration is. It exists so that the
work is a list rather than a discovery: the claim "integrable without drama"
is worth nothing unless the eleven assumptions below are named and costed.

The pin is upstream and is *supposed* to be fixed; the line numbers below are
relative to that commit and move with it.

## Verdict

**Integrable, and only by writing a new backend layer and correcting eleven
named assumptions.** There is no hard blocker, and no syscall-surface change,
and no threads or processes are required.

The library was written for a freestanding target on purpose. Three facts make
that true rather than hopeful:

- It has **no locks, no atomics and no thread-local storage** anywhere
  (`C99/docs/PUBLIC-API.md:251`), and its own documentation says so as a
  portability property.
- Its central entry point **never waits**: `wt_runtime_session_pump(session,
  now)` reads what is there, flushes what is owed and returns
  (`C99/include/webtransport/runtime/session.h:24-26`). The caller owns the
  clock and passes the time in.
- The allocator is caller-supplied (`C99/include/webtransport/allocator.h:31-52`),
  logging is a callback (`C99/src/core/log.c:5-38`), and the certificate
  policy it recommends for this operating system is already written into its
  own headers: `C99/include/webtransport/tls/trust.h:26-28` calls the pinned-key
  mode *"the model the XAIOS port uses"*, and `C99/include/webtransport/crypto/crypto.h:9-14`
  names BearSSL as what *"a freestanding target (XAIOS) would need"*.

## What `C99/platform/` is, and what the real seam is

`C99/platform/{debian,freebsd,macos26,windows11}/` contains build scripts and
READMEs only -- **zero C lines**; `C99/platform/README.md:3` describes them as
"OS-specific build entrypoints". `C99/third_party/` is empty (only
`.gitkeep`) even though `C99/CMakeLists.txt` refers to the vendored crypto the
library will link. Porting is therefore *not* a matter of adding a fifth
directory beside those four.

The real seam is three things:

| Seam | Where | Shape |
|---|---|---|
| UDP sockets | `C99/src/runtime/udp_platform.h` (649 lines) | ~19 private functions, POSIX branch at `:38-649` |
| Monotonic clock | `C99/src/core/time.c:55-59` | `clock_gettime(CLOCK_MONOTONIC, ...)` at `:57` |
| Crypto primitives | `C99/include/webtransport/crypto/crypto.h` | 20 entry points, `:70-210` |

`C99/src/runtime/udp.h:12-17` states the rule the port should keep: this is
*"the one POSIX part of the tree (WT-13) ... Nothing above this layer may
include `<sys/socket.h>`"*. `C99/docs/PORTABILITY.md:223-225` mechanically
checks the POSIX surface it uses: `close fcntl O_NONBLOCK poll errno recvmsg
sendmsg MSG_PEEK MSG_TRUNC sendto recvfrom snprintf inet_pton inet_ntop
setsockopt getsockopt socket bind`.

The **crypto seam is not complete**, and that is the largest structural
finding. Only `C99/src/crypto/crypto_openssl.c:22-27` is behind the declared
seam; OpenSSL is also called directly from three TLS files:

- `C99/src/tls/keyshare.c:42-75,:103-129` -- X25519 through `EVP_PKEY_*`.
- `C99/src/tls/trust.c:14-19,:76-127,:210-281` -- X.509 inline: `d2i_X509`,
  `i2d_X509_PUBKEY`, `X509_STORE_set_default_paths`, `PEM_read_bio_X509_AUX`,
  `X509_verify_cert`.
- `C99/src/tls/self_signed.c:18-111` -- server and test path only.

Swapping the crypto backend is therefore a change to four files, not one.
`C99/CMakeLists.txt` refuses any backend other than OpenSSL at configure time
(`FATAL_ERROR "... only openssl is"`, and `find_package(OpenSSL 3.0
REQUIRED)`), so an XAIOS build must not use that file at all: vendor the source
list and compile it.

## What XAIOS already provides

Verified against this tree, not assumed:

| The library needs | XAIOS has | Evidence |
|---|---|---|
| UDP socket, ephemeral port | `XAIOS_SYSCALL_NET_OPEN_UDP` (55) | `kernel/include/xaios/syscall.h:66`; the comment at `:61-65` says the call exists *because* "QUIC sends the first packet of a connection from an ephemeral port" |
| Datagram send / receive | `xaios_net_sendto`, `xaios_net_recvfrom` | `userspace/include/xaios_user.h:447`, `:435`; `userspace/lib/xaios_user.c:673`, `:646` |
| Readiness wait | `xaios_wait_events` | `userspace/include/xaios_user.h:396`; `XAIOS_WAIT_EVENT_SOCKET` at `:68-70` |
| Monotonic clock | `xaios_clock_nanos_kind(XAIOS_CLOCK_MONOTONIC)` | `userspace/include/xaios_user.h:91`, `:337` |
| Randomness | `xaios_random` -> `XAIOS_SYSCALL_RANDOM` (35) | `userspace/include/xaios_user.h:338`; `kernel/user/syscall.c:896-906`, at most 4096 bytes per call |
| Address type | `xaios_ip_addr_user_t` | `userspace/include/xaios_user.h:263-266`, the same shape as `wt_udp_address_t` (`C99/src/runtime/udp.h:60-65`) |

`NET_RECV` is non-blocking and reports an empty queue as `XAIOS_OK` with zero
bytes (`kernel/user/syscall.c:2201`, `:2231`), which maps to `WT_ERR_AGAIN` and
is exactly what the pump wants.

## The eleven assumptions to fix

| # | Assumption | Where | Fix | Size |
|---|---|---|---|---|
| A1 | `clock_gettime` exists | `C99/src/core/time.c:57` | add it to `userspace/libc/os_adapter.c` over `XAIOS_CLOCK_MONOTONIC`, or guard `time.c` on this port's clock | ~20 lines |
| A2 | POSIX sockets exist | `C99/src/runtime/udp_platform.h:40-48` | an XAIOS branch over `xaios_net_open_udp`/`_sendto`/`_recvfrom`/`_close` + `xaios_wait_events` | ~250-350 lines, one file |
| A3 | `inet_pton`/`inet_ntop` exist | `udp_platform.h:375,:573,:425,:632` | numeric v4/v6 in-tree; the library does no name resolution (`C99/src/runtime/udp.h:161`) | ~80 lines |
| A4 | Crypto backend is OpenSSL | `C99/CMakeLists.txt` ~`:92-101` | do not use CMake; compile the source list from the Makefile | 0 |
| A5 | Twenty crypto primitives | `crypto/crypto.h:70-210` | a BearSSL backend. `userspace/wt/src/wt_crypto_bearssl.c` already supplies most of them | ~500 lines, ~150 genuinely new |
| A6 | X25519 through `EVP_PKEY_*` | `C99/src/tls/keyshare.c:42-129` | rewrite onto the in-tree X25519 (`userspace/wt/include/wt_crypto.h:144-149`, RFC 7748 vectors) | ~60 lines changed |
| A7 | X.509 parsed by OpenSSL | `C99/src/tls/trust.c:14-19,:76-281` | a pin-only verify: SHA-256 of the leaf DER, constant-time compare, SPKI extraction | ~200 lines replacing 451 |
| A8 | A system trust store exists | `C99/src/tls/trust.c:216` | already refused with `WT_ERR_UNSUPPORTED` at `:219` | 0 |
| A9 | The default allocator is `malloc` | `C99/include/webtransport/allocator.h:57` | pass an arena; Picolibc's heap here is 256 KiB (`scripts/build-libc.sh:108`) | 0 |
| A10 | `getenv` returns settings | `C99/src/http3/driver.c:589`, `C99/src/tls/session.c:413,:489`, `C99/src/quic/connection.c:606` | nothing to do: `environ` is never populated, so the four diagnostic dumps are inert | 0 |
| A11 | `abort()`/`assert()` on error paths | -- | none present in `C99/src/` | 0 |

**Compiled-in scope:** `quic` 8857 + `tls` 3558 + `crypto` 599 + `core` 860 +
`runtime` 1764 = **about 15.6k lines** for a handshake; `http3` (5422) and
`webtransport` (1332) add a request; `cli` (590) and `api` (811) are optional.
Upstream's own tests (31477 lines) and apps are not needed.

## Entropy

One call site: `wt_random_bytes()` at `C99/src/crypto/crypto_openssl.c:591-599`
calls `RAND_bytes`. Consumers are the X25519 ephemeral key
(`C99/src/tls/keyshare.c:116-121`), connection identifiers, and Retry tokens.
The replacement is `xaios_random`, chunked at 4096 bytes.

**A gate that claims a real handshake must give the guest a real entropy
source.** `kernel/runtime/entropy.c:210-218` reports production grade only when
the source is the firmware RNG or a device RNG; `entropy.c:192-199` records
that the development seed file *"is the same on every boot and on every machine
built from the same image, so a key derived from it is a key anyone holding
that image already has."* A QEMU guest without `virtio-rng-pci` gets that seed,
so an ephemeral QUIC key would be predictable.

## Trust

`wt_tls_trust_verify` (`C99/src/tls/trust.c:129-290`) has four modes
(`trust.h:58-63`). Two are viable here and two are not:

- **SYSTEM** calls `X509_STORE_set_default_paths` (`:216`) and already returns
  `WT_ERR_UNSUPPORTED` when there is no store (`:219`). Not viable, correctly
  refused today.
- **STORE** takes a PEM bundle *in memory* (`BIO_new_mem_buf` `:228`), so it
  needs no filesystem.
- **PINNED** is a SHA-256 over the leaf DER with a constant-time compare
  (`:147-179`), at most `WT_TLS_PINNED_MAX` = 4 entries. This is the intended
  path for XAIOS, and `userspace/wt/src/wt_tls_pin.c` already implements the
  same model in-tree.
- **LOCAL_DEVELOPMENT** skips validation and is refused for non-loopback names
  (`:69-73`, `:185`), which is what a QEMU gate wants.

There is no trust callback and no prompt (`trust.h:11-16`). The sting is that
even pinned mode extracts the leaf SPKI through `d2i_X509` (`:76-99`) and
`i2d_X509_PUBKEY` (`:102-121`), so **no path through `trust.c` avoids DER
X.509 parsing**; A7 is not optional.

## Relationship to the in-tree work

`userspace/wt/` already holds about 7100 lines of QUIC and TLS 1.3 work --
`wt_crypto_bearssl.c` (450 lines), `wt_tls_handshake.c`, `wt_tls_client.c`
(1078 lines), `wt_quic_pkt.c`, pin and certificate handling -- with host gates
`make wt-host-test`, `make wt-host-sanitize` and `make wt-vectors-check`
checking them against RFC 8448 and RFC 9001 vectors recomputed independently in
Python.

That changes the shape of `B-131` from "adopt a library" to "reconcile two
implementations". The upstream library is larger and has the interop evidence
(seven Phase-11 proofs against five independent implementations, 97 tests
green on two operating systems); the in-tree work is smaller, already compiles
against this libc, and already carries the pin model and the BearSSL backend
the upstream port needs.

The honest sequencing is to reuse the in-tree crypto and pin layers as the
backend for the upstream library rather than to write a second one, and to
retire the in-tree wire code only once the upstream code completes a handshake
on a booted guest -- never before.

One in-tree claim is already known to be wrong and is corrected in the same
change: `userspace/wt/include/wt_crypto.h:13-15` says BearSSL has no Poly1305
and no RSA-PSS. Both are present in the vendored tree
(`third_party/bearssl/src/symcipher/poly1305_ctmul{,32,q}.c`,
`third_party/bearssl/src/rsa/rsa_default_pss_vrfy.c`).

## Minimal path to a QEMU gate

The smallest change that boots a guest completing a QUIC v1 handshake
(TLS 1.3, `TLS_AES_128_GCM_SHA256`, x25519) against a host-side server:

1. `userspace/libc/os_adapter.c` -- `clock_gettime` (A1), or do it in the
   vendored `time.c` and leave libc alone.
2. `userspace/wt/src/wt_udp_xaios.c` (**new**, ~300 lines) -- the socket
   backend (A2, A3).
3. `userspace/wt/src/wt_crypto_bearssl.c` -- the ~8 more entry points
   `crypto/crypto.h` needs (A5).
4. `userspace/wt/src/wt_tls_trust_xaios.c` (**new**, ~200 lines) -- pin-only
   verify (A7).
5. `userspace/apps/wtqtest.c` (**new**, ~150 lines) -- open an ephemeral UDP
   socket, start a client session against `10.0.2.2:4433`, pump, print
   `WT-HANDSHAKE-OK` when `wt_runtime_session_handshake_done` turns true.
6. `Makefile` and `scripts/create-initfs.py` -- the vendored source list, the
   BearSSL objects, and one more initfs entry. **The initial filesystem's
   directory is finite**: `MAX_FILES` (`scripts/create-initfs.py:18`) and
   `INITFS_MAX_FILES` (`kernel/fs/initramfs.c:18`) are both 80 and
   `qemu-abi-contract` compares them, so they move together or the build fails
   with `too many initfs files`.

Host side: build `wt-server-c99` from the upstream `apps/` with CMake and
OpenSSL, or use `C99/tests/interop/peer/aioquic_peer.py`. Guest side: QEMU user
networking already reaches the host at `10.0.2.2` under the existing scripts
(`platform/qemu/run-qemu-aarch64.sh:455-456`), so no port forwarding is
needed; add `-device virtio-rng-pci` so the entropy claim above is honest.

Cheapest first step that fails informatively: **A1 and A2 alone**, against a
host responder that answers only the QUIC Initial. That proves the socket path
before any crypto is written, and the pump's own counters (`last_receive`,
`receive_errors`, `first_receive_error`, `C99/include/webtransport/runtime/session.h:64-69`)
name the cause of the first failing round.

## What this document does not claim

No handshake on a booted XAIOS guest has been observed yet, and the crypto
backend, the trust verifier, the test application and the gate are not written.
Every line number is at the pin above and will move when the library moves. The
verdict is that the work is bounded and enumerated -- not that it is done. The
observation of a completed handshake is what `B-131` closes on; the vendoring
and the platform and crypto backends that have landed since are recorded at
the end of this document.

## Landed so far (2026-09-17)

Two things below the line above are now measurements rather than estimates.

**The tree is vendored at the pin.** `third_party/webtransport-c99/` is
upstream's `include/` and `src/` at
`46937e29eb734887ca7b739abfedaf68ae565de2`, with `MANIFEST.sha256` and
`tests/repository/check-webtransport-vendor.py` keeping it exactly upstream's.

**A1, A2, A5 and A6 are written, and the compile surface is one file.** The
seam the plan says must come from beside the tree does:
`userspace/wt/xaios/wt_xaios_platform.{h,c}` implements the socket layer over
`NET_OPEN_UDP`, `NET_SEND`, `NET_RECV` and `WAIT_EVENTS`, and
`wt_xaios_clock.c` implements `clock_gettime` over `CLOCK_NANOS`. The build
defines `WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H` and force-includes the seam for
`src/runtime/udp.c` only, so the vendored POSIX branch is inert and upstream is
unmodified. `wt_crypto_bearssl_upstream.c` supplies A5's twenty primitives over
BearSSL, and `wt_keyshare_xaios.c` supplies A6's X25519 from the ladder this
repository already checks against RFC 7748 -- which moved to
`userspace/wt/src/wt_x25519.c` so the in-tree module and the port link one copy.
`scripts/build-wt-upstream.sh` (make `wt-upstream-compile`) builds 41 sources
for aarch64, x86_64 and riscv64 with no errors, and
`tests/security/test_wt_upstream_crypto.c` checks the crypto against published
vectors in `make wt-host-test`.

A7 is written too: `userspace/wt/xaios/wt_trust_xaios.c` carries the trust
policy, and the leaf's SubjectPublicKeyInfo is read by a definite-length DER
reader in `userspace/wt/src/wt_x509_spki.c` rather than by OpenSSL. The scheme
dispatch moved out of `wt_tls_cert.c` into `userspace/wt/src/wt_sigverify.c` so
the in-tree module and the port share one implementation, and the port reaches
it through `wt_xaios_x509.c` -- a bridge with an opaque key buffer, because the
port's `webtransport/crypto/crypto.h` and this repository's `wt_crypto.h`
declare the same identifiers for different types and one translation unit
cannot hold both. Signing is refused by name: upstream signs only in its server
half and this port is a client.

So every upstream file in the handshake set is now built or replaced:
`src/crypto/crypto_openssl.c`, `src/tls/keyshare.c` and `src/tls/trust.c` are
replaced, and `src/tls/self_signed.c` is a server and test helper that no
compiled translation unit references. The whole of `core/`, `quic/`,
`runtime/` and the remaining `tls/` files compile untouched. The whole client
stack is built, not only the handshake set: `api/`, `webtransport/` and
`http3/` compile against the same backends, which is 78 sources per
architecture and the surface the application will link.

The vector test is not ceremony: its first run found that a zero-length AEAD
message was refused for want of an output buffer, and that a second `final` on
a context hashed the zeroed state into a plausible digest instead of reporting
`WT_ERR_STATE`. Both were in the adaptation, and neither would have been
visible from the compile.

Two details the implementation settled that the plan left open. XAIOS opens and
binds a UDP socket in one syscall, so the seam's handles are indices into a
small table and the kernel descriptor is created when the port is first known.
And there is no `MSG_PEEK`, which the library uses to look at a datagram without
consuming it, so the seam keeps a one-datagram stash per socket and serves the
next receive from it.


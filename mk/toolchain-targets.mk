# Hosted tooling: the engine CLI, the libc sysroot and the WebTransport port.

engine-cli:
	@mkdir -p build/hosted
	$(HOST_CC) $(HOST_CFLAGS) -Iengine/include \
	  engine/src/model_v2.c engine/src/sha256.c engine/src/architecture.c \
	  engine/src/service.c engine/src/backend_scalar.c \
	  engine/src/backend_neon.c engine/src/backend_avx2.c engine/src/packed.c engine/src/packed_simd.c \
	  tools/xaios_engine_cli.c -o build/hosted/xaios-engine

libc:
	./scripts/build-libc.sh

# The WebTransport C99 crypto and TLS tests. Host tests, not target tests: the
# target is XAIOS, which has no way to print a digest and compare it to an RFC,
# and the values under test are arithmetic over byte strings. The code is the
# same code the target builds, over the same vendored BearSSL.
wt-host-test:
	./tests/security/run-wt-host-tests.sh

# The same tests under AddressSanitizer and UndefinedBehaviorSanitizer. It has
# already found two test bugs and one undefined-behaviour bug in a verifier that
# the plain run passed, so it is worth having rather than remembering.
wt-host-sanitize:
	WT_SANITIZE=1 ./tests/security/run-wt-host-tests.sh

# The same vectors recomputed independently in Python, so the C tests are not
# checking themselves. Needs the `cryptography` package; skips cleanly without
# it rather than failing.
# The vendored WebTransport C99 library's compile step (B-131).
#
# It builds the whole client stack for every architecture the port claims --
# against the hosted libc sysroot, so `make libc` has to have run. No upstream
# source is left unbuilt: the four files that called OpenSSL are replaced from
# the XAIOS side, and docs/WEBTRANSPORT-C99-INTEGRATION.md is why those were
# the whole list.
wt-upstream-compile:
	./scripts/build-wt-upstream.sh --arch aarch64
	./scripts/build-wt-upstream.sh --arch x86_64
	./scripts/build-wt-upstream.sh --arch riscv64

# The port's client and server meeting over a real socket (B-131). One binary,
# both roles, all of it this repository's crypto: a completed handshake here is
# the claim the QEMU gate makes about a booted guest, checked where a failure
# can name itself. It also runs the negative controls -- a wrong pin and a
# development bypass asked for off loopback -- because a positive case alone
# would pass for a trust check that never ran.
wt-interop-test:
	./tests/security/run-wt-interop-test.sh

# The last claim of B-131 and the only one the host cannot make: a booted guest
# completing the handshake. It depends on the image because the application
# lives in it, and the host peer it talks to is the same binary the interop test
# uses -- one implementation, two places it is exercised.
qemu-quic-handshake-gate:
	XAIOS_BOOT_TEST_APPS=1 XAIOS_WT_HANDSHAKE_TEST=1 ./scripts/build-image.sh
	python3 tests/scripts/qemu-quic-handshake-gate.py

wt-vectors-check:
	python3 tests/security/verify_wt_rfc8448_key_schedule.py
	python3 tests/security/verify_wt_rfc9001_packets.py
	# The generated fixtures, re-verified rather than regenerated. Both
	# ECDSA and RSA-PSS signing draw a random nonce, so a rewrite would produce
	# a different but equally valid fixture on every run; re-verifying them
	# against the `cryptography` package is what keeps a corrupted header from
	# being believed. The peer identity is re-derived from the throwaway PEM
	# pair beside it, so a DER file that had drifted from its source is found
	# here rather than by a failing handshake.
	python3 tests/security/generate_wt_peer_identity.py
	python3 tests/security/generate_wt_ecdsa_vectors.py
	python3 tests/security/generate_wt_quic_flight.py

libc-check: libc
	python3 tests/repository/check-libc-contract.py
	./scripts/build-c99-app.sh --arch aarch64 --main void tests/libc/c99_main_void.c build/libc/aarch64/c99-app-builder-probe.elf
	./scripts/build-c99-app.sh --arch x86_64 --main void tests/libc/c99_main_void.c build/libc/x86_64/c99-app-builder-probe.elf

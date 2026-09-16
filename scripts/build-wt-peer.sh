#!/bin/sh
# Build the host WebTransport handshake endpoint (B-131).
#
# One binary, both roles. The server signs with this repository's BearSSL
# backend through the same files the guest uses, so the interop test and the
# QEMU gate run the port rather than a second implementation of it -- and
# nothing here needs OpenSSL, on the host or in CI.
#
# The backend is compiled from the same sources as the target's, without the
# XAIOS platform seam: the vendored tree's POSIX socket branch is what a host
# build wants, and `wt_xaios_platform.c` is not built at all.
#
# Usage: scripts/build-wt-peer.sh [--arch aarch64|x86_64|riscv64]
# Default is the host, native.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VENDOR="$ROOT/third_party/webtransport-c99"
BEARSSL="$ROOT/third_party/bearssl"
SEAM="$ROOT/userspace/wt/xaios"
ARCH=${XAIOS_WT_PEER_ARCH:-host}

case "$ARCH" in
  host) OUT="$ROOT/build/wt-peer/host" ;;
  aarch64|x86_64|riscv64) OUT="$ROOT/build/wt-peer/$ARCH" ;;
  *)
    printf 'error: unknown arch: %s\n' "$ARCH" >&2
    exit 2
    ;;
esac

mkdir -p "$OUT/bearssl" "$OUT/objects"

CC=${CC:-clang}
CFLAGS="-std=c99 -g -O1 -Wall -Wextra -Werror -fno-strict-aliasing"
INCLUDES="-I$BEARSSL/inc -I$BEARSSL/src -I$VENDOR/include -I$VENDOR/src \
-I$ROOT/userspace/wt/include -I$ROOT/userspace/wt/xaios -I$ROOT/userspace/include"

# The whole BearSSL tree, by exclusion, for the same reason the target's archive
# is built that way: a project that names upstream's modules one at a time is
# wrong the first time upstream adds one. Objects are cached, so a rerun only
# compiles what changed.
archive="$OUT/libbearssl-host.a"
stale=0
for relative in $(CDPATH= cd -- "$BEARSSL" && find src -name '*.c' \
    ! -path 'src/symcipher/des_*' \
    ! -path 'src/ssl/*' | LC_ALL=C sort); do
  object="$OUT/bearssl/$(printf '%s' "$relative" | tr '/' '_').o"
  if [ ! -f "$object" ] || [ "$BEARSSL/$relative" -nt "$object" ]; then
    # shellcheck disable=SC2086
    $CC $CFLAGS $INCLUDES -c "$BEARSSL/$relative" -o "$object"
    stale=1
  fi
  set -- "$@" "$object"
done
if [ "$stale" = 1 ] || [ ! -f "$archive" ]; then
  llvm-ar rcs "$archive" "$@"
fi

objects=""
compile() {
  source=$1
  name=$2
  object="$OUT/objects/$name.o"
  if [ ! -f "$object" ] || [ "$source" -nt "$object" ]; then
    # shellcheck disable=SC2086
    $CC $CFLAGS $INCLUDES -c "$source" -o "$object"
  fi
  objects="$objects $object"
}

# The upstream runtime: core, the QUIC connection, the socket branch and the
# TLS handshake. Nothing above the handshake is driven here.
# The object name comes from the path, not the basename: `handshake.c` and
# `session.c` each exist in two of these directories, and one overwriting the
# other is a link error that names the missing function rather than the file.
for source in "$VENDOR"/src/core/*.c "$VENDOR"/src/quic/*.c \
              "$VENDOR"/src/runtime/server_retry.c \
              "$VENDOR"/src/runtime/session.c "$VENDOR"/src/runtime/udp.c \
              "$VENDOR"/src/tls/extension.c "$VENDOR"/src/tls/handshake.c \
              "$VENDOR"/src/tls/keyschedule.c "$VENDOR"/src/tls/session.c; do
  relative=${source#"$VENDOR"/src/}
  compile "$source" "vendor-$(printf '%s' "${relative%.c}" | tr '/' '_')"
done

# The XAIOS side: the BearSSL crypto backend, the key share, the trust and
# signature file, and the certificate helpers.
for source in "$SEAM"/wt_crypto_bearssl_upstream.c "$SEAM"/wt_keyshare_xaios.c \
              "$SEAM"/wt_trust_xaios.c "$SEAM"/wt_xaios_x509.c \
              "$ROOT"/userspace/wt/src/wt_x25519.c \
              "$ROOT"/userspace/wt/src/wt_x509_spki.c \
              "$ROOT"/userspace/wt/src/wt_sigverify.c \
              "$ROOT"/userspace/wt/src/wt_aes128.c; do
  compile "$source" "seam-$(basename "$source" .c)"
done

peer_object="$OUT/objects/wt_peer.o"
if [ ! -f "$peer_object" ] || [ "$ROOT/tests/security/wt_peer.c" -nt "$peer_object" ]; then
  # shellcheck disable=SC2086
  $CC $CFLAGS $INCLUDES -c "$ROOT/tests/security/wt_peer.c" -o "$peer_object"
fi

# shellcheck disable=SC2086
$CC $CFLAGS -o "$OUT/wt_peer" "$peer_object" $objects "$archive"

printf 'wt-peer: built %s\n' "$OUT/wt_peer"

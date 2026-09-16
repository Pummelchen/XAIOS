#!/bin/sh
# The WebTransport handshake, both ends, on the host (B-131).
#
# This is the port's own client and its own server meeting over a real UDP
# socket: the vendored library's runtime session, this repository's BearSSL
# crypto backend, this repository's key share, and this repository's trust,
# certificate and signature code. Nothing here is OpenSSL and nothing here is
# the in-tree client, so a pass says the port completes a TLS 1.3 handshake --
# which is the claim the QEMU gate will make about a booted guest.
#
# Three cases, because the positive one alone would pass for a trust check that
# never ran:
#
#   1. the client pins the server's certificate fingerprint and completes;
#   2. the client pins a different fingerprint and is REFUSED, with the
#      refusal named;
#   3. the client uses the development bypass against a name that is not
#      loopback and is refused, which is the restriction the mode carries.
#
# Usage: tests/security/run-wt-interop-test.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
PEER="$ROOT/build/wt-peer/host/wt_peer"
CERT="$ROOT/tests/fixtures/wt-peer-cert.der"
KEY="$ROOT/tests/fixtures/wt-peer-key.der"

for fixture in "$CERT" "$KEY"; do
  if [ ! -f "$fixture" ]; then
    printf 'error: missing %s; run tests/security/generate_wt_peer_identity.py --force\n' \
      "$fixture" >&2
    exit 1
  fi
done

"$ROOT/scripts/build-wt-peer.sh" >/dev/null

WORK=$(mktemp -d "${TMPDIR:-/tmp}/xaios-wt-interop.XXXXXX")
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT HUP INT TERM

failures=0
checks=0

check() {
  description=$1
  if [ "$2" = 1 ]; then
    checks=$((checks + 1))
    printf '  ok   %s\n' "$description"
  else
    checks=$((checks + 1))
    failures=$((failures + 1))
    printf '  FAIL %s\n' "$description"
  fi
}

# Poll a log for a marker, up to a bound. A handshake that stalls is reported
# as a timeout rather than as a missing marker, so the two are distinguishable.
wait_for() {
  file=$1
  pattern=$2
  rounds=${3:-100}
  index=0
  while [ "$index" -lt "$rounds" ]; do
    if grep -q "$pattern" "$file" 2>/dev/null; then return 0; fi
    sleep 0.1
    index=$((index + 1))
  done
  return 1
}

# Start a server on an ephemeral port and answer with the port and the pin it
# will present. Port 0 lets the operating system choose, which is what keeps two
# runs of this script from colliding.
start_server() {
  log=$1
  : > "$log"
  "$PEER" --server --host 127.0.0.1 --port 0 --cert "$CERT" --key "$KEY" \
    >"$log" 2>&1 &
  if ! wait_for "$log" 'WT-PEER-BOUND' 100; then
    printf 'error: the server never bound\n' >&2
    cat "$log" >&2
    exit 1
  fi
  port=$(sed -n 's/^WT-PEER-BOUND port=\([0-9]*\).*/\1/p' "$log" | head -1)
  pin=$(sed -n 's/^WT-PEER-PIN \([0-9a-f]*\).*/\1/p' "$log" | head -1)
  if [ -z "$port" ] || [ -z "$pin" ]; then
    printf 'error: the server did not report its port and pin\n' >&2
    cat "$log" >&2
    exit 1
  fi
}

printf 'wt-interop: %s\n' "$PEER"

# 1. A pinned client completes the handshake, and so does the server.
server_log="$WORK/server-ok.log"
start_server "$server_log"
client_log="$WORK/client-ok.log"
if "$PEER" --client --host 127.0.0.1 --port "$port" --authority localhost \
    --pin "$pin" >"$client_log" 2>&1; then
  check "the pinned client completes the handshake" 1
else
  check "the pinned client completes the handshake" 0
  cat "$client_log"
fi
check "the server sees the handshake complete" \
  "$(wait_for "$server_log" 'WT-PEER-HANDSHAKE-OK' 50 && echo 1 || echo 0)"
check "the pin the server printed is the certificate's" \
  "$([ "$pin" = d4664ca34bd74e2e2b3d4f7ac38b85007f1db172fb8bcb336068d840e9f19dca ] && echo 1 || echo 0)"
kill %1 2>/dev/null || true
wait 2>/dev/null || true

# 2. A different fingerprint is refused, and the refusal says trust.
server_log="$WORK/server-wrong-pin.log"
start_server "$server_log"
wrong_log="$WORK/client-wrong-pin.log"
if "$PEER" --client --host 127.0.0.1 --port "$port" --authority localhost \
    --pin 0000000000000000000000000000000000000000000000000000000000000000 \
    >"$wrong_log" 2>&1; then
  check "a wrong pin is refused" 0
  cat "$wrong_log"
else
  check "a wrong pin is refused" 1
fi
check "the refusal names the trust check" \
  "$(grep -q 'session failure trust' "$wrong_log" && echo 1 || echo 0)"
check "the server does not report a handshake" \
  "$(grep -q 'WT-PEER-HANDSHAKE-OK' "$server_log" && echo 0 || echo 1)"
kill %1 2>/dev/null || true
wait 2>/dev/null || true

# 3. The development bypass refuses a name that is not loopback.
server_log="$WORK/server-dev.log"
start_server "$server_log"
dev_log="$WORK/client-dev.log"
if "$PEER" --client --host 127.0.0.1 --port "$port" --authority example.com \
    >"$dev_log" 2>&1; then
  check "the development bypass refuses a non-loopback name" 0
  cat "$dev_log"
else
  check "the development bypass refuses a non-loopback name" 1
fi
check "that refusal names the trust check" \
  "$(grep -q 'session failure trust' "$dev_log" && echo 1 || echo 0)"
kill %1 2>/dev/null || true
wait 2>/dev/null || true

if [ "$failures" -ne 0 ]; then
  printf 'wt-interop: %d of %d checks failed\n' "$failures" "$checks" >&2
  exit 1
fi
printf 'wt-interop: all %d checks held; the port completed a TLS 1.3 handshake with itself\n' \
  "$checks"

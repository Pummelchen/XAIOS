#!/bin/bash
set -euo pipefail

host="${1:-host.docker.internal}"
ssh_port="${2:-2222}"
udp_port="${3:-2223}"
password="${XAIOS_SSH_PASSWORD:-admin}"
workdir="$(mktemp -d)"
holder_pids=()

cleanup() {
  for pid in "${holder_pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

ssh_options=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -p "$ssh_port"
)
sftp_options=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -P "$ssh_port"
)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_ssh() {
  sshpass -p "$password" ssh "${ssh_options[@]}" "admin@$host" "$@"
}

printf 'Debian client: '
. /etc/os-release
printf '%s %s (%s)\n' "$PRETTY_NAME" "$(dpkg --print-architecture)" "$(ssh -V 2>&1)"

auth_output="$(run_ssh 'echo docker-auth-ok')"
test "$auth_output" = "docker-auth-ok" || fail "correct-password SSH command returned '$auth_output'"
printf 'PASS: correct SSH password accepted\n'

if sshpass -p 'definitely-wrong-password' ssh "${ssh_options[@]}" \
    "admin@$host" 'echo authentication-must-not-run' \
    >"$workdir/wrong-password.stdout" 2>"$workdir/wrong-password.stderr"; then
  fail "wrong SSH password was accepted"
fi
if grep -q 'authentication-must-not-run' "$workdir/wrong-password.stdout"; then
  fail "wrong-password command reached the server"
fi
printf 'PASS: wrong SSH password rejected\n'

python3 - "$workdir/sftp-source.bin" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes((index * 37 + 11) & 0xff for index in range(8170)))
PY

if ! {
  {
    printf 'put %s /tmp/docker-sftp.bin\n' "$workdir/sftp-source.bin"
    printf 'ls -l /tmp/docker-sftp.bin\n'
    printf 'get /tmp/docker-sftp.bin %s\n' "$workdir/sftp-result.bin"
    printf 'rm /tmp/docker-sftp.bin\n'
    printf 'quit\n'
  } | sshpass -p "$password" sftp "${sftp_options[@]}" "admin@$host" \
      >"$workdir/sftp.log" 2>&1
}; then
  cat "$workdir/sftp.log" >&2
  fail "SFTP client exited unsuccessfully"
fi
cmp "$workdir/sftp-source.bin" "$workdir/sftp-result.bin" \
  || fail "SFTP round-trip payload differs"
grep -Eq -- '[[:space:]]8170[[:space:]]+.*/tmp/docker-sftp.bin' "$workdir/sftp.log" \
  || fail "SFTP stat output did not report the 8170-byte file"
printf 'PASS: SFTP write/read/stat/remove round trip\n'

python3 - "$workdir" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for index, size in ((1, 2049), (2, 3073)):
    (root / f"parallel-{index}.bin").write_bytes(
        bytes((offset * (index + 17) + index) & 0xff for offset in range(size))
    )
PY
for index in 1 2; do
  (
    {
      printf 'put %s /tmp/docker-sftp-%s.bin\n' \
        "$workdir/parallel-$index.bin" "$index"
      sleep 6
      printf 'ls -l /tmp/docker-sftp-%s.bin\n' "$index"
      printf 'get /tmp/docker-sftp-%s.bin %s\n' \
        "$index" "$workdir/parallel-result-$index.bin"
      printf 'rm /tmp/docker-sftp-%s.bin\n' "$index"
      printf 'quit\n'
    } | sshpass -p "$password" sftp "${sftp_options[@]}" "admin@$host" \
        >"$workdir/parallel-sftp-$index.log" 2>&1
  ) &
  holder_pids+=("$!")
done
sleep 3
for pid in "${holder_pids[@]}"; do
  kill -0 "$pid" 2>/dev/null || fail "parallel SFTP session exited early"
done
parallel_output="$(run_ssh 'echo parallel-sftp-isolated')"
test "$parallel_output" = "parallel-sftp-isolated" \
  || fail "SSH command failed while two SFTP sessions were active"
for pid in "${holder_pids[@]}"; do
  if ! wait "$pid"; then
    cat "$workdir"/parallel-sftp-*.log >&2
    fail "parallel SFTP client failed"
  fi
done
holder_pids=()
for index in 1 2; do
  cmp "$workdir/parallel-$index.bin" \
      "$workdir/parallel-result-$index.bin" \
    || fail "parallel SFTP payload $index differs"
done
printf 'PASS: two overlapping SFTP sessions retained isolated handles\n'

for index in 1 2 3; do
  sshpass -p "$password" ssh "${ssh_options[@]}" -N "admin@$host" \
    >"$workdir/holder-$index.log" 2>&1 &
  holder_pids+=("$!")
done
sleep 8
for pid in "${holder_pids[@]}"; do
  kill -0 "$pid" 2>/dev/null || fail "concurrent SSH holder exited early"
done
concurrent_output="$(run_ssh 'echo four-sessions-ok')"
test "$concurrent_output" = "four-sessions-ok" \
  || fail "fourth simultaneous SSH session failed"
printf 'PASS: four simultaneous SSH connections\n'
for pid in "${holder_pids[@]}"; do
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done
holder_pids=()
sleep 2

for index in $(seq 1 20); do
  if ! reconnect_output="$(sshpass -p "$password" ssh -vvv \
      "${ssh_options[@]}" "admin@$host" \
      "echo reconnect-$index" 2>"$workdir/reconnect-$index.log")"; then
    cat "$workdir/reconnect-$index.log" >&2
    fail "SSH reconnect $index failed"
  fi
  test "$reconnect_output" = "reconnect-$index" \
    || fail "SSH reconnect $index returned '$reconnect_output'"
done
printf 'PASS: 20 sequential SSH reconnects recycled connection state\n'

python3 - "$host" "$udp_port" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = b"xaios-docker-udp-payload"
address = socket.gethostbyname(host)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(10.0)
    client.sendto(payload, (address, port))
    response, peer = client.recvfrom(4096)
if response != payload:
    raise SystemExit(f"UDP payload mismatch from {peer}: {response!r}")
print(f"PASS: UDP echo payload bytes={len(payload)} peer={peer[0]}:{peer[1]}")
PY

printf 'PASS: Debian 13 SSH, SFTP, concurrency, reconnect, and UDP suite complete\n'

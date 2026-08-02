#!/bin/bash
set -euo pipefail

host="${1:-host.docker.internal}"
ssh_port="${2:-2222}"
udp_port="${3:-2223}"
password="${XAIOS_SSH_PASSWORD:-admin}"
authorized_key="${XAIOS_SSH_AUTHORIZED_KEY:-/keys/authorized}"
unauthorized_key="${XAIOS_SSH_UNAUTHORIZED_KEY:-/keys/unauthorized}"
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
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=36
  -p "$ssh_port"
)
key_ssh_options=(
  -i "$authorized_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -p "$ssh_port"
)
sftp_options=(
  -i "$authorized_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
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
  ssh "${key_ssh_options[@]}" "admin@$host" "$@"
}

run_password_ssh() {
  sshpass -p "$password" ssh "${ssh_options[@]}" "admin@$host" "$@"
}

printf 'Debian client: '
. /etc/os-release
printf '%s %s (%s)\n' "$PRETTY_NAME" "$(dpkg --print-architecture)" "$(ssh -V 2>&1)"

public_key_output="$(ssh \
  -i "$authorized_key" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o ConnectTimeout=20 \
  -p "$ssh_port" \
  "admin@$host" 'echo public-key-auth-ok')"
test "$public_key_output" = "public-key-auth-ok" \
  || fail "authorized Ed25519 key returned '$public_key_output'"
printf 'PASS: standard OpenSSH Ed25519 public-key authentication\n'

if ssh \
    -i "$unauthorized_key" \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o ConnectTimeout=20 \
    -p "$ssh_port" \
    "admin@$host" 'echo unauthorized-key-must-not-run' \
    >"$workdir/unauthorized-key.stdout" \
    2>"$workdir/unauthorized-key.stderr"; then
  fail "unauthorized Ed25519 key was accepted"
fi
printf 'PASS: unauthorized Ed25519 key rejected\n'

auth_output="$(run_password_ssh 'echo docker-auth-ok')"
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
    printf 'mkdir /tmp/docker-sftp-dir\n'
    printf 'put %s /tmp/docker-sftp-dir/original.bin\n' "$workdir/sftp-source.bin"
    printf 'ls -l /tmp/docker-sftp-dir\n'
    printf 'rename /tmp/docker-sftp-dir/original.bin /tmp/docker-sftp-dir/renamed.bin\n'
    printf 'get /tmp/docker-sftp-dir/renamed.bin %s\n' "$workdir/sftp-renamed.bin"
    printf 'rm /tmp/docker-sftp-dir/renamed.bin\n'
    printf 'rmdir /tmp/docker-sftp-dir\n'
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - "admin@$host" \
      >"$workdir/sftp.log" 2>&1
}; then
  cat "$workdir/sftp.log" >&2
  fail "SFTP client exited unsuccessfully"
fi
cmp "$workdir/sftp-source.bin" "$workdir/sftp-result.bin" \
  || fail "SFTP round-trip payload differs"
cmp "$workdir/sftp-source.bin" "$workdir/sftp-renamed.bin" \
  || fail "SFTP renamed file payload differs"
grep -Eq -- '[[:space:]]8170[[:space:]]+.*/tmp/docker-sftp.bin' "$workdir/sftp.log" \
  || fail "SFTP stat output did not report the 8170-byte file"
grep -q 'original.bin' "$workdir/sftp.log" \
  || fail "SFTP directory listing omitted the uploaded file"
printf 'PASS: SFTP file and directory read/write/stat/list/rename/remove round trip\n'

if ! {
  {
    printf 'put %s /tmp/docker-sftp-rekey.bin\n' "$workdir/sftp-source.bin"
    printf 'get /tmp/docker-sftp-rekey.bin %s\n' "$workdir/sftp-rekey.bin"
    printf 'rm /tmp/docker-sftp-rekey.bin\n'
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - -o RekeyLimit=4K "admin@$host" \
      >"$workdir/sftp-rekey.log" 2>&1
}; then
  cat "$workdir/sftp-rekey.log" >&2
  fail "SFTP transfer across an OpenSSH-forced rekey failed"
fi
cmp "$workdir/sftp-source.bin" "$workdir/sftp-rekey.bin" \
  || fail "SFTP payload changed across rekey"
printf 'PASS: client-initiated SSH rekey preserved SFTP transfer\n'

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
    } | sftp "${sftp_options[@]}" -b - "admin@$host" \
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

control_socket="$workdir/control-master.sock"
ssh "${key_ssh_options[@]}" -M -S "$control_socket" -N "admin@$host" \
  >"$workdir/control-master.log" 2>&1 &
master_pid="$!"
for _ in $(seq 1 20); do
  test -S "$control_socket" && break
  kill -0 "$master_pid" 2>/dev/null || fail "SSH control master exited early"
  sleep 1
done
test -S "$control_socket" || fail "SSH control socket was not created"
{
  {
    printf 'pwd\n'
    sleep 6
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - -o ControlPath="$control_socket" \
      "admin@$host" >"$workdir/control-sftp.log" 2>&1
} &
control_sftp_pid="$!"
sleep 2
control_output="$(ssh "${key_ssh_options[@]}" \
  -o ControlPath="$control_socket" "admin@$host" \
  'echo shared-transport-ok')"
test "$control_output" = "shared-transport-ok" \
  || fail "second channel on shared SSH transport failed"
wait "$control_sftp_pid" || {
  cat "$workdir/control-sftp.log" >&2
  fail "SFTP channel on shared SSH transport failed"
}
ssh "${key_ssh_options[@]}" -S "$control_socket" -O exit \
  "admin@$host" >/dev/null 2>&1 || true
wait "$master_pid" 2>/dev/null || true
printf 'PASS: exec and SFTP channels shared one SSH transport\n'

for index in 1 2 3; do
  ssh "${key_ssh_options[@]}" -N "admin@$host" \
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
  if ! reconnect_output="$(ssh -vvv \
      "${key_ssh_options[@]}" "admin@$host" \
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

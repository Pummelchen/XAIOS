#!/bin/bash
set -euo pipefail

host="${1:-host.docker.internal}"
ssh_port="${2:-2222}"
udp_port="${3:-2223}"
expected_arch="${4:-aarch64}"
connect_timeout="${XAIOS_TEST_CONNECT_TIMEOUT:-60}"
case "$connect_timeout" in
  ''|*[!0-9]*) printf 'FAIL: XAIOS_TEST_CONNECT_TIMEOUT must be an integer\n' >&2; exit 2 ;;
esac
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
  -o "ConnectTimeout=$connect_timeout"
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
  -o "ConnectTimeout=$connect_timeout"
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=30
  -p "$ssh_port"
)
sftp_options=(
  -i "$authorized_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
  -o "ConnectTimeout=$connect_timeout"
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=30
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

suite_dir="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$suite_dir/debian13-client-suite-checks.sh"     # SSH auth, interactive shell, utilities, archives, xaiosctl
. "$suite_dir/debian13-client-suite-transport.sh"  # SFTP, rekey, concurrency, shared transport, reconnect, UDP

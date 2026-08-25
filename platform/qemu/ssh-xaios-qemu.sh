#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
host="${XAIOS_SSH_HOST:-127.0.0.1}"
port="${XAIOS_SSH_PORT:-7788}"
user="${XAIOS_SSH_USER:-admin}"
identity="${XAIOS_SSH_IDENTITY:-$ROOT_DIR/build/local-ssh/admin}"
known_hosts="${XAIOS_SSH_KNOWN_HOSTS:-$ROOT_DIR/build/local-ssh/known_hosts}"
ssh_bin="${XAIOS_SSH_CLIENT_BIN:-ssh}"
tty_flag="-tt"

usage() {
  cat <<EOF
usage: $0 [options] [command [argument ...]]

Options:
  --host HOST          forwarded QEMU host (default: $host)
  --port PORT          forwarded SSH port (default: $port)
  --user USER          SSH account (default: $user)
  --identity PATH      Ed25519 private key (default: $identity)
  --known-hosts PATH   persistent host-key file (default: $known_hosts)
  --no-tty             do not allocate a terminal
  --help               show this help

Environment variables with matching XAIOS_SSH_* names set the defaults.
EOF
}

require_value() {
  option="$1"
  remaining="$2"
  if [ "$remaining" -lt 2 ]; then
    printf '%s\n' "error: $option requires a value" >&2
    usage >&2
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host)
      require_value "$1" "$#"
      host="$2"
      shift 2
      ;;
    --port)
      require_value "$1" "$#"
      port="$2"
      shift 2
      ;;
    --user)
      require_value "$1" "$#"
      user="$2"
      shift 2
      ;;
    --identity)
      require_value "$1" "$#"
      identity="$2"
      shift 2
      ;;
    --known-hosts)
      require_value "$1" "$#"
      known_hosts="$2"
      shift 2
      ;;
    --no-tty)
      tty_flag="-T"
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf '%s\n' "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

case "$port" in
  ''|*[!0-9]*)
    printf '%s\n' "error: --port must be an integer from 1 to 65535" >&2
    exit 2
    ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  printf '%s\n' "error: --port must be an integer from 1 to 65535" >&2
  exit 2
fi

if [ ! -r "$identity" ]; then
  printf '%s\n' "error: SSH identity is not readable: $identity" >&2
  exit 1
fi
if ! command -v "$ssh_bin" >/dev/null 2>&1 && [ ! -x "$ssh_bin" ]; then
  printf '%s\n' "error: OpenSSH client not found: $ssh_bin" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname -- "$known_hosts")"
if [ -e "$known_hosts" ]; then
  chmod 600 "$known_hosts"
fi

# OpenSSH 10 warns when this classical-only development server is selected.
# Disable that client notice only here; the server capability remains documented.
if "$ssh_bin" -G -o WarnWeakCrypto=no "$user@$host" >/dev/null 2>&1; then
  exec "$ssh_bin" "$tty_flag" \
    -i "$identity" \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$known_hosts" \
    -o LogLevel=ERROR \
    -o WarnWeakCrypto=no \
    -p "$port" \
    "$user@$host" "$@"
fi

exec "$ssh_bin" "$tty_flag" \
  -i "$identity" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$known_hosts" \
  -o LogLevel=ERROR \
  -p "$port" \
  "$user@$host" "$@"

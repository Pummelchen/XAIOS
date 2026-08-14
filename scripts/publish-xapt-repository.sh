#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOURCE=${1:-"$ROOT/build/xapt/repository"}
HOST=${XAIOS_UPDATE_HOST:-root@91.99.176.243}
DESTINATION=${XAIOS_UPDATE_ROOT:-/var/xaios_updater}
TLS_CERT=${XAIOS_XAPT_TLS_CERT:-}
TLS_KEY=${XAIOS_XAPT_TLS_KEY:-}

if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; then
  if [ "${XAIOS_ALLOW_TEST_TLS_FIXTURE:-0}" = 1 ]; then
    TLS_CERT="$ROOT/tests/fixtures/xapt-tls-cert.pem"
    TLS_KEY="$ROOT/tests/fixtures/xapt-tls-key.pem"
    printf '%s\n' \
      'warning: publishing the public test-only TLS identity; never use this endpoint in production' >&2
  else
    printf '%s\n' \
      'error: set XAIOS_XAPT_TLS_CERT and XAIOS_XAPT_TLS_KEY to an operator-managed TLS identity' >&2
    exit 2
  fi
fi
[ -r "$TLS_CERT" ] || { printf 'error: unreadable TLS certificate: %s\n' "$TLS_CERT" >&2; exit 2; }
[ -r "$TLS_KEY" ] || { printf 'error: unreadable TLS key: %s\n' "$TLS_KEY" >&2; exit 2; }

[ -d "$SOURCE" ] || {
  printf 'error: repository directory not found: %s\n' "$SOURCE" >&2
  exit 1
}
python3 "$ROOT/tools/xaios_xapt_repo.py" verify --repository "$SOURCE"
ssh "$HOST" "install -d -m 0755 '$DESTINATION'"
rsync -rlpt --delete-delay "$SOURCE/" "$HOST:$DESTINATION/"
scp "$ROOT/deploy/xapt/Caddyfile" "$HOST:/etc/caddy/Caddyfile.xapt-new"
scp "$TLS_CERT" \
  "$HOST:/etc/caddy/xapt-tls-cert.pem.new"
scp "$TLS_KEY" \
  "$HOST:/etc/caddy/xapt-tls-key.pem.new"
ssh "$HOST" "caddy validate --config /etc/caddy/Caddyfile.xapt-new && \
  install -m 0644 /etc/caddy/xapt-tls-cert.pem.new /etc/caddy/xapt-tls-cert.pem && \
  install -m 0600 /etc/caddy/xapt-tls-key.pem.new /etc/caddy/xapt-tls-key.pem && \
  install -m 0644 /etc/caddy/Caddyfile.xapt-new /etc/caddy/Caddyfile && \
  rm -f /etc/caddy/Caddyfile.xapt-new /etc/caddy/xapt-tls-cert.pem.new \
    /etc/caddy/xapt-tls-key.pem.new && \
  if systemctl is-active --quiet caddy; then \
    systemctl reload caddy; \
  else \
    systemctl enable --now caddy; \
  fi"
printf 'Published verified xapt repository to %s:%s\n' "$HOST" "$DESTINATION"

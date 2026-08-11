#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOURCE=${1:-"$ROOT/build/xapt/repository"}
HOST=${XAIOS_UPDATE_HOST:-root@91.99.176.243}
DESTINATION=${XAIOS_UPDATE_ROOT:-/var/xaios_updater}

[ -d "$SOURCE" ] || {
  printf 'error: repository directory not found: %s\n' "$SOURCE" >&2
  exit 1
}
python3 "$ROOT/tools/xaios_xapt_repo.py" verify --repository "$SOURCE"
ssh "$HOST" "install -d -m 0755 '$DESTINATION'"
rsync -rlpt --delete-delay "$SOURCE/" "$HOST:$DESTINATION/"
scp "$ROOT/deploy/xapt/Caddyfile" "$HOST:/etc/caddy/Caddyfile.xapt-new"
ssh "$HOST" "caddy validate --config /etc/caddy/Caddyfile.xapt-new && \
  install -m 0644 /etc/caddy/Caddyfile.xapt-new /etc/caddy/Caddyfile && \
  rm -f /etc/caddy/Caddyfile.xapt-new && \
  if systemctl is-active --quiet caddy; then \
    systemctl reload caddy; \
  else \
    systemctl enable --now caddy; \
  fi"
printf 'Published verified xapt repository to %s:%s\n' "$HOST" "$DESTINATION"

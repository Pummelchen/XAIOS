#!/bin/sh
set -eu

# Publish a verified xapt repository to the updater host.
#
# TLS is terminated by the master edge in /var/caddy, which also fronts the
# other projects on this host. This script therefore never writes /etc/caddy
# and never reloads the shared `caddy` service — doing so would take those
# projects down. It syncs the repository and reloads the updater's own
# instance, xaios-caddy, which serves plain HTTP on :8090 behind the master.

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOURCE=${1:-"$ROOT/build/xapt/repository"}
HOST=${XAIOS_UPDATE_HOST:-root@91.99.176.243}
DESTINATION=${XAIOS_UPDATE_ROOT:-/var/xaios_updater}
SERVICE=${XAIOS_UPDATE_SERVICE:-xaios-caddy}

[ -d "$SOURCE" ] || {
  printf 'error: repository directory not found: %s\n' "$SOURCE" >&2
  exit 1
}
python3 "$ROOT/tools/xaios_xapt_repo.py" verify --repository "$SOURCE"

ssh "$HOST" "install -d -m 0755 '$DESTINATION'"
# The updater's own server lives inside the directory it serves; excluding it
# keeps --delete-delay from removing the binary and config out from under it.
rsync -rlpt --delete-delay \
  --exclude /caddy/ --exclude /bin/ \
  "$SOURCE/" "$HOST:$DESTINATION/"

ssh "$HOST" "systemctl reload-or-restart '$SERVICE' && \
  systemctl is-active --quiet '$SERVICE'"

printf 'Published verified xapt repository to %s:%s\n' "$HOST" "$DESTINATION"
printf 'Reachable at https://xaios.91.99.176.243.nip.io/ via the master edge.\n'

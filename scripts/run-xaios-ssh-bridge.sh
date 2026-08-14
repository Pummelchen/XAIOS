#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENV_DIR="${XAIOS_SSH_VENV:-$ROOT_DIR/build/xaios-ssh-venv}"
PORT="${XAIOS_SSH_PORT:-2222}"
HOST="${XAIOS_SSH_HOST:-127.0.0.1}"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install \
  --disable-pip-version-check \
  -q \
  -r "$ROOT_DIR/requirements-dev.txt"

exec "$VENV_DIR/bin/python" "$ROOT_DIR/scripts/xaios-ssh-bridge.py" \
  --host "$HOST" \
  --port "$PORT"

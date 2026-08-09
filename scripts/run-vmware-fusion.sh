#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VMX="$ROOT_DIR/build/vmware-fusion/XAIOS.vmwarevm/XAIOS.vmx"
VMRUN="${XAIOS_VMRUN:-/Applications/VMware Fusion.app/Contents/Library/vmrun}"

if [ ! -x "$VMRUN" ]; then
  printf '%s\n' "error: VMware Fusion vmrun not found at $VMRUN" >&2
  exit 1
fi
if [ ! -f "$VMX" ]; then
  printf '%s\n' "error: missing Fusion VM; run make vmware-fusion-image" >&2
  exit 1
fi
if [ "${1:-}" = "--dry-run" ]; then
  printf "'%s' -T fusion start '%s' gui\n" "$VMRUN" "$VMX"
  exit 0
fi
if [ "$#" -ne 0 ]; then
  printf '%s\n' "usage: $0 [--dry-run]" >&2
  exit 2
fi

python3 - "$ROOT_DIR/build/vmware-fusion/XAIOS.vmwarevm/fusion-serial.log" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).unlink(missing_ok=True)
PY
exec "$VMRUN" -T fusion start "$VMX" gui

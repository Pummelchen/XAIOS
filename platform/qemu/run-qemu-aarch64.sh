#!/bin/sh
set -eu

dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=1
  shift
fi

if [ "$#" -ne 0 ]; then
  printf '%s\n' "usage: $0 [--dry-run]" >&2
  exit 2
fi

find_tool() {
  tool_name="$1"
  shift

  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return 0
  fi

  return 1
}

brew_prefix() {
  formula="$1"
  if command -v brew >/dev/null 2>&1; then
    brew --prefix "$formula" 2>/dev/null || true
  fi
}

find_aavmf_firmware() {
  if [ "${XAIOS_AAVMF_CODE:-}" != "" ]; then
    [ -f "$XAIOS_AAVMF_CODE" ] && printf '%s\n' "$XAIOS_AAVMF_CODE" && return 0
    return 1
  fi

  for candidate in \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /opt/homebrew/share/qemu/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI-pflash.raw \
    /usr/local/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI-pflash.raw \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF32_CODE.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

print_command() {
  printf 'QEMU AArch64 command:\n'
  printf '  '
  for arg in "$@"; do
    case "$arg" in
      *[!A-Za-z0-9_./:=,+-]*|'')
        printf "'%s' " "$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")"
        ;;
      *)
        printf '%s ' "$arg"
        ;;
    esac
  done
  printf '\n'
}

if [ "${XAIOS_QEMU:-}" != "" ]; then
  if [ ! -x "$XAIOS_QEMU" ]; then
    printf '%s\n' "error: XAIOS_QEMU is not executable: $XAIOS_QEMU" >&2
    exit 1
  fi
  qemu="$XAIOS_QEMU"
else
  QEMU_PREFIX="$(brew_prefix qemu)"
  QEMU_BIN=""
  if [ "$QEMU_PREFIX" != "" ]; then
    QEMU_BIN="$QEMU_PREFIX/bin"
  fi

  if ! qemu="$(find_tool qemu-system-aarch64 "$QEMU_BIN/qemu-system-aarch64")"; then
    printf '%s\n' "error: qemu-system-aarch64 not found. Install with: brew install qemu" >&2
    exit 1
  fi
fi

if ! firmware="$(find_aavmf_firmware)"; then
  printf '%s\n' "error: AArch64 UEFI firmware not found. Set XAIOS_AAVMF_CODE=/path/to/edk2-aarch64-code.fd." >&2
  exit 1
fi

accel="${XAIOS_QEMU_ACCEL:-tcg}"
if [ "$accel" = "hvf" ]; then
  printf '%s\n' \
    "warning: AArch64 HVF is experimental for XAIOS and may abort in QEMU exception handling; use XAIOS_QEMU_ACCEL=tcg for correctness gates" >&2
fi
xaios_aarch64_qemu_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$xaios_aarch64_qemu_dir/run-qemu-aarch64-config.sh"
. "$xaios_aarch64_qemu_dir/run-qemu-aarch64-args.sh"

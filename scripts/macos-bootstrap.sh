#!/bin/sh
set -eu

PROJECT_NAME="XAIOS"
HOST_OS="$(uname -s 2>/dev/null || printf unknown)"
HOST_ARCH="$(uname -m 2>/dev/null || printf unknown)"

failures=0
warnings=0

info() {
  printf 'info: %s\n' "$*"
}

ok() {
  printf 'ok: %s\n' "$*"
}

warn() {
  warnings=$((warnings + 1))
  printf 'warn: %s\n' "$*"
}

fail() {
  failures=$((failures + 1))
  printf 'fail: %s\n' "$*"
}

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

check_tool() {
  label="$1"
  tool_name="$2"
  install_hint="$3"
  shift 3

  if tool_path="$(find_tool "$tool_name" "$@")"; then
    ok "$label: $tool_path"
    return 0
  fi

  fail "$label not found. $install_hint"
  return 0
}

check_optional_tool() {
  label="$1"
  tool_name="$2"
  install_hint="$3"
  shift 3

  if tool_path="$(find_tool "$tool_name" "$@")"; then
    ok "$label: $tool_path"
    return 0
  fi

  warn "$label not found. $install_hint"
  return 0
}

check_output_contains() {
  label="$1"
  command_output="$2"
  expected="$3"
  failure_hint="$4"

  if printf '%s\n' "$command_output" | grep -q "$expected"; then
    ok "$label"
    return 0
  fi

  fail "$label missing '$expected'. $failure_hint"
  return 0
}

find_aavmf_firmware() {
  if [ "${XAIOS_AAVMF_CODE:-}" != "" ]; then
    if [ -f "$XAIOS_AAVMF_CODE" ]; then
      printf '%s\n' "$XAIOS_AAVMF_CODE"
      return 0
    fi
    return 1
  fi

  for candidate in \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd.bz2 \
    /opt/homebrew/share/qemu/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI-pflash.raw \
    /usr/local/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI-pflash.raw
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

brew_prefix() {
  formula="$1"
  if command -v brew >/dev/null 2>&1; then
    brew --prefix "$formula" 2>/dev/null || true
  fi
}

LLVM_PREFIX="$(brew_prefix llvm)"
LLD_PREFIX="$(brew_prefix lld)"
QEMU_PREFIX="$(brew_prefix qemu)"

LLVM_BIN=""
if [ "$LLVM_PREFIX" != "" ]; then
  LLVM_BIN="$LLVM_PREFIX/bin"
fi

QEMU_BIN=""
if [ "$QEMU_PREFIX" != "" ]; then
  QEMU_BIN="$QEMU_PREFIX/bin"
fi

LLD_BIN=""
if [ "$LLD_PREFIX" != "" ]; then
  LLD_BIN="$LLD_PREFIX/bin"
fi

info "$PROJECT_NAME macOS bootstrap"
info "host: $HOST_OS $HOST_ARCH"

if [ "$HOST_OS" = "Darwin" ]; then
  ok "host OS is macOS"
else
  fail "host OS is $HOST_OS, expected macOS/Darwin for this bootstrap"
fi

if [ "$HOST_ARCH" = "arm64" ]; then
  ok "host architecture is Apple Silicon arm64"
else
  warn "host architecture is $HOST_ARCH; Apple Silicon arm64 is the primary macOS target"
fi

check_tool "QEMU AArch64 system emulator" "qemu-system-aarch64" \
  "Install with: brew install qemu" \
  "$QEMU_BIN/qemu-system-aarch64"

check_tool "Clang" "clang" \
  "Install LLVM with: brew install llvm" \
  "$LLVM_BIN/clang" /usr/bin/clang

check_tool "LLD linker" "ld.lld" \
  "Install with: brew install lld, or add an existing LLD install to PATH" \
  "$LLVM_BIN/ld.lld" "$LLD_BIN/ld.lld"

check_tool "LLD COFF linker" "lld-link" \
  "Install with: brew install lld, or add an existing LLD install to PATH" \
  "$LLVM_BIN/lld-link" "$LLD_BIN/lld-link"

check_tool "LLVM objcopy" "llvm-objcopy" \
  "Install LLVM with: brew install llvm, or add Homebrew LLVM to PATH" \
  "$LLVM_BIN/llvm-objcopy"

check_tool "LLVM readelf" "llvm-readelf" \
  "Install LLVM with: brew install llvm, or add Homebrew LLVM to PATH" \
  "$LLVM_BIN/llvm-readelf"

check_tool "Python 3" "python3" \
  "Install with: brew install python" \
  /opt/homebrew/bin/python3 /usr/local/bin/python3

check_tool "Git" "git" \
  "Install Xcode command line tools or Homebrew Git" \
  /opt/homebrew/bin/git /usr/bin/git

check_tool "Make" "make" \
  "Install Xcode command line tools" \
  /usr/bin/make

check_tool "hdiutil" "hdiutil" \
  "hdiutil is provided by macOS" \
  /usr/bin/hdiutil

check_tool "diskutil" "diskutil" \
  "diskutil is provided by macOS" \
  /usr/sbin/diskutil

check_tool "dd" "dd" \
  "dd is provided by macOS" \
  /bin/dd

check_optional_tool "mtools mformat" "mformat" \
  "Install with: brew install mtools if FAT image editing scripts choose mtools" \
  /opt/homebrew/bin/mformat /usr/local/bin/mformat

check_optional_tool "mtools mcopy" "mcopy" \
  "Install with: brew install mtools if FAT image editing scripts choose mtools" \
  /opt/homebrew/bin/mcopy /usr/local/bin/mcopy

check_optional_tool "mtools mmd" "mmd" \
  "Install with: brew install mtools if FAT image editing scripts choose mtools" \
  /opt/homebrew/bin/mmd /usr/local/bin/mmd

check_optional_tool "xorriso" "xorriso" \
  "Install with: brew install xorriso for VMware Fusion packaging" \
  /opt/homebrew/bin/xorriso /usr/local/bin/xorriso

check_optional_tool "Docker" "docker" \
  "Install Docker Desktop for the VMware Fusion GRUB build and Debian gates" \
  /usr/local/bin/docker /opt/homebrew/bin/docker

check_optional_tool "VMware Fusion vmrun" "vmrun" \
  "Install VMware Fusion to use the optional ARM64 Fusion gate" \
  "/Applications/VMware Fusion.app/Contents/Library/vmrun"

if qemu_path="$(find_tool qemu-system-aarch64 "$QEMU_BIN/qemu-system-aarch64")"; then
  accel_output="$("$qemu_path" -accel help 2>/dev/null || true)"
  machine_output="$("$qemu_path" -machine help 2>/dev/null || true)"

  check_output_contains "QEMU supports HVF acceleration" "$accel_output" "hvf" \
    "Install a QEMU build with macOS HVF support or use slower TCG."
  check_output_contains "QEMU supports TCG fallback" "$accel_output" "tcg" \
    "Install a complete QEMU system emulator build."
  check_output_contains "QEMU supports AArch64 virt machine" "$machine_output" "^virt" \
    "Install a QEMU build with Arm virt machine support."
fi

if firmware_path="$(find_aavmf_firmware)"; then
  ok "AArch64 UEFI firmware: $firmware_path"
else
  fail "AArch64 UEFI firmware not found. Install an EDK2/AAVMF package or set XAIOS_AAVMF_CODE=/path/to/QEMU_EFI.fd."
fi

if [ "$failures" -eq 0 ]; then
  ok "bootstrap checks passed with $warnings warning(s)"
  exit 0
fi

printf '\n%s\n' "Bootstrap failed with $failures required problem(s) and $warnings warning(s)."
printf '%s\n' "Recommended first fixes on Apple Silicon:"
printf '%s\n' "  brew install qemu llvm lld"
printf '%s\n' "  install AArch64 EDK2/AAVMF firmware, then export XAIOS_AAVMF_CODE=/path/to/QEMU_EFI.fd"
exit 1

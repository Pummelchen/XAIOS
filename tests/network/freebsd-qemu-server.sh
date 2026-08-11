#!/bin/sh
set -eu

arch="${XAIOS_FREEBSD_ARCH:-aarch64}"
base=/images/freebsd.qcow2
seed=/seed/cidata.iso
overlay=/work/freebsd-overlay.qcow2
memory="${XAIOS_FREEBSD_MEMORY_MB:-2048}"
smp="${XAIOS_FREEBSD_SMP:-2}"

for required in "$base" "$seed"; do
  if [ ! -f "$required" ]; then
    printf 'error: missing required file: %s\n' "$required" >&2
    exit 1
  fi
done

find_firmware() {
  for candidate in "$@"; do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

rm -f "$overlay"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay"

relay_pids=""
cleanup() {
  for pid in $relay_pids; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

if [ "${XAIOS_RELAY_SSH_PORT:-}" != "" ]; then
  socat TCP4-LISTEN:2223,reuseaddr,fork \
    "TCP4:host.docker.internal:${XAIOS_RELAY_SSH_PORT}" &
  relay_pids="$relay_pids $!"
fi
if [ "${XAIOS_RELAY_UDP_PORT:-}" != "" ]; then
  socat UDP4-RECVFROM:2224,reuseaddr,fork \
    "UDP4-SENDTO:host.docker.internal:${XAIOS_RELAY_UDP_PORT}" &
  relay_pids="$relay_pids $!"
fi

case "$arch" in
  aarch64)
    firmware="$(find_firmware \
      /usr/share/AAVMF/AAVMF_CODE.fd \
      /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
      /usr/share/AAVMF/AAVMF32_CODE.fd)" || {
        printf '%s\n' 'error: AArch64 UEFI firmware not found' >&2
        exit 1
      }
    set -- qemu-system-aarch64 \
      -machine virt,accel=tcg,gic-version=3 \
      -cpu max \
      -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
      -device virtio-net-pci,netdev=net0
    ;;
  x86_64|amd64)
    firmware="$(find_firmware \
      /usr/share/OVMF/OVMF_CODE_4M.fd \
      /usr/share/OVMF/OVMF_CODE.fd \
      /usr/share/qemu/OVMF.fd)" || {
        printf '%s\n' 'error: x86_64 UEFI firmware not found' >&2
        exit 1
      }
    set -- qemu-system-x86_64 \
      -machine q35,accel=tcg \
      -cpu max \
      -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
      -device virtio-net-pci,netdev=net0,disable-legacy=on
    ;;
  *)
    printf 'error: unsupported XAIOS_FREEBSD_ARCH: %s\n' "$arch" >&2
    exit 2
    ;;
esac

printf 'XAIOS_FREEBSD_DOCKER: arch=%s memory=%s smp=%s\n' \
  "$arch" "$memory" "$smp"
exec "$@" \
  -m "$memory" \
  -smp "$smp" \
  -nographic \
  -monitor none \
  -no-reboot \
  -drive "if=none,format=qcow2,id=freebsd,file=$overlay" \
  -device virtio-blk-pci,drive=freebsd,bootindex=0 \
  -drive "if=none,format=raw,readonly=on,id=cidata,file=$seed" \
  -device virtio-blk-pci,drive=cidata \
  -netdev user,id=net0,hostfwd=tcp::2222-:22

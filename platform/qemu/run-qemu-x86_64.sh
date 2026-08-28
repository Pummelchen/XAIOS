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

find_ovmf_firmware() {
  if [ "${XAIOS_OVMF_CODE:-}" != "" ]; then
    [ -f "$XAIOS_OVMF_CODE" ] && printf '%s\n' "$XAIOS_OVMF_CODE" && return 0
    return 1
  fi

  for candidate in \
    /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
    /opt/homebrew/share/qemu/OVMF_CODE.fd \
    /opt/homebrew/share/edk2/x64/OVMF_CODE.fd \
    /usr/local/share/qemu/edk2-x86_64-code.fd \
    /usr/local/share/qemu/OVMF_CODE.fd \
    /usr/local/share/edk2/x64/OVMF_CODE.fd \
    /usr/share/qemu/edk2-x86_64-code.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/qemu/OVMF.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

print_command() {
  printf 'QEMU x86_64 command:\n'
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

QEMU_PREFIX="$(brew_prefix qemu)"
QEMU_BIN=""
if [ "$QEMU_PREFIX" != "" ]; then
  QEMU_BIN="$QEMU_PREFIX/bin"
fi

if ! qemu="$(find_tool qemu-system-x86_64 "$QEMU_BIN/qemu-system-x86_64")"; then
  printf '%s\n' "error: qemu-system-x86_64 not found. Install with: brew install qemu" >&2
  exit 1
fi

if ! firmware="$(find_ovmf_firmware)"; then
  printf '%s\n' "error: x86_64 OVMF firmware not found. Set XAIOS_OVMF_CODE=/path/to/edk2-x86_64-code.fd." >&2
  exit 1
fi

accel="${XAIOS_QEMU_X86_ACCEL:-tcg}"
machine="${XAIOS_QEMU_X86_MACHINE:-q35}"
cpu="${XAIOS_QEMU_X86_CPU:-max}"
# Two gibibytes, and not one, for a reason that is arithmetic rather than
# taste. The kernel is linked at a fixed 0x90000000 (kernel/arch/aarch64/
# linker.ld), and the three hypervisors do not agree on where usable memory
# starts: QEMU's begins at 0x40000000, Virtualization.framework's at
# 0x70000000, VMware Fusion's at 0x80000000. A guest given one gibibyte on
# QEMU therefore owns [0x40000000, 0x80000000) -- which ends exactly where
# Fusion's memory begins, so no single fixed link address can sit inside both.
# Lowering the figure means making the kernel relocatable first. Until then
# this is the smallest number that boots everywhere.
memory="${XAIOS_QEMU_X86_MEMORY:-2G}"
smp="${XAIOS_QEMU_X86_SMP:-4}"
# The boot medium is attached read-only, as the AArch64 runner has always
# attached it. A guest must not be able to write to the medium it booted from:
# testing an image would modify it, and a machine booting a CD or a
# write-protected stick cannot offer a writable one anyway.
image="${XAIOS_X86_64_IMAGE:-build/xaios-x86_64.img}"
test_block_image="${XAIOS_X86_TEST_BLOCK_IMAGE:-build/xaios-x86-virtio-test.img}"
persistent_image="${XAIOS_X86_PERSISTENT_IMAGE:-build/xaios-x86-persistent.img}"
model_volume_image="${XAIOS_MODEL_VOLUME_IMAGE:-build/xaios-x86-model-volume.img}"
system_volume_image="${XAIOS_SYSTEM_VOLUME_IMAGE:-build/xaios-x86-system.img}"
storage_admin_image="${XAIOS_X86_STORAGE_ADMIN_IMAGE:-build/xaios-x86-storage-admin.img}"
hostfwd_port="${XAIOS_QEMU_HOSTFWD_PORT:-7788}"
hostfwd_udp_port="${XAIOS_QEMU_HOSTFWD_UDP_PORT:-none}"
net_socket_host="${XAIOS_QEMU_NET_SOCKET_HOST:-127.0.0.1}"
net_socket_port="${XAIOS_QEMU_NET_SOCKET_PORT:-none}"
pcap_file="${XAIOS_QEMU_NET_DUMP:-none}"
nvme_image="${XAIOS_QEMU_X86_NVME_IMAGE:-}"
debug_log="${XAIOS_QEMU_X86_DEBUG_LOG:-}"
numa_profile="${XAIOS_QEMU_X86_NUMA:-none}"
keyboard_device="${XAIOS_QEMU_KEYBOARD:-usb}"
qmp_socket="${XAIOS_QEMU_QMP_SOCKET:-}"

case "$numa_profile" in
  none) ;;
  two-node)
    if [ "$memory" != "2G" ] || [ "$smp" != "4" ]; then
      printf '%s\n' "error: two-node NUMA profile requires XAIOS_QEMU_X86_MEMORY=2G and XAIOS_QEMU_X86_SMP=4" >&2
      exit 2
    fi
    machine="${machine},hmat=on"
    ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_X86_NUMA must be none or two-node" >&2
    exit 2
    ;;
esac

case "$keyboard_device" in
  usb|none) ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_KEYBOARD must be usb or none" >&2
    exit 2
    ;;
esac

if [ "$dry_run" -eq 0 ] && [ ! -f "$image" ]; then
  printf '%s\n' "error: missing x86_64 boot image: $image" >&2
  printf '%s\n' "       Run make image-x86_64 first, or set XAIOS_X86_64_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$persistent_image" ]; then
  printf '%s\n' "note: persistent image not found, creating: $persistent_image"
  dd if=/dev/zero of="$persistent_image" bs=512 count=32768 status=none
fi

for required_image in "$test_block_image" \
  "$model_volume_image" "$system_volume_image" "$storage_admin_image"
do
  if [ "$dry_run" -eq 0 ] && [ ! -f "$required_image" ]; then
    printf '%s\n' "error: missing x86_64 runtime image: $required_image" >&2
    printf '%s\n' "       Run make image-x86_64 first." >&2
    exit 1
  fi
done

set -- "$qemu" \
  -machine "$machine" \
  -accel "$accel" \
  -cpu "$cpu" \
  -smp "$smp" \
  -no-reboot \
  -nographic \
  -serial mon:stdio \
  -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
  -drive "if=none,format=raw,readonly=on,id=xaios_x86_boot,file=$image" \
  -device virtio-blk-pci,drive=xaios_x86_boot,bootindex=0,disable-legacy=on \
  -drive "if=none,format=raw,id=xaios_x86_test,file=$test_block_image" \
  -device virtio-blk-pci,drive=xaios_x86_test,disable-legacy=on \
  -drive "if=none,format=raw,id=xaios_x86_persistent,file=$persistent_image" \
  -device virtio-blk-pci,drive=xaios_x86_persistent,disable-legacy=on \
  -drive "if=none,format=raw,id=xaios_x86_models,file=$model_volume_image" \
  -device virtio-blk-pci,drive=xaios_x86_models,disable-legacy=on \
  -drive "if=none,format=raw,id=xaios_x86_admin,file=$storage_admin_image" \
  -device virtio-blk-pci,drive=xaios_x86_admin,disable-legacy=on \
  -blockdev "driver=file,node-name=xaios_x86_system_uefi_file,filename=$system_volume_image,locking=off" \
  -blockdev driver=raw,node-name=xaios_x86_system_uefi,file=xaios_x86_system_uefi_file \
  -device virtio-blk-pci,drive=xaios_x86_system_uefi,bootindex=1,disable-legacy=on \
  -blockdev "driver=file,node-name=xaios_x86_system_kernel_file,filename=$system_volume_image,locking=off" \
  -blockdev driver=raw,node-name=xaios_x86_system_kernel,file=xaios_x86_system_kernel_file \
  -device virtio-blk-pci,drive=xaios_x86_system_kernel,disable-legacy=on \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:57,disable-legacy=on

if [ "$keyboard_device" = "usb" ]; then
  set -- "$@" \
    -device qemu-xhci,id=xaios_xhci \
    -device usb-kbd,bus=xaios_xhci.0
fi

if [ "$qmp_socket" != "" ]; then
  rm -f "$qmp_socket"
  set -- "$@" -qmp "unix:${qmp_socket},server=on,wait=off"
fi

if [ "$numa_profile" = "two-node" ]; then
  set -- "$@" \
    -m 2G \
    -object memory-backend-ram,id=xaios_ram0,size=1G \
    -object memory-backend-ram,id=xaios_ram1,size=1G \
    -numa node,nodeid=0,cpus=0-1,memdev=xaios_ram0,initiator=0 \
    -numa node,nodeid=1,cpus=2-3,memdev=xaios_ram1,initiator=1 \
    -numa dist,src=0,dst=1,val=20 \
    -numa hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-latency,latency=10 \
    -numa hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-latency,latency=30 \
    -numa hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-latency,latency=30 \
    -numa hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-latency,latency=10 \
    -numa hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=20G \
    -numa hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G \
    -numa hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G \
    -numa hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=20G
else
  set -- "$@" -m "$memory"
fi

if [ "$net_socket_port" != "none" ]; then
  net0_user_options="user,id=net0_user,ipv6=off"
  if [ "$hostfwd_port" != "none" ]; then
    net0_user_options="${net0_user_options},hostfwd=tcp::${hostfwd_port}-:22"
  fi
  if [ "$hostfwd_udp_port" != "none" ]; then
    net0_user_options="${net0_user_options},hostfwd=udp::${hostfwd_udp_port}-:2223"
  fi
  set -- "$@" \
    -netdev "$net0_user_options" \
    -netdev "hubport,id=net0_user_hub,hubid=1,netdev=net0_user" \
    -netdev "stream,id=net0_socket,server=on,addr.type=inet,addr.host=${net_socket_host},addr.port=${net_socket_port}" \
    -netdev "hubport,id=net0_socket_hub,hubid=1,netdev=net0_socket" \
    -netdev "hubport,id=net0,hubid=1"
else
  net0_options="user,id=net0"
  if [ "$hostfwd_port" != "none" ]; then
    net0_options="${net0_options},hostfwd=tcp::${hostfwd_port}-:22"
  fi
  if [ "$hostfwd_udp_port" != "none" ]; then
    net0_options="${net0_options},hostfwd=udp::${hostfwd_udp_port}-:2223"
  fi
  set -- "$@" -netdev "$net0_options"
fi

if [ "$pcap_file" != "none" ]; then
  set -- "$@" \
    -object "filter-dump,id=xaios_x86_net_capture,netdev=net0,file=$pcap_file"
fi

if [ "${XAIOS_QEMU_RNG:-virtio}" != "none" ]; then
  set -- "$@" \
    -object rng-random,filename=/dev/urandom,id=xaios_x86_rng \
    -device virtio-rng-pci,rng=xaios_x86_rng,disable-legacy=on
fi

if [ "$debug_log" != "" ]; then
  set -- "$@" -d int,cpu_reset -D "$debug_log"
fi

if [ "$nvme_image" != "" ]; then
  if [ "$dry_run" -eq 0 ] && [ ! -f "$nvme_image" ]; then
    printf '%s\n' "error: missing x86_64 NVMe image: $nvme_image" >&2
    exit 1
  fi
  set -- "$@" \
    -drive "if=none,format=raw,id=xaios_x86_nvme,file=$nvme_image" \
    -device nvme,drive=xaios_x86_nvme,serial=XAIOSNVME
fi

# Extra QEMU arguments, for gates that need a machine configured differently
# without a second copy of this runner drifting from it. The instruction-count
# gate uses it for -icount, which changes how the virtual clock advances and so
# must not be on by default.
if [ "${XAIOS_QEMU_EXTRA_ARGS:-}" != "" ]; then
  # Deliberately unquoted: this carries several arguments.
  # shellcheck disable=SC2086
  set -- "$@" $XAIOS_QEMU_EXTRA_ARGS
fi

if [ "$dry_run" -eq 1 ]; then
  print_command "$@"
  exit 0
fi

exec "$@"

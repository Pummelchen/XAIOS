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

case "$accel" in
  hvf) cpu="${XAIOS_QEMU_CPU:-host}" ;;
  *) cpu="${XAIOS_QEMU_CPU:-cortex-a72}" ;;
esac

machine="${XAIOS_QEMU_MACHINE:-virt}"
iommu="${XAIOS_QEMU_IOMMU:-none}"
memory="${XAIOS_QEMU_MEMORY:-2G}"
smp="${XAIOS_QEMU_SMP:-4}"
image="${XAIOS_AARCH64_IMAGE:-build/xaios-aarch64.img}"
test_block_image="${XAIOS_TEST_BLOCK_IMAGE:-build/xaios-virtio-test.img}"
persistent_image="${XAIOS_PERSISTENT_IMAGE:-build/xaios-persistent.img}"
model_volume_image="${XAIOS_MODEL_VOLUME_IMAGE:-build/xaios-model-volume.img}"
system_volume_image="${XAIOS_SYSTEM_VOLUME_IMAGE:-build/xaios-system.img}"
model_volume_discard="${XAIOS_QEMU_MODEL_DISCARD:-none}"
storage_admin_image="${XAIOS_STORAGE_ADMIN_IMAGE:-none}"
nvme_image="${XAIOS_NVME_IMAGE:-none}"
hostfwd_port="${XAIOS_QEMU_HOSTFWD_PORT:-7788}"
hostfwd_udp_port="${XAIOS_QEMU_HOSTFWD_UDP_PORT:-none}"
net_socket_port="${XAIOS_QEMU_NET_SOCKET_PORT:-none}"
net_socket_port_2="${XAIOS_QEMU_NET_SOCKET_PORT_2:-none}"
net_socket_host="${XAIOS_QEMU_NET_SOCKET_HOST:-127.0.0.1}"
pcap_file="${XAIOS_QEMU_PCAP:-none}"

case "$iommu" in
  none) machine_options="$machine,accel=$accel,gic-version=3" ;;
  smmuv3)
    machine_options="$machine,accel=$accel,gic-version=3,iommu=smmuv3,acpi=off"
    ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_IOMMU must be none or smmuv3" >&2
    exit 2
    ;;
esac

if [ "$iommu" = "smmuv3" ]; then
  if ! qemu_devices="$("$qemu" -device help 2>&1)"; then
    printf '%s\n' "error: selected QEMU could not run the SMMUv3 device probe" >&2
    printf '%s\n' "$qemu_devices" >&2
    exit 1
  fi
  if ! printf '%s\n' "$qemu_devices" |
       grep -F 'name "iommu-testdev"' >/dev/null; then
    printf '%s\n' \
      "error: selected QEMU does not provide iommu-testdev required by the SMMUv3 gate" >&2
    exit 1
  fi
fi

if [ "$net_socket_port_2" != "none" ] && [ "$net_socket_port" = "none" ]; then
  printf '%s\n' "error: XAIOS_QEMU_NET_SOCKET_PORT_2 requires XAIOS_QEMU_NET_SOCKET_PORT" >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$image" ]; then
  printf '%s\n' "error: missing AArch64 boot image: $image" >&2
  printf '%s\n' "       Complete WP-003/WP-004 image creation first, or set XAIOS_AARCH64_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$test_block_image" ]; then
  printf '%s\n' "error: missing VirtIO test block image: $test_block_image" >&2
  printf '%s\n' "       Run make image first, or set XAIOS_TEST_BLOCK_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$persistent_image" ]; then
  printf '%s\n' "note: persistent image not found, creating: $persistent_image"
  dd if=/dev/zero of="$persistent_image" bs=512 count=8192 status=none
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$model_volume_image" ]; then
  printf '%s\n' "error: missing ModelFS image: $model_volume_image" >&2
  printf '%s\n' "       Run make image first, or set XAIOS_MODEL_VOLUME_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$system_volume_image" ]; then
  printf '%s\n' "error: missing A/B system volume: $system_volume_image" >&2
  printf '%s\n' "       Run make image first, or set XAIOS_SYSTEM_VOLUME_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$storage_admin_image" != "none" ] && [ "$dry_run" -eq 0 ] &&
   [ ! -f "$storage_admin_image" ]; then
  printf '%s\n' "error: missing storage administration image: $storage_admin_image" >&2
  exit 1
fi

if [ "$nvme_image" != "none" ] && [ "$dry_run" -eq 0 ] &&
   [ ! -f "$nvme_image" ]; then
  printf '%s\n' "error: missing NVMe test image: $nvme_image" >&2
  exit 1
fi

case "$model_volume_discard" in
  none) model_drive_options="" ;;
  unmap) model_drive_options=",discard=unmap,detect-zeroes=unmap" ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_MODEL_DISCARD must be none or unmap" >&2
    exit 2
    ;;
esac

set -- "$qemu" \
  -machine "$machine_options" \
  -cpu "$cpu" \
  -m "$memory" \
  -smp "$smp" \
  -global virtio-mmio.force-legacy=false \
  -nographic \
  -serial mon:stdio \
  -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
  -drive "if=none,format=raw,id=xaios_boot,file=$image" \
  -device virtio-blk-pci,drive=xaios_boot,bootindex=0 \
  -drive "if=none,format=raw,id=xaios_test_block,file=$test_block_image" \
  -device virtio-blk-device,drive=xaios_test_block,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xaios_persistent,file=$persistent_image" \
  -device virtio-blk-device,drive=xaios_persistent,bus=virtio-mmio-bus.1 \
  -drive "if=none,format=raw,id=xaios_models,file=$model_volume_image$model_drive_options" \
  -device virtio-blk-device,drive=xaios_models,bus=virtio-mmio-bus.4 \
  -blockdev "driver=file,node-name=xaios_system_uefi_file,filename=$system_volume_image,locking=off,cache.direct=on" \
  -blockdev driver=raw,node-name=xaios_system_uefi,file=xaios_system_uefi_file \
  -device virtio-blk-pci,drive=xaios_system_uefi,bootindex=1 \
  -blockdev "driver=file,node-name=xaios_system_kernel_file,filename=$system_volume_image,locking=off,cache.direct=on" \
  -blockdev driver=raw,node-name=xaios_system_kernel,file=xaios_system_kernel_file \
  -device virtio-blk-device,drive=xaios_system_kernel,bus=virtio-mmio-bus.6

if [ "$iommu" = "smmuv3" ]; then
  set -- "$@" -device iommu-testdev,addr=06.0
fi

if [ "$storage_admin_image" != "none" ]; then
  set -- "$@" \
    -drive "if=none,format=raw,discard=unmap,detect-zeroes=unmap,id=xaios_storage_admin,file=$storage_admin_image" \
    -device virtio-blk-device,drive=xaios_storage_admin,bus=virtio-mmio-bus.5
fi

if [ "$nvme_image" != "none" ]; then
  set -- "$@" \
    -drive "if=none,format=raw,id=xaios_nvme,file=$nvme_image" \
    -device nvme,serial=XAIOSNVME,drive=xaios_nvme
fi

set -- "$@" \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0

if [ "$net_socket_port" != "none" ] && {
  [ "$net_socket_port_2" != "none" ] ||
  [ "$hostfwd_port" != "none" ] ||
  [ "$hostfwd_udp_port" != "none" ]
}; then
  if [ "$hostfwd_port" != "none" ] || [ "$hostfwd_udp_port" != "none" ]; then
    # Synthetic framed IPv6 clients share this test hub. Keep SLIRP from
    # interpreting and resetting their frames; host forwarding here is IPv4.
    net1_user_options="user,id=net1_user,ipv6=off"
    if [ "$hostfwd_port" != "none" ]; then
      net1_user_options="${net1_user_options},hostfwd=tcp::${hostfwd_port}-:22"
    fi
    if [ "$hostfwd_udp_port" != "none" ]; then
      net1_user_options="${net1_user_options},hostfwd=udp::${hostfwd_udp_port}-:2223"
    fi
    set -- "$@" \
      -netdev "$net1_user_options" \
      -netdev "hubport,id=net1_user_hub,hubid=1,netdev=net1_user"
  fi
  set -- "$@" \
    -netdev "stream,id=net1_socket,server=on,addr.type=inet,addr.host=${net_socket_host},addr.port=${net_socket_port}" \
    -netdev "hubport,id=net1_socket_hub,hubid=1,netdev=net1_socket"
  if [ "$net_socket_port_2" != "none" ]; then
    set -- "$@" \
      -netdev "stream,id=net1_socket_2,server=on,addr.type=inet,addr.host=${net_socket_host},addr.port=${net_socket_port_2}" \
      -netdev "hubport,id=net1_socket_2_hub,hubid=1,netdev=net1_socket_2"
  fi
  set -- "$@" -netdev "hubport,id=net1,hubid=1"
elif [ "$net_socket_port" != "none" ]; then
  net1_options="stream,id=net1,server=on,addr.type=inet,addr.host=${net_socket_host},addr.port=${net_socket_port}"
  set -- "$@" -netdev "$net1_options"
else
  net1_options="user,id=net1"
  if [ "$hostfwd_port" != "none" ]; then
    net1_options="${net1_options},hostfwd=tcp::${hostfwd_port}-:22"
  fi
  if [ "$hostfwd_udp_port" != "none" ]; then
    net1_options="${net1_options},hostfwd=udp::${hostfwd_udp_port}-:2223"
  fi
  set -- "$@" -netdev "$net1_options"
fi

set -- "$@" \
  -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57,bus=virtio-mmio-bus.2

if [ "$pcap_file" != "none" ]; then
  set -- "$@" \
    -object "filter-dump,id=xaios_net1_capture,netdev=net1,file=$pcap_file"
fi

if [ "${XAIOS_QEMU_RNG:-virtio}" != "none" ]; then
  set -- "$@" \
    -object rng-random,filename=/dev/urandom,id=xaios_rng \
    -device virtio-rng-device,rng=xaios_rng,bus=virtio-mmio-bus.3
fi

if [ "${XAIOS_QEMU_NET_DUMP:-}" != "" ]; then
  set -- "$@" -object "filter-dump,id=xaios_net_dump,netdev=net1,file=${XAIOS_QEMU_NET_DUMP}"
fi

if [ "${XAIOS_QEMU_DEBUG:-}" != "" ]; then
  set -- "$@" -d "$XAIOS_QEMU_DEBUG"
fi

if [ "$dry_run" -eq 1 ]; then
  print_command "$@"
  exit 0
fi

exec "$@"

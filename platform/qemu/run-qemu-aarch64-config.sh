
case "$accel" in
  hvf) cpu="${XAIOS_QEMU_CPU:-host}" ;;
  *) cpu="${XAIOS_QEMU_CPU:-cortex-a72}" ;;
esac

machine="${XAIOS_QEMU_MACHINE:-virt}"
iommu="${XAIOS_QEMU_IOMMU:-none}"
# Two gibibytes, and not one, for a reason that is arithmetic rather than
# taste. The kernel is linked at a fixed 0x90000000 (kernel/arch/aarch64/
# linker.ld), and the three hypervisors do not agree on where usable memory
# starts: QEMU's begins at 0x40000000, Virtualization.framework's at
# 0x70000000, VMware Fusion's at 0x80000000. A guest given one gibibyte on
# QEMU therefore owns [0x40000000, 0x80000000) -- which ends exactly where
# Fusion's memory begins, so no single fixed link address can sit inside both.
# Lowering the figure means making the kernel relocatable first. Until then
# this is the smallest number that boots everywhere.
memory="${XAIOS_QEMU_MEMORY:-2G}"

# B-14's other half: a block device that really advertises VIRTIO_BLK_F_RO.
#
# The kernel's block self-test asks whether the medium is writable and, when
# it is not, verifies that a write is refused and runs everything that does
# not depend on having written. That branch had never executed. The row
# recorded the reason as QEMU discarding writes while still advertising the
# device as writable -- but /dev/vblk0 is this scratch device, not the boot
# medium, and this drive was never attached read-only in the first place, so
# what the guest reported said nothing about the boot drive either way.
#
# Off by default: the partition self-test writes a table to this device, and
# a read-only scratch disk is a different test rather than a stricter one.
test_block_mode="snapshot=on"
if [ "${XAIOS_QEMU_TEST_BLOCK_READONLY:-0}" = "1" ]; then
  test_block_mode="readonly=on"
fi
smp="${XAIOS_QEMU_SMP:-4}"
image="${XAIOS_AARCH64_IMAGE:-build/xaios-aarch64.img}"
test_block_image="${XAIOS_TEST_BLOCK_IMAGE:-build/xaios-virtio-test.img}"
persistent_image="${XAIOS_PERSISTENT_IMAGE:-build/xaios-persistent.img}"
xai_fs_image="${XAIOS_XAI_FS_IMAGE:-build/xaios-xaifs.img}"
system_volume_image="${XAIOS_SYSTEM_VOLUME_IMAGE:-build/xaios-system.img}"
xai_fs_discard="${XAIOS_QEMU_MODEL_DISCARD:-none}"
# Where to record every write and flush the guest sends the models volume.
#
# Unset by default and off every ordinary path. When set, the models drive is
# attached through QEMU's blklogwrites driver, which passes each request
# through to the image and also appends it -- header and full payload -- to
# this file, in the dm-log-writes format the kernel's power-failure testing
# harness uses. That log is the only thing that makes an honest power cut
# possible here: no cache mode loses a write when the emulator is killed,
# because the write already reached the host's page cache and the host
# outlives the process. Replaying the log while dropping what was never
# flushed is the device that loses it. See tools/xaios_write_log.py.
#
# The file must already exist and is overwritten from its first byte; QEMU's
# file driver will not create it.
xai_fs_write_log="${XAIOS_XAI_FS_WRITE_LOG:-none}"
storage_admin_image="${XAIOS_STORAGE_ADMIN_IMAGE:-none}"
nvme_image="${XAIOS_NVME_IMAGE:-none}"
hostfwd_port="${XAIOS_QEMU_HOSTFWD_PORT:-7788}"
hostfwd_udp_port="${XAIOS_QEMU_HOSTFWD_UDP_PORT:-none}"
# A host port carried to the guest's cluster listener.
#
# The other forwards here are fixed to the services they serve -- 22 for ssh,
# 2223 for the UDP echo. A machine acting as the listening end of a cluster
# needs its cluster port reachable from outside the guest, which is what lets
# the peer be another machine rather than a process on this host.
cluster_hostfwd_port="${XAIOS_QEMU_CLUSTER_HOSTFWD_PORT:-none}"
cluster_guest_port="${XAIOS_QEMU_CLUSTER_GUEST_PORT:-7799}"
# Which host address that forward binds. Loopback by default, because a port
# reachable from the network is a decision rather than a default; a machine
# serving a peer on another continent sets 0.0.0.0 deliberately.
cluster_hostfwd_bind="${XAIOS_QEMU_CLUSTER_HOSTFWD_BIND:-127.0.0.1}"
network_device="${XAIOS_QEMU_NETWORK_DEVICE:-virtio-net-device}"
net_socket_port="${XAIOS_QEMU_NET_SOCKET_PORT:-none}"
net_socket_port_2="${XAIOS_QEMU_NET_SOCKET_PORT_2:-none}"
net_socket_host="${XAIOS_QEMU_NET_SOCKET_HOST:-127.0.0.1}"
pcap_file="${XAIOS_QEMU_PCAP:-none}"
msi_controller="${XAIOS_QEMU_MSI_CONTROLLER:-auto}"
keyboard_device="${XAIOS_QEMU_KEYBOARD:-usb}"
qmp_socket="${XAIOS_QEMU_QMP_SOCKET:-}"

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

# The virt machine only grew an "msi" property in newer QEMU releases. Older
# builds still route MSI through the ITS whenever one is instantiated, so ask
# the binary what it supports rather than passing an option that makes it
# refuse to start: on QEMU 8.2 the explicit form fails with
# "Property 'virt-8.2-machine.msi' not found" and the guest never boots.
if "$qemu" -machine virt,help 2>/dev/null | grep -q '^[[:space:]]*msi='; then
  machine_msi_property=1
else
  machine_msi_property=0
fi

case "$msi_controller" in
  auto) ;;
  gicv2m)
    if [ "$machine_msi_property" -eq 1 ]; then
      machine_options="$machine_options,msi=gicv2m"
    else
      printf '%s\n' \
        "error: this QEMU cannot select GICv2m explicitly; it has no virt machine msi property" >&2
      exit 2
    fi
    ;;
  its)
    machine_options="$machine_options,its=on"
    if [ "$machine_msi_property" -eq 1 ]; then
      machine_options="$machine_options,msi=its"
    fi
    ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_MSI_CONTROLLER must be auto, gicv2m, or its" >&2
    exit 2
    ;;
esac

case "$network_device" in
  virtio-net-device|e1000e) ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_NETWORK_DEVICE must be virtio-net-device or e1000e" >&2
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
  dd if=/dev/zero of="$persistent_image" bs=512 \
    count="${XAIOS_PERSISTENT_SECTORS:-32768}" status=none
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$xai_fs_image" ]; then
  printf '%s\n' "error: missing xaiFS image: $xai_fs_image" >&2
  printf '%s\n' "       Run make image first, or set XAIOS_XAI_FS_IMAGE=/path/to/image.img." >&2
  exit 1
fi

# "none" attaches no system volume, which is not the same as an empty one.
#
# The loader prefers a verified A/B slot over the copy of the kernel on the
# medium, so a machine booted from a release image with a developer's system
# volume attached runs the kernel from that volume -- which looks exactly like
# the image booting and is not. A first boot on a real machine has no such
# volume, and this is how a gate arranges for the same thing.
if [ "$system_volume_image" != "none" ] && [ "$dry_run" -eq 0 ] &&
   [ ! -f "$system_volume_image" ]; then
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

case "$xai_fs_discard" in
  none) model_drive_options="" ;;
  unmap) model_drive_options=",discard=unmap,detect-zeroes=unmap" ;;
  *)
    printf '%s\n' "error: XAIOS_QEMU_MODEL_DISCARD must be none or unmap" >&2
    exit 2
    ;;
esac

# Discard and the write log together would be a quiet lie: blklogwrites does
# record discards, but the replayer has no way to know which bytes a hole
# reads back as on a device it never saw, so it would drop them and the volume
# it produced would not be the one the guest wrote. Rather than pick a
# plausible answer, refuse the combination.
if [ "$xai_fs_write_log" != "none" ] && [ "$xai_fs_discard" != "none" ]; then
  printf '%s\n' "error: XAIOS_XAI_FS_WRITE_LOG cannot be combined with XAIOS_QEMU_MODEL_DISCARD=$xai_fs_discard" >&2
  exit 2
fi
if [ "$xai_fs_write_log" != "none" ] && [ "$dry_run" -eq 0 ] &&
   [ ! -f "$xai_fs_write_log" ]; then
  printf '%s\n' "error: missing write log file: $xai_fs_write_log" >&2
  printf '%s\n' "       Create it first (an empty file is fine); QEMU's file driver does not." >&2
  exit 2
fi

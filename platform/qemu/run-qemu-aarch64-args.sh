
set -- "$qemu" \
  -machine "$machine_options" \
  -cpu "$cpu" \
  -m "$memory" \
  -smp "$smp" \
  -global virtio-mmio.force-legacy=false \
  -nographic \
  -serial mon:stdio \
  -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
  -drive "if=none,format=raw,readonly=on,id=xaios_boot,file=$image" \
  -device virtio-blk-pci,drive=xaios_boot,bootindex=0 \
  -drive "if=none,format=raw,$test_block_mode,id=xaios_test_block,file=$test_block_image" \
  -device virtio-blk-device,drive=xaios_test_block,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xaios_persistent,file=$persistent_image" \
  -device virtio-blk-device,drive=xaios_persistent,bus=virtio-mmio-bus.1

if [ "$xai_fs_write_log" = "none" ]; then
  set -- "$@" \
    -drive "if=none,format=raw,id=xaios_models,file=$xai_fs_image$model_drive_options" \
    -device virtio-blk-device,drive=xaios_models,bus=virtio-mmio-bus.4
else
  # Same device on the same bus slot, so the guest cannot tell the difference
  # and the kernel needs no knowledge of this at all -- blklogwrites sits
  # between the virtio-blk device and the image, passes every request through,
  # and writes what it saw to the log.
  #
  # log-append=off starts a fresh log: this is a per-boot recording, and
  # appending to whatever a previous run left would replay another run's
  # writes into this run's volume.
  set -- "$@" \
    -blockdev "driver=file,node-name=xaios_models_file,filename=$xai_fs_image,locking=off" \
    -blockdev "driver=raw,node-name=xaios_models_raw,file=xaios_models_file" \
    -blockdev "driver=file,node-name=xaios_models_log_file,filename=$xai_fs_write_log,locking=off" \
    -blockdev "driver=blklogwrites,node-name=xaios_models,file=xaios_models_raw,log=xaios_models_log_file,log-append=off,log-sector-size=512" \
    -device virtio-blk-device,drive=xaios_models,bus=virtio-mmio-bus.4
fi

if [ "$system_volume_image" != "none" ]; then
  set -- "$@" \
    -blockdev "driver=file,node-name=xaios_system_uefi_file,filename=$system_volume_image,locking=off,cache.direct=on" \
    -blockdev driver=raw,node-name=xaios_system_uefi,file=xaios_system_uefi_file \
    -device virtio-blk-pci,drive=xaios_system_uefi,bootindex=1 \
    -blockdev "driver=file,node-name=xaios_system_kernel_file,filename=$system_volume_image,locking=off,cache.direct=on" \
    -blockdev driver=raw,node-name=xaios_system_kernel,file=xaios_system_kernel_file \
    -device virtio-blk-device,drive=xaios_system_kernel,bus=virtio-mmio-bus.6
fi

if [ "$keyboard_device" = "usb" ]; then
  set -- "$@" \
    -device qemu-xhci,id=xaios_xhci \
    -device usb-kbd,bus=xaios_xhci.0
fi

if [ "$qmp_socket" != "" ]; then
  rm -f "$qmp_socket"
  set -- "$@" -qmp "unix:${qmp_socket},server=on,wait=off"
fi

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

# The address range SLIRP hands the guest on its routed interface. Default
# unset, which leaves QEMU's own 10.0.2.0/24 and every existing gate
# unchanged. It exists because a /24 is the only thing a guest here has ever
# been given, so anything that reads a netmask and gets it wrong looks correct
# in every test: B-18 was a routing log that printed "/24" whatever the lease
# said, and no gate could have caught it.
#
# It applies to net1 rather than net0. net1 is the interface the persistent
# network stack configures and routes through -- `routing: initialized` reports
# its network -- and net0 is a second, unrouted one. Setting it on net0 changes
# an address nothing reads.
user_net_cidr="${XAIOS_QEMU_USER_NET_CIDR:-none}"
# The IPv6 prefix this machine's user network advertises.
#
# SLIRP advertises fec0::/64 by default, which is site-local -- deprecated
# address space, and this stack deliberately keeps g_public_v6 for genuinely
# global addresses, so a guest on the default network forms a SLAAC address
# that is correctly not treated as public and reports only its link-local one.
# That is right behaviour and it left the capability matrix unable to say SLAAC
# was evidenced under QEMU at all.
#
# Setting a global prefix makes the question answerable. 2001:db8::/32 is the
# documentation range, reserved by RFC 3849 precisely so it can be used in
# examples without colliding with anyone's real allocation, and it is global
# scope, so a guest that forms an address from it exercises the same path a
# real advertisement would.
user_net_ipv6="${XAIOS_QEMU_USER_NET_IPV6:-none}"

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
    if [ "$cluster_hostfwd_port" != "none" ]; then
      net1_user_options="${net1_user_options},hostfwd=tcp:${cluster_hostfwd_bind}:${cluster_hostfwd_port}-:${cluster_guest_port}"
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
  if [ "$user_net_cidr" != "none" ]; then
    net1_options="${net1_options},net=${user_net_cidr}"
  fi
  if [ "$user_net_ipv6" != "none" ]; then
    net1_options="${net1_options},ipv6-net=${user_net_ipv6}"
  fi
  if [ "$hostfwd_port" != "none" ]; then
    net1_options="${net1_options},hostfwd=tcp::${hostfwd_port}-:22"
  fi
  if [ "$hostfwd_udp_port" != "none" ]; then
    net1_options="${net1_options},hostfwd=udp::${hostfwd_udp_port}-:2223"
  fi
  if [ "$cluster_hostfwd_port" != "none" ]; then
    net1_options="${net1_options},hostfwd=tcp:${cluster_hostfwd_bind}:${cluster_hostfwd_port}-:${cluster_guest_port}"
  fi
  set -- "$@" -netdev "$net1_options"
fi

if [ "$network_device" = "virtio-net-device" ]; then
  set -- "$@" \
    -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57,bus=virtio-mmio-bus.2
else
  set -- "$@" \
    -device e1000e,netdev=net1,mac=52:54:00:12:34:57
fi

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

if [ "${XAIOS_QEMU_TRACE:-}" != "" ]; then
  set -- "$@" -trace "$XAIOS_QEMU_TRACE"
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

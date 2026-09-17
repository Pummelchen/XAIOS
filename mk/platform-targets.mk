# Hypervisor and RISC-V platform targets and their gates.

vmware-fusion-image: image
	./platform/vmware-fusion/build-vmware-fusion.sh

vmware-fusion: vmware-fusion-image
	./platform/vmware-fusion/run-vmware-fusion.sh

vmware-fusion-smoke:
	python3 ./tests/scripts/vmware-fusion-smoke.py

# RISC-V rv64gc bring-up. Boots via OpenSBI on the QEMU `virt` board rather
# than UEFI, which is why it has its own build script and no boot medium.
# B-68: this built the kernel and stopped, while every consumer of it boots a
# machine -- and a machine needs an initial filesystem. Eight gates took this
# as a prerequisite and then died on "no initial filesystem"; the ones that
# worked did so because they repeated the image step in their own recipe. The
# fix is for the target to mean what its users assume it means. Building the
# image is idempotent and takes seconds, so the recipes that still call it
# themselves are harmless repetition rather than a second build.
riscv64:
	./scripts/build-riscv64.sh
	./scripts/build-riscv64-image.sh

qemu-riscv64-gate: riscv64
	./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-riscv64-gate.py

qemu-riscv64-boot-media-gate: riscv64
	./scripts/build-riscv64-image.sh
	./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-riscv64-boot-media-gate.py

qemu-riscv64-matrix-gate: riscv64
	./scripts/build-riscv64-image.sh
	./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-riscv64-matrix-gate.py

qemu-riscv64-durability-gate: riscv64
	./scripts/build-riscv64-image.sh
	./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-riscv64-durability-gate.py

# The release configuration -- what the other architectures ship as `make
# image` -- launches applications as processes, which the boot-test gates
# above never do. Built with the switch the other builders read.
qemu-riscv64-release-gate:
	XAIOS_BOOT_TEST_APPS=0 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=0 ./scripts/build-riscv64-image.sh
	XAIOS_BOOT_TEST_APPS=0 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-riscv64-release-gate.py

# Proves a panic on Fusion can be read, by causing one. Builds a kernel that
# asserts on purpose, so it leaves a deliberately broken image in build/ --
# rebuild before running anything else against it.
# F-04: what a snapshot means, demonstrated rather than described.
# F-03: what the guest's network does on the LAN it is bridged to. IPv6 from
# a real router advertisement, ICMPv6, TCP on both families, and a file each
# way over SFTP on the IPv6 address.
vmware-fusion-network-gate:
	python3 ./tests/scripts/vmware-fusion-network-gate.py

# F-03: outbound SSH/SCP from the guest and direct-tcpip forwarding through
# it, against a disposable container on this host's LAN address.
vmware-fusion-outbound-gate:
	python3 ./tests/scripts/vmware-fusion-outbound-gate.py

# B-37: the outbound client without a terminal. Builds its own images, one per
# identity form, because a private key reaches the guest only by being packed
# in -- the kernel refuses to store credential material at runtime.
qemu-outbound-batch-mode-gate:
	python3 ./tests/scripts/qemu-outbound-batch-mode-gate.py

# B-38: SFTP, forwards and agent channels carry arbitrary bytes, so they must
# not pass through the screen framework's alternate-screen filter. Gated on
# what the channel is, because no byte test can work on arbitrary payload.
qemu-sftp-binary-passthrough-gate:
	python3 ./tests/scripts/qemu-sftp-binary-passthrough-gate.py

# B-40: a peer that takes a trickle, and the one thread that serves everyone.
qemu-sshd-transmit-rate-gate:
	python3 ./tests/scripts/qemu-sshd-transmit-rate-gate.py

# B-41: a channel that fails, and every channel behind it.
qemu-sshd-channel-starvation-gate:
	python3 ./tests/scripts/qemu-sshd-channel-starvation-gate.py

# B-43: why a served connection closed, said on the console rather than in an
# audit file nothing reads -- and whether sshd held the machine or was not
# running, which a peer cannot tell apart.
qemu-sshd-close-visibility-gate:
	python3 ./tests/scripts/qemu-sshd-close-visibility-gate.py

# B-47: the socket-to-flow map refusing rather than accepting and dropping.
qemu-socket-flow-map-gate: image-qemu-test
	python3 ./tests/scripts/qemu-socket-flow-map-gate.py

# WT-35: a datagram socket the kernel names, which is what a QUIC client has
# before its first packet. Reads both the kernel's allocation log and what the
# caller was told, because the row is about those two agreeing.
qemu-datagram-ephemeral-port-gate: image-qemu-test
	python3 ./tests/scripts/qemu-datagram-ephemeral-port-gate.py

# B-44: how long the network stack can go unpolled, measured rather than
# assumed. Builds its own image -- it needs an authorized key baked in.
qemu-network-poll-cadence-gate:
	python3 ./tests/scripts/qemu-network-poll-cadence-gate.py

# B-45: what an audit record costs the machine, measured on both sides of the
# fix. Builds this tree three times -- the filesystem and server as they were,
# the shipped default, and a control whose key cache never invalidates -- and
# drives the same forty connections through each. The baseline is the gate's
# falsifiability: if it does not show the defect, the gate fails rather than
# reporting a clean "after". RISC-V is refused: its build scripts have no
# cflags hook and would build the same image three times.
qemu-sshd-audit-append-gate:
	python3 ./tests/scripts/qemu-sshd-audit-append-gate.py

qemu-x86_64-sshd-audit-append-gate:
	python3 ./tests/scripts/qemu-sshd-audit-append-gate.py --arch x86_64

qemu-x86_64-sftp-binary-passthrough-gate:
	python3 ./tests/scripts/qemu-sftp-binary-passthrough-gate.py --arch x86_64

qemu-riscv64-sftp-binary-passthrough-gate: riscv64
	python3 ./tests/scripts/qemu-sftp-binary-passthrough-gate.py --arch riscv64

vmware-fusion-snapshot-gate:
	python3 ./tests/scripts/vmware-fusion-snapshot-gate.py

# V-06's remaining boundary on this platform: what Fusion's own display shows
# at a login prompt, read back with vmrun captureScreen.
vmware-fusion-framebuffer-gate:
	python3 ./tests/scripts/vmware-fusion-framebuffer-gate.py

# The hypervisors at 1, 2 and 4 GiB, which qemu-memory-matrix does for the
# three QEMU architectures. Both hypervisor gates ran only at 2048 -- the one
# size where B-06 cannot occur and the only Fusion size where the framebuffer
# lands inside the identity map.
hypervisor-memory-matrix:
	python3 ./tests/scripts/hypervisor-memory-matrix.py

vmware-fusion-panic-capture:
	python3 ./tests/scripts/vmware-fusion-panic-capture.py

# Boots Fusion over and over, keeping every console. Not a gate: it is the
# reproduction harness for B-15 and exits non-zero only if it reproduces.
vmware-fusion-boot-soak:
	python3 ./tests/scripts/vmware-fusion-boot-soak.py

# F-04's remaining shape: one boot held under storage and network load, rather
# than many boots. A leak of a page per operation is invisible in a boot and
# obvious over a thousand operations.
vmware-fusion-load-soak:
	python3 ./tests/scripts/vmware-fusion-load-soak.py

# Local only: needs macOS on Apple Silicon and a signed harness, so it is not
# part of CI and its result is not qualification evidence.
vz-harness:
	mkdir -p build/vz
	xcrun swiftc -O -o build/vz/xaios-vz platform/virtualization-framework/xaios_vz.swift
	codesign --force --sign - --entitlements platform/virtualization-framework/xaios-vz.entitlements build/vz/xaios-vz

# The gate reads the kernel log, which boot_ui silences on a quiet boot, so it
# builds a verbose image rather than depending on the default one.
# Boot by hand, with every volume refreshed first. Attaching a volume older
# than the last build can boot the kernel that volume carries instead of the
# one just built, silently. See platform/virtualization-framework/run-vz.sh.
# DHCPv6 against a real server on the guest's link. No environment XAIOS boots
# in runs one, so the gate supplies it; see tests/network/qemu-dhcpv6-server.py.
qemu-dhcpv6-gate: image-qemu-test
	python3 ./tests/scripts/qemu-dhcpv6-gate.py

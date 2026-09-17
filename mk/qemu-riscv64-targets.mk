# QEMU runners and the RISC-V gates that boot through them.

qemu:
	./platform/qemu/run-qemu-aarch64.sh

qemu-aarch64:
	./platform/qemu/run-qemu-aarch64.sh

qemu-x86_64: image-x86_64
	./platform/qemu/run-qemu-x86_64.sh

# The RISC-V machine, beside the other two. A gate that boots a guest asks
# make for the machine rather than reaching for a runner, so an architecture
# without this target cannot be reached by any of them -- which is one
# reason this one had six gates against seventy.
qemu-riscv64:
	./platform/qemu/run-qemu-riscv64.sh

# The full boot closure on RISC-V, through the same helper that runs it on
# AArch64: the shared markers are shared, and each architecture is required
# to describe its own interrupt controller, page tables and timer in its own
# words rather than to imitate another's.
qemu-riscv64-smoke:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-smoke.py --arch riscv64

# The RISC-V IOMMU's isolation proof (B-130): a guest booted with the PCI
# device and two iommu-testdev functions attached, one whose DMA the driver
# translates and one whose context it deliberately never installs. The report
# says the run is about correctness rather than performance, and
# docs/RISCV-IOMMU.md says what this board cannot prove.
qemu-riscv64-iommu-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-riscv-iommu-gate.py

# The same seven milestones on RISC-V. What each asserts is a property of
# the system rather than of the machine, so the configuration is shared and
# only the boot underneath it changes.

qemu-riscv64-filesystem-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 62 --arch riscv64

qemu-riscv64-app-agent-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 63 --arch riscv64

qemu-riscv64-network-full-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 64 --arch riscv64

qemu-riscv64-cpu-ai-runtime-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 65 --arch riscv64

qemu-riscv64-ai-cell-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 66 --arch riscv64

qemu-riscv64-security-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 67 --arch riscv64

qemu-riscv64-update-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-milestone-gate.py 68 --arch riscv64

# Seven more that only ever needed a boot they could name. Same assertions,
# same helper, a different machine underneath.

qemu-riscv64-process-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-process-gate.py --arch riscv64

qemu-riscv64-osctl-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-osctl-gate.py --arch riscv64

qemu-riscv64-userspace-suite:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-userspace-suite.py --arch riscv64

qemu-riscv64-network-suite:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-network-suite.py --arch riscv64

qemu-riscv64-cpu-ai-suite:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-cpu-ai-suite.py --arch riscv64

qemu-riscv64-fault-injection:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-fault-injection.py --arch riscv64

qemu-riscv64-regression-suite:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-regression-suite.py --arch riscv64

# Storage that survives a reboot, on RISC-V. The disks live in a state
# directory there rather than in a named image, which is the whole reason
# this gate could not simply be pointed at another runner.
qemu-riscv64-persistence-reboot:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-persistence-reboot.py --arch riscv64

# What only this architecture has: SBI, hart state management, Sv48, the
# permission bits RISC-V spells no-execute with, and a hart leased out of
# the scheduler. The shared gates ask every machine the same questions,
# which says nothing about the ones only this machine can answer.
qemu-riscv64-isa-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-riscv64-isa-gate.py

# The framebuffer console on RISC-V: a login typed at the machine's own
# screen rather than over the network. The console parity gate already
# proves this machine has a framebuffer; this proves a person can use it.
qemu-riscv64-local-console-gate:
	python3 ./tests/scripts/qemu-local-console-gate.py --arch riscv64

# Write ordering on RISC-V: what the driver actually issued, in what order,
# and what the volume held afterwards. The runner takes a caller's own
# models volume now, which is what this gate needs to read back.
# Power loss at the two A/B metadata write points, on this architecture's
# block driver and through this architecture's firmware. The boot media are a
# prerequisite rather than a nicety: with -kernel nothing chooses a system
# slot, so the guest would come up with no A/B volume attached and the gate
# would watch a machine that never writes metadata at all.
qemu-riscv64-storage-crash-test:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-storage-crash-test.py --arch riscv64

# The other half of durability on this architecture: a machine killed at an
# arbitrary point in an ingest, and a volume that must hold either the whole
# commit or none of it. Same script, same fixture, this machine's driver.
# What a person sitting at this machine sees when it has finished booting,
# read back as pixels from outside the guest. The display is the same
# virtio-gpu the console-xtop gate uses here.
# Typing at the machine: a USB keyboard on the xHCI controller, keys injected
# through QMP, and a login that reaches a shell prompt on the local console.
# The HID driver is shared; what this proves here is that the controller is
# found and its interrupts are delivered on this machine's controller.
# A network that is not a /24, so a log line that says "/24" whatever the mask
# is fails here rather than looking right everywhere. The routing table is
# shared code; what this checks on this machine is that its one NIC takes the
# lease and the stack reports the mask it was actually given.
# What the block path and /models actually cost on this machine, cold and
# warm. Reported rather than asserted, except the one claim with teeth: a
# warm read must beat a cold one, which is what the read cache is for.
# What an operation costs in this architecture's instructions, counted by the
# emulator's own clock. Its own baseline: an instruction count is a count of
# these instructions, and a shared one would either fail everywhere but one
# machine or be too loose to catch anything.
# DHCPv6 against a real server on this machine's link, both the rapid-commit
# and the four-message exchange. Needs the second interface: the synthetic
# server speaks to the guest over a frame socket on it.
# More than a link's worth of IPv6 out of the guest, which it has to break up
# itself. The driver underneath is what differs here, so this is a test of
# this machine's descriptor chain and not a repeat of AArch64's.
# A model package pushed in over SFTP, interrupted, resumed, registered and
# then deleted, with the space it occupied actually released back to the
# host. Needs Docker for the Debian client half, as it does elsewhere.
# Three identical boots, and the invariants that must not move between them:
# core count, page totals, sector count, migrations, context switches, failed
# processes, flow/core mismatches, checksum errors.
# The hosted C99 runtime on this machine alone. The shared gate runs all
# three; this is the one leg, for when that is what changed.
# Three faults the kernel is built to take on purpose, and the class name
# this machine reports for each. RISC-V distinguishes load, store and
# instruction page faults, so "the write to read-only data was refused" is
# checkable here rather than inferred from a shared data-abort class.
# NVMe on a machine whose interrupt controller carries no messages: the
# queues run on polled completion, which the driver's wait path has always
# done while waiting. Everything else is held to the same answers as the
# other two.
# Repeated boots, to catch what one boot cannot: a resource that leaks, a
# race that only loses sometimes, a device that comes up on the second try.
# Two clients, macOS and Debian 13, loading one guest at once over SSH, SFTP
# and UDP while the wire is captured. Needs Docker for the Debian half.
# The full external-client network suite on this machine: a Debian 13
# container and a native macOS client against one guest, over SSH, SFTP,
# IPv6, UDP and a framed socket, with the credential policy checked by
# building images that must be refused.
# The package manager over pinned TLS on this machine: install, execute,
# upgrade, roll back, refuse a corrupted package, and take an OS slot update.
qemu-riscv64-xapt-gate:
	python3 tests/scripts/qemu-xapt-gate.py --arch riscv64

qemu-riscv64-docker-network-suite:
	python3 ./tests/scripts/qemu-docker-network-suite.py --arch riscv64

qemu-riscv64-parallel-network-load:
	python3 ./tests/scripts/qemu-parallel-network-load.py --arch riscv64

qemu-riscv64-soak-gate:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-soak-gate.py --arch riscv64

qemu-riscv64-nvme-gate: riscv64
	python3 ./tests/scripts/qemu-nvme-gate.py --arch riscv64

# The same kernel on both of this architecture's boards: polled on the PLIC
# one, delivered messages by the APLIC/IMSIC pair on the other. Separate from
# the NVMe gate because it also covers the wired half, which NVMe does not
# touch -- an NVMe MSI arrives from PCI and never passes through an APLIC.
qemu-riscv64-aia-gate: riscv64
	./scripts/build-riscv64-image.sh
	./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-riscv64-aia-gate.py

qemu-riscv64-fault-matrix:
	python3 ./tests/scripts/qemu-fault-matrix.py --arch riscv64

# The build these two lines used to carry is the RISC-V row of the gate's own
# image table, so this target is now the gate restricted to one architecture.
# Two copies of the build was how the full gate came to boot an image nothing
# in its own dependency chain had built.
qemu-riscv64-libc-gate: libc-check
	python3 tests/scripts/qemu-libc-gate.py --arch riscv64

# The boot, its telemetry and a manifest of what was actually run.
qemu-riscv64-preview:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-preview.py --arch riscv64

qemu-riscv64-boot-loop:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-boot-loop.py --arch riscv64

# One boot, its telemetry, and the contract gates read off it.
qemu-riscv64-benchmark:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-benchmark.py --arch riscv64

qemu-riscv64-model-sftp-gate: riscv64
	python3 ./tests/scripts/qemu-model-sftp-gate.py --arch riscv64

qemu-riscv64-outbound-fragmentation-gate: riscv64
	python3 ./tests/scripts/qemu-outbound-fragmentation-gate.py --arch riscv64

qemu-riscv64-dhcpv6-gate: riscv64
	python3 ./tests/scripts/qemu-dhcpv6-gate.py --arch riscv64

qemu-riscv64-instruction-cost-gate:
	XAIOS_STRESS_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-instruction-cost-gate.py --arch riscv64

qemu-riscv64-storage-bench:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_cache_fixture.py \
	  build/xaios-cache-fixture.img
	XAIOS_BOOT_TEST_APPS=1 XAIOS_STORAGE_BENCH=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-storage-bench.py --arch riscv64

qemu-riscv64-routing-prefix-gate: riscv64
	python3 ./tests/scripts/qemu-routing-prefix-gate.py --arch riscv64

qemu-riscv64-keyboard-input-gate:
	python3 ./tests/scripts/qemu-keyboard-input-gate.py --arch riscv64

qemu-riscv64-framebuffer-gate: riscv64
	python3 ./tests/scripts/qemu-framebuffer-gate.py --arch riscv64

qemu-riscv64-crash-safety-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_TEST_APPS=1 XAIOS_CRASH_WRITER=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	# The signed A/B system volume, which nothing else in this target
	# produces. The RISC-V runner copies it into its state directory and
	# fails at that copy before QEMU starts, so on a clean tree this gate
	# reported a guest that never committed a chunk -- and pointed at
	# XAIOS_CRASH_WRITER -- when what had happened was that no machine
	# was ever started.
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-crash-safety-gate.py --arch riscv64

qemu-riscv64-write-ordering-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_TEST_APPS=1 XAIOS_CRASH_WRITER=1 XAIOS_IO_TRACE=1 \
	  ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	# The signed A/B system volume, which nothing else in this target
	# produces. The RISC-V runner copies it into its state directory and
	# fails at that copy before QEMU starts, so on a clean tree this gate
	# reported a guest that never committed a chunk -- and pointed at
	# XAIOS_CRASH_WRITER -- when what had happened was that no machine
	# was ever started.
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-write-ordering-gate.py --arch riscv64

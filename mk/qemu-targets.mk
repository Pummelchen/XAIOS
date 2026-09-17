# The QEMU gate targets for the shared and per-architecture machines.

qemu-x86_64-numa-gate:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
	python3 tests/scripts/qemu-x86_64-numa-gate.py

qemu-aarch64-sve2-gate: image-qemu-test
	python3 tests/scripts/qemu-aarch64-sve2-gate.py

qemu-dry-run:
	./platform/qemu/run-qemu-aarch64.sh --dry-run
	./platform/qemu/run-qemu-x86_64.sh --dry-run
	./platform/qemu/run-qemu-riscv64.sh --dry-run

qemu-smoke: image-qemu-test
	python3 ./tests/scripts/qemu-smoke.py

# One disk, the way a machine XAIOS has been installed onto is arranged. The
# gate builds its own image, so it is not listed as depending on one.
qemu-installed-disk-gate:
	python3 ./tests/scripts/qemu-installed-disk-gate.py

qemu-riscv64-installed-disk-gate:
	python3 ./tests/scripts/qemu-installed-disk-gate.py --arch riscv64

# The install path runs on this architecture and had no evidence of it: the
# tracker said the gates proving it "run AArch64 QEMU and nothing else", and
# x86-64 has no install evidence at all despite running the same code.
qemu-x86_64-installed-disk-gate:
	python3 ./tests/scripts/qemu-installed-disk-gate.py --arch x86_64

# The kits a person downloads, booted from their own archives. Builds them
# first: a gate that tested last week's kit would pass while this week's is
# broken.
vm-packages:
	./scripts/build-vm-packages.sh

vm-package-gate: vm-packages
	python3 ./tests/scripts/vm-package-gate.py

# The two routes onto hardware rather than into a hypervisor: a stick a person
# writes, and a machine with no disk asking the network what to boot. Kept
# apart from vm-packages because they are different artifacts -- the netboot
# kit is not the image at all, it is a binary with the system inside it.
boot-media:
	./scripts/build-boot-media.sh

# Neither kit can be booted here -- one needs a stick in a machine, the other a
# server on a network -- so this checks what does live here: that the kits
# carry the files their READMEs name, that those files are the ones gated
# elsewhere, and that the install command has not been renamed underneath them.
boot-media-gate: boot-media
	python3 ./tests/scripts/boot-media-gate.py

# A machine with no account, set up by hand, and then used. Builds its own
# image because every ordinary build packages a credential and so never
# reaches setup at all.
qemu-setup-gate:
	python3 ./tests/scripts/qemu-setup-gate.py

qemu-riscv64-setup-gate:
	python3 ./tests/scripts/qemu-setup-gate.py --arch riscv64

# A machine with no kernel on its medium, installing itself onto a blank disk.
# The install at boot is what this gate is for, and an ordinary image does not
# carry it. The gate builds its own image and asks for it, so it behaves the
# same however it is invoked -- CI runs the script directly.
qemu-netboot-gate:
	python3 ./tests/scripts/qemu-netboot-gate.py

qemu-riscv64-netboot-gate:
	python3 ./tests/scripts/qemu-netboot-gate.py --arch riscv64

# Two nodes exchanging a sealed frame over a real network, one of them on the
# host with its own reading of the wire format.
# Two XAIOS machines rather than XAIOS and a host process: one listens, the
# other dials, and the sealed frame is opened and answered by the far end.
qemu-cluster-two-node-gate:
	python3 ./tests/scripts/qemu-cluster-two-node-gate.py

qemu-riscv64-cluster-two-node-gate:
	python3 ./tests/scripts/qemu-cluster-two-node-gate.py --arch riscv64

# Three machines, heartbeats, and two of them killed with no warning. The
# two-node gate above tests a cluster whose members announce their departures;
# this one tests the case they cannot -- a peer that simply stops answering --
# and the quorum question that does not exist until there is a third node to
# make a majority out of.
qemu-cluster-three-node-gate:
	python3 ./tests/scripts/qemu-cluster-three-node-gate.py

qemu-riscv64-cluster-three-node-gate:
	python3 ./tests/scripts/qemu-cluster-three-node-gate.py --arch riscv64

# Three machines and a broken link rather than a broken machine. The gate
# above kills an emulator, which stops answering AND stops sending; this one
# puts a fault-injecting relay between the nodes and cuts the links while
# every machine stays up, so both sides are alive, both are still
# heartbeating, and both have to decide separately what they are entitled to
# do. It cuts symmetrically (a 2-1 split), repairs it, then cuts one node's
# outbound links only -- heard by nobody, hearing everybody -- which is the
# case that breaks quorum logic written as though silence were mutual.
qemu-cluster-partition-gate:
	python3 ./tests/scripts/cluster_fault_relay.py --self-test
	python3 ./tests/scripts/qemu-cluster-partition-gate.py --self-test
	python3 ./tests/scripts/qemu-cluster-partition-gate.py

qemu-riscv64-cluster-partition-gate:
	python3 ./tests/scripts/cluster_fault_relay.py --self-test
	python3 ./tests/scripts/qemu-cluster-partition-gate.py --self-test
	python3 ./tests/scripts/qemu-cluster-partition-gate.py --arch riscv64

qemu-cluster-gate:
	XAIOS_CLUSTER_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-cluster-gate.py

qemu-riscv64-cluster-gate:
	XAIOS_CLUSTER_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_CLUSTER_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-cluster-gate.py --arch riscv64

qemu-process-gate: image-qemu-test
	python3 ./tests/scripts/qemu-process-gate.py

qemu-osctl-gate: image-qemu-test
	python3 ./tests/scripts/qemu-osctl-gate.py

qemu-filesystem-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 62

qemu-app-agent-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 63

qemu-network-full-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 64

qemu-cpu-ai-runtime-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 65

qemu-ai-cell-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 66

qemu-security-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 67

qemu-update-gate: image-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 68

# The same milestone on the third machine. There was no x86-64 update gate at
# all, so "it updates itself" was evidenced on two architectures of three and
# the third was never asked; the reason it could not be asked is in B-115 and
# B-116, and the gate builds its own image now rather than booting whichever one
# happened to be in build/.
qemu-x86_64-update-gate: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-milestone-gate.py 68 --arch x86_64

qemu-soak-gate: image-qemu-test
	python3 ./tests/scripts/qemu-soak-gate.py

qemu-release: image
	python3 ./tests/scripts/qemu-release.py

qemu-100-gate: image-qemu-test
	python3 ./tests/scripts/qemu-100-gate.py

# The paravirtual NIC VMware offers, on a machine that can be booted in a
# loop. QEMU implements the same device, so the driver written for Fusion is
# now testable in ninety seconds instead of by hand on one laptop -- which is
# how F-02's two layout defects were found.
qemu-x86_64-vmxnet3:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	XAIOS_QEMU_X86_NIC=vmxnet3 ./platform/qemu/run-qemu-x86_64.sh

qemu-vmxnet3-gate:
	python3 ./tests/scripts/qemu-vmxnet3-gate.py

# E4: the device steering received frames by flow hash. Linux, root and a
# multi-queue tap only -- macOS has no multi-queue backend for either transport.
qemu-rss-steering-gate:
	python3 ./tests/scripts/qemu-rss-steering-gate.py

qemu-x86_64-smoke: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-x86_64-smoke.py

intel-desktop-gate:
	python3 ./tests/scripts/intel-desktop-gate.py

qemu-operations-closure:
	python3 ./tests/scripts/qemu-operations-closure.py

qemu-high-core-gate: image-qemu-test
	python3 ./tests/scripts/qemu-high-core-gate.py

qemu-qualification-readiness:
	python3 ./tests/scripts/qemu-qualification-readiness.py

qemu-smmu-gate: image-qemu-test
	python3 ./tests/scripts/qemu-smmu-gate.py

# B-100's reproduction harness rather than a gate: the same row, repeated, with
# the host held under eight busy loops, because the defect appears in about two
# runs in ninety and a single run therefore tells you nothing. It exits non-zero
# when a run fails and says whether the failure was the self-test or the
# harness. It defaults to the row the defect was seen on, and
# `python3 tests/scripts/nvme-stress-soak.py --help` has the rest.
qemu-nvme-stress-soak: image-qemu-test image-x86_64-qemu-test riscv64
	python3 ./tests/scripts/nvme-stress-soak.py

qemu-x86_64-nvme-gate: image-x86_64-qemu-test
	XAIOS_QEMU_NVME_ARCH=x86_64 python3 ./tests/scripts/qemu-nvme-gate.py

qemu-preview: image-qemu-test
	python3 ./tests/scripts/qemu-preview.py

qemu-matrix:
	python3 ./tests/scripts/qemu-matrix.py

qemu-cpu-matrix: image-qemu-test image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-cpu-matrix.py

qemu-riscv64-cpu-matrix:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	XAIOS_QEMU_CPU_MATRIX_ARCH=riscv64 python3 ./tests/scripts/qemu-cpu-matrix.py

qemu-x86_64-cpu-matrix: image-x86_64-qemu-test
	XAIOS_QEMU_CPU_MATRIX_ARCH=x86_64 \
	XAIOS_QEMU_CPU_MATRIX_REPORT=build/qemu-x86_64-cpu-matrix-report.json \
	python3 ./tests/scripts/qemu-cpu-matrix.py

qemu-x86_64-platform-matrix: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-x86_64-platform-matrix.py

qemu-x86_64-repeat-boot: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-x86_64-repeat-boot.py

# What an operation costs in instructions, which is the same number on every
# machine. Regression detection now, and a baseline for when hardware arrives.
# perfbench runs only under XAIOS_STRESS_TEST, so an ordinary test image does
# not contain the measurement this gate reads. Depending on image-qemu-test
# meant the gate booted a machine that never reported anything and failed for
# a reason that looked like a timeout.
qemu-instruction-cost-gate:
	XAIOS_STRESS_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-instruction-cost-gate.py

qemu-benchmark: image-qemu-test
	python3 ./tests/scripts/qemu-benchmark.py

qemu-persistence-reboot:
	XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-persistence-reboot.py

qemu-storage-crash-test: image-qemu-test
	python3 ./tests/scripts/qemu-storage-crash-test.py

# Cut power to a machine in the middle of writing a model package, repeatedly,
# and check that nothing broken survived. Needs its own kernel, because the
# guest side is a writer that never returns, and its own volume, because the
# gate kills the machine while it is being written to.
qemu-crash-safety-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py 	  build/xaios-crash-fixture.img
	XAIOS_BOOT_VERBOSE=1 XAIOS_CRASH_WRITER=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-crash-safety-gate.py

# The flushes that volatile-cache safety depends on, checked from a trace the
# driver emits. Needs the crash writer for something to commit and the trace
# for something to read.
# A device that acknowledges writes and then loses the unflushed ones, for
# real: the models volume is recorded through QEMU's blklogwrites filter, the
# emulator is killed mid-ingest, and the recording is replayed while dropping
# what was never flushed. Then the result is booted. Needs the crash writer
# for something to commit, and the fixture for it to commit into. No trace
# build: this gate reads the device's own recording rather than the driver's
# account of itself.
qemu-power-loss-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_VERBOSE=1 XAIOS_CRASH_WRITER=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-power-loss-gate.py
qemu-riscv64-power-loss-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_TEST_APPS=1 XAIOS_CRASH_WRITER=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	# The signed A/B system volume, which nothing else in this target
	# produces. The RISC-V runner copies it into its state directory and
	# fails at that copy before QEMU starts, so on a clean tree the gate
	# reported a guest that never committed a chunk when what had happened
	# was that no machine was ever started.
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-power-loss-gate.py --arch riscv64
# The measurement the gate above is built around: which QEMU backend loses a
# write it has acknowledged when the process is killed. Prints, asserts
# nothing, needs no build -- every answer here is a fact about the emulator.
qemu-write-cache-probe:
	python3 ./tests/scripts/qemu-write-cache-probe.py

qemu-write-ordering-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_VERBOSE=1 XAIOS_CRASH_WRITER=1 XAIOS_IO_TRACE=1 \
	  ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-write-ordering-gate.py

# Throughput of the block path and of /models, cold and warm. Reports rather
# than asserts: the absolute figures are an emulator's, and pinning them would
# make this a gate on the host's mood.
qemu-storage-bench:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_cache_fixture.py 	  build/xaios-cache-fixture.img
	XAIOS_BOOT_VERBOSE=1 XAIOS_STORAGE_BENCH=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-storage-bench.py

qemu-fault-matrix:
	python3 ./tests/scripts/qemu-fault-matrix.py

# The third machine. The gate is architecture-neutral -- it asks whether the
# kernel faults where it was told to and reports it the way the other two do --
# and this target did not exist at all, which B-112 had assumed it did.
qemu-x86_64-fault-matrix:
	python3 ./tests/scripts/qemu-fault-matrix.py --arch x86_64

qemu-docker-network-suite:
	python3 ./tests/scripts/qemu-docker-network-suite.py

qemu-freebsd-network-suite:
	python3 ./tests/scripts/qemu-freebsd-network-suite.py

qemu-riscv64-freebsd-network-suite:
	python3 ./tests/scripts/qemu-freebsd-network-suite.py --arch riscv64

qemu-freebsd-bidirectional-suite:
	python3 ./tests/scripts/qemu-freebsd-bidirectional-suite.py

qemu-riscv64-freebsd-bidirectional-suite:
	XAIOS_QEMU_NETWORK_ARCH=riscv64 \
	  python3 ./tests/scripts/qemu-freebsd-bidirectional-suite.py

qemu-four-endpoint-network-suite:
	@test -n "$(XAIOS_INTEL_VPS)" || { \
	  printf '%s\n' 'error: set XAIOS_INTEL_VPS to an SSH destination' >&2; \
	  exit 2; \
	}
	python3 ./tests/scripts/qemu-four-endpoint-network-suite.py \
	  --vps "$(XAIOS_INTEL_VPS)"

qemu-parallel-network-load:
	python3 ./tests/scripts/qemu-parallel-network-load.py

parser-fuzz:
	python3 ./tests/scripts/run-parser-fuzz.py

qemu-network-adversarial-gate:
	python3 ./tests/scripts/qemu-network-adversarial-gate.py

# B-18: hand the guest a network that is not a /24 and require it to say so.
qemu-routing-prefix-gate: image-qemu-test
	python3 ./tests/scripts/qemu-routing-prefix-gate.py

# V-06: photograph the screen from outside the guest and measure it, rather
# than trusting what the guest logged about its own drawing.
qemu-framebuffer-gate: image
	python3 ./tests/scripts/qemu-framebuffer-gate.py

qemu-local-console-gate:
	python3 ./tests/scripts/qemu-local-console-gate.py

# Boots with a framebuffer, runs xtop on the local console, reads the screen
# back as pixels and decodes it through the kernel's own font tables, then
# compares that frame with one taken over SSH at the same cell size.
qemu-console-xtop-gate:
	python3 ./tests/scripts/qemu-console-xtop-gate.py

# The same comparison on the other two architectures. Every one of the three
# must draw the same picture on its console and in an SSH client.
qemu-console-xtop-gate-x86_64:
	python3 ./tests/scripts/qemu-console-xtop-gate.py --arch x86_64

qemu-console-xtop-gate-riscv64:
	python3 ./tests/scripts/qemu-console-xtop-gate.py --arch riscv64

qemu-keyboard-input-gate:
	python3 ./tests/scripts/qemu-keyboard-input-gate.py --arch aarch64
	python3 ./tests/scripts/qemu-keyboard-input-gate.py --arch x86_64

qemu-ssh-smoke:
	python3 ./tests/scripts/qemu-ssh-smoke.py

qemu-model-sftp-gate:
	python3 ./tests/scripts/qemu-model-sftp-gate.py

qemu-ssh-session-exhaustion-gate:
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py

# B-28: the accept-rate limit, and whether a refusal says why it happened.
# Builds the image it boots, with a key it can authenticate against.
qemu-ssh-connection-rate-gate:
	python3 ./tests/scripts/qemu-ssh-connection-rate-gate.py

# B-02: a join that has to run a thread inside itself, and the CPU it
# borrowed. The image is built here rather than by the gate, and it has to be
# the test-apps profile -- /bin/joinnest is only launched by a boot that runs
# the diagnostic applications. The gate boots the runner directly and refuses
# a medium older than the sources it exists to test.
qemu-thread-join-soak: image-qemu-test
	python3 ./tests/scripts/qemu-thread-join-soak.py

qemu-x86_64-thread-join-soak: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-thread-join-soak.py --arch x86_64

qemu-riscv64-thread-join-soak:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	python3 ./tests/scripts/qemu-thread-join-soak.py --arch riscv64

qemu-x86_64-ssh-session-exhaustion-gate:
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py --arch x86_64

qemu-riscv64-ssh-session-exhaustion-gate: riscv64
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py --arch riscv64

xaios-ssh-bridge:
	./scripts/run-xaios-ssh-bridge.sh

qemu-readiness-gate:
	python3 ./tests/scripts/qemu-readiness-gate.py

qemu-full-os-rc:
	python3 ./tests/scripts/qemu-full-os-rc.py

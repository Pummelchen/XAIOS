SHELL := /bin/sh
HOST_CC ?= clang
HOST_CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic

.PHONY: all bootstrap test image image-qemu-test image-x86_64 image-x86_64-qemu-test image-libc-test qemu-libc-gate xapt-test xapt-repository qemu-xapt-gate engine-cli libc libc-check initfs-format-test vmware-fusion-image vmware-fusion vmware-fusion-smoke vmware-fusion-network-gate vmware-fusion-snapshot-gate riscv64 qemu-riscv64 qemu-riscv64-xapt-gate qemu-riscv64-docker-network-suite qemu-riscv64-parallel-network-load qemu-riscv64-soak-gate qemu-riscv64-nvme-gate qemu-riscv64-fault-matrix qemu-riscv64-libc-gate qemu-riscv64-preview qemu-riscv64-boot-loop qemu-riscv64-benchmark qemu-riscv64-model-sftp-gate qemu-riscv64-outbound-fragmentation-gate qemu-riscv64-dhcpv6-gate qemu-riscv64-instruction-cost-gate qemu-riscv64-storage-bench qemu-riscv64-routing-prefix-gate qemu-riscv64-keyboard-input-gate qemu-riscv64-framebuffer-gate qemu-riscv64-crash-safety-gate qemu-riscv64-ai-cell-gate qemu-riscv64-app-agent-gate qemu-riscv64-cpu-ai-runtime-gate qemu-riscv64-cpu-ai-suite qemu-riscv64-fault-injection qemu-riscv64-filesystem-gate qemu-riscv64-isa-gate qemu-riscv64-local-console-gate qemu-riscv64-network-full-gate qemu-riscv64-network-suite qemu-riscv64-osctl-gate qemu-riscv64-persistence-reboot qemu-riscv64-process-gate qemu-riscv64-regression-suite qemu-riscv64-security-gate qemu-riscv64-smoke qemu-riscv64-storage-crash-test qemu-riscv64-update-gate qemu-riscv64-userspace-suite qemu-riscv64-write-ordering-gate qemu-riscv64-gate qemu-riscv64-boot-media-gate qemu-riscv64-matrix-gate qemu-riscv64-durability-gate qemu-riscv64-release-gate vmware-fusion-panic-capture vmware-fusion-boot-soak vmware-fusion-dry-run vz-harness vz-gate vz-bridged-gate qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-smoke qemu-x86_64-cpu-matrix qemu-x86_64-platform-matrix qemu-x86_64-numa-gate qemu-aarch64-sve2-gate qemu-x86_64-repeat-boot intel-desktop-gate qemu-core-os-rc qemu-operations-closure qemu-high-core-gate qemu-smmu-gate qemu-nvme-gate qemu-outbound-fragmentation-gate qemu-qualification-readiness qemu-dry-run qemu-smoke qemu-installed-disk-gate vm-packages vm-package-gate boot-media boot-media-gate qemu-setup-gate qemu-netboot-gate qemu-cluster-gate qemu-cluster-two-node-gate qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-storage-crash-test qemu-crash-safety-gate qemu-write-ordering-gate qemu-storage-bench qemu-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-freebsd-network-suite qemu-freebsd-bidirectional-suite qemu-four-endpoint-network-suite qemu-parallel-network-load qemu-network-adversarial-gate qemu-local-console-gate qemu-console-xtop-gate qemu-console-xtop-gate-x86_64 qemu-console-xtop-gate-riscv64 qemu-keyboard-input-gate qemu-framebuffer-gate qemu-routing-prefix-gate qemu-cpu-ai-suite qemu-ssh-smoke qemu-model-sftp-gate qemu-ssh-session-exhaustion-gate qemu-x86_64-ssh-session-exhaustion-gate qemu-riscv64-ssh-session-exhaustion-gate xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc parser-fuzz compile-check hosted-test hosted-sanitizer-test crash-test model-v2-test code-scanning-contract docs-check platform-neutrality-check doc-freshness-check production-source-audit qemu-baseline clean clean-persistent
.PHONY: firmware-profiles-check firmware-profile-macos-qemu-aarch64 firmware-profile-macos-vmware-fusion-aarch64 firmware-profile-intel-vps-qemu-x86_64 firmware-profiles qemu-x86_64-nvme-gate

all: bootstrap image

bootstrap:
	./scripts/macos-bootstrap.sh

test: bootstrap image qemu-dry-run

image:
	./scripts/build-image.sh

image-qemu-test:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh

image-x86_64:
	XAIOS_TARGET_ARCH=x86_64 ./scripts/build-image.sh

image-x86_64-qemu-test:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh

image-libc-test: libc
	XAIOS_LIBC_TEST=1 XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
	XAIOS_TARGET_ARCH=x86_64 XAIOS_LIBC_TEST=1 XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh

qemu-libc-gate: libc-check image-libc-test
	python3 tests/scripts/qemu-libc-gate.py
	python3 tests/scripts/generate-libc-report.py

xapt-test:
	python3 -m unittest tests/xapt/test_xapt_repo.py

xapt-repository:
	./scripts/build-xapt-repository.sh

initfs-format-test:
	python3 tests/scripts/test-initfs-image.py

qemu-xapt-gate:
	python3 tests/scripts/qemu-xapt-gate.py

vmware-fusion-image: image
	./platform/vmware-fusion/build-vmware-fusion.sh

vmware-fusion: vmware-fusion-image
	./platform/vmware-fusion/run-vmware-fusion.sh

vmware-fusion-smoke:
	python3 ./tests/scripts/vmware-fusion-smoke.py

# RISC-V rv64gc bring-up. Boots via OpenSBI on the QEMU `virt` board rather
# than UEFI, which is why it has its own build script and no boot medium.
riscv64:
	./scripts/build-riscv64.sh

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

vmware-fusion-snapshot-gate:
	python3 ./tests/scripts/vmware-fusion-snapshot-gate.py

vmware-fusion-panic-capture:
	python3 ./tests/scripts/vmware-fusion-panic-capture.py

# Boots Fusion over and over, keeping every console. Not a gate: it is the
# reproduction harness for B-15 and exits non-zero only if it reproduces.
vmware-fusion-boot-soak:
	python3 ./tests/scripts/vmware-fusion-boot-soak.py

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

# One bootable file for every environment: hybrid ISO 9660 and GPT, both
# architectures, bootable as optical media, as a disk, or from a USB stick.
# Both architectures are built here rather than taken from whatever build/
# happens to hold. The kernel's console behaviour is a build-time choice: a
# non-verbose build sends its log to the boot display instead of the console,
# so an image assembled from one boots perfectly and satisfies none of the
# markers the gates look for. That is not a stale image and the staleness
# check does not catch it -- it is a correct image of the wrong build, and it
# happened when make vmware-fusion-image rebuilt the kernel in passing.
# All three halves, built here rather than picked up from the tree.
#
# The RISC-V kernel and initial filesystem were taken from whatever build/
# happened to contain, so the shipped image carried whichever configuration
# someone had last built -- and, once, a kernel from an older build number
# than the image it was inside. Nothing said so: the image was assembled from
# files that existed, and files that exist look like files that were built.
unified-image:
	XAIOS_BOOT_VERBOSE=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	./scripts/build-unified-image.sh

# The release package: the image, and the zip that carries it where a 220 MB
# file cannot go.
release-package: unified-image
	./scripts/build-release.sh

# Boot that one file on every environment available here. Shallower than the
# per-platform gates by design: they each boot their own image, so all four can
# pass while the unified image boots nothing.
unified-image-gate: unified-image
	python3 ./tests/scripts/unified-image-gate.py

# Everything CI cannot run: the two hypervisors and the half of the unified
# image gate that drives them. Writes build/local-gates.json naming the commit
# it checked, so "was this verified on the hypervisors?" has an answer.
local-gates:
	python3 ./tests/scripts/local-gates.py

# Everything that must be true before this commit is tagged or shipped.
#
# CI already proves the part a Linux runner can reach, on every push. What it
# cannot reach is either hypervisor, so two of the four environments XAIOS
# names are covered only by make local-gates -- and until this target existed
# nothing required that to have happened. A release could be cut having been
# tested on half the platforms it claims.
#
# This does not automate the hypervisors. It makes shipping without them a
# deliberate override rather than an oversight.
#
# It also requires the release package, because the archive is what people
# actually receive: the image is too large for git, so the zip is the release
# as far as anyone downloading it is concerned, and a zip is a copy that can go
# stale without looking any different. Build 1's first one did, within an hour.
release-check: docs-check
	python3 ./tests/repository/check-local-gate-record.py
	python3 ./tests/repository/check-release-package.py
	@printf '%s\n' "release-check: this commit is verified on all four environments"

local-gate-record-check:
	python3 ./tests/repository/check-local-gate-record.py

vz-run: vz-harness
	./platform/virtualization-framework/run-vz.sh $(VZ_RUN_ARGS)

vz-gate: vz-harness
	XAIOS_BOOT_VERBOSE=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	python3 ./tests/scripts/vz-gate.py

# The privileged vmnet relay. It lives in build/, which image builds recreate,
# so it needs a target rather than a command in a README: without one it
# silently disappears and the next run fails with "command not found".
vmnet-helper:
	mkdir -p build/vz
	cc -O2 -Wall -Wextra -o build/vz/vmnet-helper platform/virtualization-framework/vmnet-helper.c \
	  -framework vmnet

# Sustained multi-core load on real cores. Repeats the boot because every
# defect it has found so far appeared on some runs and not others.
# V-03: the guest on the real LAN, through the privileged vmnet relay rather
# than through an entitlement Apple will not issue. The relay is the operator's
# to start -- it runs as root -- and the gate prints the command and stops if
# it is not there.
vz-bridged-gate: vz-harness vmnet-helper
	python3 ./tests/scripts/vz-bridged-gate.py

vz-stress-gate: vz-harness
	XAIOS_STRESS_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	python3 ./tests/scripts/vz-stress-gate.py

vmware-fusion-dry-run:
	./platform/vmware-fusion/run-vmware-fusion.sh --dry-run

firmware-profiles-check:
	python3 tests/repository/check-firmware-platform-profiles.py

firmware-profile-macos-qemu-aarch64:
	python3 tests/scripts/firmware-platform-profiles.py --profile macos-qemu-aarch64

firmware-profile-macos-vmware-fusion-aarch64:
	python3 tests/scripts/firmware-platform-profiles.py --profile macos-vmware-fusion-aarch64

firmware-profile-intel-vps-qemu-x86_64:
	python3 tests/scripts/firmware-platform-profiles.py --profile intel-vps-qemu-x86_64

firmware-profiles:
	@test -n "$(XAIOS_INTEL_VPS_PROFILE_EVIDENCE)" || { \
	  printf '%s\n' 'error: set XAIOS_INTEL_VPS_PROFILE_EVIDENCE to the imported Intel VPS evidence JSON' >&2; \
	  exit 2; \
	}
	python3 tests/scripts/firmware-platform-profiles.py --profile macos-qemu-aarch64
	python3 tests/scripts/firmware-platform-profiles.py --profile macos-vmware-fusion-aarch64
	python3 tests/scripts/firmware-platform-profiles.py --aggregate \
	  --evidence build/firmware-profiles/macos-qemu-aarch64.json \
	  --evidence build/firmware-profiles/macos-vmware-fusion-aarch64.json \
	  --evidence "$(XAIOS_INTEL_VPS_PROFILE_EVIDENCE)"

engine-cli:
	@mkdir -p build/hosted
	$(HOST_CC) $(HOST_CFLAGS) -Iengine/include \
	  engine/src/model_v2.c engine/src/sha256.c engine/src/architecture.c \
	  engine/src/service.c engine/src/backend_scalar.c \
	  engine/src/backend_neon.c engine/src/backend_avx2.c engine/src/packed.c \
	  tools/xaios_engine_cli.c -o build/hosted/xaios-engine

libc:
	./scripts/build-libc.sh

libc-check: libc
	python3 tests/repository/check-libc-contract.py
	./scripts/build-c99-app.sh --arch aarch64 --main void tests/libc/c99_main_void.c build/libc/aarch64/c99-app-builder-probe.elf
	./scripts/build-c99-app.sh --arch x86_64 --main void tests/libc/c99_main_void.c build/libc/x86_64/c99-app-builder-probe.elf

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

qemu-riscv64-fault-matrix:
	python3 ./tests/scripts/qemu-fault-matrix.py --arch riscv64

qemu-riscv64-libc-gate: libc-check
	XAIOS_BOOT_TEST_APPS=1 XAIOS_LIBC_TEST=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 XAIOS_LIBC_TEST=1 ./scripts/build-riscv64-image.sh
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
	python3 ./tests/scripts/qemu-crash-safety-gate.py --arch riscv64

qemu-riscv64-write-ordering-gate:
	PYTHONPATH=tools python3 ./tests/xai_fs/create_crash_fixture.py \
	  build/xaios-crash-fixture.img
	XAIOS_BOOT_TEST_APPS=1 XAIOS_CRASH_WRITER=1 XAIOS_IO_TRACE=1 \
	  ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	python3 ./tests/scripts/qemu-write-ordering-gate.py --arch riscv64

qemu-x86_64-numa-gate:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
	python3 tests/scripts/qemu-x86_64-numa-gate.py

qemu-aarch64-sve2-gate: image-qemu-test
	python3 tests/scripts/qemu-aarch64-sve2-gate.py

qemu-dry-run:
	./platform/qemu/run-qemu-aarch64.sh --dry-run
	./platform/qemu/run-qemu-x86_64.sh --dry-run

qemu-smoke: image-qemu-test
	python3 ./tests/scripts/qemu-smoke.py

# One disk, the way a machine XAIOS has been installed onto is arranged. The
# gate builds its own image, so it is not listed as depending on one.
qemu-installed-disk-gate:
	python3 ./tests/scripts/qemu-installed-disk-gate.py

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

# A machine with no kernel on its medium, installing itself onto a blank disk.
# The install at boot is what this gate is for, and an ordinary image does not
# carry it. The gate builds its own image and asks for it, so it behaves the
# same however it is invoked -- CI runs the script directly.
qemu-netboot-gate:
	python3 ./tests/scripts/qemu-netboot-gate.py

# Two nodes exchanging a sealed frame over a real network, one of them on the
# host with its own reading of the wire format.
# Two XAIOS machines rather than XAIOS and a host process: one listens, the
# other dials, and the sealed frame is opened and answered by the far end.
qemu-cluster-two-node-gate:
	python3 ./tests/scripts/qemu-cluster-two-node-gate.py

qemu-cluster-gate:
	XAIOS_CLUSTER_TEST=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-cluster-gate.py

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

qemu-soak-gate: image-qemu-test
	python3 ./tests/scripts/qemu-soak-gate.py

qemu-release: image
	python3 ./tests/scripts/qemu-release.py

qemu-100-gate: image-qemu-test
	python3 ./tests/scripts/qemu-100-gate.py

qemu-x86_64-smoke: image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-x86_64-smoke.py

intel-desktop-gate:
	python3 ./tests/scripts/intel-desktop-gate.py

qemu-core-os-rc:
	python3 ./tests/scripts/qemu-core-os-rc.py

qemu-operations-closure:
	python3 ./tests/scripts/qemu-operations-closure.py

qemu-high-core-gate: image-qemu-test
	python3 ./tests/scripts/qemu-high-core-gate.py

qemu-qualification-readiness:
	python3 ./tests/scripts/qemu-qualification-readiness.py

qemu-smmu-gate: image-qemu-test
	python3 ./tests/scripts/qemu-smmu-gate.py

qemu-nvme-gate: image-qemu-test image-x86_64-qemu-test riscv64
	python3 ./tests/scripts/qemu-nvme-gate.py

qemu-x86_64-nvme-gate: image-x86_64-qemu-test
	XAIOS_QEMU_NVME_ARCH=x86_64 python3 ./tests/scripts/qemu-nvme-gate.py

# All three machines by default: the exchange is the same and the driver
# underneath it is not, so this is three tests rather than one repeated.
qemu-outbound-fragmentation-gate: image image-x86_64 riscv64
	python3 ./tests/scripts/qemu-outbound-fragmentation-gate.py

qemu-preview: image-qemu-test
	python3 ./tests/scripts/qemu-preview.py

qemu-matrix:
	python3 ./tests/scripts/qemu-matrix.py

qemu-cpu-matrix: image-qemu-test image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-cpu-matrix.py

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

qemu-regression-suite: image-qemu-test
	python3 ./tests/scripts/qemu-regression-suite.py

qemu-fault-injection: image-qemu-test
	python3 ./tests/scripts/qemu-fault-injection.py

qemu-abi-contract:
	python3 ./tests/scripts/qemu-abi-contract.py

qemu-boot-loop: image-qemu-test
	python3 ./tests/scripts/qemu-boot-loop.py

qemu-userspace-suite: image-qemu-test
	python3 ./tests/scripts/qemu-userspace-suite.py

qemu-network-suite: image-qemu-test
	python3 ./tests/scripts/qemu-network-suite.py

qemu-docker-network-suite:
	python3 ./tests/scripts/qemu-docker-network-suite.py

qemu-freebsd-network-suite:
	python3 ./tests/scripts/qemu-freebsd-network-suite.py

qemu-freebsd-bidirectional-suite:
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

qemu-cpu-ai-suite: image-qemu-test
	python3 ./tests/scripts/qemu-cpu-ai-suite.py

qemu-ssh-smoke:
	python3 ./tests/scripts/qemu-ssh-smoke.py

qemu-model-sftp-gate:
	python3 ./tests/scripts/qemu-model-sftp-gate.py

qemu-ssh-session-exhaustion-gate:
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py

qemu-x86_64-ssh-session-exhaustion-gate:
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py --arch x86_64

qemu-riscv64-ssh-session-exhaustion-gate: riscv64
	python3 ./tests/scripts/qemu-ssh-session-exhaustion-gate.py --arch riscv64

xaios-ssh-bridge:
	./scripts/run-xaios-ssh-bridge.sh

qemu-developer-ux:
	python3 ./tests/scripts/qemu-developer-ux.py

qemu-post51-gate: image image-x86_64
	python3 ./tests/scripts/qemu-post51-gate.py

qemu-readiness-gate:
	python3 ./tests/scripts/qemu-readiness-gate.py

qemu-full-os-rc:
	python3 ./tests/scripts/qemu-full-os-rc.py

compile-check: libc
	@mkdir -p build/compile-check/x86-kernel build/compile-check/x86-userspace
	@failed=0; \
	for f in $$(find kernel -name '*.c' ! -path '*/x86_64/*' ! -path '*/riscv64/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel/arch/riscv64 -name '*.c'); do \
	  clang --target=riscv64-unknown-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -mno-relax -march=rv64gc -mabi=lp64d \
	    -mcmodel=medany \
	    -Wall -Wextra -Werror -pedantic -Ikernel/include -Iengine/include \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel/arch/x86_64 -name '*.c'); do \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel -name '*.c' ! -path '*/arch/aarch64/*' \
	    ! -path '*/arch/x86_64/*' ! -path '*/arch/riscv64/*'); do \
	  object=build/compile-check/x86-kernel/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -DXAIOS_X86_COMMON_RUNTIME=1 \
	    -Ikernel/include -Iengine/include -Ithird_party/bearssl/inc \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*' \
	    ! -path 'userspace/apps/hosted/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Iuserspace/include -Iuserspace/sshd \
	    -Iengine/include \
	    -Iuserspace/apps/terminal -Ithird_party/mlkem-native/mlkem \
	    -Ithird_party/openbsd-compat -Ithird_party/bearssl/inc -Itests \
	    -isystem build/libc/aarch64/sysroot/include \
	    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*' \
	    ! -path 'userspace/apps/hosted/*'); do \
	  object=build/compile-check/x86-userspace/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -Iuserspace/include -Iuserspace/sshd \
	    -Iengine/include \
	    -Iuserspace/apps/terminal -Ithird_party/mlkem-native/mlkem \
	    -Ithird_party/openbsd-compat -Ithird_party/bearssl/inc -Itests \
	    -isystem build/libc/x86_64/sysroot/include \
	    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	if [ "$$failed" -ne 0 ]; then \
	  printf '%s\n' "$$failed file(s) failed compilation" >&2; \
	  exit 1; \
	fi; \
	printf '%s\n' "All freestanding C files compiled clean; hosted libc uses make libc-check"

hosted-test: engine-cli
	@mkdir -p build/hosted
	./build/hosted/xaios-engine probe
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include tests/system/test_cpuset.c \
	  -o build/hosted/test-cpuset
	./build/hosted/test-cpuset
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/arch/x86_64/acpi.c tests/system/test_x86_acpi.c \
	  -o build/hosted/test-x86-acpi
	./build/hosted/test-x86-acpi
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/arch/aarch64/acpi.c tests/system/test_aarch64_acpi.c \
	  -o build/hosted/test-aarch64-acpi
	./build/hosted/test-aarch64-acpi
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/model_v2.c engine/src/sha256.c \
	  engine/src/architecture.c engine/src/service.c engine/src/backend_scalar.c \
	  engine/src/backend_neon.c engine/src/backend_avx2.c engine/src/packed.c \
	  tests/model_v2/test_engine.c -o build/hosted/test-engine
	./build/hosted/test-engine
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include -Iengine/src engine/src/cluster.c engine/src/sha256.c \
	  tests/model_v2/test_cluster.c -o build/hosted/test-cluster
	./build/hosted/test-cluster
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/kimi_k3_mini.c \
	  tests/model_v2/test_kimi_k3_mini.c -lm -o build/hosted/test-kimi-k3-mini
	./build/hosted/test-kimi-k3-mini
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/backend_scalar.c engine/src/backend_neon.c \
	  engine/src/backend_avx2.c engine/src/packed.c \
	  tests/model_v2/test_packed.c \
	  -o build/hosted/test-packed
	./build/hosted/test-packed
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include userspace/lib/xaios_control_client.c \
	  tests/control/test_control_client.c -o build/hosted/test-control-client
	./build/hosted/test-control-client
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include -Ikernel/include userspace/lib/xaios_screen.c \
	  tests/system/test_screen.c -o build/hosted/test-screen
	./build/hosted/test-screen
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c \
	  tests/storage/test_block_device.c -o build/hosted/test-block-device
	./build/hosted/test-block-device
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/partition_device.c \
	  tests/storage/test_gpt.c -o build/hosted/test-gpt
	./build/hosted/test-gpt
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/partition_device.c \
	  kernel/storage/storage_admin.c kernel/fs/fat.c \
	  tests/storage/test_storage_admin.c \
	  -o build/hosted/test-storage-admin
	./build/hosted/test-storage-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/fs/fat.c \
	  tests/storage/test_fat.c -o build/hosted/test-fat
	./build/hosted/test-fat
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include -Iengine/include -Iengine/src -Iuserspace/include \
	  -Iuserspace/sshd kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/partition_device.c \
	  kernel/storage/storage_admin.c kernel/fs/fat.c \
	  kernel/fs/xai_fs_admin.c \
	  engine/src/xai_fs.c engine/src/xai_fs_writer.c \
	  engine/src/sha256.c userspace/sshd/ssh_crypto.c \
	  userspace/sshd/tweetnacl_subset.c \
	  tests/storage/test_xai_fs_admin.c \
	  -o build/hosted/test-xaifs-admin
	./build/hosted/test-xaifs-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/vfs.c tests/storage/test_vfs.c \
	  -o build/hosted/test-vfs
	./build/hosted/test-vfs
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_mirror.c \
	  -o build/hosted/test-mutable-fs-mirror
	./build/hosted/test-mutable-fs-mirror
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_v6.c \
	  -o build/hosted/test-xaiboot-fs-v6
	./build/hosted/test-xaiboot-fs-v6
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include -Iuserspace/sshd -Iuserspace/apps/terminal \
	  -Ikernel/include \
	  userspace/sshd/sftp_server.c tests/storage/test_sftp_large.c \
	  -o build/hosted/test-sftp-large
	./build/hosted/test-sftp-large
	python3 tests/scripts/generate-dnssec-fixture.py build/hosted/dnssec_fixture.h
	$(HOST_CC) $(HOST_CFLAGS) -D_DEFAULT_SOURCE \
	  -Ikernel/include -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
	  -Ithird_party/bearssl/src -Ibuild/hosted \
	  kernel/net/dns.c kernel/net/dnssec.c kernel/net/ipv4.c \
	  userspace/sshd/ssh_crypto.c userspace/sshd/tweetnacl_subset.c \
	  $$(find third_party/bearssl/src -name '*.c' | LC_ALL=C sort) \
	  tests/crashtest/test_dns.c -o build/hosted/test-dns
	./build/hosted/test-dns
	$(HOST_CC) $(HOST_CFLAGS) \
	  -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
	  -Iuserspace/sshd -Ithird_party/mlkem-native/mlkem \
	  third_party/mlkem-native/mlkem/mlkem_native.c \
	  tests/security/test_mlkem.c -o build/hosted/test-mlkem
	./build/hosted/test-mlkem
	rm -f build/hosted/id-ed25519 build/hosted/id-ed25519.pub \
	  build/hosted/id-ed25519-encrypted build/hosted/id-ed25519-encrypted.pub
	ssh-keygen -q -t ed25519 -N '' -f build/hosted/id-ed25519
	ssh-keygen -q -t ed25519 -N xaios-test-passphrase \
	  -f build/hosted/id-ed25519-encrypted
	$(HOST_CC) $(HOST_CFLAGS) -DXAIOS_IDENTITY_HOSTED=1 -Wno-unknown-attributes \
	  -Iuserspace/include -Iuserspace/sshd -Ithird_party/openbsd-compat \
	  userspace/sshd/ssh_identity.c userspace/sshd/ssh_crypto.c \
	  userspace/sshd/tweetnacl_subset.c \
	  third_party/openbsd-compat/blowfish.c \
	  third_party/openbsd-compat/bcrypt_pbkdf.c \
	  tests/security/test_ssh_identity.c -o build/hosted/test-ssh-identity
	./build/hosted/test-ssh-identity build/hosted/id-ed25519 \
	  build/hosted/id-ed25519-encrypted
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/net/ipv4.c kernel/net/ipv6.c \
	  tests/network/test_ip_fragments.c -o build/hosted/test-ip-fragments
	./build/hosted/test-ip-fragments
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/lib/inflate.c tests/system/test_inflate.c -lz \
	  -o build/hosted/test-inflate
	./build/hosted/test-inflate
	$(HOST_CC) $(HOST_CFLAGS) -Iuserspace/include -Iuserspace/sshd \
	  -Iuserspace/apps/terminal \
	  userspace/apps/terminal/pong_game.c tests/system/test_pong_game.c \
	  -o build/hosted/test-pong-game
	./build/hosted/test-pong-game
	PYTHONPATH=. python3 -m unittest discover -s tests/system -p 'test_*.py'
	PYTHONPATH=tools python3 -m unittest discover -s tests/model_v2 -p 'test_*.py'
	PYTHONPATH=tools python3 -m unittest discover -s tests/xai_fs -p 'test_*.py'
	PYTHONPATH=tools python3 tests/xai_fs/create_c_fixture.py \
	  build/hosted/xaifs-c-fixture.img
	PYTHONPATH=tools python3 tests/xai_fs/create_c_sparse_fixture.py \
	  build/hosted/xaifs-c-sparse.img
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	  -Iuserspace/apps/terminal \
	  -Ikernel/include engine/src/xai_fs.c \
	  engine/src/xai_fs_writer.c engine/src/model_file.c \
	  engine/src/sha256.c \
	  userspace/sshd/ssh_crypto.c userspace/sshd/tweetnacl_subset.c \
	  tests/xai_fs/test_xai_fs_reader.c \
	  -o build/hosted/test-xaifs-reader
	./build/hosted/test-xaifs-reader \
	  build/hosted/xaifs-c-fixture.img \
	  build/hosted/xaifs-c-sparse.img
	$(HOST_CC) $(HOST_CFLAGS) -Iengine/src \
	  tests/engine/test_sha256_accel.c \
	  engine/src/sha256.c engine/src/sha256_accel.c \
	  -o build/hosted/test-sha256-accel
	./build/hosted/test-sha256-accel

hosted-sanitizer-test:
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(MAKE) hosted-test \
	  HOST_CFLAGS='-std=c99 -Wall -Wextra -Werror -pedantic -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined'

crash-test: hosted-sanitizer-test
	python3 -m compileall -q scripts tools tests

model-v2-test: hosted-test

# XAIOS behaves the same everywhere it boots; firmware supplies capabilities,
# never identity. See docs/PLATFORM-NEUTRALITY.md.
platform-neutrality-check:
	python3 tests/repository/check-platform-neutrality.py

# Prose cannot be enforced by shape, so this checks the claims that expire:
# evidence commits that have fallen behind, and review dates that predate the
# page's own last edit.
doc-freshness-check:
	python3 tests/repository/check-doc-freshness.py

docs-check:
	python3 tests/repository/check-platform-neutrality.py
	python3 tests/repository/check-doc-freshness.py
	python3 tests/repository/check-test-layout.py
	python3 tests/repository/check-firmware-platform-profiles.py
	python3 tests/repository/check-code-scanning-contract.py
	python3 tests/repository/check-wiki-layout.py
	python3 tests/repository/check-user-docs.py
	python3 tests/repository/check-model-support.py
	python3 tests/repository/check-platform-support.py
	python3 tests/repository/check-core-os-status.py

code-scanning-contract:
	python3 tests/repository/check-code-scanning-contract.py

production-source-audit:
	python3 tests/repository/check-production-source.py

qemu-baseline: image
	python3 ./tests/scripts/benchmark-baseline.py

clean:
	rm -rf build out dist

clean-persistent:
	rm -f build/xaios-persistent.img

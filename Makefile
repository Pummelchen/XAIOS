SHELL := /bin/sh
HOST_CC ?= clang
HOST_CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic

.PHONY: all bootstrap test wt-interop-test qemu-quic-handshake-gate image image-qemu-test image-x86_64 image-x86_64-qemu-test image-libc-test qemu-libc-gate xapt-test xapt-repository qemu-xapt-gate engine-cli libc libc-check initfs-format-test vmware-fusion-image vmware-fusion vmware-fusion-smoke vmware-fusion-network-gate vmware-fusion-outbound-gate qemu-outbound-batch-mode-gate qemu-sftp-binary-passthrough-gate qemu-sshd-transmit-rate-gate qemu-sshd-channel-starvation-gate qemu-sshd-close-visibility-gate qemu-socket-flow-map-gate qemu-datagram-ephemeral-port-gate qemu-network-poll-cadence-gate qemu-sshd-audit-append-gate qemu-x86_64-sshd-audit-append-gate qemu-x86_64-sftp-binary-passthrough-gate qemu-riscv64-sftp-binary-passthrough-gate vmware-fusion-snapshot-gate riscv64 qemu-riscv64 qemu-riscv64-xapt-gate qemu-riscv64-docker-network-suite qemu-riscv64-parallel-network-load qemu-riscv64-soak-gate qemu-riscv64-nvme-gate qemu-riscv64-fault-matrix qemu-riscv64-libc-gate qemu-riscv64-preview qemu-riscv64-boot-loop qemu-riscv64-benchmark qemu-riscv64-model-sftp-gate qemu-riscv64-outbound-fragmentation-gate qemu-riscv64-dhcpv6-gate qemu-riscv64-instruction-cost-gate qemu-riscv64-storage-bench qemu-riscv64-routing-prefix-gate qemu-riscv64-keyboard-input-gate qemu-riscv64-framebuffer-gate qemu-riscv64-crash-safety-gate qemu-riscv64-ai-cell-gate qemu-riscv64-app-agent-gate qemu-riscv64-cpu-ai-runtime-gate qemu-riscv64-cpu-ai-suite qemu-riscv64-fault-injection qemu-riscv64-filesystem-gate qemu-riscv64-isa-gate qemu-riscv64-local-console-gate qemu-riscv64-network-full-gate qemu-riscv64-network-suite qemu-riscv64-osctl-gate qemu-riscv64-persistence-reboot qemu-riscv64-process-gate qemu-riscv64-regression-suite qemu-riscv64-security-gate qemu-riscv64-smoke qemu-riscv64-storage-crash-test qemu-riscv64-update-gate qemu-riscv64-userspace-suite qemu-riscv64-write-ordering-gate qemu-riscv64-gate qemu-riscv64-boot-media-gate qemu-riscv64-matrix-gate qemu-riscv64-durability-gate qemu-riscv64-release-gate vmware-fusion-panic-capture vmware-fusion-boot-soak vmware-fusion-dry-run vz-harness vz-gate vz-bridged-gate qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-vmxnet3 qemu-vmxnet3-gate qemu-rss-steering-gate qemu-x86_64-smoke qemu-x86_64-cpu-matrix qemu-x86_64-platform-matrix qemu-x86_64-numa-gate qemu-aarch64-sve2-gate qemu-x86_64-repeat-boot intel-desktop-gate qemu-core-os-rc qemu-operations-closure qemu-high-core-gate qemu-smmu-gate qemu-nvme-gate qemu-nvme-stress-soak qemu-outbound-fragmentation-gate qemu-qualification-readiness qemu-dry-run qemu-smoke qemu-installed-disk-gate qemu-riscv64-installed-disk-gate qemu-x86_64-installed-disk-gate qemu-x86_64-update-gate vm-packages vm-package-gate boot-media boot-media-gate qemu-setup-gate qemu-riscv64-setup-gate qemu-netboot-gate qemu-riscv64-netboot-gate qemu-cluster-gate qemu-riscv64-cluster-gate qemu-cluster-two-node-gate qemu-riscv64-cluster-two-node-gate qemu-cluster-three-node-gate qemu-riscv64-cluster-three-node-gate qemu-cluster-partition-gate qemu-riscv64-cluster-partition-gate qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-riscv64-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-storage-crash-test qemu-crash-safety-gate qemu-power-loss-gate qemu-riscv64-power-loss-gate qemu-write-cache-probe qemu-write-ordering-gate qemu-storage-bench qemu-fault-matrix qemu-x86_64-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-freebsd-network-suite qemu-riscv64-freebsd-network-suite qemu-freebsd-bidirectional-suite qemu-riscv64-freebsd-bidirectional-suite qemu-four-endpoint-network-suite qemu-parallel-network-load qemu-network-adversarial-gate qemu-local-console-gate qemu-console-xtop-gate qemu-console-xtop-gate-x86_64 qemu-console-xtop-gate-riscv64 qemu-keyboard-input-gate qemu-framebuffer-gate qemu-routing-prefix-gate qemu-cpu-ai-suite qemu-ssh-smoke qemu-model-sftp-gate qemu-ssh-session-exhaustion-gate qemu-ssh-connection-rate-gate qemu-thread-join-soak qemu-x86_64-thread-join-soak qemu-riscv64-thread-join-soak qemu-x86_64-ssh-session-exhaustion-gate qemu-riscv64-ssh-session-exhaustion-gate xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc parser-fuzz wt-host-test wt-host-sanitize wt-vectors-check compile-check hosted-test hosted-sanitizer-test crash-test model-v2-test code-scanning-contract docs-check platform-neutrality-check doc-freshness-check wiki-parity-check production-source-audit qemu-baseline clean clean-persistent qemu-riscv64-aia-gate qemu-riscv64-iommu-gate wt-upstream-compile
.PHONY: firmware-profiles-check firmware-profile-macos-qemu-aarch64 firmware-profile-macos-vmware-fusion-aarch64 firmware-profile-intel-vps-qemu-x86_64 firmware-profiles qemu-x86_64-nvme-gate

all: bootstrap image

bootstrap:
	./scripts/macos-bootstrap.sh

test: bootstrap image qemu-dry-run

# These targets are matched as source text in this file, not through the
# includes, by tests/scripts/qemu-developer-ux.py (REQUIRED_MAKE_TARGETS),
# tests/scripts/qemu-abi-contract.py (qemu-core-os-rc) and
# tests/repository/check-aggregate-budgets.py -- the last only for gates that
# carry a smoke_timeout(...) wait. Keep them here; moving one into mk/ makes
# its check stop seeing it, silently in the aggregate-budget case.

# B-05, B-06 and B-11: every architecture at 1, 2 and 4 GiB, asserting that
# each one manages the memory it was actually given. The address-space bugs
# these rows record were all invisible at the one size the gates ran at.
qemu-memory-matrix:
	python3 ./tests/scripts/qemu-memory-matrix.py

# B-14: a block device that really advertises VIRTIO_BLK_F_RO, and the same
# image on a writable one. The read-only branch had never executed.
qemu-readonly-medium-gate:
	python3 ./tests/scripts/qemu-readonly-medium-gate.py

qemu-core-os-rc:
	python3 ./tests/scripts/qemu-core-os-rc.py

# B-68: the `riscv64` prerequisite builds the kernel and stops there, so the
# RISC-V legs died on "no initial filesystem" while the two that had images
# passed. Every other RISC-V gate adds the image script to its own recipe; this
# one and the fragmentation gate below were the two that did not.
qemu-nvme-gate: image-qemu-test image-x86_64-qemu-test riscv64
	python3 ./tests/scripts/qemu-nvme-gate.py

# All three machines by default: the exchange is the same and the driver
# underneath it is not, so this is three tests rather than one repeated.
qemu-outbound-fragmentation-gate: image image-x86_64 riscv64
	python3 ./tests/scripts/qemu-outbound-fragmentation-gate.py

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

qemu-cpu-ai-suite: image-qemu-test
	python3 ./tests/scripts/qemu-cpu-ai-suite.py

qemu-developer-ux:
	python3 ./tests/scripts/qemu-developer-ux.py

# The boot-test images, not the release ones.
#
# This asked for `image image-x86_64`, which is the release configuration:
# the boot UI owns the console there and the kernel log is suppressed. Every
# suite this target then runs reads that log, so all of them reported a guest
# that had produced none of their markers -- on a machine that boots perfectly
# to a login prompt with sshd up.
qemu-post51-gate: image-qemu-test image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-post51-gate.py

# The rest of the build is grouped into fragments, included here after every
# variable and the .PHONY lists above.
include mk/image-targets.mk
include mk/platform-targets.mk
include mk/release-targets.mk
include mk/toolchain-targets.mk
include mk/qemu-riscv64-targets.mk
include mk/qemu-targets.mk
include mk/hosted-tests.mk
include mk/repository-targets.mk

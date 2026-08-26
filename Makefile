SHELL := /bin/sh
HOST_CC ?= clang
HOST_CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic

.PHONY: all bootstrap test image image-qemu-test image-x86_64 image-x86_64-qemu-test image-libc-test qemu-libc-gate xapt-test xapt-repository qemu-xapt-gate engine-cli libc libc-check initfs-format-test vmware-fusion-image vmware-fusion vmware-fusion-smoke vmware-fusion-dry-run vz-harness vz-gate qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-smoke qemu-x86_64-cpu-matrix qemu-x86_64-platform-matrix qemu-x86_64-numa-gate qemu-aarch64-sve2-gate qemu-x86_64-repeat-boot intel-desktop-gate qemu-core-os-rc qemu-operations-closure qemu-high-core-gate qemu-smmu-gate qemu-nvme-gate qemu-outbound-fragmentation-gate qemu-qualification-readiness qemu-dry-run qemu-smoke qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-storage-crash-test qemu-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-freebsd-network-suite qemu-freebsd-bidirectional-suite qemu-four-endpoint-network-suite qemu-parallel-network-load qemu-network-adversarial-gate qemu-local-console-gate qemu-keyboard-input-gate qemu-cpu-ai-suite qemu-ssh-smoke qemu-model-sftp-gate xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc parser-fuzz compile-check hosted-test hosted-sanitizer-test crash-test model-v2-test code-scanning-contract docs-check platform-neutrality-check doc-freshness-check production-source-audit qemu-baseline clean clean-persistent
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

vz-run: vz-harness
	./platform/virtualization-framework/run-vz.sh $(VZ_RUN_ARGS)

vz-gate: vz-harness
	XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
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

qemu-nvme-gate: image-qemu-test image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-nvme-gate.py

qemu-x86_64-nvme-gate: image-x86_64-qemu-test
	XAIOS_QEMU_NVME_ARCH=x86_64 python3 ./tests/scripts/qemu-nvme-gate.py

qemu-outbound-fragmentation-gate: image image-x86_64
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

qemu-benchmark: image-qemu-test
	python3 ./tests/scripts/qemu-benchmark.py

qemu-persistence-reboot:
	XAIOS_BOOT_VERBOSE=1 ./scripts/build-image.sh
	python3 ./tests/scripts/qemu-persistence-reboot.py

qemu-storage-crash-test: image-qemu-test
	python3 ./tests/scripts/qemu-storage-crash-test.py

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

qemu-local-console-gate:
	python3 ./tests/scripts/qemu-local-console-gate.py

qemu-keyboard-input-gate:
	python3 ./tests/scripts/qemu-keyboard-input-gate.py --arch aarch64
	python3 ./tests/scripts/qemu-keyboard-input-gate.py --arch x86_64

qemu-cpu-ai-suite: image-qemu-test
	python3 ./tests/scripts/qemu-cpu-ai-suite.py

qemu-ssh-smoke:
	python3 ./tests/scripts/qemu-ssh-smoke.py

qemu-model-sftp-gate:
	python3 ./tests/scripts/qemu-model-sftp-gate.py

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
	for f in $$(find kernel -name '*.c' ! -path '*/x86_64/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
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
	    ! -path '*/arch/x86_64/*'); do \
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
	  kernel/storage/storage_admin.c tests/storage/test_storage_admin.c \
	  -o build/hosted/test-storage-admin
	./build/hosted/test-storage-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include -Iengine/include -Iengine/src -Iuserspace/include \
	  -Iuserspace/sshd kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/partition_device.c \
	  kernel/storage/storage_admin.c kernel/fs/model_volume_admin.c \
	  engine/src/model_volume.c engine/src/model_volume_writer.c \
	  engine/src/sha256.c userspace/sshd/ssh_crypto.c \
	  userspace/sshd/tweetnacl_subset.c \
	  tests/storage/test_model_volume_admin.c \
	  -o build/hosted/test-model-volume-admin
	./build/hosted/test-model-volume-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/vfs.c tests/storage/test_vfs.c \
	  -o build/hosted/test-vfs
	./build/hosted/test-vfs
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/mutable_fs.c kernel/dev/block_device.c \
	  tests/storage/test_mutable_fs_mirror.c \
	  -o build/hosted/test-mutable-fs-mirror
	./build/hosted/test-mutable-fs-mirror
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
	PYTHONPATH=tools python3 -m unittest discover -s tests/model_volume -p 'test_*.py'
	PYTHONPATH=tools python3 tests/model_volume/create_c_fixture.py \
	  build/hosted/model-volume-c-fixture.img
	PYTHONPATH=tools python3 tests/model_volume/create_c_sparse_fixture.py \
	  build/hosted/model-volume-c-sparse.img
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	  -Iuserspace/apps/terminal \
	  -Ikernel/include engine/src/model_volume.c \
	  engine/src/model_volume_writer.c engine/src/model_file.c \
	  engine/src/sha256.c \
	  userspace/sshd/ssh_crypto.c userspace/sshd/tweetnacl_subset.c \
	  tests/model_volume/test_model_volume_reader.c \
	  -o build/hosted/test-model-volume-reader
	./build/hosted/test-model-volume-reader \
	  build/hosted/model-volume-c-fixture.img \
	  build/hosted/model-volume-c-sparse.img

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

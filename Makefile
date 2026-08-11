SHELL := /bin/sh
HOST_CC ?= clang
HOST_CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic

.PHONY: all bootstrap test image image-qemu-test image-x86_64 image-x86_64-qemu-test image-libc-test qemu-libc-gate engine-cli libc libc-check vmware-fusion-image vmware-fusion vmware-fusion-smoke vmware-fusion-dry-run qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-smoke qemu-x86_64-cpu-matrix qemu-x86_64-platform-matrix qemu-x86_64-repeat-boot intel-desktop-gate qemu-core-os-rc qemu-operations-closure qemu-high-core-gate qemu-smmu-gate qemu-nvme-gate qemu-outbound-fragmentation-gate qemu-dry-run qemu-smoke qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-storage-crash-test qemu-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-freebsd-network-suite qemu-freebsd-bidirectional-suite qemu-four-endpoint-network-suite qemu-parallel-network-load qemu-local-console-gate qemu-cpu-ai-suite qemu-ssh-smoke qemu-model-sftp-gate xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc compile-check hosted-test hosted-sanitizer-test crash-test model-v2-test docs-check production-source-audit qemu-baseline clean clean-persistent

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

vmware-fusion-image: image
	./scripts/build-vmware-fusion.sh

vmware-fusion: vmware-fusion-image
	./scripts/run-vmware-fusion.sh

vmware-fusion-smoke: vmware-fusion-image
	python3 ./tests/scripts/vmware-fusion-smoke.py

vmware-fusion-dry-run:
	./scripts/run-vmware-fusion.sh --dry-run

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
	python3 tests/scripts/check-libc-contract.py
	./scripts/build-c99-app.sh --arch aarch64 --main void tests/libc/c99_main_void.c build/libc/aarch64/c99-app-builder-probe.elf
	./scripts/build-c99-app.sh --arch x86_64 --main void tests/libc/c99_main_void.c build/libc/x86_64/c99-app-builder-probe.elf

qemu:
	./scripts/run-qemu-aarch64.sh

qemu-aarch64:
	./scripts/run-qemu-aarch64.sh

qemu-x86_64: image-x86_64
	./scripts/run-qemu-x86_64.sh

qemu-dry-run:
	./scripts/run-qemu-aarch64.sh --dry-run
	./scripts/run-qemu-x86_64.sh --dry-run

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

qemu-smmu-gate: image-qemu-test
	python3 ./tests/scripts/qemu-smmu-gate.py

qemu-nvme-gate: image-qemu-test image-x86_64-qemu-test
	python3 ./tests/scripts/qemu-nvme-gate.py

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

qemu-local-console-gate:
	python3 ./tests/scripts/qemu-local-console-gate.py

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

compile-check:
	@mkdir -p build/compile-check/x86-kernel build/compile-check/x86-userspace
	@failed=0; \
	for f in $$(find kernel -name '*.c' ! -path '*/x86_64/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd \
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
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Iuserspace/include -Itests -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*'); do \
	  object=build/compile-check/x86-userspace/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -Iuserspace/include -Itests \
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
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/model_v2.c engine/src/sha256.c \
	  engine/src/architecture.c engine/src/service.c engine/src/backend_scalar.c \
	  engine/src/backend_neon.c engine/src/backend_avx2.c engine/src/packed.c \
	  tests/model_v2/test_engine.c -o build/hosted/test-engine
	./build/hosted/test-engine
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
	  -Iuserspace/include -Iuserspace/sshd -Ikernel/include \
	  userspace/sshd/sftp_server.c tests/storage/test_sftp_large.c \
	  -o build/hosted/test-sftp-large
	./build/hosted/test-sftp-large
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/net/dns.c kernel/net/ipv4.c \
	  tests/crashtest/test_dns.c -o build/hosted/test-dns
	./build/hosted/test-dns
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/net/ipv4.c kernel/net/ipv6.c \
	  tests/network/test_ip_fragments.c -o build/hosted/test-ip-fragments
	./build/hosted/test-ip-fragments
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/lib/inflate.c tests/system/test_inflate.c -lz \
	  -o build/hosted/test-inflate
	./build/hosted/test-inflate
	$(HOST_CC) $(HOST_CFLAGS) -Iuserspace/include -Iuserspace/sshd \
	  userspace/sshd/pong_game.c tests/system/test_pong_game.c \
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

docs-check:
	python3 tests/scripts/check-test-layout.py
	python3 tests/scripts/check-wiki-layout.py
	python3 tests/scripts/check-user-docs.py
	python3 tests/scripts/check-model-support.py
	python3 tests/scripts/check-platform-support.py
	python3 tests/scripts/check-core-os-status.py

production-source-audit:
	python3 tests/scripts/check-production-source.py

qemu-baseline: image
	python3 ./tests/scripts/benchmark-baseline.py

clean:
	rm -rf build out dist

clean-persistent:
	rm -f build/xaios-persistent.img

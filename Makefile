SHELL := /bin/sh
HOST_CC ?= clang
HOST_CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic

.PHONY: all bootstrap test image image-x86_64 qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-smoke qemu-x86_64-cpu-matrix qemu-x86_64-platform-matrix intel-desktop-gate qemu-core-os-rc qemu-high-core-gate qemu-smmu-gate qemu-nvme-gate qemu-dry-run qemu-smoke qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-storage-crash-test qemu-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-parallel-network-load qemu-cpu-ai-suite qemu-ssh-smoke qemu-model-sftp-gate xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc compile-check hosted-test hosted-sanitizer-test crash-test model-v2-test docs-check production-source-audit qemu-baseline clean clean-persistent

all: bootstrap image

bootstrap:
	./scripts/macos-bootstrap.sh

test: bootstrap image qemu-dry-run

image:
	./scripts/build-image.sh

image-x86_64:
	./scripts/build-image-x86_64.sh

qemu:
	./scripts/run-qemu-aarch64.sh

qemu-aarch64:
	./scripts/run-qemu-aarch64.sh

qemu-x86_64: image-x86_64
	./scripts/run-qemu-x86_64.sh

qemu-dry-run:
	./scripts/run-qemu-aarch64.sh --dry-run
	./scripts/run-qemu-x86_64.sh --dry-run

qemu-smoke: image
	python3 ./scripts/qemu-smoke.py

qemu-process-gate: image
	python3 ./scripts/qemu-process-gate.py

qemu-osctl-gate: image
	python3 ./scripts/qemu-osctl-gate.py

qemu-filesystem-gate: image
	python3 ./scripts/qemu-milestone-gate.py 62

qemu-app-agent-gate: image
	python3 ./scripts/qemu-milestone-gate.py 63

qemu-network-full-gate: image
	python3 ./scripts/qemu-milestone-gate.py 64

qemu-cpu-ai-runtime-gate: image
	python3 ./scripts/qemu-milestone-gate.py 65

qemu-ai-cell-gate: image
	python3 ./scripts/qemu-milestone-gate.py 66

qemu-security-gate: image
	python3 ./scripts/qemu-milestone-gate.py 67

qemu-update-gate: image
	python3 ./scripts/qemu-milestone-gate.py 68

qemu-soak-gate: image
	python3 ./scripts/qemu-soak-gate.py

qemu-release: image
	python3 ./scripts/qemu-release.py

qemu-100-gate: image
	python3 ./scripts/qemu-100-gate.py

qemu-x86_64-smoke: image-x86_64
	python3 ./scripts/qemu-x86_64-smoke.py

intel-desktop-gate:
	python3 ./scripts/intel-desktop-gate.py

qemu-core-os-rc:
	python3 ./scripts/qemu-core-os-rc.py

qemu-high-core-gate: image
	python3 ./scripts/qemu-high-core-gate.py

qemu-smmu-gate: image
	python3 ./scripts/qemu-smmu-gate.py

qemu-nvme-gate: image
	python3 ./scripts/qemu-nvme-gate.py

qemu-preview: image
	python3 ./scripts/qemu-preview.py

qemu-matrix:
	python3 ./scripts/qemu-matrix.py

qemu-cpu-matrix: image image-x86_64
	python3 ./scripts/qemu-cpu-matrix.py

qemu-x86_64-cpu-matrix: image-x86_64
	XAIOS_QEMU_CPU_MATRIX_ARCH=x86_64 \
	XAIOS_QEMU_CPU_MATRIX_REPORT=build/qemu-x86_64-cpu-matrix-report.json \
	python3 ./scripts/qemu-cpu-matrix.py

qemu-x86_64-platform-matrix: image-x86_64
	python3 ./scripts/qemu-x86_64-platform-matrix.py

qemu-benchmark:
	python3 ./scripts/qemu-benchmark.py

qemu-persistence-reboot: image
	python3 ./scripts/qemu-persistence-reboot.py

qemu-storage-crash-test: image
	python3 ./scripts/qemu-storage-crash-test.py

qemu-fault-matrix:
	python3 ./scripts/qemu-fault-matrix.py

qemu-regression-suite: image
	python3 ./scripts/qemu-regression-suite.py

qemu-fault-injection: image
	python3 ./scripts/qemu-fault-injection.py

qemu-abi-contract:
	python3 ./scripts/qemu-abi-contract.py

qemu-boot-loop: image
	python3 ./scripts/qemu-boot-loop.py

qemu-userspace-suite: image
	python3 ./scripts/qemu-userspace-suite.py

qemu-network-suite: image
	python3 ./scripts/qemu-network-suite.py

qemu-docker-network-suite:
	python3 ./scripts/qemu-docker-network-suite.py

qemu-parallel-network-load:
	python3 ./scripts/qemu-parallel-network-load.py

qemu-cpu-ai-suite: image
	python3 ./scripts/qemu-cpu-ai-suite.py

qemu-ssh-smoke:
	python3 ./scripts/qemu-ssh-smoke.py

qemu-model-sftp-gate:
	python3 ./scripts/qemu-model-sftp-gate.py

xaios-ssh-bridge:
	./scripts/run-xaios-ssh-bridge.sh

qemu-developer-ux:
	python3 ./scripts/qemu-developer-ux.py

qemu-post51-gate: image image-x86_64
	python3 ./scripts/qemu-post51-gate.py

qemu-readiness-gate:
	python3 ./scripts/qemu-readiness-gate.py

qemu-full-os-rc:
	python3 ./scripts/qemu-full-os-rc.py

compile-check:
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
	for f in $$(find userspace -name '*.c'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Iuserspace/include -Itests -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	if [ "$$failed" -ne 0 ]; then \
	  printf '%s\n' "$$failed file(s) failed compilation" >&2; \
	  exit 1; \
	fi; \
	printf '%s\n' "All C files compiled clean"

hosted-test:
	@mkdir -p build/hosted
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include tests/system/test_cpuset.c \
	  -o build/hosted/test-cpuset
	./build/hosted/test-cpuset
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/model_v2.c engine/src/sha256.c \
	  engine/src/architecture.c engine/src/backend_scalar.c \
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
	python3 scripts/check-model-support.py
	python3 scripts/check-core-os-status.py

production-source-audit:
	python3 scripts/check-production-source.py

qemu-baseline: image
	python3 ./scripts/benchmark-baseline.py

clean:
	rm -rf build out dist

clean-persistent:
	rm -f build/xaios-persistent.img

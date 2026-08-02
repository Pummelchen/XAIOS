SHELL := /bin/sh

.PHONY: all bootstrap test image image-x86_64 qemu qemu-aarch64 qemu-x86_64 qemu-x86_64-smoke intel-desktop-gate qemu-dry-run qemu-smoke qemu-process-gate qemu-osctl-gate qemu-filesystem-gate qemu-app-agent-gate qemu-network-full-gate qemu-cpu-ai-runtime-gate qemu-ai-cell-gate qemu-security-gate qemu-update-gate qemu-soak-gate qemu-release qemu-100-gate qemu-preview qemu-matrix qemu-cpu-matrix qemu-benchmark qemu-persistence-reboot qemu-fault-matrix qemu-regression-suite qemu-fault-injection qemu-abi-contract qemu-boot-loop qemu-userspace-suite qemu-network-suite qemu-docker-network-suite qemu-cpu-ai-suite qemu-ssh-smoke xaios-ssh-bridge qemu-developer-ux qemu-post51-gate qemu-readiness-gate qemu-full-os-rc compile-check hosted-test model-v2-test docs-check qemu-baseline clean clean-persistent

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

qemu-preview: image
	python3 ./scripts/qemu-preview.py

qemu-matrix:
	python3 ./scripts/qemu-matrix.py

qemu-cpu-matrix: image image-x86_64
	python3 ./scripts/qemu-cpu-matrix.py

qemu-benchmark:
	python3 ./scripts/qemu-benchmark.py

qemu-persistence-reboot: image
	python3 ./scripts/qemu-persistence-reboot.py

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

qemu-cpu-ai-suite: image
	python3 ./scripts/qemu-cpu-ai-suite.py

qemu-ssh-smoke:
	python3 ./scripts/qemu-ssh-smoke.py

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
	    -Wall -Wextra -Werror -Ikernel/include -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel/arch/x86_64 -name '*.c'); do \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -Ikernel/include -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -name 'crashtest_client.c'); do \
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
	clang -std=c99 -Wall -Wextra -Werror -pedantic \
	  -Iengine/include engine/src/model_v2.c engine/src/sha256.c \
	  engine/src/architecture.c engine/src/backend_scalar.c \
	  tests/model_v2/test_engine.c -o build/hosted/test-engine
	./build/hosted/test-engine
	PYTHONPATH=tools python3 -m unittest discover -s tests/model_v2 -p 'test_*.py'

model-v2-test: hosted-test

docs-check:
	python3 scripts/check-model-support.py

qemu-baseline: image
	python3 ./scripts/benchmark-baseline.py

clean:
	rm -rf build out dist

clean-persistent:
	rm -f build/xaios-persistent.img

# Image builds and the small image-level checks.
# Included from the Makefile; see its comment beside the include lines.

image:
	./scripts/build-image.sh

image-qemu-test:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh

image-x86_64:
	XAIOS_TARGET_ARCH=x86_64 ./scripts/build-image.sh

image-x86_64-qemu-test:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh

# B-31: this built two of the three images the gate boots, and the RISC-V leg
# booted whatever was already in build/. The list of architectures now lives
# in the gate, which builds each one immediately before booting it; this
# target is the same build without the boots.
image-libc-test: libc
	python3 tests/scripts/qemu-libc-gate.py --build-only

qemu-libc-gate: libc-check
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

# The matrix claimed SLAAC and nothing supported it. Two networks, because
# either alone proves the wrong thing: site-local space must NOT become a
# public address, and a global prefix must.
qemu-slaac-gate:
	python3 ./tests/scripts/qemu-slaac-gate.py

# Release images, the release package, local gates and firmware profiles.

# One bootable file for every environment: hybrid ISO 9660 and GPT, both
# architectures, bootable as optical media, as a disk, or from a USB stick.
# Both architectures are built here rather than taken from whatever build/
# happens to hold. The kernel's console behaviour is a build-time choice: a
# non-verbose build sends its log to the boot display instead of the console,
# so an image assembled from one boots perfectly and satisfies none of the
# markers the gates look for. That is not a stale image and the staleness
# check does not catch it -- it is a correct image of the wrong build, and it
# happened when make vmware-fusion-image rebuilt the kernel in passing.
# One architecture, one image. Each target builds that architecture's payload
# and then wraps it, and neither half knows about the other two -- which is the
# point: a boot that goes wrong has one kernel, one initial filesystem and one
# loader on the medium to be wrong about.
#
# Built here rather than picked up from the tree. The RISC-V kernel and initial
# filesystem used to be taken from whatever build/ happened to contain, so the
# shipped image carried whichever configuration someone had last built -- and,
# once, a kernel from an older build number than the image it was inside.
# Nothing said so: the image was assembled from files that existed, and files
# that exist look like files that were built.
release-image-aarch64:
	XAIOS_BOOT_VERBOSE=1 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	XAIOS_TARGET_ARCH=aarch64 ./scripts/build-arch-image.sh

release-image-x86_64:
	XAIOS_TARGET_ARCH=x86_64 XAIOS_BOOT_TEST_APPS=1 ./scripts/build-image.sh
	XAIOS_TARGET_ARCH=x86_64 ./scripts/build-arch-image.sh

release-image-riscv64:
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh
	XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-boot-media.sh
	XAIOS_TARGET_ARCH=riscv64 ./scripts/build-arch-image.sh

# All three, for a release. Serial rather than parallel: each one runs the
# same builders over the same build/ directory, and in parallel they would
# overwrite each other's intermediate objects.
release-images: release-image-aarch64 release-image-x86_64 release-image-riscv64

# The release package: the three images, and a zip beside each one.
release-package: release-images
	./scripts/build-release.sh

# Boot each released image on every environment that can run it. Shallower
# than the per-platform gates by design: those each boot an image they built
# for themselves, so all five can pass while the files a release actually
# contains boot nothing.
release-image-gate: release-images
	python3 ./tests/scripts/release-image-gate.py

# Everything CI cannot run: the two hypervisors and the half of the release
# image gate that drives them. Writes build/local-gates.json naming the commit
# it checked, so "was this verified on the hypervisors?" has an answer.
local-gates:
	python3 ./tests/scripts/local-gates.py

# Everything that must be true before this commit is tagged or shipped.
#
# CI already proves the part a Linux runner can reach, on every push. What it
# cannot reach is either hypervisor, so two of the five environments XAIOS
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
# The fifth environment is the runner, and it is the one that catches what this
# Mac cannot see. The sentence below used to be printed on the strength of the
# two local checks alone, which is how build 6 came to be cut in the middle of
# nine days of red CI.
release-check: docs-check
	python3 ./tests/repository/check-local-gate-record.py
	python3 ./tests/repository/check-release-package.py
	python3 ./tests/repository/check-ci-status.py
	@printf '%s\n' "release-check: this commit is verified on all four environments here, and on the runner"

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

# V-06's other named boundary: what Virtualization.framework's own display
# shows. Reachable where Fusion's is not, because the view is ours -- an
# NSView can be asked for its own pixels, and vmrun captureScreen cannot be
# asked at all without VMware Tools in the guest.
vz-framebuffer-gate: vz-harness
	python3 ./tests/scripts/vz-framebuffer-gate.py

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

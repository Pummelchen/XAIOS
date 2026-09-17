#!/bin/sh
# Package the two ways XAIOS reaches a machine that is not a virtual one.
#
# build-vm-packages.sh covers the environments that run XAIOS as a guest. What
# it does not cover is hardware: a stick you carry to a machine, and a machine
# with no disk at all that asks the network what to boot. Those are different
# artifacts with different failure modes, so they are packaged apart rather
# than as two more launchers beside the emulators.
#
# Two kits per architecture, rather than two kits that carry every
# architecture. XAIOS used to ship one image with all three loaders inside it,
# and these kits inherited that shape: one USB kit and one netboot kit, each
# answering whichever machine turned up. The images are separate now, so the
# kits are. It also matches how either one is actually used -- a stick is
# written for the machine in front of you, and a netboot server is pointed at
# one architecture's binary far more often than at three -- and it puts the
# architecture in the filename, where a person choosing a download can see it.
#
# The USB kit is that architecture's image and a writer. The image is already a
# GPT-partitioned disk with an EFI System Partition -- that is what makes it
# bootable as a disk rather than only as optical media -- so writing it to a
# stick is a copy, not a conversion, and the writer exists to name the device
# out loud rather than to transform anything.
#
# The netboot kit is a different binary. Firmware that boots from the network
# fetches exactly one file and then has nowhere to go back to, so that file
# carries the kernel and the initial filesystem inside itself; see
# build-netboot-image.sh. It carries a plain copy of the loader too, which is
# what makes a diskless machine able to install onto a disk it finds.
#
# Every kit documents the same installer, because it is the same installer.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
STAGE_ROOT="$BUILD_DIR/boot-media"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"

# Which architectures get kits. Same variable and same spelling as
# build-release.sh, because the two are asked the same question and a release
# built for a subset should not produce kits for the rest.
ARCHS="${XAIOS_RELEASE_ARCHS:-aarch64 x86_64 riscv64}"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}

# shasum is the Perl script macOS ships; sha256sum is the coreutils name and is
# what Linux has. The fallback has to be attached to the checksum command
# rather than to the pipeline: a pipeline reports the status of its last
# command, so `shasum ... | cut || sha256sum ...` never falls back at all --
# cut succeeds on empty input, and the kit ships a SHA256SUMS of blank
# checksums that `shasum -c` then refuses to parse.
sha_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

loader_for() {
  case "$1" in
    aarch64) printf 'BOOTAA64.EFI' ;;
    x86_64)  printf 'BOOTX64.EFI' ;;
    riscv64) printf 'BOOTRISCV64.EFI' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# How the architecture is written in prose, as opposed to how it is spelled in
# a filename.
label_for() {
  case "$1" in
    aarch64) printf 'AArch64' ;;
    x86_64)  printf 'x86-64' ;;
    riscv64) printf 'RISC-V 64-bit' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# The architecture as dnsmasq's --pxe-service wants it. Two of the three have
# names in its table; RISC-V does not, so it is given as the number. 27
# (0x001b) is "RISC-V 64-bit UEFI" in the IANA DHCPv6/BOOTP Processor
# Architecture Types registry, the same registry ARM64_EFI is 11 in, and
# dnsmasq documents a numeric CSA as the alternative to a name for exactly
# this case.
pxe_service_for() {
  case "$1" in
    aarch64) printf 'ARM64_EFI' ;;
    x86_64)  printf 'X86-64_EFI' ;;
    riscv64) printf '27' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# The value a client of this architecture puts in DHCP option 93, written as
# the README should say it. This is the field a hand-configured DHCP server
# selects the boot filename on, and getting it wrong is the failure this kit
# cannot detect from here.
option93_for() {
  case "$1" in
    aarch64) printf '`0x000b` (ARM64 EFI)' ;;
    x86_64)  printf '`0x0007` or `0x0009` (x86-64 EFI)' ;;
    riscv64) printf '`0x001b` (RISC-V 64-bit EFI)' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# Everything is checked before anything is written, the same way
# build-release.sh checks: a run that fails half-way leaves release/ holding
# some of this build's kits and some of the last one's, which is harder to
# notice than nothing having happened.
for arch in $ARCHS; do
  image="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  [ -f "$image" ] || {
    printf '%s\n' "missing: $image" "run: make release-package" >&2
    exit 1
  }
done

rm -rf "$STAGE_ROOT"
mkdir -p "$STAGE_ROOT" "$RELEASE_DIR"

# ------------------------------------------------------- the installer text
#
# Written once and pasted into every README. The kits reach the shell by
# different routes and everything after that is identical, so describing it
# once per kit would be six chances to describe it differently.
installer_section() {
  cat <<'EOF'
## Installing onto the machine's own disk

XAIOS installs with one command. It creates a GPT partition table on the
target, sizes an EFI System Partition from what is actually being copied,
formats it, writes the loader, kernel, initial filesystem and entropy seed,
and adds a state partition. There is no separate formatting step to run first
-- the formatting is what installing is.

Log in, then find the disk you mean:

    xaiosctl storage device list

That prints every block device the kernel found. Pick the target, and read its
GPT identity back:

    xaiosctl storage partition verify DISK

The `disk_guid` in that output is the confirmation the installer requires. It
is not a flag you can guess: passing the wrong one is refused, which is the
point -- it means the disk was looked at before it was overwritten.

    xaiosctl storage install DISK from ESP \
      --principal KEY --confirm-device DISK_GUID --operation-id N

`DISK` is the disk to install onto. `ESP` is where the files come from, which
on a USB boot is the EFI System Partition of the stick itself. `--operation-id`
is any nonzero number not used before on this machine; it is what makes a
retried request idempotent rather than a second install.

The installer refuses to write to the disk the source lives on. Installing
onto the stick you booted from is not a mistake it will let you make.

### If you want the partitions separately

`storage install` is the whole job. The pieces underneath it are also commands,
for a machine being laid out to a plan rather than installed onto:

    xaiosctl storage partition plan-create DISK ...   # what would change
    xaiosctl storage partition create DISK ...        # do it
    xaiosctl storage format-plan VOLUME ...           # what would change
    xaiosctl storage format VOLUME ...                # do it

Every mutation takes `--operation-id` and an exact UUID confirmation, and every
destructive one has a `plan-` form that reports what it would do and changes
nothing.
EOF
}

verification_section() {
  cat <<EOF

## Verifying what you downloaded

Checksums for every file in this kit are in \`SHA256SUMS\`:

    shasum -a 256 -c SHA256SUMS

The image embeds a fresh boot entropy seed on every build, so rebuilding this
commit produces a working image with a different checksum. That checksum
identifies this artifact, not the commit.

## What was tested, and where

See \`xaios_b${BUILD_NUMBER}.md\` in the release for the exact hosts and
firmware each route was booted on. Nothing there is inferred from a similar
configuration.
EOF
}

KITS=""

. "$ROOT_DIR/scripts/lib/boot-media-kits.sh"

. "$ROOT_DIR/scripts/lib/boot-media-checksums.sh"

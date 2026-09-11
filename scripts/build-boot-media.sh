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

for arch in $ARCHS; do
  IMAGE="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  IMAGE_NAME="xaios_b${BUILD_NUMBER}-${arch}.iso"
  LOADER=$(loader_for "$arch")
  LABEL=$(label_for "$arch")
  PXE_SERVICE=$(pxe_service_for "$arch")
  OPTION93=$(option93_for "$arch")

  # ----------------------------------------------------------------- USB
  USB_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-${arch}-usb"
  mkdir -p "$USB_DIR"
  cp "$IMAGE" "$USB_DIR/$IMAGE_NAME"

  cat > "$USB_DIR/write-usb.sh" <<EOF
#!/bin/sh
# Write XAIOS to a USB stick, having said which stick out loud.
#
# This is dd with the arguments filled in and one question asked. The question
# is the reason it exists: every account of someone destroying the wrong disk
# with dd ends with them having typed a device name they had not checked, and
# a script that names the device back and waits is the cheapest thing that
# breaks that.
#
# The image beside this script is $LABEL. Nothing here checks the machine you
# will boot the stick on, because the stick is written on one machine and
# booted on another and this script only sees the first.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)
IMAGE="\${XAIOS_IMAGE:-\$DIR/$IMAGE_NAME}"

[ -f "\$IMAGE" ] || { printf '%s\n' "missing: \$IMAGE" >&2; exit 1; }

if [ \$# -ne 1 ]; then
  printf '%s\n' "usage: \$0 /dev/rdiskN     (macOS)" \\
                "       \$0 /dev/sdX        (Linux)" "" \\
                "List the disks first, and read the sizes:" >&2
  if [ "\$(uname -s)" = "Darwin" ]; then
    printf '%s\n' "  diskutil list external physical" >&2
  else
    printf '%s\n' "  lsblk -o NAME,SIZE,MODEL,TRAN" >&2
  fi
  exit 2
fi

TARGET="\$1"
[ -e "\$TARGET" ] || { printf '%s\n' "no such device: \$TARGET" >&2; exit 1; }

printf '%s\n' "" "About to overwrite \$TARGET completely." ""
if [ "\$(uname -s)" = "Darwin" ]; then
  diskutil info "\$TARGET" 2>/dev/null |
    grep -E 'Device / Media Name|Disk Size|Removable Media|Protocol' || true
else
  lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINT "\$TARGET" 2>/dev/null || true
fi

printf '\n%s' "Everything on it will be lost. Type the device name to confirm: "
read -r CONFIRM
[ "\$CONFIRM" = "\$TARGET" ] || {
  printf '%s\n' "not confirmed; nothing was written" >&2
  exit 1
}

# macOS holds the disk until it is unmounted, and refuses the write otherwise.
if [ "\$(uname -s)" = "Darwin" ]; then
  diskutil unmountDisk "\$TARGET" || true
fi

printf '%s\n' "writing \$IMAGE to \$TARGET ..."
# 4 MiB blocks: the default 512 bytes turns a two-minute write into an hour.
dd if="\$IMAGE" of="\$TARGET" bs=4m 2>/dev/null ||
  dd if="\$IMAGE" of="\$TARGET" bs=4M
sync
printf '%s\n' "done. Eject before removing:"
if [ "\$(uname -s)" = "Darwin" ]; then
  printf '%s\n' "  diskutil eject \$TARGET"
fi
EOF
  chmod +x "$USB_DIR/write-usb.sh"

  {
    cat <<EOF
# XAIOS build $BUILD_NUMBER — bootable USB, $LABEL

One stick, two ways to use it: run XAIOS from it without touching the
machine's disks, or install onto one of them.

\`$IMAGE_NAME\` is an ISO 9660 filesystem and a GPT-partitioned
disk with an EFI System Partition at the same time. Firmware that boots
removable media opens the ESP and finds a loader there, which is why writing it
to a stick is a copy rather than a conversion.

## Which machines this stick boots

This stick boots $LABEL machines and no others. The loader on its ESP is
\`$LOADER\`, which is the name $LABEL firmware looks for on
removable media, and it is the only loader in the image.

XAIOS used to ship one image carrying all three architectures behind all three
loader names. It ships one image per architecture now. A stick written from
this kit and taken to a machine of another architecture does not half-boot:
firmware finds nothing under the name it looks for, and moves on to the next
boot entry as though the stick were blank.

## Writing the stick

    ./write-usb.sh /dev/rdiskN     # macOS
    ./write-usb.sh /dev/sdX        # Linux

Run it with no arguments first: it prints the command that lists your disks.
It names the target back, waits for you to type the device, and writes nothing
until you do.

Any 512 MiB stick is large enough. Writing the image does not leave free space
you can use for anything else, and it is not meant to -- see below.

## 1. Running it directly

Boot the machine from the stick. On most firmware that is a boot-menu key at
power-on (F12, F10, Esc, or Option on a Mac) and picking the USB entry; on some
you set the order in firmware setup instead.

XAIOS starts, reaches a login prompt, and takes an address by DHCP if a network
is present. Nothing is written to any disk in the machine. This is the mode for
looking at hardware you have not installed onto yet -- \`xaiosctl hardware\`
reports what the kernel found, and \`xaiosctl storage device list\` reports the
disks, without changing any of them.

The stick itself is read-only in this mode. XAIOS keeps its durable state on a
separate volume, and a live boot has none, so configuration made here lasts
until the machine is turned off. A machine that should keep its state is a
machine to install.

EOF
    installer_section
    cat <<'EOF'

On a USB boot the source is the stick's own EFI System Partition. Take the ESP
identifier from `xaiosctl storage device list` -- it is the partition on the
device you booted from -- and the target is a different disk entirely.

EOF
    verification_section
  } > "$USB_DIR/README.md"

  # ------------------------------------------------------------- netboot
  NETBOOT_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-${arch}-netboot"
  mkdir -p "$NETBOOT_DIR"

  # One binary, built here rather than taken from build/: the kit has to carry
  # the netboot file for this build, and a leftover from a previous one is
  # indistinguishable from a current one once it is inside a zip.
  XAIOS_TARGET_ARCH="$arch" \
  XAIOS_NETBOOT_IMAGE="$NETBOOT_DIR/$LOADER" \
    "$ROOT_DIR/scripts/build-netboot-image.sh" >/dev/null
  [ -f "$NETBOOT_DIR/$LOADER" ] || {
    printf '%s\n' "error: netboot image for $arch was not produced" >&2
    exit 1
  }

  # The RISC-V pxe-service entry is a number rather than a name, and the
  # comment in the served script has to say why, because a bare 27 in a command
  # line is the kind of thing someone later replaces with a guess.
  if [ "$arch" = riscv64 ]; then
    PXE_NOTE='# RISC-V has no name in dnsmasq'"'"'s architecture table, so it is given as the
# number: 27 (0x001b) is "RISC-V 64-bit UEFI" in the IANA DHCPv6/BOOTP
# Processor Architecture Types registry, the same registry ARM64_EFI is 11 in.
# dnsmasq documents a numeric CSA as the alternative to a name for this case.'
  else
    PXE_NOTE='# The architecture token below is dnsmasq'"'"'s name for this client
# architecture. It has to match what the machine puts in option 93, or the
# machine gets no answer and falls through to its next boot entry.'
  fi

  cat > "$NETBOOT_DIR/serve-netboot.sh" <<EOF
#!/bin/sh
# Serve this one file to $LABEL machines on this network that boot from it.
#
# dnsmasq in proxy-DHCP mode: it answers the boot half of DHCP and leaves
# addresses to the router that already hands them out. That distinction is the
# whole reason this is safe to run on a network you share -- a second DHCP
# server issuing addresses would fight the first one, and this does not issue
# any.
#
# This kit is one architecture. Machines of another architecture on the same
# network ask for their own client architecture in option 93, are not matched
# by the service below, and are left alone -- which is the behaviour wanted:
# the alternative, answering everyone with the only file present, is a machine
# that fetches successfully and then faults on a binary built for something
# else. Serve the other architectures by running their own kits beside this
# one, on their own hosts or with dnsmasq configured by hand.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)

command -v dnsmasq >/dev/null 2>&1 || {
  printf '%s\n' "error: dnsmasq is required" \\
    "  macOS:  brew install dnsmasq" \\
    "  Debian: apt install dnsmasq" >&2
  exit 1
}

if [ \$# -lt 1 ]; then
  printf '%s\n' "usage: \$0 <this-host-ipv4> [interface]" "" \\
    "The address is the one machines booting from this network can reach." \\
    "It goes in the TFTP redirect, so a wrong one produces a machine that" \\
    "gets an answer and then times out fetching the file." >&2
  exit 2
fi
SERVER="\$1"
IFACE="\${2:-}"

# Architecture is client-supplied (DHCP option 93) and each one boots a
# different file.
$PXE_NOTE
set -- \\
  --port=0 \\
  --dhcp-range="\$SERVER,proxy" \\
  --enable-tftp --tftp-root="\$DIR" \\
  --pxe-service=$PXE_SERVICE,"XAIOS build $BUILD_NUMBER ($arch)",$LOADER,"\$SERVER" \\
  --log-dhcp --no-daemon
[ -n "\$IFACE" ] && set -- "\$@" --interface="\$IFACE"

printf '%s\n' \\
  "serving $LOADER from \$DIR as \$SERVER, to $LABEL clients only" \\
  "proxy DHCP only: addresses still come from your existing server" \\
  "needs root, because DHCP and TFTP are privileged ports" ""
exec sudo dnsmasq "\$@"
EOF
  chmod +x "$NETBOOT_DIR/serve-netboot.sh"

  {
    cat <<EOF
# XAIOS build $BUILD_NUMBER — network boot (PXE), $LABEL

One file, for a $LABEL machine with no disk, or with a disk whose
contents you are about to replace.

\`$LOADER\` — $LABEL

It is a complete system. Firmware that boots from the network fetches one file
over TFTP and then has nowhere to go back to for a second one, so the kernel,
the initial filesystem and an entropy seed are inside the binary as PE sections
rather than beside it as files. There is no directory of extra payloads to
serve, and adding one would not help: the loader does not ask.

It also carries a plain copy of the loader, which is what lets a machine that
arrived over the network write a bootable disk. A running PE cannot be copied
back out -- firmware maps its sections at their virtual addresses, so what is
in memory is not the file that was fetched -- so the file it would need is
carried rather than reconstructed.

## Serving it

    ./serve-netboot.sh 192.0.2.10 en0

The address is this host's, as reachable by the machines booting. dnsmasq runs
in proxy-DHCP mode: it answers only the boot question and leaves addresses to
whatever already hands them out, so it does not collide with the network's own
DHCP server. It needs root for ports 67 and 69.

Then set the machine to boot from the network -- usually a boot-menu entry
named PXE, or the network interface itself.

## The architecture has to match

This kit serves $LABEL clients and nothing else. A machine
announces what it is in DHCP option 93, and the value that selects
\`$LOADER\` is $OPTION93.

The other two XAIOS binaries answer to their own values: \`0x000b\` (ARM64
EFI) selects \`BOOTAA64.EFI\`, \`0x0007\` or \`0x0009\` (x86-64 EFI) selects
\`BOOTX64.EFI\`, and \`0x001b\` (RISC-V 64-bit EFI) selects
\`BOOTRISCV64.EFI\`.

\`serve-netboot.sh\` matches on that value, so a machine of another
architecture gets no answer from it and moves on. If you configure your own
DHCP server instead, the two options that matter are the next-server address
and the boot filename, and the filename has to be selected on option 93 rather
than handed to everyone. Serving one file to all comers is the common mistake,
and it produces a machine that fetches successfully and then faults on a binary
built for another architecture -- a failure that looks like a corrupt download
and is a routing decision.

EOF
    if [ "$arch" = riscv64 ]; then
      cat <<'EOF'
## What has not been exercised here

Netboot has never been exercised on RISC-V in this project. No RISC-V machine
that netboots has been in front of it, so nothing here has watched a RISC-V
client send option 93, be matched, fetch this file and start it.

What is unproven is that fetch and that selection, not the system inside the
binary. The file is built by the same script that builds the other two, from
the same loader, kernel and initial filesystem that the RISC-V gates boot from
disk. The 27 in `serve-netboot.sh` is read from the IANA registry rather than
from a machine that accepted it.

EOF
    fi
    installer_section
    cat <<'EOF'

A netbooted machine has no EFI System Partition to copy from, and does not need
one: the installer writes the loader, kernel and initial filesystem out of the
binary it booted from. Give it the target disk, and the source is the image
itself.

EOF
    verification_section
  } > "$NETBOOT_DIR/README.md"

  KITS="$KITS $USB_DIR $NETBOOT_DIR"
done

# ------------------------------------------------------------- checksums
# Per-kit, and covering the kit's own files rather than the release as a whole,
# so `shasum -c` works in the directory a person extracted without them having
# to fetch anything else.
for kit in $KITS; do
  ( cd "$kit" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort |
      while read -r file; do
        printf '%s  %s\n' "$(sha_of "$file")" "$file"
      done > SHA256SUMS )
done

# -------------------------------------------------------------- archives
printf '%s\n' "XAIOS build $BUILD_NUMBER boot media kits"
for kit in $KITS; do
  name=$(basename "$kit")
  archive="$RELEASE_DIR/$name.zip"
  rm -f "$archive"
  ( cd "$STAGE_ROOT" && zip -qr "$archive" "$name" )
  printf '  %s\n' "$name.zip"
  printf '    %s bytes\n' "$(wc -c < "$archive" | tr -d ' ')"
  printf '    SHA-256 %s\n' "$(sha_of "$archive")"
done
for arch in $ARCHS; do
  printf '  image %-8s %s\n' "$arch" \
    "$(sha_of "$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso")"
done

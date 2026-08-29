#!/bin/sh
# Package XAIOS as something a person downloads, extracts and starts.
#
# The release already carries the image. What it does not carry is a way to run
# it: a person who downloads xaios_b<n>.iso still has to know that QEMU wants
# gic-version=3, that Fusion boots it from a SATA CD-ROM and needs a .vmx, and
# that Virtualization.framework needs a harness they have to sign themselves.
# All of that is written down in this repository and none of it travels with
# the file.
#
# One image, three kits. The unified image already boots all four environments
# -- that is what makes it unified -- so shipping three copies of the same 222
# MB would be three chances for them to disagree, not three products. Each kit
# carries the image once, the launcher for that environment, and a README that
# says what was tested and exactly what to run.
#
# Virtualization.framework is the exception and says so in its own README: the
# harness has to be code-signed with entitlements on the machine that runs it,
# so the kit carries the source and the build script rather than a binary
# nobody else's Mac would accept.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
STAGE_ROOT="$BUILD_DIR/vm-packages"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
IMAGE="$RELEASE_DIR/xaios_b${BUILD_NUMBER}.iso"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}
[ -f "$IMAGE" ] || {
  printf '%s\n' "missing: $IMAGE" "run: make release-package" >&2
  exit 1
}

IMAGE_SHA=$(shasum -a 256 "$IMAGE" 2>/dev/null | cut -d' ' -f1 ||
            sha256sum "$IMAGE" | cut -d' ' -f1)
IMAGE_NAME="xaios_b${BUILD_NUMBER}.iso"

rm -rf "$STAGE_ROOT"
mkdir -p "$STAGE_ROOT" "$RELEASE_DIR"

# Shared by every README: the image is one artifact with one checksum, and a
# rebuild deliberately does not reproduce it.
common_footer() {
  cat <<EOF

## Verifying what you downloaded

\`$IMAGE_NAME\` — SHA-256 \`$IMAGE_SHA\`

    shasum -a 256 $IMAGE_NAME

The image embeds a fresh boot entropy seed on every build, so rebuilding this
commit produces a working image with a different checksum. That checksum
identifies this artifact, not the commit: verify a download against it, and do
not expect a rebuild to match.

## What was tested, and where

See \`xaios_b${BUILD_NUMBER}.md\` in the release for the exact host, hypervisor
versions and firmware each environment was booted on. Nothing there is inferred
from a similar configuration.
EOF
}

# ---------------------------------------------------------------- QEMU
QEMU_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-qemu"
mkdir -p "$QEMU_DIR"
cp "$IMAGE" "$QEMU_DIR/$IMAGE_NAME"

cat > "$QEMU_DIR/run-aarch64.sh" <<EOF
#!/bin/sh
# Start XAIOS on QEMU, AArch64.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)
IMAGE="\${XAIOS_IMAGE:-\$DIR/$IMAGE_NAME}"
DATA="\${XAIOS_DATA:-\$DIR/xaios-data.img}"

# A writable volume, created empty the first time and kept afterwards. XAIOS
# formats a blank one itself on the boot that finds it. Without one the SSH
# server refuses to start -- its configuration lives on durable storage, so a
# machine with nowhere to keep it has no configuration to load, and reports
# that rather than starting an unconfigured server.
if [ ! -f "\$DATA" ]; then
  printf '%s\n' "creating a 64 MiB writable volume: \$DATA"
  dd if=/dev/zero of="\$DATA" bs=1048576 count=64 status=none
fi

# gic-version=3 is not optional. Without it the machine faults in the GIC
# redistributor before the kernel prints anything, and the failure looks like a
# broken image rather than a missing flag.
MACHINE="virt,gic-version=3"

for candidate in \\
  /opt/homebrew/share/qemu/edk2-aarch64-code.fd \\
  /usr/local/share/qemu/edk2-aarch64-code.fd \\
  /usr/share/AAVMF/AAVMF_CODE.fd \\
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
do
  [ -f "\$candidate" ] && FIRMWARE="\$candidate" && break
done
[ -n "\${FIRMWARE:-}" ] || {
  printf '%s\n' "error: no AArch64 UEFI firmware found." \\
    "  macOS:  brew install qemu" \\
    "  Debian: apt install qemu-efi-aarch64" >&2
  exit 1
}

# The network device goes on the MMIO bus, not PCI. QEMU's virt machine offers
# both, and this image's virtio-net driver binds the MMIO one; attached only to
# PCI it finds no network device at all, reports that IPv4 is not ready and
# withholds the SSH server. Measured by shipping it that way once.
#
# Port 2222 on the host reaches port 22 in the guest, so the SSH server this
# image starts is reachable without configuring anything.
exec qemu-system-aarch64 \\
  -machine "\$MACHINE" -cpu cortex-a72 -smp 4 -m 2048 \\
  -global virtio-mmio.force-legacy=false \\
  -drive "if=pflash,format=raw,readonly=on,file=\$FIRMWARE" \\
  -drive "if=none,format=raw,readonly=on,id=xaios,file=\$IMAGE" \\
  -device virtio-blk-pci,drive=xaios,bootindex=0 \\
  -drive "if=none,format=raw,id=xaios_data,file=\$DATA" \\
  -device virtio-blk-device,drive=xaios_data,bus=virtio-mmio-bus.1 \\
  -netdev "user,id=net0,hostfwd=tcp::\${XAIOS_SSH_PORT:-2222}-:22" \\
  -device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.2 \\
  -nographic -serial mon:stdio
EOF

cat > "$QEMU_DIR/run-x86_64.sh" <<EOF
#!/bin/sh
# Start XAIOS on QEMU, x86-64. The same image: firmware picks the kernel.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)
IMAGE="\${XAIOS_IMAGE:-\$DIR/$IMAGE_NAME}"
DATA="\${XAIOS_DATA:-\$DIR/xaios-data-x86.img}"
SCRATCH="\${XAIOS_SCRATCH:-\$DIR/xaios-scratch-x86.img}"

# Two volumes, and the order is what matters rather than the count: the driver
# numbers PCI functions and expects durable storage at the second one after the
# boot disk.
#
# Which is also why disable-legacy=on appears on the boot disk below and not
# only on these. Without it QEMU presents the boot disk as a transitional
# device, whose PCI identity this image's driver does not recognise -- so it is
# not counted, every ordinal shifts by one, and the driver looks for durable
# storage past the last disk attached. The machine then boots perfectly and
# reports no persistent storage, which reads as a missing disk and is a missing
# flag on a different one.
for volume in "\$SCRATCH" "\$DATA"; do
  if [ ! -f "\$volume" ]; then
    printf '%s\n' "creating a 64 MiB volume: \$volume"
    dd if=/dev/zero of="\$volume" bs=1048576 count=64 status=none
  fi
done

for candidate in \\
  /opt/homebrew/share/qemu/edk2-x86_64-code.fd \\
  /usr/local/share/qemu/edk2-x86_64-code.fd \\
  /usr/share/OVMF/OVMF_CODE.fd \\
  /usr/share/ovmf/OVMF.fd
do
  [ -f "\$candidate" ] && FIRMWARE="\$candidate" && break
done
[ -n "\${FIRMWARE:-}" ] || {
  printf '%s\n' "error: no x86-64 UEFI firmware found." \\
    "  macOS:  brew install qemu" \\
    "  Debian: apt install ovmf" >&2
  exit 1
}

# disable-legacy=on is deliberate: without it QEMU presents a transitional
# device whose PCI identity this image's driver does not match, and the machine
# comes up with no network.
exec qemu-system-x86_64 \\
  -machine q35 -cpu max -smp 4 -m 2048 \\
  -drive "if=pflash,format=raw,readonly=on,file=\$FIRMWARE" \\
  -drive "if=none,format=raw,readonly=on,id=xaios,file=\$IMAGE" \\
  -device virtio-blk-pci,drive=xaios,bootindex=0,disable-legacy=on \\
  -drive "if=none,format=raw,id=xaios_scratch,file=\$SCRATCH" \\
  -device virtio-blk-pci,drive=xaios_scratch,disable-legacy=on \\
  -drive "if=none,format=raw,id=xaios_data,file=\$DATA" \\
  -device virtio-blk-pci,drive=xaios_data,disable-legacy=on \\
  -netdev "user,id=net0,hostfwd=tcp::\${XAIOS_SSH_PORT:-2222}-:22" \\
  -device virtio-net-pci,netdev=net0,disable-legacy=on \\
  -nographic -serial mon:stdio
EOF
chmod +x "$QEMU_DIR/run-aarch64.sh" "$QEMU_DIR/run-x86_64.sh"

{
  cat <<EOF
# XAIOS build $BUILD_NUMBER — QEMU

    ./run-aarch64.sh      # AArch64
    ./run-x86_64.sh       # x86-64

Both scripts boot the same image; the firmware selects the kernel for its
architecture. The console is on the terminal you started it from.

Port 2222 on your machine reaches the guest's SSH server. Set \`XAIOS_SSH_PORT\`
to use a different one.

Needs \`qemu-system-aarch64\` or \`qemu-system-x86_64\` and the matching UEFI
firmware. The scripts look for the firmware in the usual places and say what to
install if they cannot find it.

To leave the guest, press \`Ctrl-a\` then \`x\`.

## Two flags that matter, if you write your own command line

\`gic-version=3\` on AArch64. Without it the machine faults in the GIC
redistributor before the kernel prints anything, which looks like a broken
image rather than a missing flag.

And the network device has to be one this image binds. On AArch64 that is
\`virtio-net-device\` on \`virtio-mmio-bus.2\`, *with*
\`-global virtio-mmio.force-legacy=false\`: without that global QEMU presents a
legacy MMIO device, the driver requires a modern one, and the machine finds no
network at all. On x86-64 it is \`virtio-net-pci,disable-legacy=on\`, for the
same reason on the other transport.

Attached any other way the machine boots, reports that IPv4 is not ready and
withholds the SSH server -- which reads as a broken image and is a wrong flag.
Both mistakes were made while writing these scripts.
EOF
  common_footer
} > "$QEMU_DIR/README.md"

# ------------------------------------------------------- VMware Fusion
FUSION_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-vmware-fusion"
BUNDLE="$FUSION_DIR/XAIOS.vmwarevm"
mkdir -p "$BUNDLE"
cp "$IMAGE" "$BUNDLE/$IMAGE_NAME"
# The profile points at the packaged image and keeps the writable disk. An
# earlier version of this script dropped the disk, on the theory that a kit
# should start without the recipient creating one first. That was wrong twice
# over: XAIOS refuses to start its SSH server without durable storage, because
# the configuration sshd loads lives there -- so the kit would have booted to a
# console and nothing else -- and Fusion creates the disk itself on first power
# on when the descriptor names a file that is not there.
sed -e "s|sata0:0.fileName = \"xaios-fusion.iso\"|sata0:0.fileName = \"$IMAGE_NAME\"|" \
    -e "s|sata0:1.fileName = \"xaios-fusion.vmdk\"|sata0:1.fileName = \"xaios-data.vmdk\"|" \
    "$ROOT_DIR/platform/vmware-fusion/XAIOS.vmx.in" > "$BUNDLE/XAIOS.vmx"
# Build the disk here if this machine can, so the kit arrives complete.
VDISK_MANAGER="${XAIOS_FUSION_VDISK_MANAGER:-/Applications/VMware Fusion.app/Contents/Library/vmware-vdiskmanager}"
if [ -x "$VDISK_MANAGER" ]; then
  "$VDISK_MANAGER" -c -s "${XAIOS_FUSION_DISK_SIZE:-256MB}" -a lsilogic -t 0 \
    "$BUNDLE/xaios-data.vmdk" >/dev/null
else
  printf '%s\n' "note: no vmware-vdiskmanager here; the Fusion kit ships without" \
    "      its data disk and Fusion will create one on first power on." >&2
fi

{
  cat <<EOF
# XAIOS build $BUILD_NUMBER — VMware Fusion

Double-click \`XAIOS.vmwarevm\`, or:

    open XAIOS.vmwarevm

Fusion boots the image from a SATA CD-ROM. The console appears in the Fusion
window.

The profile runs four vCPUs and attaches a 256 MB writable disk beside the
image. XAIOS formats that disk on the boot that first finds it, and keeps its
SSH host key and configuration there afterwards.

## If you are editing the profile

Keep the writable disk. Without durable storage XAIOS starts, takes an address,
and then declines to run its SSH server, because the configuration sshd loads
lives on that disk and a machine with nowhere to keep it has none to load. The
machine looks healthy and is unreachable.
EOF
  common_footer
} > "$FUSION_DIR/README.md"

# ------------------------------------ Apple Virtualization.framework
VZ_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-virtualization-framework"
mkdir -p "$VZ_DIR"
cp "$IMAGE" "$VZ_DIR/$IMAGE_NAME"
cp "$ROOT_DIR/platform/virtualization-framework/xaios_vz.swift" "$VZ_DIR/"
cp "$ROOT_DIR/platform/virtualization-framework/xaios-vz.entitlements" "$VZ_DIR/"

cat > "$VZ_DIR/build-and-run.sh" <<EOF
#!/bin/sh
# Build, sign and start the Virtualization.framework harness.
#
# The binary cannot be shipped built. Virtualization.framework requires the
# com.apple.security.virtualization entitlement, and an entitled binary must be
# signed by a certificate the running Mac trusts -- so it is signed here, on
# the machine that will run it, with an ad-hoc signature.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)
IMAGE="\${XAIOS_IMAGE:-\$DIR/$IMAGE_NAME}"
SCRATCH="\${XAIOS_SCRATCH:-\$DIR/xaios-scratch.img}"
DATA="\${XAIOS_DATA:-\$DIR/xaios-data.img}"

# The harness takes the boot disk first and then volumes in a fixed order, of
# which durable storage is the second. Both are created empty the first time
# and kept afterwards; XAIOS formats a blank one on the boot that finds it.
# Without them the machine boots, gets an address on vmnet, and then refuses to
# start its SSH server, because the configuration sshd loads lives on durable
# storage and there is none.
for volume in "\$SCRATCH" "\$DATA"; do
  if [ ! -f "\$volume" ]; then
    printf '%s\n' "creating a 64 MiB volume: \$volume"
    dd if=/dev/zero of="\$volume" bs=1048576 count=64 status=none
  fi
done

command -v swiftc >/dev/null 2>&1 || {
  printf '%s\n' "error: swiftc is required; install the Xcode command line tools" >&2
  exit 1
}
swiftc -O -o "\$DIR/xaios-vz" "\$DIR/xaios_vz.swift"
codesign --sign - --entitlements "\$DIR/xaios-vz.entitlements" \\
  --force "\$DIR/xaios-vz"
exec "\$DIR/xaios-vz" "\$IMAGE" "\$SCRATCH" "\$DATA" \\
  --memory-mib 2048 --cpus 4
EOF
chmod +x "$VZ_DIR/build-and-run.sh"

{
  cat <<EOF
# XAIOS build $BUILD_NUMBER — Apple Virtualization.framework

    ./build-and-run.sh

This is the only kit that builds something on your machine, and the reason is
not packaging convenience. Virtualization.framework requires the
\`com.apple.security.virtualization\` entitlement, and an entitled binary has
to be signed by a certificate the running Mac trusts. A binary signed here
would not run there, so the harness is compiled and ad-hoc signed on the Mac
that will run it. Needs the Xcode command line tools.

The kernel log streams to the terminal over the virtio console. XAIOS reaches a
login prompt, takes an address on vmnet by DHCP and listens for SSH on port 22
of that address.

Two 64 MiB volumes are created beside the image on the first run and kept
afterwards. The harness takes them in a fixed order and durable storage is the
second; without it the machine boots and gets an address, then refuses to start
its SSH server, because the configuration sshd loads lives on durable storage.

## Why this target exists

QEMU cannot run XAIOS under HVF: it aborts while emulating MMIO whose trap
carries no instruction syndrome, which is QEMU's limitation and reproduces from
other guests. What remains under QEMU is TCG, which models no cache or timing
behaviour. Virtualization.framework runs the guest on the host's own cores with
the real interrupt controller and timer, so it is the route to correctness and
timing behaviour on real silicon.
EOF
  common_footer
} > "$VZ_DIR/README.md"

# ------------------------------------------------------------- archives
printf '%s\n' "XAIOS build $BUILD_NUMBER virtual machine kits"
for kit in "$QEMU_DIR" "$FUSION_DIR" "$VZ_DIR"; do
  name=$(basename "$kit")
  archive="$RELEASE_DIR/$name.zip"
  rm -f "$archive"
  (cd "$STAGE_ROOT" && zip -qr "$archive" "$name")
  sha=$(shasum -a 256 "$archive" 2>/dev/null | cut -d' ' -f1 ||
        sha256sum "$archive" | cut -d' ' -f1)
  printf '  %s\n' "$name.zip"
  printf '    %s bytes\n' "$(wc -c < "$archive" | tr -d ' ')"
  printf '    SHA-256 %s\n' "$sha"
done
printf '  image: %s\n' "$IMAGE_SHA"

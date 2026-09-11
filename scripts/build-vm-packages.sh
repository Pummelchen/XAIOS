#!/bin/sh
# Package XAIOS as something a person downloads, extracts and starts.
#
# The release already carries the images. What it does not carry is a way to
# run one: a person who downloads xaios_b<n>-aarch64.iso still has to know that
# QEMU wants gic-version=3, that Fusion boots it from a SATA CD-ROM and needs a
# .vmx, and that Virtualization.framework needs a harness they have to sign
# themselves. All of that is written down in this repository and none of it
# travels with the file.
#
# One kit per environment per architecture. There used to be one image that
# booted every environment, and three kits carrying a copy of it; the images
# are per-architecture now, so the QEMU kit is too, and each one carries the
# image for its own architecture and the launcher that starts it. A kit with
# one image and one runner cannot be started against the wrong file.
#
# Fusion and Virtualization.framework are AArch64 only, and that is not a gap
# waiting to be filled -- see their READMEs. Both run guests on this host's own
# cores, and this host's cores are AArch64, so an x86-64 or RISC-V guest here
# is emulation, which is what the QEMU kit already is.
#
# Virtualization.framework is also the one kit that ships source: the harness
# has to be code-signed with entitlements on the machine that runs it, so it
# carries the source and the build script rather than a binary nobody else's
# Mac would accept.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
STAGE_ROOT="$BUILD_DIR/vm-packages"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"

# Which architectures get kits. Same variable and same spelling as
# build-release.sh and build-boot-media.sh, because all three are asked the
# same question about the same release.
ARCHS="${XAIOS_RELEASE_ARCHS:-aarch64 x86_64 riscv64}"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}

# The fallback belongs on the checksum command rather than after the pipeline:
# a pipeline reports the status of its last command, so `shasum ... | cut ||
# sha256sum ...` never falls back -- cut succeeds on empty input and the
# printed checksum is a blank line.
sha_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

label_for() {
  case "$1" in
    aarch64) printf 'AArch64' ;;
    x86_64)  printf 'x86-64' ;;
    riscv64) printf 'RISC-V 64-bit' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# Checked before anything is copied, so a run that fails leaves the previous
# release's kits alone rather than replacing half of them.
for arch in $ARCHS; do
  image="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  [ -f "$image" ] || {
    printf '%s\n' "missing: $image" "run: make release-package" >&2
    exit 1
  }
done

rm -rf "$STAGE_ROOT"
mkdir -p "$STAGE_ROOT" "$RELEASE_DIR"

# Shared by every README: the image in the kit is one artifact with one
# checksum, and a rebuild deliberately does not reproduce it. Takes the name
# and the checksum as arguments now that they differ between kits -- a footer
# that named one image while the kit carried another would be worse than none.
common_footer() {
  cat <<EOF

## Verifying what you downloaded

\`$1\` — SHA-256 \`$2\`

    shasum -a 256 $1

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

KITS=""

for arch in $ARCHS; do
  IMAGE="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  IMAGE_NAME="xaios_b${BUILD_NUMBER}-${arch}.iso"
  IMAGE_SHA=$(sha_of "$IMAGE")
  LABEL=$(label_for "$arch")

  # ---------------------------------------------------------------- QEMU
  QEMU_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-${arch}-qemu"
  mkdir -p "$QEMU_DIR"
  cp "$IMAGE" "$QEMU_DIR/$IMAGE_NAME"

  # The runner keeps its architecture in its name -- run-aarch64.sh, not
  # run.sh -- even though a kit now holds exactly one. A bug report quoting
  # `./run-riscv64.sh` says which kit it came from; one quoting `./run.sh`
  # does not, and the archives are extracted side by side often enough that
  # the name is worth the redundancy. The README says so too.
  case "$arch" in
  aarch64)
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
    ;;
  x86_64)
    cat > "$QEMU_DIR/run-x86_64.sh" <<EOF
#!/bin/sh
# Start XAIOS on QEMU, x86-64.
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
    ;;
  riscv64)
    cat > "$QEMU_DIR/run-riscv64.sh" <<EOF
#!/bin/sh
# Start XAIOS on QEMU, RISC-V 64-bit.
#
# This board is the one of the three that can also be started by handing QEMU
# the kernel ELF directly, and most of this project's RISC-V gates do exactly
# that because it is much faster. This script does not, and the difference is
# not a preference: started that way there is no loader, so nothing has read
# the medium and the guest is not booting the image at all. The point of a kit
# built around an image is the image.
set -eu
DIR=\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)
IMAGE="\${XAIOS_IMAGE:-\$DIR/$IMAGE_NAME}"
DATA="\${XAIOS_DATA:-\$DIR/xaios-data-riscv64.img}"

if [ ! -f "\$DATA" ]; then
  printf '%s\n' "creating a 64 MiB writable volume: \$DATA"
  dd if=/dev/zero of="\$DATA" bs=1048576 count=64 status=none
fi

# EDK2 for RISC-V comes as a code image and a variable store, and the two are a
# pair. The store is written by the firmware on every boot, so a copy is made
# beside this script rather than editing the one the package manager installed.
for candidate in \\
  /opt/homebrew/share/qemu/edk2-riscv-code.fd \\
  /usr/local/share/qemu/edk2-riscv-code.fd \\
  /usr/share/qemu/edk2-riscv-code.fd \\
  /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd
do
  [ -f "\$candidate" ] && FIRMWARE="\$candidate" && break
done
[ -n "\${FIRMWARE:-}" ] || {
  printf '%s\n' "error: no RISC-V UEFI firmware found." \\
    "  macOS:  brew install qemu" \\
    "  Debian: apt install qemu-efi-riscv64" >&2
  exit 1
}
VARS_SOURCE=\$(printf '%s' "\$FIRMWARE" | sed -e 's/-code\.fd\$/-vars.fd/' \\
                                              -e 's/_CODE\.fd\$/_VARS.fd/')
[ -f "\$VARS_SOURCE" ] || {
  printf '%s\n' "error: found \$FIRMWARE but no matching variable store at" \\
    "       \$VARS_SOURCE -- the two ship together and a code image without" \\
    "       its store cannot record a boot entry." >&2
  exit 1
}
VARS="\$DIR/edk2-riscv-vars.fd"
[ -f "\$VARS" ] || cp "\$VARS_SOURCE" "\$VARS"

# acpi=off is required rather than incidental. With ACPI on, this EDK2 build
# publishes no device tree, and this port reads its interrupt controller, its
# timebase and its virtio window from one -- so the machine starts, finds none
# of the three, and stops without saying why.
#
# force-legacy=false matters as much: QEMU's virtio-mmio transports default to
# the legacy interface, which the driver refuses because it requires version 2.
# Without it every MMIO slot reads as empty, so the durable volume and the
# network below are simply absent.
#
# The durable volume is on virtio-mmio-bus.1 and the network on
# virtio-mmio-bus.2, matching the AArch64 kit's runner: the driver scans the
# MMIO windows before falling back to PCI, so a NIC attached only to PCI leaves
# the machine reporting that IPv4 is not ready and withholding the SSH server.
exec qemu-system-riscv64 \\
  -machine virt,acpi=off -cpu "\${XAIOS_RISCV64_CPU:-rv64}" -smp 4 -m 2048 \\
  -global virtio-mmio.force-legacy=false \\
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=\$FIRMWARE" \\
  -drive "if=pflash,format=raw,unit=1,file=\$VARS" \\
  -drive "if=none,format=raw,readonly=on,id=xaios,file=\$IMAGE" \\
  -device virtio-blk-pci,drive=xaios,bootindex=0,disable-legacy=on \\
  -drive "if=none,format=raw,id=xaios_data,file=\$DATA" \\
  -device virtio-blk-device,drive=xaios_data,bus=virtio-mmio-bus.1 \\
  -device virtio-rng-pci,disable-legacy=on \\
  -netdev "user,id=net0,hostfwd=tcp::\${XAIOS_SSH_PORT:-2222}-:22" \\
  -device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.2 \\
  -display none -serial mon:stdio
EOF
    ;;
  esac
  chmod +x "$QEMU_DIR/run-${arch}.sh"

  {
    cat <<EOF
# XAIOS build $BUILD_NUMBER — QEMU, $LABEL

    ./run-${arch}.sh

One image and one runner. The runner keeps the architecture in its name rather
than being called \`run.sh\`, so that a command line copied out of a terminal
says which kit it came from.

The console is on the terminal you started it from. Port 2222 on your machine
reaches the guest's SSH server; set \`XAIOS_SSH_PORT\` to use a different one,
which is also what to do when a second XAIOS guest is already running and has
the port.

Needs \`qemu-system-${arch}\` and the matching UEFI firmware. The runner looks
for the firmware in the usual places and says what to install if it cannot find
it.

To leave the guest, press \`Ctrl-a\` then \`x\`.

EOF
    case "$arch" in
    aarch64)
      cat <<'EOF'
## Speed, on an Apple-silicon host

This guest is the host's own architecture, and QEMU still interprets it. Its
HVF accelerator aborts on this guest while emulating MMIO whose trap carries no
instruction syndrome -- that is QEMU's limitation and reproduces from other
guests -- so what runs here is TCG, which also models no cache or timing
behaviour. The route to the host's own cores, the real interrupt controller and
the real timer is the Virtualization.framework kit.

## Flags that matter, if you write your own command line

`gic-version=3`. Without it the machine faults in the GIC redistributor before
the kernel prints anything, which looks like a broken image rather than a
missing flag.

The network device has to be one this image binds: `virtio-net-device` on
`virtio-mmio-bus.2`, *with* `-global virtio-mmio.force-legacy=false`. Without
that global QEMU presents a legacy MMIO device, the driver requires a modern
one, and the machine finds no network at all. The durable volume sits on
`virtio-mmio-bus.1` for the same reason -- the driver scans the MMIO windows
before falling back to PCI.

Attached any other way the machine boots, reports that IPv4 is not ready and
withholds the SSH server -- which reads as a broken image and is a wrong flag.
Both mistakes were made while writing this runner.
EOF
      ;;
    x86_64)
      cat <<'EOF'
## Speed, on an Apple-silicon host

This guest is emulated instruction by instruction and takes several times
longer to reach a login prompt than a native one; that is the emulator, not the
system. Neither VMware Fusion nor Virtualization.framework helps, which is why
there are no Fusion or Virtualization.framework kits for x86-64: both run
guests on this host's own AArch64 cores, so an x86-64 guest here is emulation
either way, and this is the kit for that.

On an x86-64 host the same runner uses the host's own instruction set, which is
where it is fast.

## Flags that matter, if you write your own command line

`disable-legacy=on`, on every virtio device including the boot disk. Without it
QEMU presents a transitional device whose PCI identity this image's driver does
not recognise. On the network device the machine comes up with no network at
all. On the boot disk the effect is stranger: the disk is not counted, every
ordinal after it shifts by one, and the driver looks for durable storage past
the last disk attached -- so the machine boots perfectly and reports no
persistent storage, which reads as a missing disk and is a missing flag on a
different one.

The volume order is part of the contract too: the driver numbers PCI functions
and expects durable storage at the second volume after the boot disk, which is
why the runner creates two.
EOF
      ;;
    riscv64)
      cat <<'EOF'
## Speed, on an Apple-silicon host

This guest is emulated instruction by instruction and takes several times
longer to reach a login prompt than a native one; that is the emulator, not the
system. Neither VMware Fusion nor Virtualization.framework helps, which is why
there are no Fusion or Virtualization.framework kits for RISC-V: both run
guests on this host's own AArch64 cores, so a RISC-V guest here is emulation
either way, and this is the kit for that.

## Flags that matter, if you write your own command line

`acpi=off`. With ACPI on, the EDK2 build publishes no device tree, and this
port reads its interrupt controller, its timebase and its virtio window from
one -- so the machine starts, finds none of the three, and stops without
explaining itself.

`-global virtio-mmio.force-legacy=false`. QEMU's virtio-mmio transports default
to the legacy interface and the driver requires version 2, so without it every
MMIO slot reads as empty: the durable volume and the network are simply absent.
The durable volume is on `virtio-mmio-bus.1` and the network device is
`virtio-net-device` on `virtio-mmio-bus.2`, because the driver scans the MMIO
windows before falling back to PCI; a NIC attached only to PCI leaves the
machine reporting that IPv4 is not ready and withholding the SSH server.

EDK2's variable store has to be present beside its code image. The two ship as
a pair, the firmware writes the store on every boot, and the runner copies it
next to itself rather than writing to the installed one.

The kernel ELF can be handed to QEMU directly, and most of this project's
RISC-V gates do that because it is faster. This runner does not: started that
way there is no loader, nothing has read the medium, and the guest is not
booting the image this kit is built around.
EOF
      ;;
    esac
    common_footer "$IMAGE_NAME" "$IMAGE_SHA"
  } > "$QEMU_DIR/README.md"

  KITS="$KITS $QEMU_DIR"
done

# --------------------------------------------- VMware Fusion (AArch64)
#
# Built only when aarch64 is being packaged, because Fusion on this host runs
# AArch64 guests and there is no x86-64 or RISC-V profile to write.
case " $ARCHS " in
*" aarch64 "*)
  IMAGE_NAME="xaios_b${BUILD_NUMBER}-aarch64.iso"
  IMAGE="$RELEASE_DIR/$IMAGE_NAME"
  IMAGE_SHA=$(sha_of "$IMAGE")

  FUSION_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-aarch64-vmware-fusion"
  BUNDLE="$FUSION_DIR/XAIOS.vmwarevm"
  mkdir -p "$BUNDLE"
  cp "$IMAGE" "$BUNDLE/$IMAGE_NAME"

  # Kept in step with platform/vmware-fusion/build-vmware-fusion.sh, which
  # takes the same variable and the same default.
  FUSION_MEMSIZE="${XAIOS_FUSION_MEMSIZE:-2048}"
  case "$FUSION_MEMSIZE" in
    ''|*[!0-9]*)
      printf '%s\n' "error: XAIOS_FUSION_MEMSIZE must be a count of mebibytes" >&2
      exit 1 ;;
  esac

  # The profile points at the packaged image and keeps the writable disk. An
  # earlier version of this script dropped the disk, on the theory that a kit
  # should start without the recipient creating one first. That was wrong twice
  # over: XAIOS refuses to start its SSH server without durable storage, because
  # the configuration sshd loads lives there -- so the kit would have booted to a
  # console and nothing else -- and Fusion creates the disk itself on first power
  # on when the descriptor names a file that is not there.
  #
  # The profile names its network device and its memory size by placeholders so
  # that the F-02 work can ask for VMXNET3 without editing the file. A kit is
  # not the place for that choice: E1000E is the qualified profile, and a .vmx
  # that still holds a placeholder is one Fusion refuses to power on at all --
  # which is what it did, until the kit gate booted the archive rather than the
  # profile. Every @@...@@ in the template has to be answered here, and the
  # check below is what says so when a new one is added to the template and not
  # to this list.
  sed -e "s|sata0:0.fileName = \"xaios-fusion.iso\"|sata0:0.fileName = \"$IMAGE_NAME\"|" \
      -e "s|sata0:1.fileName = \"xaios-fusion.vmdk\"|sata0:1.fileName = \"xaios-data.vmdk\"|" \
      -e "s/@@XAIOS_FUSION_NIC@@/e1000e/" \
      -e "s/@@XAIOS_FUSION_MEMSIZE@@/$FUSION_MEMSIZE/" \
      "$ROOT_DIR/platform/vmware-fusion/XAIOS.vmx.in" > "$BUNDLE/XAIOS.vmx"
  if grep -q '@@' "$BUNDLE/XAIOS.vmx"; then
    printf '%s\n' "error: the Fusion profile still holds a placeholder:" >&2
    grep -n '@@' "$BUNDLE/XAIOS.vmx" >&2
    exit 1
  fi
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
# XAIOS build $BUILD_NUMBER — VMware Fusion, AArch64

Double-click \`XAIOS.vmwarevm\`, or:

    open XAIOS.vmwarevm

Fusion boots the image from a SATA CD-ROM. The console appears in the Fusion
window.

The profile runs four vCPUs with ${FUSION_MEMSIZE} MiB of memory, an E1000E
network device, and a 256 MB writable disk beside the image. XAIOS formats that
disk on the boot that first finds it, and keeps its SSH host key and
configuration there afterwards.

## Why there is no x86-64 or RISC-V Fusion kit

Fusion on Apple silicon runs AArch64 guests. It is a hypervisor, not an
emulator: it runs guest instructions on the host's own cores, so the guest has
to be the host's architecture. An x86-64 or RISC-V XAIOS guest on this host is
emulation, and the kit for that is \`xaios_b${BUILD_NUMBER}-x86_64-qemu.zip\`
or \`xaios_b${BUILD_NUMBER}-riscv64-qemu.zip\`.

## If you are editing the profile

Keep the writable disk. Without durable storage XAIOS starts, takes an address,
and then declines to run its SSH server, because the configuration sshd loads
lives on that disk and a machine with nowhere to keep it has none to load. The
machine looks healthy and is unreachable.

Keep E1000E unless you are deliberately testing something else: it is the
qualified profile. The template this .vmx was generated from carries the device
name as a placeholder, and a .vmx that still holds one is a file Fusion refuses
to power on at all.
EOF
    common_footer "$IMAGE_NAME" "$IMAGE_SHA"
  } > "$FUSION_DIR/README.md"

  KITS="$KITS $FUSION_DIR"

  # ------------------------ Apple Virtualization.framework (AArch64)
  VZ_DIR="$STAGE_ROOT/xaios_b${BUILD_NUMBER}-aarch64-virtualization-framework"
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
# XAIOS build $BUILD_NUMBER — Apple Virtualization.framework, AArch64

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

## Why there is no x86-64 or RISC-V kit here

That is the same sentence read the other way. Virtualization.framework runs the
guest on the host's own cores, and on this host those cores are AArch64, so an
AArch64 guest is the only guest it can run. An x86-64 or RISC-V XAIOS guest on
this host is emulation, and the kit for that is
\`xaios_b${BUILD_NUMBER}-x86_64-qemu.zip\` or
\`xaios_b${BUILD_NUMBER}-riscv64-qemu.zip\`.
EOF
    common_footer "$IMAGE_NAME" "$IMAGE_SHA"
  } > "$VZ_DIR/README.md"

  KITS="$KITS $VZ_DIR"
  ;;
*)
  printf '%s\n' "note: aarch64 is not in XAIOS_RELEASE_ARCHS, so no VMware" \
    "      Fusion or Virtualization.framework kit was built. Both run" \
    "      AArch64 guests on this host and have no other form." >&2
  ;;
esac

# ------------------------------------------------------------- archives
printf '%s\n' "XAIOS build $BUILD_NUMBER virtual machine kits"
for kit in $KITS; do
  name=$(basename "$kit")
  archive="$RELEASE_DIR/$name.zip"
  rm -f "$archive"
  (cd "$STAGE_ROOT" && zip -qr "$archive" "$name")
  printf '  %s\n' "$name.zip"
  printf '    %s bytes\n' "$(wc -c < "$archive" | tr -d ' ')"
  printf '    SHA-256 %s\n' "$(sha_of "$archive")"
done
for arch in $ARCHS; do
  printf '  image %-8s %s\n' "$arch" \
    "$(sha_of "$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso")"
done

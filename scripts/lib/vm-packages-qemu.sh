# Sourced by scripts/build-vm-packages.sh; not a standalone script.
#
# The QEMU kits: one archived directory per architecture, each carrying the
# image built for that architecture and run-<arch>.sh, plus the README that
# explains the flags its runner sets. Runs in the caller's shell, so it
# appends to $KITS and reuses the helpers sha_of, label_for and
# common_footer plus ARCHS, BUILD_NUMBER, RELEASE_DIR and STAGE_ROOT as the
# parent defined them.

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

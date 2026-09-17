# Sourced by scripts/build-vm-packages.sh; not a standalone script.
#
# The two AArch64-only kits: the VMware Fusion bundle with its generated
# .vmx profile and writable disk, and the Virtualization.framework kit that
# ships the harness source, its entitlements and a build-and-run.sh which
# compiles and ad-hoc signs it on the machine that will run it. Guarded by
# " $ARCHS " so neither is built for an architecture this host cannot run
# natively, and both append to $KITS.

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

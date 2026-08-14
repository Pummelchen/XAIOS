#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/vmware-fusion"
STAGE_DIR="$BUILD_DIR/iso-root"
VM_BUNDLE="$BUILD_DIR/XAIOS.vmwarevm"
ESP_IMAGE="$STAGE_DIR/efi.img"
GRUB_EFI="$BUILD_DIR/BOOTAA64.EFI"
ISO_IMAGE="$VM_BUNDLE/xaios-fusion.iso"
DATA_DISK="$VM_BUNDLE/xaios-fusion.vmdk"
VDISK_MANAGER="${XAIOS_FUSION_VDISK_MANAGER:-/Applications/VMware Fusion.app/Contents/Library/vmware-vdiskmanager}"
GRUB_IMAGE="${XAIOS_FUSION_GRUB_IMAGE:-xaios-vmware-grub:debian13-arm64}"
ENTROPY_SEED="${XAIOS_FUSION_ENTROPY_SEED:-$ROOT_DIR/build/fusion-entropy.seed}"

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  printf '%s\n' "error: VMware Fusion packaging requires Apple Silicon macOS" >&2
  exit 1
fi

for tool in docker mformat mmd mcopy xorriso "$VDISK_MANAGER"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "error: missing required tool: $tool" >&2
    exit 1
  fi
done
for artifact in \
  "$ROOT_DIR/build/uefi/BOOTAA64.EFI" \
  "$ROOT_DIR/build/kernel/kernel.elf" \
  "$ROOT_DIR/build/xaios-virtio-test.img"
do
  if [ ! -f "$artifact" ]; then
    printf '%s\n' "error: missing build artifact: $artifact; run make image" >&2
    exit 1
  fi
done

if [ ! -f "$ENTROPY_SEED" ]; then
  umask 077
  dd if=/dev/urandom of="$ENTROPY_SEED" bs=64 count=1 status=none
fi
if [ "$(wc -c < "$ENTROPY_SEED" | tr -d '[:space:]')" != "64" ]; then
  printf '%s\n' "error: Fusion entropy seed must contain exactly 64 bytes: $ENTROPY_SEED" >&2
  exit 1
fi
chmod 600 "$ENTROPY_SEED"

python3 - "$BUILD_DIR" <<'PY'
import shutil
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.exists():
    shutil.rmtree(path)
path.mkdir(parents=True)
PY
mkdir -p "$STAGE_DIR/EFI/BOOT" "$STAGE_DIR/EFI/XAIOS" "$VM_BUNDLE"

docker build --platform linux/arm64 \
  --file "$ROOT_DIR/platform/vmware-fusion/Dockerfile.grub" \
  --tag "$GRUB_IMAGE" "$ROOT_DIR/platform/vmware-fusion"
docker run --rm --platform linux/arm64 \
  --volume "$ROOT_DIR:/workspace" \
  "$GRUB_IMAGE" \
  -O arm64-efi \
  --modules="part_gpt part_msdos fat iso9660 search search_fs_file chain normal" \
  --output="/workspace/build/vmware-fusion/BOOTAA64.EFI" \
  "boot/grub/grub.cfg=/workspace/platform/vmware-fusion/grub.cfg"

cp "$GRUB_EFI" "$STAGE_DIR/EFI/BOOT/BOOTAA64.EFI"
cp "$ROOT_DIR/build/uefi/BOOTAA64.EFI" "$STAGE_DIR/EFI/XAIOS/XAIOS.EFI"
cp "$ROOT_DIR/build/kernel/kernel.elf" "$STAGE_DIR/EFI/XAIOS/kernel.elf"
cp "$ROOT_DIR/build/xaios-virtio-test.img" "$STAGE_DIR/EFI/XAIOS/initfs.img"
cp "$ENTROPY_SEED" "$STAGE_DIR/EFI/XAIOS/entropy.seed"

dd if=/dev/zero of="$ESP_IMAGE" bs=1m count=16 status=none
mformat -i "$ESP_IMAGE" -v XAIOS_ESP ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
mcopy -i "$ESP_IMAGE" "$GRUB_EFI" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -i "$ESP_IMAGE" "$ROOT_DIR/build/uefi/BOOTAA64.EFI" ::/EFI/XAIOS/XAIOS.EFI
mcopy -i "$ESP_IMAGE" "$ROOT_DIR/build/kernel/kernel.elf" ::/EFI/XAIOS/kernel.elf
mcopy -i "$ESP_IMAGE" "$ROOT_DIR/build/xaios-virtio-test.img" ::/EFI/XAIOS/initfs.img
mcopy -i "$ESP_IMAGE" "$ENTROPY_SEED" ::/EFI/XAIOS/entropy.seed

xorriso -as mkisofs -quiet -R -V XAIOS_FUSION \
  -e efi.img -no-emul-boot \
  -o "$ISO_IMAGE" "$STAGE_DIR"
cp "$ROOT_DIR/platform/vmware-fusion/XAIOS.vmx.in" "$VM_BUNDLE/XAIOS.vmx"
"$VDISK_MANAGER" -c -s "${XAIOS_FUSION_DISK_SIZE:-256MB}" -a lsilogic -t 0 \
  "$DATA_DISK" >/dev/null

printf '%s\n' "Created VMware Fusion VM: $VM_BUNDLE"
printf '%s\n' "Boot ISO: $ISO_IMAGE"
printf '%s\n' "Persistent SATA disk: $DATA_DISK"

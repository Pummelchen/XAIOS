# The models volume this architecture's runner boots.
#
# It was produced only by scripts/build-image.sh, which builds AArch64 and
# x86_64 and is never run on a machine doing RISC-V alone. run-qemu-riscv64.sh
# copies it to seed the guest's /models, and under `set -e` a missing source
# ended the runner before QEMU started -- so on CI, where the RISC-V job builds
# only RISC-V, every RISC-V boot failed at `cp` and was reported as a guest that
# had not printed its boot markers. It had not printed anything, because it had
# never been started.
#
# Built here so the RISC-V build produces everything the RISC-V runner boots.
# It is the same fixture and the same builder the other architectures use; the
# file is shared rather than per-architecture because its contents are a signed
# model package, which is architecture-neutral.
# $BUILD_DIR here is this script's own output directory, not the tree's
# build/. The runner reads the tree's, so name it explicitly.
XAI_FS_IMAGE="$ROOT_DIR/build/xaios-xaifs.img"
if [ ! -f "$XAI_FS_IMAGE" ]; then
  printf '%s\n' "Creating signed xaiFS fixture: $XAI_FS_IMAGE"
  PYTHONPATH="$ROOT_DIR/tools" "$PYTHON3" \
    "$ROOT_DIR/tests/xai_fs/create_c_fixture.py" "$XAI_FS_IMAGE"
  printf '%s\n' "Created $XAI_FS_IMAGE"
fi

# The signed A/B system volume, for the same reason and with the same history.
#
# It was produced only by build-riscv64-boot-media.sh, which the RISC-V CI job
# does not run, and run-qemu-riscv64.sh copies it with a bare `cp`. So fixing
# the models volume above moved the failure one line down rather than removing
# it: the next CI run died on this file instead, with the same shape of error
# and the same misleading report of a guest that would not boot.
#
# These are the two volumes the runner needs and the build did not make. The
# other three it reads are either produced here already, optional, or created
# by the runner itself when absent.
SYSTEM_VOLUME="$ROOT_DIR/build/xaios-riscv64-system.img"
RISCV_KERNEL="$ROOT_DIR/build/kernel-riscv64/kernel.elf"
if [ ! -f "$SYSTEM_VOLUME" ] && [ -f "$RISCV_KERNEL" ]; then
  printf '%s\n' "Creating signed A/B system volume: $SYSTEM_VOLUME"
  PYTHONPATH="$ROOT_DIR" "$PYTHON3" "$ROOT_DIR/tools/xaios_system_volume.py" \
    create "$SYSTEM_VOLUME" "$RISCV_KERNEL"
  PYTHONPATH="$ROOT_DIR" "$PYTHON3" "$ROOT_DIR/tools/xaios_system_volume.py" \
    verify "$SYSTEM_VOLUME"
fi

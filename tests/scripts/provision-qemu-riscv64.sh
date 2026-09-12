#!/bin/sh
# A QEMU new enough to model the RISC-V CPUs the contract requires.
#
# contracts/qemu-rc-v1.json lists twelve RISC-V boot tiers, all of them
# required -- the contract has no opt-out key. Ubuntu 24.04, which is what the
# CI runner is, ships QEMU 8.2.2, and that knows five of their CPU models:
# rv64, max, veyron-v1, sifive-u54 and thead-c906. The other seven --
# thead-c908, xiangshan-kunminghu, tt-ascalon, mips-p8700, rva22s64, rva23s64
# and xiangshan-nanhu -- were all added after 8.2.2, and nothing newer exists
# in noble, noble-updates, noble-security or noble-backports. So the emulator
# has to be built.
#
# The alternative was marking those tiers not required, which would turn the
# gate green while the coverage simply vanished on the runner. This repository's
# rule is the opposite: a check that cannot be made says so and exits non-zero,
# naming the host rather than the guest. Losing seven tiers quietly is exactly
# what that rule exists to prevent.
#
# Same shape as provision-qemu-smmu-testdev.sh: pinned by commit, cached by it,
# and verified by asking the built binary whether it can actually do the thing.
# Here that means every CPU model the contract requires appearing in -cpu help,
# so a pin that is too old fails loudly instead of silently testing less.
set -eu

# QEMU v11.1.1. Not the earliest release that would do -- some of these models
# are older than that -- but the one whose binary was checked model by model
# against the contract before the pin was written down. The verification below
# is what enforces it either way, so raising the pin is safe and lowering it
# fails loudly rather than testing less.
QEMU_COMMIT="${XAIOS_QEMU_RISCV64_COMMIT:-5e35f26695645b20931e10d8567c7e0169e62c07}"
QEMU_REPOSITORY="https://gitlab.com/qemu-project/qemu.git"

cache_base="${XAIOS_QEMU_RISCV64_ROOT:-${TMPDIR:-/tmp}/xaios-qemu-riscv64}"
source_dir="$cache_base/$QEMU_COMMIT/source"
build_dir="$cache_base/$QEMU_COMMIT/build"
qemu="$build_dir/qemu-system-riscv64"
source_stamp="$build_dir/.xaios-source-commit"

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# The models to require, read from the contract rather than repeated here, so
# adding a tier cannot leave this script quietly behind. Every tier listed is
# required: the contract has no opt-out key, and inventing one here would let a
# model go untested by omission.
required_models() {
  python3 - "$root_dir/contracts/qemu-rc-v1.json" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as handle:
    matrix = json.load(handle)["cpu_matrix"]
tiers = matrix["riscv64_boot_tiers"]
if not tiers:
    raise SystemExit("cpu_matrix.riscv64_boot_tiers is empty; refusing to "
                     "verify a QEMU against no models at all")
print("\n".join(sorted({tier["cpu"] for tier in tiers})))
PY
}

verify_qemu() {
  [ -x "$qemu" ] || return 1
  [ -f "$source_stamp" ] || return 1
  [ "$(cat "$source_stamp")" = "$QEMU_COMMIT" ] || return 1
  # -cpu help prints "  <model>", sometimes with a description after it. Take
  # the first field of each line and match it whole: grep -w counts "-" as a
  # word boundary, so a model named "thead" would match the line "thead-c906"
  # and a tier would pass on an emulator that cannot model it.
  listed=$("$qemu" -cpu help 2>/dev/null |
           sed 's/^[[:space:]]*//; s/[[:space:]].*$//') || return 1
  missing=""
  for model in $(required_models); do
    printf '%s\n' "$listed" | grep -qxF -- "$model" || missing="$missing $model"
  done
  if [ -n "$missing" ]; then
    printf '%s\n' \
      "qemu-riscv64-provision: the built QEMU does not model:$missing" \
      "  The pin is older than the contract requires. Raise" \
      "  XAIOS_QEMU_RISCV64_COMMIT to a release that carries them." >&2
    return 1
  fi
  return 0
}

if verify_qemu; then
  printf '%s\n' "qemu-riscv64-provision: cached binary verified: $qemu"
  exit 0
fi

mkdir -p "$cache_base/$QEMU_COMMIT"
if [ ! -d "$source_dir/.git" ]; then
  if [ -e "$source_dir" ]; then
    printf '%s\n' "error: non-git QEMU source path exists: $source_dir" >&2
    exit 1
  fi
  git clone --filter=blob:none --no-checkout "$QEMU_REPOSITORY" "$source_dir"
fi
git -C "$source_dir" fetch --depth 1 origin "$QEMU_COMMIT"
git -C "$source_dir" checkout --detach FETCH_HEAD

mkdir -p "$build_dir"
if [ ! -f "$build_dir/build.ninja" ]; then
  ( cd "$build_dir" &&
    "$source_dir/configure" \
      --target-list=riscv64-softmmu \
      --disable-docs \
      --disable-gtk \
      --disable-sdl \
      --disable-vnc \
      --disable-tools > xaios-configure.log 2>&1 ) || {
    cat "$build_dir/xaios-configure.log" >&2
    exit 1
  }
fi
ninja --quiet -C "$build_dir" qemu-system-riscv64
printf '%s\n' "$QEMU_COMMIT" > "$source_stamp"

verify_qemu || exit 1
printf '%s\n' "qemu-riscv64-provision: built and verified: $qemu"

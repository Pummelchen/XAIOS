#!/bin/sh
set -eu

QEMU_COMMIT="6ce361b02c825b4a12a9684c47342859ee967cb2"
QEMU_REPOSITORY="https://gitlab.com/qemu-project/qemu.git"
cache_base="${XAIOS_QEMU_SMMU_ROOT:-${TMPDIR:-/tmp}/xaios-qemu-smmu}"
source_dir="$cache_base/$QEMU_COMMIT/source"
build_dir="$cache_base/$QEMU_COMMIT/build"
qemu="$build_dir/qemu-system-aarch64"
source_stamp="$build_dir/.xaios-source-commit"

verify_qemu() {
  [ -x "$qemu" ] &&
    [ -f "$source_stamp" ] &&
    [ "$(cat "$source_stamp")" = "$QEMU_COMMIT" ] &&
    "$qemu" -device help 2>/dev/null | grep -F 'name "iommu-testdev"' >/dev/null
}

if verify_qemu; then
  printf '%s\n' "qemu-smmu-provision: cached binary verified: $qemu"
  exit 0
fi

mkdir -p "$cache_base/$QEMU_COMMIT"
if [ ! -d "$source_dir/.git" ]; then
  if [ -e "$source_dir" ]; then
    printf '%s\n' "error: non-git QEMU source path exists: $source_dir" >&2
    exit 1
  fi
  git clone --filter=blob:none --no-checkout "$QEMU_REPOSITORY" "$source_dir"
  git -C "$source_dir" fetch --depth=1 origin "$QEMU_COMMIT"
  git -C "$source_dir" checkout --detach FETCH_HEAD
fi

source_commit="$(git -C "$source_dir" rev-parse HEAD)"
if [ "$source_commit" != "$QEMU_COMMIT" ]; then
  printf '%s\n' \
    "error: cached QEMU source is $source_commit, expected $QEMU_COMMIT" >&2
  exit 1
fi

mkdir -p "$build_dir"
if [ ! -f "$build_dir/build.ninja" ]; then
  if ! (
    cd "$build_dir"
    "$source_dir/configure" \
      --target-list=aarch64-softmmu \
      --enable-tcg \
      --disable-debug-info \
      --disable-docs \
      --disable-guest-agent \
      --enable-slirp \
      --disable-tools > xaios-configure.log 2>&1
  ); then
    cat "$build_dir/xaios-configure.log" >&2
    exit 1
  fi
fi

ninja --quiet -C "$build_dir" qemu-system-aarch64
printf '%s\n' "$QEMU_COMMIT" > "$source_stamp"
if ! verify_qemu; then
  printf '%s\n' \
    "error: pinned QEMU build does not expose the required iommu-testdev" >&2
  exit 1
fi

printf '%s\n' "qemu-smmu-provision: built and verified: $qemu"

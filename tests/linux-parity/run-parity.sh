#!/bin/sh
# Run one script from this directory inside the CI-parity image.
#
#   tests/linux-parity/run-parity.sh riscv-smoke.sh
#
# The source goes in over stdin rather than through a bind mount: Docker Desktop
# does not share every host path, and a -v of one it cannot see silently creates
# an empty directory instead of failing, which costs a run to notice.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
HERE=tests/linux-parity
SCRIPT=${1:?usage: run-parity.sh <script-in-this-directory>}

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' "error: docker is required" >&2; exit 1; }

# Which machine to be. On an Apple Silicon Mac the container is arm64 by
# default, and the CI runner is x86_64 -- so this is Linux parity, not runner
# parity, and anything x86_64-specific is invisible here.
#
# It cost a reproduction to learn that. Three gates were "reproduced" failing
# on the runner, and all three had in fact died building x86_64 picolibc with
# `gcc: unrecognized command-line option -m64`, which is what an arm64 gcc says
# when asked to target x86_64. On the runner that build works. The result said
# nothing about CI and was thrown away.
#
# XAIOS_PARITY_PLATFORM=linux/amd64 gets the runner's architecture through
# emulation. It is slow -- a guest inside it is emulated twice -- but for a
# build-time difference it is the only honest answer available on this machine.
PLATFORM=${XAIOS_PARITY_PLATFORM:-}
PLATFORM_ARG=""
PLATFORM_TAG=""
if [ -n "$PLATFORM" ]; then
  PLATFORM_ARG="--platform=$PLATFORM"
  PLATFORM_TAG="-$(printf '%s' "$PLATFORM" | tr '/' '-')"
fi

# The tag carries a digest of the Dockerfile, so editing the package list
# produces a name that does not exist yet and the image is rebuilt. Tagged by
# hand it would not: `docker image inspect` would find the old one and the run
# would test the old toolchain while reporting on the new one. The platform is
# in the tag for the same reason: an amd64 image and an arm64 image built from
# one Dockerfile are not interchangeable, and reusing one for the other is
# exactly the confusion this is here to prevent.
DIGEST=$(shasum -a 256 "$ROOT/$HERE/Dockerfile.ci-parity" 2>/dev/null \
         || sha256sum "$ROOT/$HERE/Dockerfile.ci-parity")
DIGEST=$(printf '%s' "$DIGEST" | cut -c1-12)
IMAGE=${XAIOS_PARITY_IMAGE:-xaios-ci-parity:$DIGEST$PLATFORM_TAG}

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  printf '%s\n' "building $IMAGE ..."
  # shellcheck disable=SC2086 -- PLATFORM_ARG is one word or empty
  docker build $PLATFORM_ARG -q -t "$IMAGE" -f "$ROOT/$HERE/Dockerfile.ci-parity" "$ROOT/$HERE" >/dev/null
}

# The pin the libc build asserts. picolibc's files travel in the tar but its
# submodule metadata does not, and the pin check has an override for that.
PIN=$(sed -n 's/^PIN=\([0-9a-f]\{40\}\)$/\1/p' "$ROOT/scripts/build-libc.sh" | head -1)
[ -n "$PIN" ] || { printf '%s\n' "error: could not read the picolibc pin" >&2; exit 1; }

# COPYFILE_DISABLE stops macOS tar embedding AppleDouble ._* files, which clang
# then tries to compile.
cd "$ROOT"
printf '%s\n' "parity: image=$IMAGE platform=${PLATFORM:-native}"
COPYFILE_DISABLE=1 tar czf - \
  --exclude=./build --exclude=./.git --exclude=./.claude --exclude=./release \
  --exclude='*.iso' --exclude='*.img' --exclude='*.zip' . \
| docker run -i --rm $PLATFORM_ARG \
    -e "XAIOS_PICOLIBC_REVISION_OVERRIDE=$PIN" "$IMAGE" \
    sh -c "tar xzf - && exec sh $HERE/$SCRIPT"

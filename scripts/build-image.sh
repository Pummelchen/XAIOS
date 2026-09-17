#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
TARGET_ARCH="${XAIOS_TARGET_ARCH:-aarch64}"
case "$TARGET_ARCH" in
  aarch64)
    TARGET_TRIPLE=aarch64-none-elf
    UEFI_TARGET=aarch64-unknown-windows
    UEFI_MACHINE=arm64
    UEFI_BOOT_NAME=BOOTAA64.EFI
    ARCH_BUILD_SUFFIX=""
    ARCH_KERNEL_DIR=aarch64
    ARCH_LINKER="$ROOT_DIR/kernel/arch/aarch64/linker.ld"
    INIT_SOURCE="$ROOT_DIR/userspace/init/init.S"
    SERVICE_MANAGER_SOURCE="$ROOT_DIR/userspace/service-manager/service-manager.S"
    WORKER_SOURCE="$ROOT_DIR/userspace/worker/worker.S"
    IMAGE_PATH="${XAIOS_AARCH64_IMAGE:-$BUILD_DIR/xaios-aarch64.img}"
    TEST_BLOCK_IMAGE="${XAIOS_TEST_BLOCK_IMAGE:-$BUILD_DIR/xaios-virtio-test.img}"
    PERSISTENT_IMAGE="${XAIOS_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-persistent.img}"
    ;;
  x86_64)
    TARGET_TRIPLE=x86_64-none-elf
    UEFI_TARGET=x86_64-unknown-windows
    UEFI_MACHINE=x64
    UEFI_BOOT_NAME=BOOTX64.EFI
    ARCH_BUILD_SUFFIX=-x86_64
    ARCH_KERNEL_DIR=x86_64
    ARCH_LINKER="$ROOT_DIR/kernel/arch/x86_64/linker.ld"
    INIT_SOURCE="$ROOT_DIR/userspace/init/init-x86_64.S"
    SERVICE_MANAGER_SOURCE="$ROOT_DIR/userspace/service-manager/service-manager-x86_64.S"
    WORKER_SOURCE="$ROOT_DIR/userspace/worker/worker-x86_64.S"
    IMAGE_PATH="${XAIOS_X86_64_IMAGE:-$BUILD_DIR/xaios-x86_64.img}"
    TEST_BLOCK_IMAGE="${XAIOS_X86_TEST_BLOCK_IMAGE:-$BUILD_DIR/xaios-x86-virtio-test.img}"
    PERSISTENT_IMAGE="${XAIOS_X86_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-x86-persistent.img}"
    ;;
  *)
    printf '%s\n' "error: XAIOS_TARGET_ARCH must be aarch64 or x86_64" >&2
    exit 2
    ;;
esac
EFI_BUILD_DIR="$BUILD_DIR/uefi$ARCH_BUILD_SUFFIX"
KERNEL_BUILD_DIR="$BUILD_DIR/kernel$ARCH_BUILD_SUFFIX"
INIT_BUILD_DIR="$BUILD_DIR/init$ARCH_BUILD_SUFFIX"
XAI_FS_IMAGE_CONFIGURED="${XAIOS_XAI_FS_IMAGE:-}"
if [ "$TARGET_ARCH" = x86_64 ]; then
  XAI_FS_IMAGE="${XAI_FS_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-x86-xaifs.img}"
else
  XAI_FS_IMAGE="${XAI_FS_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-xaifs.img}"
fi
SYSTEM_VOLUME_IMAGE_CONFIGURED="${XAIOS_SYSTEM_VOLUME_IMAGE:-}"
if [ "$TARGET_ARCH" = x86_64 ]; then
  SYSTEM_VOLUME_IMAGE="${SYSTEM_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-x86-system.img}"
  STORAGE_ADMIN_IMAGE="${XAIOS_X86_STORAGE_ADMIN_IMAGE:-$BUILD_DIR/xaios-x86-storage-admin.img}"
else
  SYSTEM_VOLUME_IMAGE="${SYSTEM_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-system.img}"
  STORAGE_ADMIN_IMAGE=""
fi
LOADER_OBJ="$EFI_BUILD_DIR/loader_main.obj"
LOADER_SYSTEM_OBJ="$EFI_BUILD_DIR/system_volume_loader.obj"
LOADER_PLATFORM_OBJ="$EFI_BUILD_DIR/loader_platform.obj"
LOADER_IMAGE_OBJ="$EFI_BUILD_DIR/loader_image.obj"
LOADER_SHA256_OBJ="$EFI_BUILD_DIR/sha256.obj"
LOADER_SSH_CRYPTO_OBJ="$EFI_BUILD_DIR/ssh_crypto.obj"
LOADER_TWEETNACL_OBJ="$EFI_BUILD_DIR/tweetnacl_subset.obj"
LOADER_EFI="$EFI_BUILD_DIR/$UEFI_BOOT_NAME"
KERNEL_ELF="$KERNEL_BUILD_DIR/kernel.elf"
INIT_OBJ="$INIT_BUILD_DIR/init.o"
INIT_ELF="$INIT_BUILD_DIR/init.elf"
SERVICE_MANAGER_OBJ="$INIT_BUILD_DIR/service-manager.o"
SERVICE_MANAGER_ELF="$INIT_BUILD_DIR/service-manager.elf"
WORKER_OBJ="$INIT_BUILD_DIR/worker.o"
WORKER_ELF="$INIT_BUILD_DIR/worker.elf"
USER_START_OBJ="$INIT_BUILD_DIR/user-start.o"
USER_LIB_OBJ="$INIT_BUILD_DIR/xaios-user.o"
USER_SCREEN_OBJ="$INIT_BUILD_DIR/xaios-screen.o"
USER_CONTROL_OBJ="$INIT_BUILD_DIR/xaios-control-client.o"
USER_CONTROL_PRIM_OBJ="$INIT_BUILD_DIR/xaios-control-primitives.o"
USER_CONTROL_SYS_OBJ="$INIT_BUILD_DIR/xaios-control-system.o"
USER_CONTROL_STORAGE_OBJ="$INIT_BUILD_DIR/xaios-control-storage.o"
USER_CONTROL_OPS_OBJ="$INIT_BUILD_DIR/xaios-control-ops.o"
USER_CONTROL_CONFIG_OBJ="$INIT_BUILD_DIR/xaios-control-config.o"
USER_CONTROL_REQUEST_OBJ="$INIT_BUILD_DIR/xaios-control-request.o"
USER_APPS="xaios-shell xaiosctl xapt nano xtop pong hello spin sysinfo systest smptest joinnest smpstress perfbench nettest netmqtest netsocktest lstm-xor sshtest mltest posix-shell agenttest clustertest xaios-setup"
# Which end of a cluster this image is, and where its peer is.
#
# The two ends are mirror images: one listens, the other dials, and each is the
# other's peer. A server image needs no address; a client image is pointed at
# one, which is what lets a machine here reach a machine somewhere else rather
# than only the host process on the other side of the QEMU user network.
CLUSTER_ROLE_SERVER="${XAIOS_CLUSTER_ROLE_SERVER:-0}"
case "$CLUSTER_ROLE_SERVER" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_CLUSTER_ROLE_SERVER must be 0 or 1" >&2
    exit 1
    ;;
esac
CLUSTER_APP_CFLAGS="-DXAIOS_CLUSTER_ROLE_SERVER=$CLUSTER_ROLE_SERVER"
if [ -n "${XAIOS_CLUSTER_PEER_IPV4:-}" ]; then
  # Four octets, checked here rather than discovered as a link failure or, far
  # worse, as a machine quietly dialling the wrong address.
  cluster_peer_ok=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | awk -F. '
    NF == 4 {
      for (i = 1; i <= 4; ++i) {
        if ($i !~ /^[0-9]+$/ || $i + 0 > 255) { print "no"; exit }
      }
      print "yes"; exit
    }
    { print "no" }')
  if [ "$cluster_peer_ok" != yes ]; then
    printf '%s\n' "error: XAIOS_CLUSTER_PEER_IPV4 must be a dotted IPv4 address" >&2
    exit 1
  fi
  cluster_a=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f1)
  cluster_b=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f2)
  cluster_c=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f3)
  cluster_d=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f4)
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_A=${cluster_a}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_B=${cluster_b}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_C=${cluster_c}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_D=${cluster_d}U"
fi
if [ -n "${XAIOS_CLUSTER_PEER_PORT:-}" ]; then
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DCLUSTER_PEER_PORT=${XAIOS_CLUSTER_PEER_PORT}U"
fi
# The three-node mesh, which is a different program in the same file.
#
# Node id and the three ports are compile-time because the app has no
# discovery and inventing one here would test the invention. They are checked
# here rather than left to the compiler: a node id of zero produces a peer
# table xaios_cluster_init rejects at run time, on a machine whose console
# nobody is reading yet, and a port that is not a number becomes a macro that
# fails to expand into something a person can recognise.
if [ -n "${XAIOS_CLUSTER_MESH_NODES:-}" ]; then
  case "$XAIOS_CLUSTER_MESH_NODES" in
    0|3) ;;
    *)
      printf '%s\n' "error: XAIOS_CLUSTER_MESH_NODES must be 0 or 3" >&2
      exit 1
      ;;
  esac
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_NODES=${XAIOS_CLUSTER_MESH_NODES}"
  if [ "$XAIOS_CLUSTER_MESH_NODES" = 3 ]; then
    case "${XAIOS_CLUSTER_NODE_ID:-}" in
      1|2|3) ;;
      *)
        printf '%s\n' \
          "error: XAIOS_CLUSTER_NODE_ID must be 1, 2 or 3 for a three-node mesh" >&2
        exit 1
        ;;
    esac
    CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_NODE_ID=${XAIOS_CLUSTER_NODE_ID}U"
    for mesh_index in 1 2 3; do
      eval "mesh_port=\${XAIOS_CLUSTER_MESH_PORT_${mesh_index}:-}"
      case "$mesh_port" in
        ''|*[!0-9]*)
          printf '%s\n' \
            "error: XAIOS_CLUSTER_MESH_PORT_${mesh_index} must be a port number" >&2
          exit 1
          ;;
      esac
      if [ "$mesh_port" -lt 1 ] || [ "$mesh_port" -gt 65535 ]; then
        printf '%s\n' \
          "error: XAIOS_CLUSTER_MESH_PORT_${mesh_index} is not a port" >&2
        exit 1
      fi
      CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_PORT_${mesh_index}=${mesh_port}U"
    done
    # Whether a node that loses quorum stops or keeps running. The kill gate
    # wants it to stop: its peers were SIGKILLed and are not coming back. The
    # partition gate wants it to keep running, because its peers are alive on
    # the far side of a cut link and the repair is the half of that test which
    # has not happened yet. Default zero, so the existing gate is unchanged by
    # this knob existing.
    MESH_HOLD="${XAIOS_CLUSTER_MESH_HOLD:-0}"
    case "$MESH_HOLD" in
      0|1) ;;
      *)
        printf '%s\n' "error: XAIOS_CLUSTER_MESH_HOLD must be 0 or 1" >&2
        exit 1
        ;;
    esac
    CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_HOLD=${MESH_HOLD}"
  fi
fi
UTILITY_APPS="ls mkdir touch cp mv rm rmdir stat cat head tail less grep find sed write tar cpio zip unzip ps df du"
HOSTED_USER_APPS="helloworldc99 wtqtest"

BUILD_MODE="${XAIOS_BUILD_MODE:-development}"
case "$BUILD_MODE" in
  development|release) ;;
  *)
    printf '%s\n' "error: XAIOS_BUILD_MODE must be development or release" >&2
    exit 2
    ;;
esac
BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-0}"
case "$BOOT_TEST_APPS" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_BOOT_TEST_APPS must be 0 or 1" >&2
    exit 2
    ;;
esac
LIBC_TEST="${XAIOS_LIBC_TEST:-0}"
case "$LIBC_TEST" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_LIBC_TEST must be 0 or 1" >&2
    exit 2
    ;;
esac
BOOT_VERBOSE="${XAIOS_BOOT_VERBOSE:-0}"
case "$BOOT_VERBOSE" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_BOOT_VERBOSE must be 0 or 1" >&2
    exit 2
    ;;
esac
FAILURE_TEST_APP="${XAIOS_FAILURE_TEST_APP:-0}"
case "$FAILURE_TEST_APP" in
  0) ;;
  1) USER_APPS="$USER_APPS app-fail app-crash" ;;
  *)
    printf '%s\n' "error: XAIOS_FAILURE_TEST_APP must be 0 or 1" >&2
    exit 2
    ;;
esac
PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=0"
SSH_USERS_FILE="${XAIOS_SSH_USERS_FILE:-}"
if [ "${XAIOS_SSH_PASSWORD_AUTH+x}" = "x" ]; then
  SSH_PASSWORD_AUTH_EXPLICIT=1
else
  SSH_PASSWORD_AUTH_EXPLICIT=0
fi
# "none" asks for a development image that packages no account, so the first
# boot runs setup exactly as a release image does. Without it every
# development build has the development credential and setup is unreachable.
if [ "$SSH_USERS_FILE" = "none" ]; then
  SSH_USERS_FILE=""
  SSH_PASSWORD_AUTH_EXPLICIT=1
elif [ "$BUILD_MODE" = "development" ] && [ "$SSH_USERS_FILE" = "" ] && [ "$SSH_PASSWORD_AUTH_EXPLICIT" = 0 ]; then
  SSH_USERS_FILE="$ROOT_DIR/config/development-sshd-users"
fi
# The rule here used to be "release images have no password authentication".
# That forbade the code, which forbade the only way a released machine could
# ever get an account: a person making one on it. The property worth keeping
# is narrower and is the one that actually matters -- a released image
# contains no credential anybody outside this build has. So the code is
# always compiled, and packaging a credential into a release image is what is
# refused.
#
# /bin/xaios-setup creates the account on first boot, with a salt from the
# machine's own entropy, and writes it to that machine's state volume. Nothing
# secret is in the download, which is what the old rule was protecting.
PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=1"
if [ "$SSH_USERS_FILE" != "" ]; then
  if [ "${XAIOS_SSH_PASSWORD_AUTH:-}" != "1" ]; then
    if [ "$SSH_USERS_FILE" != "$ROOT_DIR/config/development-sshd-users" ]; then
      printf '%s\n' "error: password credentials require XAIOS_SSH_PASSWORD_AUTH=1" >&2
      exit 2
    fi
  fi
  if [ "$BUILD_MODE" = "release" ]; then
    printf '%s\n' \
      "error: a release image must not package a password credential." \
      "       Password support is compiled in and /bin/xaios-setup creates" \
      "       the account on first boot; a packaged record would be a" \
      "       credential every copy of the download shares." >&2
    exit 2
  fi
elif [ "${XAIOS_SSH_PASSWORD_AUTH:-0}" != "0" ]; then
  printf '%s\n' "error: XAIOS_SSH_PASSWORD_AUTH requires XAIOS_SSH_USERS_FILE" >&2
  exit 2
fi

# Local console PIN. It is console-only and never accepted over SSH, and it
# rides along with password authentication: an image without a password user
# database stays key-only and packages no PIN record.
CONSOLE_PIN_FILE="${XAIOS_CONSOLE_PIN_FILE:-}"
if [ "$BUILD_MODE" = "development" ] && [ "$CONSOLE_PIN_FILE" = "" ] && \
   [ "$SSH_USERS_FILE" = "$ROOT_DIR/config/development-sshd-users" ]; then
  CONSOLE_PIN_FILE="$ROOT_DIR/config/development-console-pin"
fi
if [ "$CONSOLE_PIN_FILE" != "" ]; then
  if [ "$BUILD_MODE" = "release" ]; then
    printf '%s\n' \
      "error: a release image must not package a console PIN." \
      "       Setup enrols one on first boot; see the password rule above." >&2
    exit 2
  fi
  if [ "$SSH_USERS_FILE" = "" ]; then
    printf '%s\n' "error: XAIOS_CONSOLE_PIN_FILE requires XAIOS_SSH_USERS_FILE" >&2
    exit 2
  fi
fi

# Cleanup only failures that occur after the build profile has been accepted.
cleanup() {
  if [ $? -ne 0 ]; then
    printf '%s\n' "Build failed, cleaning up partial artifacts..." >&2
    # What this build produced, and nothing else that happens to live in
    # build/. The Virtualization.framework harness, the vmnet helper and its
    # socket, SSH test keys and durable volumes are all created by other
    # tooling and kept here; taking them out on an unrelated build failure has
    # cost real time more than once. A running helper ends up holding an
    # unlinked socket that nothing can connect to, and the next run fails with
    # nothing more useful than "command not found".
    find "$BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name vz -exec rm -rf {} +
    printf '%s\n' "Cleaned up $BUILD_DIR (kept $BUILD_DIR/vz)" >&2
  fi
}
trap cleanup EXIT

find_tool() {
  tool_name="$1"
  shift

  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return 0
  fi

  return 1
}

require_tool() {
  label="$1"
  tool_name="$2"
  install_hint="$3"
  shift 3

  if tool_path="$(find_tool "$tool_name" "$@")"; then
    printf '%s\n' "$tool_path"
    return 0
  fi

  printf '%s\n' "error: $label not found. $install_hint" >&2
  exit 1
}

brew_prefix() {
  formula="$1"
  if command -v brew >/dev/null 2>&1; then
    brew --prefix "$formula" 2>/dev/null || true
  fi
}

LLVM_PREFIX="$(brew_prefix llvm)"
LLD_PREFIX="$(brew_prefix lld)"

LLVM_BIN=""
if [ "$LLVM_PREFIX" != "" ]; then
  LLVM_BIN="$LLVM_PREFIX/bin"
fi

LLD_BIN=""
if [ "$LLD_PREFIX" != "" ]; then
  LLD_BIN="$LLD_PREFIX/bin"
fi

CLANG="$(require_tool "Clang" clang "Install with: brew install llvm" "$LLVM_BIN/clang" /usr/bin/clang)"
LLD_LINK="$(require_tool "LLD COFF linker" lld-link "Install with: brew install lld" "$LLD_BIN/lld-link" "$LLVM_BIN/lld-link")"
LD_LLD="$(require_tool "LLD ELF linker" ld.lld "Install with: brew install lld" "$LLD_BIN/ld.lld" "$LLVM_BIN/ld.lld")"
MFORMAT="$(require_tool "mtools mformat" mformat "Install with: brew install mtools" /opt/homebrew/bin/mformat /usr/local/bin/mformat)"
MMD="$(require_tool "mtools mmd" mmd "Install with: brew install mtools" /opt/homebrew/bin/mmd /usr/local/bin/mmd)"
MCOPY="$(require_tool "mtools mcopy" mcopy "Install with: brew install mtools" /opt/homebrew/bin/mcopy /usr/local/bin/mcopy)"
PYTHON3="$(require_tool "Python 3" python3 "Install with: brew install python" /opt/homebrew/bin/python3 /usr/local/bin/python3)"

mkdir -p "$EFI_BUILD_DIR" "$KERNEL_BUILD_DIR" "$INIT_BUILD_DIR"

. "$ROOT_DIR/scripts/lib/build-uefi-loader.sh"

. "$ROOT_DIR/scripts/lib/kernel-config.sh"
. "$ROOT_DIR/scripts/lib/kernel-objects.sh"
. "$ROOT_DIR/scripts/lib/kernel-compile.sh"

. "$ROOT_DIR/scripts/lib/userspace-runtime.sh"

. "$ROOT_DIR/scripts/lib/user-apps.sh"

. "$ROOT_DIR/scripts/lib/user-utilities.sh"

. "$ROOT_DIR/scripts/lib/hosted-apps.sh"

. "$ROOT_DIR/scripts/lib/sshd-build.sh"

. "$ROOT_DIR/scripts/lib/image-assembly.sh"

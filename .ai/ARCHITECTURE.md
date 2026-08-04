<!--
AI onboarding file.
Mode: refresh
Indexed base commit: 8ddefb26f3dbc366dc4402677a156cf235daed82
Last refreshed: 2026-08-04
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Architecture

## Verified high-level architecture

XAIOS contains both a freestanding OS and a portable hosted C99 inference-engine
foundation. The current source builds an AArch64 UEFI/QEMU path, kernel and
userspace ELFs, storage images, and hosted model-v2/engine tests. The x86_64
image boots a platform bring-up kernel and executes shared CRC, block, VFS,
architecture-registry, scalar-backend and packed-engine code; full x86 platform
and userspace parity remains incomplete.

Evidence:
- `docs/ARCHITECTURE.md`
- `scripts/build-image.sh`
- `kernel/core/kmain.c`
- `scripts/run-qemu-aarch64.sh`

## Boot/runtime flow

1. UEFI firmware loads `BOOTAA64.EFI` from the FAT image.
2. `boot/uefi/loader_main.c` loads `kernel.elf` and passes `xaios_boot_info_t`.
3. `kernel/core/kmain.c` initializes architecture, memory, device, filesystem, security, network, process, AI runtime, and telemetry subsystems.
4. The kernel loads `/init`, `/bin/service-manager`, workers, and userspace apps from initramfs.
5. The kernel emits telemetry and enters an idle `wfe` loop.

## Major components

| Component | Files | Responsibility |
|---|---|---|
| Bootloader | `boot/uefi/loader_main.c`, `boot/uefi/linker.ld` | UEFI entry and kernel handoff. |
| Kernel init | `kernel/core/kmain.c` | Strict init/self-test order and userspace launch. |
| Memory | `kernel/mm/`, `kernel/arch/aarch64/mmu.c` | Physical/virtual memory, NUMA, heaps, arenas, ELF loading. |
| Devices | `kernel/dev/virtio/`, `kernel/arch/aarch64/pci.c`, `kernel/arch/aarch64/smmu.c` | VirtIO block/net, PCI, SMMU. |
| Worker threads | `kernel/sched/thread.c`, `kernel/arch/aarch64/smp.c` | CPU-assigned jobs with bounded cancel/join and dynamic CPU-capacity sizing. |
| Storage/filesystems | `kernel/dev/block_device.c`, `kernel/storage/`, `kernel/fs/`, `engine/src/model_volume.c`, `engine/src/model_file.c`, `tools/xaios_model_volume.py` | 64-bit block/GPT/VFS, MutableFS root, immutable active ModelFS, online signed staging lifecycle, scrub/trim, and hosted administration. |
| Process/API | `kernel/user/`, `userspace/include/xaios_user.h` | Process table, service supervisor, syscall ABI/wrappers. |
| Network | `kernel/net/`, `kernel/runtime/network_stack.c` | Protocols, socket buffers, network telemetry. |
| Security | `kernel/runtime/security.c` | Capabilities, credential-material rejection, update policy, sandbox path checks. |
| AI runtime | `kernel/runtime/cpu_ai_runtime.c`, `kernel/runtime/model_arena.c`, `kernel/runtime/ai_cell.c` | CPU-only inference simulation/runtime, shared model arena, resource isolation. |
| Portable engine | `engine/include/xaios_engine/`, `engine/src/` | model-v2/ModelFS parsing, architecture registry, backend API, scalar projection, and no-expand INT4/INT6 scalar plus experimental NEON/AVX2 GEMV/GEMM. |
| Remote/admin | `kernel/runtime/admin_control.c`, `kernel/runtime/control_protocol.c`, `userspace/lib/xaios_control_client.c`, `kernel/runtime/remote_login.c`, `userspace/sshd/` | Persistent role-based config/key/audit administration plus per-connection shell and SSH/SFTP surfaces. |

## Trust boundaries

- EL0 userspace crosses into kernel via syscall dispatch in `kernel/user/syscall.c`.
- Syscalls are gated by capability masks in `kernel/include/xaios/syscall.h` and dispatch table entries.
- Filesystem access is constrained by security policy in `kernel/runtime/security.c`.
- Mutable state and updates cross persistence/update boundaries in `kernel/fs/`, `kernel/runtime/persistence.c`, and `kernel/runtime/update.c`.
- Network/SSH paths cross from QEMU host forwarding into socket and SSH code.
- Model-v2 writing streams caller-provided section sources to positional package
  extents. Official model import is not yet implemented.
- Storage flow: explicit block device -> optional bounded GPT partition -> VFS
  backend. MutableFS serves small root state; a dedicated VirtIO slot 4 ModelFS
  volume mounts at `/models`. Active packages are immutable. Administrator-only
  signed registration allocates staging records; verified chunk writes,
  cleanup/reuse, activation, scrub/quarantine and free-only trim publish COW
  generations. Package reads verify touched chunks and the portable model-file
  layer streams into caller-owned arenas.

## Data/job flows

- Build flow: `make image` -> `scripts/build-image.sh` -> Clang/LLD/mtools -> `build/xaios-aarch64.img`, kernel/userspace ELFs, VirtIO images.
- Smoke flow: `make qemu-smoke` -> `scripts/qemu-smoke.py` -> boot QEMU -> scan output markers and telemetry.
- ABI flow: `scripts/qemu-abi-contract.py` -> `scripts/qemu_gate_lib.py` -> compare source syscall header/initfs/model constants against `contracts/qemu-rc-v1.json`.
- Hosted engine flow: `make hosted-test` -> C parser/backend canary -> Python/C
  model-v2 round trips, malformed packages, sparse >4 GiB package and bounded
  chunk streaming.
- Userspace app flow: compile app from `userspace/apps/`, pack into initramfs, launch from `kmain()` with per-app capability mask.
- Control flow: local or SSH `xaiosctl` -> shared parser with authenticated
  principal/role -> syscall 37 -> capability-derived maximum role -> typed
  query or replay-protected mutation -> persistent audit -> shared renderer.
- SSH shell flow: connection/channel -> syscall 38 lazy-execute/close -> one of 16
  bounded kernel contexts with independent cwd/parser state.

## Current architecture risks

- The model-v1 kernel path is an explicitly named QEMU fixture; production
  transformer decode returns `XAIOS_ERR_UNSUPPORTED`.
- Userspace ELFs start at `0x100000000`, outside the kernel's first-4-GiB
  identity map. The ABI gate checks the C/linker constants.
- Hardware performance is not validated by QEMU gates.
- Administrative state is intentionally bounded to 16 active keys, 16 revoked
  fingerprints and 64 audit records; those are fixture limits, not fleet scale.
- Security update signature validation is documented in source as QEMU dev-mode format validation, not production cryptographic verification.
- ModelFS lifecycle and administration are hosted- and QEMU-tested, including
  dynamic registration, cleanup/reuse, format/mount/grow/fsck, persisted scrub
  and free-only trim. QEMU VirtIO uses interrupt-dispatched network/block
  completions, event-index suppression, indirect descriptors, and eight block
  request slots, with direct contiguous DMA or a per-request bounce page. A
  focused emulated-NVMe gate initializes admin/I/O queues and validates
  write/flush/read plus host backing bytes. Production NVMe multiqueue,
  interrupt affinity, physical durability, and performance are unverified.

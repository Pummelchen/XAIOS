<!--
AI onboarding file.
Mode: refresh
Indexed base commit: 8404c1ec1b76c02157bb08d8a3a9466a93e5c2cb
Last refreshed: 2026-08-01
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
image remains an early-boot image and does not link the common kernel/runtime.

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
| Filesystems | `kernel/fs/`, `scripts/create-initfs.py` | RO initramfs and mutable persistent filesystem. |
| Process/API | `kernel/user/`, `userspace/include/xaios_user.h` | Process table, service supervisor, syscall ABI/wrappers. |
| Network | `kernel/net/`, `kernel/runtime/network_stack.c` | Protocols, socket buffers, network telemetry. |
| Security | `kernel/runtime/security.c` | Capabilities, credential-material rejection, update policy, sandbox path checks. |
| AI runtime | `kernel/runtime/cpu_ai_runtime.c`, `kernel/runtime/model_arena.c`, `kernel/runtime/ai_cell.c` | CPU-only inference simulation/runtime, shared model arena, resource isolation. |
| Portable engine | `engine/include/xaios_engine/`, `engine/src/` | model-v2 parser, architecture registry, backend API and scalar projection canary. |
| Remote/admin | `kernel/runtime/remote_login.c`, `userspace/sshd/` | Remote login and SSH/SFTP surfaces. |

## Trust boundaries

- EL0 userspace crosses into kernel via syscall dispatch in `kernel/user/syscall.c`.
- Syscalls are gated by capability masks in `kernel/include/xaios/syscall.h` and dispatch table entries.
- Filesystem access is constrained by security policy in `kernel/runtime/security.c`.
- Mutable state and updates cross persistence/update boundaries in `kernel/fs/`, `kernel/runtime/persistence.c`, and `kernel/runtime/update.c`.
- Network/SSH paths cross from QEMU host forwarding into socket and SSH code.
- Model-v2 writing streams caller-provided section sources to positional package
  extents. Official model import is not yet implemented.

## Data/job flows

- Build flow: `make image` -> `scripts/build-image.sh` -> Clang/LLD/mtools -> `build/xaios-aarch64.img`, kernel/userspace ELFs, VirtIO images.
- Smoke flow: `make qemu-smoke` -> `scripts/qemu-smoke.py` -> boot QEMU -> scan output markers and telemetry.
- ABI flow: `scripts/qemu-abi-contract.py` -> `scripts/qemu_gate_lib.py` -> compare source syscall header/initfs/model constants against `contracts/qemu-rc-v1.json`.
- Hosted engine flow: `make hosted-test` -> C parser/backend canary -> Python/C
  model-v2 round trips, malformed packages, sparse >4 GiB package and bounded
  chunk streaming.
- Userspace app flow: compile app from `userspace/apps/`, pack into initramfs, launch from `kmain()` with per-app capability mask.

## Current architecture risks

- The model-v1 kernel path is an explicitly named QEMU fixture; production
  transformer decode returns `XAIOS_ERR_UNSUPPORTED`.
- Userspace ELFs start at `0x100000000`, outside the kernel's first-4-GiB
  identity map. The ABI gate checks the C/linker constants.
- Hardware performance is not validated by QEMU gates.
- Security update signature validation is documented in source as QEMU dev-mode format validation, not production cryptographic verification.

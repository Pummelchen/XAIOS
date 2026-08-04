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
# Components

## Bootloader

- Responsibility: Load kernel ELF from FAT image and transfer control with boot info.
- Key files: `boot/uefi/loader_main.c`, `boot/uefi/linker.ld`, `scripts/build-image.sh`.
- Risks: earliest boot failures; toolchain/linker sensitivity.
- Validate: `make image`, `make qemu-smoke`.

## Kernel initialization/core

- Responsibility: strict subsystem initialization and userspace launch.
- Key files: `kernel/core/kmain.c`, `kernel/core/telemetry.c`, `kernel/core/klog.c`.
- Invariants: self-tests run before dependent runtime paths; capability masks match app needs.
- Validate: `make compile-check`, `make qemu-smoke`.

## Memory and process loading

- Responsibility: PMM/NUMA/VMM, arenas, heap, ELF loading, process address spaces.
- Key files: `kernel/mm/`, `kernel/arch/aarch64/mmu.c`, `kernel/user/user.c`.
- Risks: boot failure, address-space corruption, user-buffer validation regressions.
- Validate: compile check plus smoke/regression.

## Syscall/API surface

- Responsibility: kernel/user boundary and userspace wrappers.
- Key files: `kernel/include/xaios/syscall.h`, `kernel/user/syscall.c`, `userspace/include/xaios_user.h`, `userspace/lib/xaios_user.c`.
- Public interfaces: syscall numbers, request structs, capability bits, wrapper functions.
- Risks: docs/contract drift; missing capability enforcement.
- Validate: `python3 scripts/qemu-abi-contract.py`, `make qemu-smoke`.

## Filesystem, persistence, update

- Responsibility: initramfs, VFS, MutableFS small state, signed ModelFS package
  reads, persistent state, update/rollback, and portable model streaming.
- Key files: `kernel/dev/block_device.c`, `kernel/dev/nvme.c`,
  `kernel/dev/virtio/`, `kernel/storage/`, `kernel/fs/`,
  `engine/src/model_volume.c`, `engine/src/model_file.c`,
  `tools/xaios_model_volume.py`, `scripts/create-initfs.py`.
- Invariants: all ranges are checked 64-bit; partitions cannot escape parents;
  active packages are immutable; signatures and touched chunk hashes validate
  before delivery; signed registration, cleanup/reuse, activation, scrub and
  trim are capability-gated, replay-protected and audited.
- Risks: data loss, rollback/auth bypass, corrupt metadata, cross-filesystem
  activation/audit atomicity, no production NVMe multiqueue/affinity, no
  trusted-replica repair, and no physical-device evidence.
- Validate: `make hosted-test`, `make compile-check`, `make qemu-abi-contract`,
  `make qemu-smoke`, `make qemu-storage-crash-test`, `make qemu-nvme-gate`,
  `make qemu-model-sftp-gate`, then
  filesystem/update/readiness gates as appropriate.

## Network and SSH

- Responsibility: packet/protocol/socket paths and remote administration surfaces.
- Key files: `kernel/net/`, `kernel/runtime/network_stack.c`, `userspace/sshd/`, `scripts/run-qemu-aarch64.sh`, `scripts/qemu-docker-network-suite.py`, `tests/network/`.
- External dependency: QEMU host forwarding defaults to host port `2222` for guest SSH port 22.
- Risks: auth/security regressions, socket accounting mismatch.
- Validate: `make qemu-network-suite`, `make qemu-docker-network-suite`, and the
  host-bridge SSH smoke where relevant.

## Administrative control

- Responsibility: bounded measured queries, role-authorized persistent
  config/key mutations, revocation, audit and deterministic human/JSON output.
- Key files: `kernel/runtime/admin_control.c`,
  `kernel/include/xaios/admin_control.h`, `kernel/runtime/control_protocol.c`,
  `kernel/include/xaios/control_protocol.h`,
  `userspace/lib/xaios_control_client.c`, `userspace/apps/xaiosctl.c`.
- Invariants: exact protocol version/length checks, trusted maximum role from
  capabilities, replay IDs and failure-atomic config, no secret payloads in
  audit/logs, unknown values explicit, no arbitrary SSH execution.
- Validate: `make hosted-test`, `make qemu-abi-contract`, `make qemu-smoke`,
  `make qemu-docker-network-suite`.

## CPU-AI runtime and AI Cell

- Responsibility: CPU-only inference runtime/model handling and resource isolation.
- Key files: `kernel/runtime/cpu_ai_runtime.c`, `kernel/runtime/model_arena.c`, `kernel/runtime/ai_cell.c`, `tools/convert_gguf_to_xaios.py`.
- Risks: model format mismatch, unsupported hardware-performance claims, arena/KV-cache accounting bugs.
- Validate: CPU-AI suite, AI Cell gate, smoke.

## Build/gate system

- Responsibility: reproducible build images and QEMU validation reports.
- Key files: `Makefile`, `scripts/build-image.sh`, `scripts/qemu-*.py`, `scripts/qemu_gate_lib.py`, `.github/workflows/ci.yml`.
- Generated outputs: `build/` reports/images/ELFs.
- Validate: relevant make targets; do not commit generated reports.

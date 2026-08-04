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
# AI Index: XAIOS

## Snapshot

| Field | Value |
|---|---|
| Repository | `Pummelchen/XAIOS` |
| Indexed base commit | `8ddefb26f3dbc366dc4402677a156cf235daed82` plus the current working tree |
| Operation mode | `refresh` |
| Default branch | `main` |
| Primary languages | C99, Assembly, Python, Shell |
| Runtime target | AArch64 UEFI/QEMU OS correctness path plus a native hosted portable-engine/service foundation; x86_64 has AP/ring-3/XSAVE/ACPI/modern-VirtIO bring-up but not full OS-service parity. |

## Read first

1. `AI_INDEX.md` — this map.
2. `AGENTS.md` — repository-specific working rules for any AI coding agent.
3. `.ai/START_HERE.md` — compact first-session prompt.
4. `.ai/PROJECT_MAP.md` — top-level and module map.
5. `.ai/COMMANDS.md` and `.ai/TESTING.md` — validation commands and gates.
6. `.ai/KNOWN_UNKNOWNS.md` — conflicts, stale docs, and questions to ask humans.

Always inspect current source files before editing. These onboarding files are guidance, not a source-code substitute.

## Verified repository purpose

XAIOS is an experimental freestanding operating system and portable
inference-engine foundation. The current OS path validates deterministic
kernel/runtime fixtures under QEMU; it does not yet execute a real transformer.
The hosted C99 engine provides model-v2 parsing, architecture/backend
boundaries, caller-owned service/model/session lifecycle, direct async range
I/O, scalar packed INT4/INT6 correctness kernels, and an experimental
canary-gated AArch64 NEON backend plus an x86 AVX2 QEMU correctness path for
native macOS/Linux and future XAIOS-service builds. The freestanding OS also
exposes the QEMU/OpenSSH-tested
Phase 2 `xaios.control.v1`/`xaiosctl` administration surface: persistent
role-mapped keys/revocation, strict config transactions, host-key rotation and
redacted audit. ModelFS additionally supports signed online registration,
resumable SFTP, cleanup/reuse, verified activation, scrub/quarantine and safe
trim. Model-v2 execution loading, cluster control and an inference data plane do
not yet exist.

Evidence:
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/GETTING-STARTED.md`
- `kernel/core/kmain.c`
- `scripts/build-image.sh`

## Architecture summary

Boot starts in `boot/uefi/loader_main.c`, which loads `kernel.elf` and passes boot information to `kmain()` in `kernel/core/kmain.c`. `kmain()` initializes exceptions, timers, SMP/topology, NUMA/PMM/VMM, SMMU/PCI/GIC, VirtIO block/network, persistence, mutable filesystem, security, source index, Git workspace, sandboxing, services, syscalls, scheduler, model arena, CPU-AI runtime, AI Cell, agent protocol, telemetry, and then runs userspace programs.

Runtime structure:
- Portable hosted engine: `engine/`
- Kernel code: `kernel/`
- Userspace runtime/apps/daemon: `userspace/`
- Build and QEMU gates: `scripts/`
- ABI/release-candidate contracts: `contracts/`
- User docs: `docs/`, `wiki/`, `HARDWARE-READINESS.md`, `PROJECT-TRACKER.md`

## Directory map

| Path | Responsibility | Notes |
|---|---|---|
| `boot/uefi/` | AArch64/x86_64 UEFI loader and linker scripts. | Earliest boot code. |
| `kernel/arch/aarch64/` | EL1 entry, FP/SIMD-preserving vectors, timer, GIC, MMU, SMP, SMMU, PCI, RTC, watchdog. | Hardware-sensitive. |
| `kernel/arch/x86_64/` | ACPI, AP trampoline/IPI work, GDT/TSS/ring-3, XSAVE, local APIC and focused modern VirtIO/MSI-X operation. | QEMU bring-up; full services remain open. |
| `kernel/core/` | `kmain`, logging, telemetry, panic/assert, stack canaries. | `kmain.c` is the central init map. |
| `kernel/mm/` | PMM, NUMA, VMM support, heap/arena, ELF loading. | Boot and process-loader sensitive. |
| `kernel/dev/virtio/`, `kernel/dev/nvme.c`, `kernel/dev/block_device.c` | Queued VirtIO, focused QEMU NVMe, and generic 64-bit block API. | QEMU correctness only; production NVMe and physical durability remain open. |
| `kernel/storage/` | GPT primary/backup parser/writer and bounded partition devices. | Hosted- and QEMU-administration tested. |
| `kernel/fs/` | Initramfs, VFS, MutableFS root, immutable ModelFS reads, dynamic staging lifecycle, scrub and trim. | ModelFS is dedicated VirtIO slot 4 in QEMU. |
| `kernel/net/` | ARP, IPv4/IPv6, ICMP/ICMPv6, NDP, DNS, routing, socket buffers. | Validate with network gates. |
| `kernel/runtime/` | AI Cell, CPU-AI runtime, model arena, security, sandbox, persistence, update, remote login, control protocol, agent protocol, source index, Git workspace. | Security/AI-runtime sensitive. |
| `kernel/user/` | Process table, service supervisor, syscall dispatch. | API and capability sensitive. |
| `userspace/` | EL0 runtime, init, service manager, worker, apps, SSH daemon. | Built into initramfs by `scripts/build-image.sh`. |
| `engine/` | Portable C99 model-v2, ModelFS/model-file, architecture/backend and caller-owned service interfaces. | Native hosted tests exist; it is not wired to real model execution. |
| `tests/model_v2/`, `tests/model_volume/`, `tests/storage/` | Model/package round trips, malformed input, sparse large files, block/GPT/VFS/SFTP tests. | Run with `make hosted-test`. |
| `scripts/` | Build scripts, QEMU runners, gates, report generation, initfs creation. | Primary validation surface. |
| `contracts/` | Machine-readable QEMU release-candidate contract. | May lag newer source. |
| `.github/workflows/` | CI compile, ABI, build/smoke, regression jobs. | Ubuntu toolchain/QEMU path. |

## Entrypoints and commands

| Task | Command |
|---|---|
| Toolchain verification | `make bootstrap` |
| Default build | `make all` |
| Build AArch64 image | `make image` |
| Build x86_64 image | `make image-x86_64` |
| Build native engine CLI | `make engine-cli` |
| Interactive AArch64 QEMU | `make qemu` or `make qemu-aarch64` |
| Dry-run QEMU commands | `make qemu-dry-run` |
| Primary smoke gate | `make qemu-smoke` |
| Debian 13 SSH/network gate | `make qemu-docker-network-suite` |
| ModelFS SFTP gate | `make qemu-model-sftp-gate` |
| Full readiness gate | `make qemu-readiness-gate` |
| Full OS release-candidate gate | `make qemu-full-os-rc` |
| Aggregate core-OS gate | `make qemu-core-os-rc` |
| SMMUv3/NVMe/high-core gates | `make qemu-smmu-gate`, `make qemu-nvme-gate`, `make qemu-high-core-gate` |
| Compile syntax check | `make compile-check` |
| Hosted engine/model-v2 tests | `make hosted-test` |
| Hosted sanitizers/source audit | `make hosted-sanitizer-test`, `make production-source-audit` |
| Support-status docs check | `make docs-check` |
| SSH bridge | `make xaios-ssh-bridge` |

## Common task map

| Change type | Start with | Also inspect/update |
|---|---|---|
| Boot/UEFI | `boot/uefi/`, `scripts/build-image.sh` | `kernel/core/kmain.c`, `docs/ARCHITECTURE.md` |
| Kernel subsystem | Relevant `kernel/*` module | Matching header, `kmain()` init/self-test order, QEMU gate markers |
| Syscall/API | `kernel/include/xaios/syscall.h` | `kernel/user/syscall.c`, `userspace/include/xaios_user.h`, `docs/API.md`, `contracts/qemu-rc-v1.json`, `scripts/qemu_gate_lib.py` |
| Userspace app | `userspace/apps/` | `scripts/build-image.sh`, `kernel/core/kmain.c`, `scripts/qemu-smoke.py` |
| SSH/network | `userspace/sshd/`, `kernel/net/`, `kernel/runtime/network_stack.c` | Socket syscalls, QEMU network gates, and the Debian 13 Docker client suite |
| Administration/control | `kernel/runtime/admin_control.c`, `kernel/runtime/control_protocol.c`, `userspace/lib/xaios_control_client.c` | Persistent schema/key/audit state, protocol mirrors, syscall/capabilities, `docs/XAIOSCTL.md`, ABI contract and SSH tests |
| Security/update | `kernel/runtime/security.c`, `kernel/runtime/update.c` | `SECURITY.md`, `.ai/SECURITY.md`, QEMU security/update gates |
| Production model/engine | `engine/`, `tools/xaios_model_v2.py` | `tests/model_v2/`, model-v2/adapter/backend docs |
| Storage/ModelFS | `kernel/dev/block_device.c`, `kernel/storage/`, `kernel/fs/vfs*.c`, `tools/xaios_model_volume.py` | `engine/src/model_volume.c`, `engine/src/model_file.c`, `tests/storage/`, `tests/model_volume/`, storage docs |
| QEMU model fixture | `kernel/runtime/cpu_ai_runtime.c`, `tools/create_xaios_v1_fixture.py` | `contracts/qemu-rc-v1.json`, smoke markers; never call it real inference |
| CI/gates | `.github/workflows/ci.yml`, `Makefile`, `scripts/qemu-*.py` | `.ai/TESTING.md`, `HARDWARE-READINESS.md` |

## Important conventions

- C is freestanding C99, compiled with `-Wall -Wextra -Werror`; do not assume libc or POSIX in kernel/userspace.
- Userspace APIs use `userspace/include/xaios_user.h` and fixed-size buffers; no documented userspace `malloc` path.
- New kernel modules should include or update self-tests and ensure init/self-test order in `kmain()` is correct.
- Syscalls require capability mapping and user-buffer validation.
- QEMU gates are correctness evidence. Do not make hardware performance claims from QEMU-only results.

## Security-sensitive areas

- `kernel/runtime/security.c`
- `kernel/user/syscall.c`
- `kernel/fs/`, `kernel/runtime/persistence.c`, `kernel/runtime/update.c`
- `kernel/runtime/sandbox.c`, `kernel/runtime/git_workspace.c`, `kernel/runtime/source_index.c`
- `userspace/sshd/`
- `scripts/run-qemu-aarch64.sh` host forwarding and local SSH bridge

## Generated or do-not-edit zones

- Ignored generated outputs: `build/`, `out/`, `dist/`, `*.img`, `*.efi`, `*.elf`, `*.bin`, `*.map`, `*.log`, `.cache/`, `__pycache__/`, `compile_commands.json`.
- Do not hand-edit generated QEMU reports under `build/`.
- `.qoder/repowiki/` appears to be generated repository-wiki material; do not treat it as source of truth.

## Known conflicts and unknowns

High-impact items are tracked in `.ai/KNOWN_UNKNOWNS.md`. The syscall/API
contract and primary readiness/support docs are synchronized in the current
working tree. Remaining material risks include no real Qwen/K3 execution, no
model-executing native backend, production NVMe/physical-device evidence,
incomplete x86 EL0/network/SSH/filesystem/security service parity, and no
production model/cluster data plane. Platform status is authoritative in
`docs/PLATFORM-SUPPORT.json`.
Licensing is defined by `LICENSE` and `COMMERCIAL-LICENSE.md`.

## What changed since last index

Refreshed for queued VirtIO and emulated NVMe, translated SMMUv3, crash
recovery, runtime-sized EL0 threads/high-core metadata, DNS/fragment/TCP
hardening, x86 interrupt delivery, and the expanded aggregate core-OS gate.

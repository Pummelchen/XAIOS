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
# AI Index: XAIOS

## Snapshot

| Field | Value |
|---|---|
| Repository | `Pummelchen/XAIOS` |
| Indexed base commit | `8404c1ec1b76c02157bb08d8a3a9466a93e5c2cb` plus the current working tree |
| Operation mode | `refresh` |
| Default branch | `main` |
| Primary languages | C99, Assembly, Python, Shell |
| Runtime target | AArch64 UEFI/QEMU OS correctness path plus a hosted portable-engine foundation; x86_64 remains early bring-up only. |

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
boundaries, and a scalar projection canary for future native macOS/Linux and
XAIOS-service builds.

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
| `boot/uefi/` | AArch64 UEFI loader and linker script. | Earliest boot code. |
| `kernel/arch/aarch64/` | EL1 entry, vectors, timer, GIC, MMU, SMP, SMMU, PCI, RTC, watchdog. | Hardware-sensitive. |
| `kernel/core/` | `kmain`, logging, telemetry, panic/assert, stack canaries. | `kmain.c` is the central init map. |
| `kernel/mm/` | PMM, NUMA, VMM support, heap/arena, ELF loading. | Boot and process-loader sensitive. |
| `kernel/dev/virtio/` | VirtIO transport, block, network drivers. | Recent HEAD changes block-device selection. |
| `kernel/fs/` | Initramfs and mutable persistent filesystem. | Coupled to `scripts/create-initfs.py` and contract JSON. |
| `kernel/net/` | ARP, IPv4/IPv6, ICMP/ICMPv6, NDP, DNS, routing, socket buffers. | Validate with network gates. |
| `kernel/runtime/` | AI Cell, CPU-AI runtime, model arena, security, sandbox, persistence, update, remote login, agent protocol, source index, Git workspace. | Security/AI-runtime sensitive. |
| `kernel/user/` | Process table, service supervisor, syscall dispatch. | API and capability sensitive. |
| `userspace/` | EL0 runtime, init, service manager, worker, apps, SSH daemon. | Built into initramfs by `scripts/build-image.sh`. |
| `engine/` | Portable C99 model-v2, architecture and backend interfaces. | Hosted tests exist; it is not wired to real model execution. |
| `tests/model_v2/` | C/Python round-trip, malformed-input, sparse >4 GiB and streaming tests. | Run with `make hosted-test`. |
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
| Interactive AArch64 QEMU | `make qemu` or `make qemu-aarch64` |
| Dry-run QEMU commands | `make qemu-dry-run` |
| Primary smoke gate | `make qemu-smoke` |
| Debian 13 SSH/network gate | `make qemu-docker-network-suite` |
| Full readiness gate | `make qemu-readiness-gate` |
| Full OS release-candidate gate | `make qemu-full-os-rc` |
| Compile syntax check | `make compile-check` |
| Hosted engine/model-v2 tests | `make hosted-test` |
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
| Security/update | `kernel/runtime/security.c`, `kernel/runtime/update.c` | `SECURITY.md`, `.ai/SECURITY.md`, QEMU security/update gates |
| Production model/engine | `engine/`, `tools/xaios_model_v2.py` | `tests/model_v2/`, model-v2/adapter/backend docs |
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
native optimized backend, fixed-size OS memory/NUMA/storage prototypes, the
x86 image not linking the common runtime, and ambiguous licensing.

## What changed since last index

Refreshed for the model-v2/portable-engine foundation, explicit model-v1
fixture isolation, independent CI jobs, honest support status, and current ABI
and QEMU correctness contracts.

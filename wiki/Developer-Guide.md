# Developer Guide

This page is the human-oriented entry point for working on XAIOS. Current
source code and build configuration are authoritative. The Wiki explains the
project, while machine-readable support state is maintained in
`docs/MODEL-SUPPORT.json` and `docs/PLATFORM-SUPPORT.json`.

## Repository map

| Path | Responsibility |
|---|---|
| `boot/uefi/` | AArch64 and x86_64 UEFI loading and boot handoff. |
| `kernel/arch/aarch64/` | AArch64 entry, exceptions, timer, GIC, MMU, SMP, PCI, SMMU, RTC, and watchdog. |
| `kernel/arch/x86_64/` | ACPI, AP startup, GDT/TSS, ring 3, XSAVE, local APIC, and focused VirtIO/MSI-X bring-up. |
| `kernel/core/` | Kernel initialization, logging, telemetry, panic handling, and global self-test order. |
| `kernel/mm/` | Physical and virtual memory, NUMA state, heap, arenas, and ELF loading. |
| `kernel/dev/` and `kernel/storage/` | VirtIO, NVMe, block devices, GPT, and partitions. |
| `kernel/fs/` | Initramfs, VFS, MutableFS, and ModelFS integration. |
| `kernel/net/` | Ethernet, ARP, IPv4, IPv6, ICMP, NDP, DNS, routing, TCP, UDP, and socket buffers. |
| `kernel/runtime/` | Security, persistence, updates, control protocol, AI Cell, model arena, remote login, and supporting services. |
| `kernel/user/` | Process lifecycle, service supervision, and syscall dispatch. |
| `userspace/` | Freestanding runtime, init, service manager, applications, and SSH/SFTP daemon. |
| `engine/` | Portable C99 model-v2, ModelFS, architecture, backend, model, session, and service interfaces. |
| `tests/` | Hosted control, storage, model-v2, ModelFS, and backend tests. |
| `scripts/` | Image builds, QEMU launchers, contract checks, and acceptance gates. |
| `tools/` | Model-v2 and ModelFS host tooling plus explicitly named model-v1 fixture tooling. |
| `platform/vmware-fusion/` | Apple Silicon VMware Fusion compatibility-stage inputs. |
| `contracts/` | Machine-readable QEMU release-candidate ABI contract. |
| `docs/` | Detailed specifications and machine-readable support status. |
| `wiki/` | Source-controlled mirrors of human-facing Wiki pages checked with the repository. |

## Primary entry points

- UEFI loader: `boot/uefi/loader_main.c`
- AArch64 kernel initialization: `kernel/core/kmain.c`
- x86_64 entry and bring-up: `kernel/arch/x86_64/entry.S` and
  `kernel/arch/x86_64/early.c`
- Syscall dispatch: `kernel/user/syscall.c`
- Userspace API: `userspace/include/xaios_user.h`
- Image build: `scripts/build-image.sh`
- QEMU launchers: `scripts/run-qemu-aarch64.sh` and
  `scripts/run-qemu-x86_64.sh`
- Primary smoke gate: `scripts/qemu-smoke.py`
- Aggregate gate: `scripts/qemu-core-os-rc.py`
- Portable engine API: `engine/include/xaios_engine/`

## Toolchain

On macOS:

```sh
brew install llvm lld qemu mtools python3 xorriso
make bootstrap
```

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 mtools python3
make bootstrap
```

Optional hosted Python tools use:

```sh
python3 -m pip install -r requirements-dev.txt
```

## Build and run commands

| Task | Command |
|---|---|
| Default build | `make all` |
| AArch64 image | `make image` |
| x86_64 image | `make image-x86_64` |
| Native engine CLI | `make engine-cli` |
| Interactive AArch64 QEMU | `make qemu` or `make qemu-aarch64` |
| Interactive x86_64 QEMU | `make qemu-x86_64` |
| VMware Fusion bundle | `make vmware-fusion-image` |
| VMware Fusion smoke | `make vmware-fusion-smoke` |
| QEMU command dry run | `make qemu-dry-run` |
| Remove generated outputs | `make clean` |

The AArch64 launcher defaults to TCG on every host. HVF is an explicit
experimental override because current QEMU/HVF exception handling can abort on
Apple Silicon. QEMU and VMware results are correctness evidence, not physical
performance evidence.

## Core validation commands

| Scope | Command |
|---|---|
| Cross-architecture compile | `make compile-check` |
| Hosted engine, storage, and model tests | `make hosted-test` |
| Hosted ASan and UBSan | `make hosted-sanitizer-test` |
| Python syntax | `python3 -m compileall -q scripts tools tests` |
| Documentation contracts | `make docs-check` |
| Production unfinished-marker audit | `make production-source-audit` |
| ABI contract | `make qemu-abi-contract` |
| Primary AArch64 smoke | `make qemu-smoke` |
| Regression suite | `make qemu-regression-suite` |
| Aggregate core OS gate | `make qemu-core-os-rc` |
| Full release-candidate gate | `make qemu-full-os-rc` |

See [[Testing and Benchmarking|Testing-and-Benchmarking]] for the focused gate
matrix.

## Coding conventions

- Kernel and userspace code is freestanding C99 with minimal architecture
  assembly. Do not assume libc, POSIX headers, host filesystem APIs, or dynamic
  allocation unless the local subsystem explicitly provides them.
- Keep module prefixes such as `pmm_`, `vmm_`, `smmu_`, and `virtio_` in kernel
  code. Public userspace wrappers use `xaios_`.
- Use bounded arithmetic and validate every untrusted offset, length, count,
  pointer, and narrowing conversion.
- Userspace uses fixed-size buffers or explicitly owned arenas; there is no
  general userspace `malloc` contract.
- New kernel modules require focused self-tests and correct initialization order
  in `kernel/core/kmain.c`.
- QEMU output may establish correctness or ABI behavior only. Performance and
  production-readiness claims require physical evidence under the benchmark
  contract.

## Change procedures

### Syscall or capability

Update every ABI surface together:

1. `kernel/include/xaios/syscall.h`
2. `kernel/user/syscall.c`
3. `userspace/include/xaios_user.h`
4. `userspace/lib/xaios_user.c` when a wrapper is needed
5. `docs/API.md`
6. `contracts/qemu-rc-v1.json`
7. ABI and smoke tests

Run `make compile-check`, `make qemu-abi-contract`, and the focused QEMU gate.

### Userspace application

1. Add the source under `userspace/apps/`.
2. Register it in `scripts/build-image.sh`.
3. For an SSH diagnostic, add its exact name, path, and smallest capability
   mask to `g_remote_apps` in `kernel/runtime/remote_login.c`; arguments and
   arbitrary executable paths remain unsupported.
4. Add a `run_user_app` call under `XAIOS_BOOT_TEST_APPS` only when the
   diagnostic must participate in deterministic boot validation.
5. Add a functional smoke marker when it participates in boot validation.
6. Run `make image && make qemu-smoke`.

### Kernel subsystem

1. Keep the implementation in the established subsystem directory.
2. Update the matching header and architecture build list.
3. Add or extend `*_self_test()` coverage.
4. Place initialization after its dependencies and before its consumers.
5. Run compile, focused, smoke, and regression gates appropriate to the blast
   radius.

### Filesystem, storage, or model package

Preserve 64-bit offsets, overflow checks, immutable active packages, explicit
flush ordering, and bounded memory. Run hosted tests, sanitizers, ABI, smoke,
ModelFS SFTP, storage crash, and relevant device gates.

### Network, SSH, or administration

Preserve process ownership, bounded buffers, role/capability checks, replay
protection, secret redaction, and fail-closed credential behavior. Run the
network suite, FreeBSD reference gate, Debian/OpenSSH cross-client gate, and the
macOS/Debian parallel load gate when available.

### Security or update behavior

Do not weaken capability checks, credential-material rejection, path
validation, signed-update authorization, or rollback behavior. Run compile,
security, update, smoke, and the affected storage or network gates.

## Generated files

Do not commit build products or generated reports under `build/`, `out/`, or
`dist/`. Disk images, EFI/ELF binaries, maps, logs, packet captures, Python byte
code, and QEMU JSON evidence are generated artifacts unless a benchmark or
release process explicitly records an immutable artifact elsewhere.

## Documentation policy

- Human project documentation belongs in the GitHub Wiki and selected
  source-controlled mirrors under `wiki/`.
- Detailed executable specifications remain under `docs/` beside the source
  and machine-readable contracts they describe.
- Update documentation whenever architecture, APIs, commands, test gates,
  security boundaries, or support status changes.
- Keep claims aligned with `docs/MODEL-SUPPORT.json`,
  `docs/PLATFORM-SUPPORT.json`, and immutable test evidence.

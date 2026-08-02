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
# Project map

## Top-level structure

| Path | Role |
|---|---|
| `boot/uefi/` | AArch64 UEFI loader, PE/COFF build, handoff to kernel. |
| `kernel/` | Freestanding kernel source. |
| `userspace/` | EL0 runtime, init/service manager, apps, worker, SSH daemon. |
| `engine/` | Portable hosted C99 inference-engine boundary and model-v2 reader. |
| `tests/model_v2/` | Hosted C/Python model-v2 and scalar-backend tests. |
| `tests/network/` | Disposable Debian 13 client image and SSH/SFTP/UDP interoperability suite. |
| `tools/` | Model-v2 streaming writer plus explicit v1 fixture tooling. |
| `scripts/` | Build image, create initfs, run QEMU, smoke/regression/readiness gates. |
| `contracts/` | QEMU release-candidate contract JSON. |
| `docs/` | Architecture, getting started, API docs. |
| `wiki/` | Local mirrors of selected live Wiki status/design pages; model support and delivery rows are checked by `make docs-check`. |
| `.github/workflows/` | CI. |
| `benchmarks/` | Benchmark methodology. |
| `.qoder/repowiki/` | Generated repo-wiki material; non-authoritative for this onboarding system. |

## Kernel module map

| Path | Main responsibility |
|---|---|
| `kernel/arch/aarch64/` | Assembly entry, exception vectors, timer, GIC, MMU, SMP, PCI/SMMU/RTC/watchdog. |
| `kernel/core/` | `kmain()`, logging, telemetry, panic/assert, stack canaries. |
| `kernel/mm/` | PMM, NUMA, VMM support, heap/arena, ELF loader. |
| `kernel/dev/virtio/` | VirtIO transport, block, net drivers. |
| `kernel/fs/` | Initramfs and mutable filesystem. |
| `kernel/net/` | ARP, IPv4/IPv6, ICMP/ICMPv6, NDP, routing, DNS, socket buffers. |
| `kernel/runtime/` | AI Cell, CPU-AI runtime, model arena, security, sandbox, update, persistence, remote login, source index, Git workspace, agent protocol. |
| `kernel/sched/` | Scheduler and AArch64 context switch. |
| `kernel/user/` | Process lifecycle, service supervisor, syscall dispatch. |
| `kernel/include/xaios/` | Kernel public/internal headers. |

## Userspace map

| Path | Role |
|---|---|
| `userspace/include/xaios_user.h` | Userspace syscall numbers, wrappers, data structures. |
| `userspace/lib/` | Userspace start and support library. |
| `userspace/init/` | `/init` and init config. |
| `userspace/service-manager/` | Service manager and service descriptor. |
| `userspace/worker/` | Worker process used for lifecycle/scheduler validation. |
| `userspace/apps/` | Shell, tests, ML/network/system apps, `agenttest`. |
| `userspace/sshd/` | SSH/SFTP daemon implementation. |

## Entrypoints

- Bootloader: `boot/uefi/loader_main.c`
- Kernel entry/init: `kernel/core/kmain.c`
- Syscall dispatch: `kernel/user/syscall.c`
- Userspace API: `userspace/include/xaios_user.h`, `userspace/lib/xaios_user.c`
- Build image: `scripts/build-image.sh`
- QEMU run: `scripts/run-qemu-aarch64.sh`, `scripts/run-qemu-x86_64.sh`
- Primary smoke: `scripts/qemu-smoke.py`
- ABI gate: `scripts/qemu-abi-contract.py`, `scripts/qemu_gate_lib.py`
- Model conversion: `tools/convert_gguf_to_xaios.py`
- Model-v2 writer/reader: `tools/xaios_model_v2.py`
- Portable engine APIs: `engine/include/xaios_engine/`
- Hosted engine tests: `tests/model_v2/`

## External dependencies

- Host toolchain: Clang, LLD, mtools, QEMU, Python 3.
- Python dev dependency: `paramiko==3.5.1` in `requirements-dev.txt`.
- The current model-v2 writer uses the Python standard library. Official
  SafeTensors/config/tokenizer and GGUF importers are not implemented.
- Docker is used only for the disposable Debian 13 network client gate; it is
  not an XAIOS deployment mechanism. No database, ORM, migration framework,
  Node package manager, Rust/Cargo, Go module, Java build, or web framework was
  detected in inspected files.

## Important config/files

- `Makefile`
- `.github/workflows/ci.yml`
- `.gitignore`
- `contracts/qemu-rc-v1.json`
- `userspace/init/xaios-init.conf`
- `userspace/service-manager/source-index.svc`
- `SECURITY.md`
- `HARDWARE-READINESS.md`

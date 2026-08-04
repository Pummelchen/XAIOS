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
# Project map

## Top-level structure

| Path | Role |
|---|---|
| `boot/uefi/` | AArch64 UEFI loader, PE/COFF build, handoff to kernel. |
| `kernel/` | Freestanding kernel source. |
| `userspace/` | EL0 runtime, init/service manager, apps, worker, SSH daemon. |
| `engine/` | Portable C99 inference boundary, model-v2 reader, signed ModelFS reader and model-file streaming API. |
| `tests/model_v2/` | Hosted C/Python model-v2 and scalar-backend tests. |
| `tests/model_volume/` | ModelFS lifecycle, recovery, corruption, sparse >100 GiB, and Python-writer/C-reader tests. |
| `tests/storage/` | Hosted block, GPT, VFS, and 64-bit SFTP packet tests. |
| `tests/control/` | Hosted deterministic `xaiosctl` parser/renderer/protocol tests. |
| `tests/network/` | Disposable Debian 13 client image and SSH/SFTP/UDP interoperability suite. |
| `tools/` | Model-v2 streaming writer, ModelFS host administrator, plus explicit model-v1 fixture tooling. |
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
| `kernel/dev/virtio/`, `kernel/dev/nvme.c`, `kernel/dev/block_device.c` | VirtIO transport/drivers, focused QEMU NVMe path, and backend-neutral 64-bit block registry. |
| `kernel/storage/` | GPT parser/writer and bounded partition block device. |
| `kernel/fs/` | Initramfs, VFS, MutableFS adapter, immutable ModelFS reads, and bounded staging writes/activation. |
| `kernel/net/` | ARP, IPv4/IPv6, ICMP/ICMPv6, NDP, routing, DNS, socket buffers. |
| `kernel/runtime/` | AI Cell, CPU-AI runtime, model arena, security, sandbox, update, persistence, per-session remote login, persistent admin control, typed control protocol, source index, Git workspace, agent protocol. |
| `kernel/sched/` | Scheduler, general thread runtime, and AArch64 context switch. |
| `kernel/user/` | Process lifecycle, service supervisor, syscall dispatch. |
| `kernel/include/xaios/` | Kernel public/internal headers. |

## Userspace map

| Path | Role |
|---|---|
| `userspace/include/xaios_user.h` | Userspace syscall numbers, wrappers, data structures. |
| `userspace/lib/` | Userspace start, syscall support and shared `xaiosctl` client library. |
| `userspace/init/` | `/init` and init config. |
| `userspace/service-manager/` | Service manager and service descriptor. |
| `userspace/worker/` | Worker process used for lifecycle/scheduler validation. |
| `userspace/apps/` | Shell, `xaiosctl`, tests, ML/network/system apps and `agenttest`. |
| `userspace/sshd/` | SSH/SFTP daemon implementation. |

## Entrypoints

- Bootloader: `boot/uefi/loader_main.c`
- Kernel entry/init: `kernel/core/kmain.c`
- Syscall dispatch: `kernel/user/syscall.c`
- Userspace API: `userspace/include/xaios_user.h`, `userspace/lib/xaios_user.c`
- Build image: `scripts/build-image.sh`
- QEMU run: `scripts/run-qemu-aarch64.sh`, `scripts/run-qemu-x86_64.sh`
- Primary smoke: `scripts/qemu-smoke.py`
- Aggregate core-OS gate: `scripts/qemu-core-os-rc.py`
- Focused device/capacity gates: `scripts/qemu-smmu-gate.py`,
  `scripts/qemu-nvme-gate.py`, `scripts/qemu-high-core-gate.py`, and
  `scripts/qemu-storage-crash-test.py`
- ABI gate: `scripts/qemu-abi-contract.py`, `scripts/qemu_gate_lib.py`
- Control service: `kernel/runtime/admin_control.c`, `kernel/runtime/control_protocol.c`, `userspace/lib/xaios_control_client.c`
- Model conversion: `tools/convert_gguf_to_xaios.py`
- Model-v2 writer/reader: `tools/xaios_model_v2.py`
- ModelFS administrator: `tools/xaios_model_volume.py`
- ModelFS guest interoperability: `scripts/qemu-model-sftp-gate.py`
- Portable engine APIs: `engine/include/xaios_engine/`
- Hosted engine/storage tests: `tests/model_v2/`, `tests/model_volume/`, `tests/storage/`

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

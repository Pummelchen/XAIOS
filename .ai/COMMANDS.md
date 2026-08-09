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
# Commands

Run commands from the repository root unless noted.

## Toolchain install / verification

macOS prerequisites documented in `docs/GETTING-STARTED.md`:

```sh
brew install llvm lld qemu mtools python3
make bootstrap
```

Ubuntu/Debian prerequisites documented in `docs/GETTING-STARTED.md` and CI:

```sh
sudo apt-get update
sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 mtools python3
make bootstrap
```

Optional Python dev dependency:

```sh
python3 -m pip install -r requirements-dev.txt
```

The retired GGUF converter now fails closed. The model-v2 writer currently uses
only the Python standard library. ModelFS signing/fixture generation requires
the `cryptography` package, installed by the QEMU CI jobs.

## Build

| Task | Command |
|---|---|
| Default build | `make all` |
| AArch64 image | `make image` |
| x86_64 image | `make image-x86_64` |
| VMware Fusion ARM64 bundle | `make vmware-fusion-image` |
| Native engine CLI | `make engine-cli` |
| Clean generated outputs | `make clean` |
| Clean persistent image | `make clean-persistent` |
| Syntax-only C compile check | `make compile-check` |
| Hosted engine/model-v2/storage tests | `make hosted-test` |
| Hosted ASan/UBSan tests | `make hosted-sanitizer-test` |
| Model-v2 tests (alias) | `make model-v2-test` |
| Model/platform support docs contract | `make docs-check` |
| Production unfinished-marker audit | `make production-source-audit` |

ModelFS host administration starts with:

```sh
PYTHONPATH=tools python3 tools/xaios_model_volume.py --help
```

See `docs/STORAGE-TOOLS.md` for hosted format, stage, verify, activate, fsck,
scrub, grow, recovery and trim commands. Guest `xaiosctl storage` provides typed
device/GPT/filesystem lifecycle, scrub and trim operations. Guest `xaiosctl
model` provides signed register, verify, activate and staging cleanup. Mutations
require administrator role, dedicated capability and replay-protected operation
ID; destructive target operations also require exact confirmation.

## Run locally

| Task | Command |
|---|---|
| AArch64 QEMU | `make qemu` or `make qemu-aarch64` |
| x86_64 QEMU | `make qemu-x86_64` |
| Dry-run QEMU command lines | `make qemu-dry-run` |
| VMware Fusion GUI | `make vmware-fusion` |
| VMware Fusion dry run | `make vmware-fusion-dry-run` |
| VMware Fusion smoke | `make vmware-fusion-smoke` |
| SSH bridge | `make xaios-ssh-bridge` |
| Connect to local SSH bridge | `ssh -p 2222 admin@localhost` |

`run-qemu-aarch64.sh` supports environment overrides such as `XAIOS_QEMU`, `XAIOS_AAVMF_CODE`, `XAIOS_QEMU_ACCEL`, `XAIOS_QEMU_CPU`, `XAIOS_QEMU_MACHINE`, `XAIOS_QEMU_MEMORY`, `XAIOS_QEMU_SMP`, `XAIOS_QEMU_HOSTFWD_PORT`, `XAIOS_QEMU_HOSTFWD_UDP_PORT`, `XAIOS_QEMU_NET_SOCKET_HOST`, `XAIOS_QEMU_NET_SOCKET_PORT`, and `XAIOS_QEMU_NET_SOCKET_PORT_2`.
The AArch64 launcher defaults to TCG on every host. HVF remains an explicit,
experimental `XAIOS_QEMU_ACCEL=hvf` override because current QEMU/HVF exception
handling can abort on Apple Silicon.

For direct IPv6/TCP from a Mac client, run QEMU with
`XAIOS_QEMU_HOSTFWD_PORT=none XAIOS_QEMU_NET_SOCKET_PORT=12345` and then run
`python3 scripts/qemu-ipv6-tcp-client.py --port 12345` in another terminal.

## Test/gates

| Gate | Command | Notes |
|---|---|---|
| Primary smoke | `make qemu-smoke` | Boots with an isolated disposable persistent image, scans functional markers, and validates telemetry JSON. |
| Process | `make qemu-process-gate` | Process lifecycle/scheduler. |
| OS control | `make qemu-osctl-gate` | Control-plane telemetry. |
| Filesystem | `make qemu-filesystem-gate` | Mutable filesystem. |
| ModelFS SFTP interoperability | `make qemu-model-sftp-gate` | Concurrent native macOS/Debian 13 dynamic registration, resumable upload/download, byte comparison, cleanup/reuse, activation, scrub and VirtIO discard against one QEMU guest. |
| Network | `make qemu-network-suite` or `make qemu-network-full-gate` | TCP/UDP/network paths. |
| FreeBSD Unix-reference interoperability | `make qemu-freebsd-network-suite` | Checksum-pinned FreeBSD 15.1 OpenSSH/SFTP client validates key acceptance/rejection, `xaiosctl`, SFTP, PTY ANSI `htop`, and UDP against one XAIOS guest. |
| Linux/OpenSSH cross-client interoperability | `make qemu-docker-network-suite` | Debian 13 exercises Phase 2 roles/config/key/revocation/audit/rotation, password policy, secret redaction, persistence, SSH/SFTP sessions and rekey, UDP, and malformed/reordered/retransmitted TCP. |
| macOS and Debian parallel network load | `make qemu-parallel-network-load` | Runs native macOS and Debian OpenSSH/SFTP, UDP, and direct TCP concurrently against one successful guest; requires macOS and Docker. |
| Generate an SSH password record | `python3 scripts/create-sshd-user-config.py --password-file PATH --output PATH` | Produces the strict PBKDF2-HMAC-SHA256 database; building it requires `XAIOS_SSH_USERS_FILE=PATH XAIOS_SSH_PASSWORD_AUTH=1`, and release mode rejects it. |
| CPU-AI | `make qemu-cpu-ai-suite` or `make qemu-cpu-ai-runtime-gate` | CPU-only AI runtime. |
| AI Cell | `make qemu-ai-cell-gate` | Resource contracts. |
| Security | `make qemu-security-gate` | Security policy markers. |
| Update | `make qemu-update-gate` | Update/rollback paths. |
| Regression | `make qemu-regression-suite` | Broader regression suite. |
| ABI contract | `make qemu-abi-contract` or `python3 scripts/qemu-abi-contract.py` | Contract/source validation. |
| x86 CPU compatibility matrix | `make qemu-x86_64-cpu-matrix` | Runs every contract-defined x86 CPU profile without requiring AArch64 QEMU; writes `build/qemu-x86_64-cpu-matrix-report.json`. |
| x86 platform matrix | `make qemu-x86_64-platform-matrix` | Boots q35/pc, 1/2/4/8/128/256-vCPU, xAPIC/x2APIC, 512 MiB-4 GiB, TCG single/multi-thread, AP/ring-3/XSAVE/modern-VirtIO checks, and opt-in NVMe inventory; writes `build/qemu-x86_64-platform-matrix-report.json`. |
| x86 repeated boot | `make qemu-x86_64-repeat-boot` | Runs 20 x86 smoke boots by default and writes per-boot logs plus `build/qemu-x86_64-repeat-boot-report.json`; set `XAIOS_QEMU_X86_REPEAT_COUNT` to 1-1000. |
| Readiness | `make qemu-readiness-gate` | Full local QEMU readiness. |
| Full OS RC | `make qemu-full-os-rc` | Release-candidate gate. |
| Core OS aggregate RC | `make qemu-core-os-rc` | Compile, hosted sanitizers, docs/source/ABI, AArch64, fault, storage-crash, SMMUv3, NVMe, network, high-core and x86 correctness in one non-skipping gate. |
| High-core capacity | `make qemu-high-core-gate` | Focused 130-vCPU TCG gate for runtime-sized SMP and NUMA CPU metadata; correctness evidence only. |
| SMMUv3 isolation | `make qemu-smmu-gate` | QEMU translated DMA, fault, revocation and teardown correctness. |
| Emulated NVMe | `make qemu-nvme-gate` | QEMU admin/I/O queue identify, write, flush, read and host backing-byte verification. |
| System metadata crash recovery | `make qemu-storage-crash-test` | Kills QEMU at both redundant metadata write points and verifies recovery after reboot. |

The translated SMMUv3 gate requires QEMU's test-only `iommu-testdev`, introduced
by upstream commit `6ce361b02c825b4a12a9684c47342859ee967cb2`. CI runs
`scripts/provision-qemu-smmu-testdev.sh` to build and verify that exact revision;
ordinary distro QEMU packages remain selected for gates that do not require this
device. The provisioner needs Git, Ninja, a C build toolchain, Python virtual
environment support, GLib, Pixman, libfdt, libslirp and zlib development
packages. `XAIOS_QEMU_SMMU` selects the focused gate binary without replacing
the distro emulator used by the aggregate gate's other scenarios.

## Format/lint/typecheck

No standalone formatter or linter command exists. `make compile-check` is the
repository's warnings-as-errors C type/syntax gate. Python syntax can be checked
with the repo-used command `python3 -m compileall -q scripts tools tests`.

## Database, migrations, Docker, deploy

No database migration tooling or deploy command was detected. The repository
has no application container deployment; `tests/network/Dockerfile.debian13`
builds only a disposable Linux/OpenSSH cross-client used by
`make qemu-docker-network-suite` and `make qemu-parallel-network-load`.
The FreeBSD Unix-reference gate uses an official checksum-pinned QEMU image,
not Docker.

## Release/readiness artifacts

Readiness and RC gates write reports under `build/`, including `build/qemu-readiness-report.json` and `build/qemu-full-os-rc-report.json`. These are generated artifacts and should not be committed.

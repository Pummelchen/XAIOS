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
# Testing

## Test model

Validation is based on:

- hosted C assertions under `tests/control/` and `tests/storage/`, plus
  C/Python model tests under `tests/model_v2/` and `tests/model_volume/`;
- kernel/userspace self-tests run during boot;
- Python QEMU gates that search serial output and telemetry markers;
- an official Debian 13 Docker client interoperability gate for the guest
  SSH/SFTP, UDP, and direct IPv6/TCP paths;
- a concurrent native macOS/Debian 13 ModelFS lifecycle and discard gate;
- a native macOS plus Debian 13 parallel load gate against one successful guest;
- ABI/contract Python checks;
- CI compile checks and QEMU smoke/regression jobs.

Evidence:
- `kernel/core/kmain.c`
- `scripts/qemu-smoke.py`
- `scripts/qemu-abi-contract.py`
- `scripts/qemu_gate_lib.py`
- `.github/workflows/ci.yml`
- `Makefile`

## Main validations

| Validation | Command | When to use |
|---|---|---|
| Syntax-only C check | `make compile-check` | Small C changes; quicker than booting QEMU. |
| Hosted engine/model-v2/storage | `make hosted-test` | Every engine, model-v2, ModelFS, block, GPT, VFS, SFTP, adapter or backend change. |
| Hosted sanitizers | `make hosted-sanitizer-test` | Hosted C ownership, parser, storage, and packed-kernel changes. |
| Production source audit | `make production-source-audit` | Reject unfinished implementation markers in boot, engine, kernel, and userspace source. |
| Support docs contract | `make docs-check` | README/tracker/readiness support-status changes. |
| Smoke gate | `make qemu-smoke` | Most code changes. |
| ABI contract | `python3 scripts/qemu-abi-contract.py` | Syscall, initfs, contract, model format changes. |
| Regression | `make qemu-regression-suite` | Broader kernel/userspace changes. |
| Network suite | `make qemu-network-suite` | Network/socket/SSH-adjacent changes. |
| Debian 13 network interoperability | `make qemu-docker-network-suite` | Changes to guest SSH/SFTP, TCP lifecycle, socket buffering, UDP, IPv6, or VirtIO net. |
| ModelFS SFTP interoperability | `make qemu-model-sftp-gate` | Dynamic registration, concurrent macOS/Debian SFTP, cleanup/reuse, verification, activation, scrub, trim and VirtIO discard. |
| macOS and Debian parallel network load | `make qemu-parallel-network-load` | Concurrency, capacity, reconnect, or post-load recovery changes; requires macOS and Docker. |
| CPU-AI suite | `make qemu-cpu-ai-suite` | AI runtime/model changes. |
| Readiness | `make qemu-readiness-gate` | Changes that may affect QEMU readiness. |
| Full OS RC | `make qemu-full-os-rc` | Release-candidate or hardware-entry decisions. |
| Core OS aggregate RC | `make qemu-core-os-rc` | All independent hosted and QEMU-testable core gates, including storage crash recovery, SMMUv3 isolation, emulated NVMe, high-core capacity and x86 interrupt delivery. |
| High-core capacity | `make qemu-high-core-gate` | Dynamic SMP registry or NUMA CPU-set changes; stops after the >128-CPU capacity invariants to avoid conflating slow TCG late boot with failure. |
| SMMUv3 isolation | `make qemu-smmu-gate` | DMA mapping, translation fault, revocation, or stream teardown changes. |
| Emulated NVMe | `make qemu-nvme-gate` | NVMe queue, BAR mapping, command, or block-I/O changes. |
| Storage crash recovery | `make qemu-storage-crash-test` | System-slot metadata, update, flush ordering, or redundant-write changes. |

## CI behavior

GitHub Actions workflow `.github/workflows/ci.yml` runs:

- architecture-correct AArch64/x86_64 kernel and AArch64 userspace compile checks;
- hosted engine/model-v2 tests;
- support-status documentation contract;
- ABI contract validation;
- `make image` followed by `scripts/qemu-smoke.py`;
- `make image` followed by `scripts/qemu-regression-suite.py`.
- the independent `make qemu-model-sftp-gate` native OpenSSH job, with the
  guest serial log uploaded even on failure;
- the independent `make qemu-docker-network-suite` Debian interoperability
  job, with logs, JSON, and packet capture uploaded even on failure.

CI installs toolchain packages with apt and sets `XAIOS_QEMU_SMOKE_TIMEOUT=120` for QEMU smoke/regression jobs.

## Focused testing guidance

- Syscall/API change: run `make compile-check` and `python3 scripts/qemu-abi-contract.py`; then `make qemu-smoke` if QEMU is available.
- Control/`xaiosctl` change: run `make hosted-test`, `make qemu-smoke`, and
  `make qemu-docker-network-suite`; the last gate verifies real OpenSSH exit and
  JSON behavior against the guest.
- Userspace app change: run `make image && make qemu-smoke`; update smoke markers if expected output changes.
- Security/update change: run relevant security/update gates plus smoke.
- Filesystem/storage change: run `make hosted-test`, `make compile-check`, the
  ABI contract, `make qemu-smoke`, and `make qemu-model-sftp-gate`; run
  filesystem/update/readiness gates for broader persistence changes. Sparse
  >100 GiB tests prove addressing and bounded memory, not physical throughput.
- Network/SSH change: run `make qemu-network-suite` and
  `make qemu-docker-network-suite` when Docker is available. On macOS, also run
  `make qemu-parallel-network-load` for dual-origin load and recovery evidence.
- The Docker gate validates Phase 2 roles, key enrollment/revocation, config
  validation/apply/replay/rollback, audit/log redaction, sensitive-state denial,
  host-key persistence/rotation, independent cwd state, command limits,
  Ed25519 and password acceptance/rejection, default-disabled and malformed
  credentials, entropy failure, SFTP isolation, shared channels, forced rekey,
  four simultaneous sessions, reconnects, UDP echo, malformed IPv4/IPv6 input,
  reordering, and TCP retransmission. See
  `docs/NETWORK-SSH-STATUS.md` for the exact evidence boundary.
- The parallel load gate adds simultaneous native macOS and Debian traffic,
  strict SFTP status handling, four-connection/eight-channel saturation,
  over-capacity rejection, 40 combined reconnects, and post-load recovery.
- Docs-only change: validate Markdown links, manifest JSON, changed-file scope, and secret-like patterns; source tests may be skipped with explanation.

## Fixtures and generated reports

- QEMU marker lists live in scripts such as `scripts/qemu-smoke.py`.
- Contract data lives in `contracts/qemu-rc-v1.json`.
- ModelFS test images are generated under `build/hosted`; the 128 GiB logical
  fixture is sparse and must not be copied by a tool that materializes holes.
- Gate reports are generated under `build/` and should not be committed.

## Known testing caveats

- QEMU gates are correctness evidence only and do not authorize hardware performance claims.
- The ABI gate requires complete source/contract syscall and capability parity,
  not merely matching listed entries.
- AArch64 QEMU defaults to TCG on every host. Explicit
  `XAIOS_QEMU_ACCEL=hvf` remains experimental because current QEMU/HVF can abort
  in exception handling on Apple Silicon.
- The CPU matrix invokes HVF only when
  `XAIOS_QEMU_RUN_OPTIONAL_HVF=1` is explicitly set.
- `make qemu-x86_64-cpu-matrix` runs only the contract-defined x86 tiers and
  preserves the combined matrix report by writing a separate x86 report.
- Future CPU models absent from the installed QEMU are recorded as optional
  skips; every listed model that QEMU provides must pass its boot markers.
- `make qemu-x86_64-platform-matrix` validates x86 CPU-count reporting across
  q35/pc, 1-256 vCPUs, xAPIC/x2APIC, constrained/large memory, TCG thread
  modes and an opt-in QEMU NVMe PCI inventory.
- `make qemu-x86_64-repeat-boot` performs bounded repeated x86 smoke boots and
  retains each serial log for nondeterministic-failure diagnosis.
- Local QEMU gates require host QEMU/firmware/toolchain availability.
- The Debian 13 interoperability gate additionally requires Docker. Its direct
  IPv6 phase temporarily exposes the QEMU framed socket on the host so the
  isolated container can connect; cleanup removes the listener.
- The parallel load gate requires both macOS and Docker and is therefore not a
  Linux GitHub Actions job. It uses two framed socket listeners so both raw
  clients can exercise the same guest while SLIRP carries SSH/SFTP/UDP traffic.
- `make qemu-ssh-smoke` currently covers the host bridge, not the freestanding
  guest SSH daemon. Do not use that target alone as guest interoperability
  evidence.

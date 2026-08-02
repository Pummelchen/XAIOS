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
# Testing

## Test model

Validation is based on:

- hosted C assertions and Python `unittest` under `tests/model_v2/`;
- kernel/userspace self-tests run during boot;
- Python QEMU gates that search serial output and telemetry markers;
- an official Debian 13 Docker client interoperability gate for the guest
  SSH/SFTP, UDP, and direct IPv6/TCP paths;
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
| Hosted engine/model-v2 | `make hosted-test` | Every engine, model-v2, adapter or backend change. |
| Support docs contract | `make docs-check` | README/tracker/readiness support-status changes. |
| Smoke gate | `make qemu-smoke` | Most code changes. |
| ABI contract | `python3 scripts/qemu-abi-contract.py` | Syscall, initfs, contract, model format changes. |
| Regression | `make qemu-regression-suite` | Broader kernel/userspace changes. |
| Network suite | `make qemu-network-suite` | Network/socket/SSH-adjacent changes. |
| Debian 13 network interoperability | `make qemu-docker-network-suite` | Changes to guest SSH/SFTP, TCP lifecycle, socket buffering, UDP, IPv6, or VirtIO net. |
| macOS and Debian parallel network load | `make qemu-parallel-network-load` | Concurrency, capacity, reconnect, or post-load recovery changes; requires macOS and Docker. |
| CPU-AI suite | `make qemu-cpu-ai-suite` | AI runtime/model changes. |
| Readiness | `make qemu-readiness-gate` | Changes that may affect QEMU readiness. |
| Full OS RC | `make qemu-full-os-rc` | Release-candidate or hardware-entry decisions. |

## CI behavior

GitHub Actions workflow `.github/workflows/ci.yml` runs:

- architecture-correct AArch64/x86_64 kernel and AArch64 userspace compile checks;
- hosted engine/model-v2 tests;
- support-status documentation contract;
- ABI contract validation;
- `make image` followed by `scripts/qemu-smoke.py`;
- `make image` followed by `scripts/qemu-regression-suite.py`.
- the independent `make qemu-docker-network-suite` Debian interoperability
  job, with logs, JSON, and packet capture uploaded even on failure.

CI installs toolchain packages with apt and sets `XAIOS_QEMU_SMOKE_TIMEOUT=120` for QEMU smoke/regression jobs.

## Focused testing guidance

- Syscall/API change: run `make compile-check` and `python3 scripts/qemu-abi-contract.py`; then `make qemu-smoke` if QEMU is available.
- Userspace app change: run `make image && make qemu-smoke`; update smoke markers if expected output changes.
- Security/update change: run relevant security/update gates plus smoke.
- Filesystem/persistence change: run filesystem/update/readiness gates.
- Network/SSH change: run `make qemu-network-suite` and
  `make qemu-docker-network-suite` when Docker is available. On macOS, also run
  `make qemu-parallel-network-load` for dual-origin load and recovery evidence.
- The Docker gate validates Ed25519 and password acceptance/rejection,
  default-disabled and malformed credential handling, entropy failure, host-key
  persistence, SFTP offsets and isolation, shared channels, forced rekey, four
  simultaneous SSH sessions, 20 reconnects, UDP echo, malformed IPv4/IPv6
  transport input, reordering, and TCP retransmission. See
  `docs/NETWORK-SSH-STATUS.md` for the exact evidence boundary.
- The parallel load gate adds simultaneous native macOS and Debian traffic,
  strict SFTP status handling, four-connection/eight-channel saturation,
  over-capacity rejection, 40 combined reconnects, and post-load recovery.
- Docs-only change: validate Markdown links, manifest JSON, changed-file scope, and secret-like patterns; source tests may be skipped with explanation.

## Fixtures and generated reports

- QEMU marker lists live in scripts such as `scripts/qemu-smoke.py`.
- Contract data lives in `contracts/qemu-rc-v1.json`.
- Gate reports are generated under `build/` and should not be committed.

## Known testing caveats

- QEMU gates are correctness evidence only and do not authorize hardware performance claims.
- The ABI gate requires complete source/contract syscall and capability parity,
  not merely matching listed entries.
- AArch64 QEMU defaults to TCG on every host. Explicit
  `XAIOS_QEMU_ACCEL=hvf` remains experimental because current QEMU/HVF can abort
  in exception handling on Apple Silicon.
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

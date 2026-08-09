# Testing and Benchmarking

XAIOS validation combines hosted unit tests, boot-time self-tests, QEMU gates,
external OpenSSH/SFTP clients, ABI contracts, and GitHub Actions. Every result
must be described at the level it actually proves.

## Evidence levels

- **Hosted-tested** means native C or Python tests passed on a host operating
  system.
- **QEMU-tested** means an emulated correctness or ABI gate passed.
- **Interoperability-tested** means a named external client completed a bounded
  protocol suite against a QEMU guest.
- **Physically validated** requires the named real hardware and immutable raw
  evidence.
- **Production supported** additionally requires the project security,
  reliability, deployment, and operational acceptance gates.

QEMU throughput and timing are never physical performance evidence.

## Main validations

| Validation | Command | Use |
|---|---|---|
| Cross-architecture compile | `make compile-check` | Any C or architecture-boundary change. |
| Hosted tests | `make hosted-test` | Engine, model-v2, ModelFS, block, GPT, VFS, SFTP, adapter, or backend changes. |
| Hosted sanitizers | `make hosted-sanitizer-test` | Parser, ownership, storage, and packed-kernel changes. |
| Documentation contract | `make docs-check` | Support status, trackers, README, Wiki, or readiness changes. |
| Source completeness audit | `make production-source-audit` | Reject unfinished markers in production source. |
| ABI contract | `make qemu-abi-contract` | Syscalls, capabilities, initfs, fixtures, or model format changes. |
| Primary smoke | `make qemu-smoke` | Most kernel and userspace changes. |
| Regression suite | `make qemu-regression-suite` | Broad kernel and userspace changes. |
| Aggregate core OS | `make qemu-core-os-rc` | Non-skipping hosted and QEMU-testable core acceptance. |
| Full OS RC | `make qemu-full-os-rc` | Release-candidate and hardware-entry decisions. |

## Focused gates

| Area | Command |
|---|---|
| Process and scheduler | `make qemu-process-gate` |
| Filesystem | `make qemu-filesystem-gate` |
| Network stack | `make qemu-network-suite` |
| FreeBSD Unix reference | `make qemu-freebsd-network-suite` |
| Debian/OpenSSH cross-client | `make qemu-docker-network-suite` |
| macOS and Debian parallel load | `make qemu-parallel-network-load` |
| ModelFS SFTP lifecycle | `make qemu-model-sftp-gate` |
| Security | `make qemu-security-gate` |
| Update and rollback | `make qemu-update-gate` |
| Persistence reboot | `make qemu-persistence-reboot` |
| Storage crash recovery | `make qemu-storage-crash-test` |
| SMMUv3 isolation | `make qemu-smmu-gate` |
| Emulated NVMe | `make qemu-nvme-gate` |
| High CPU count | `make qemu-high-core-gate` |
| x86 CPU matrix | `make qemu-x86_64-cpu-matrix` |
| x86 platform matrix | `make qemu-x86_64-platform-matrix` |
| x86 repeated boot | `make qemu-x86_64-repeat-boot` |

The FreeBSD gate uses an official checksum-pinned FreeBSD 15.1 AArch64 image.
The Debian gate uses a disposable Docker client. These clients validate wire
behavior and do not imply FreeBSD or Linux binary ABI compatibility.

## CI

`.github/workflows/ci.yml` keeps architecture-specific jobs independent so an
unrelated failure cannot silently skip later evidence. The workflow currently
covers compile, hosted engine/model-v2, documentation, ABI, AArch64 smoke,
regression, x86_64 bring-up, aggregate core OS, ModelFS SFTP, Debian/OpenSSH,
and FreeBSD interoperability jobs. Logs and machine-readable reports are
uploaded for the long QEMU gates.

The translated SMMUv3 gate needs QEMU's test-only `iommu-testdev` from pinned
upstream commit `6ce361b02c825b4a12a9684c47342859ee967cb2`. CI provisions and
verifies that exact emulator while retaining distro QEMU for unrelated gates.

## Test selection

- A syscall change requires compile, ABI, focused behavior, and smoke gates.
- A userspace application requires image and smoke validation.
- A filesystem or storage change requires hosted tests, sanitizers, ABI,
  smoke, ModelFS SFTP, and relevant crash/device gates.
- A network or SSH change requires the network suite, FreeBSD gate,
  Debian/OpenSSH gate, and parallel macOS/Debian load when available.
- A security or update change requires its focused gate plus smoke and every
  storage or network gate affected by the policy boundary.
- A packed backend change requires scalar differential tests, randomized
  values and shapes, every packing tail, startup known-answer canaries, and
  physical validation before performance claims.

## Benchmark contract

Every performance artifact must identify the source and executable commits,
model/package revision, exactness mode, backend/layout, hardware, firmware,
memory and NUMA topology, workload, warm/cold state, repeated measurements, and
raw results. Comparisons must use the same model revision, quantization,
prompt/context, and hardware. Independent microbenchmark gains must not be
multiplied into an end-to-end claim.

See the repository's `docs/BENCHMARK-CONTRACT.md` for the complete required
schema and [[Current Limitations|Current-Limitations]] for evidence not yet
available.

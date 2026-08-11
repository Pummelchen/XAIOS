# XAIOS test suite

This directory is the authoritative home for test source, test runners, guest
fixtures, network clients, Docker test images, and fuzz seeds. The top-level
`scripts/` directory is reserved for build, image creation, launch, and host
bridge utilities.

## Layout

| Path | Contents |
|---|---|
| `tests/scripts/` | Python and shell gate runners, status validators, QEMU orchestration, fault injection, release checks, and benchmark-evidence generators. |
| `tests/network/` | Debian and FreeBSD interoperability Dockerfiles, client/server scripts, IPv4/IPv6 helpers, keys generated at runtime, and network fixtures. |
| `tests/model_v2/` | Python/C model-v2 round trips, malformed packages, sparse files, and memory-bound conversion checks. |
| `tests/hosted/` | Hosted C correctness tests for portable kernel/runtime components. |
| `tests/libc/` | ISO C99 requirement inventories plus strict language, library, startup and termination probes. |
| `tests/fuzz/` | Parser fuzz entrypoints and corpora. |
| `tests/fixtures/` | Deterministic test inputs that are safe to version. |

`tests/scripts/check-test-layout.py` rejects test runners in `scripts/`, missing
Docker build inputs, and test-image inputs outside `tests/`. It runs through
`make docs-check`.

## Main commands

| Scope | Command |
|---|---|
| C compile boundary | `make compile-check` |
| Hosted unit tests | `make hosted-test` |
| Hosted sanitizers | `make hosted-sanitizer-test` |
| Hosted ISO C99 contract | `make libc-check` |
| Hosted ISO C99 dual-architecture runtime | `make qemu-libc-gate` |
| Documentation and test layout | `make docs-check` |
| Production-source audit | `make production-source-audit` |
| ABI contract | `make qemu-abi-contract` |
| Primary AArch64 smoke | `make qemu-smoke` |
| x86_64 full-service smoke | `make qemu-x86_64-smoke` |
| Aggregate QEMU core OS | `make qemu-core-os-rc` |
| IPv4/IPv6 source fragmentation on ARM/x86 | `make qemu-outbound-fragmentation-gate` |
| NVMe queues and PRP lists on ARM/x86 | `make qemu-nvme-gate` |
| Power/recovery/operations closure | `make qemu-operations-closure` |
| Debian/OpenSSH interoperability | `make qemu-docker-network-suite` |
| FreeBSD client interoperability | `make qemu-freebsd-network-suite` |
| Bidirectional FreeBSD SSH/SCP | `make qemu-freebsd-bidirectional-suite` |
| Four-endpoint network matrix | `XAIOS_INTEL_VPS=root@HOST make qemu-four-endpoint-network-suite` |

The complete command catalog is maintained in `Makefile`; focused runners live
in `tests/scripts/` and are normally entered through a Make target.

`qemu-operations-closure` builds authenticated AArch64 and x86_64 images and
uses the real guest SSH server to check abrupt-stop detection, persisted clean
reboot/shutdown, service controls, network diagnostics, DNS, ICMP, SNTP,
resource-pressure reporting, update status, configuration export/import, and
redacted support bundles. By default it also runs a Debian 13 OpenSSH client
from the reproducible Docker image; `--skip-docker` is used by the aggregate
gate where Docker interoperability has a separate required job.

## Rebuilding disposable Docker test images

No required test program exists only inside a Docker layer. Every `COPY` input
is versioned below `tests/network/`, and package installation is declared in
the Dockerfile. Rebuild after moving to another Docker host with:

```sh
docker build -f tests/network/Dockerfile.debian13 -t xaios-debian13-network-client:13 .
docker build -f tests/network/Dockerfile.freebsd-qemu -t xaios-freebsd-qemu:15.1 .
```

The FreeBSD container supplies a reproducible QEMU harness; it does not pretend
that a Linux container has a FreeBSD kernel. The gate downloads the official
FreeBSD VM image, verifies its pinned SHA-256 identity, and stores the cache
under `~/.cache/xaios/freebsd/`. Docker images and that cache may be deleted at
any time and reconstructed from the repository plus the official download.

Do not commit downloaded VM images, generated SSH keys, passwords, build
outputs, or reports. Test runners create ephemeral credentials and write
artifacts under `build/`.

## Evidence boundary

Hosted and QEMU results prove only the behavior named by each gate. QEMU timing
does not establish physical performance, durability, NUMA behavior, or hardware
support. See `docs/BENCHMARK-CONTRACT.md` and the Wiki
[`Testing XAIOS`](../wiki/Testing-XAIOS.md) page.

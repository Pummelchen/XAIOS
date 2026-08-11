# Testing XAIOS

All maintained test runners, fixtures, client scripts, and Docker definitions
are versioned under [`tests/`](https://github.com/Pummelchen/XAIOS/tree/main/tests).
The `scripts/` directory contains product build, image, launch, and bridge tools,
not test runners.

Gate orchestration is under `tests/scripts/`; protocol clients and reproducible
Debian/FreeBSD environments are under `tests/network/`.

## Core validation

| Command | Purpose |
|---|---|
| `make docs-check` | Wiki/catalog/status and test-layout contracts. |
| `make compile-check` | Freestanding C compile checks with warnings treated as failures. |
| `make hosted-test` | Hosted model-v2, engine, parser, kernel, and utility tests. |
| `make qemu-abi-contract` | Syscall, image, service, telemetry, and fixture ABI contract. |
| `make qemu-smoke` | Primary AArch64 boot and deterministic self-test gate. |
| `make qemu-regression-suite` | Broader process, filesystem, network, and runtime regression suite. |
| `make qemu-operations-closure` | Both-architecture abrupt-stop, power, recovery, diagnostics, clock, pressure, update/config, support, and Debian-client gate. |
| `make qemu-full-os-rc` | Aggregate mandatory QEMU core-OS release-candidate gate. |

Focused gates cover boot loops, faults, security, local console, storage,
ModelFS, SMMUv3, NVMe, CPU-count/topology, x86_64, VMware Fusion, and developer
UX. The exact current inventory and prerequisites are maintained in
[`tests/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md).

## External interoperability

```sh
make qemu-docker-network-suite
make qemu-freebsd-network-suite
```

The Debian suite rebuilds from `tests/network/Dockerfile.debian13`. The FreeBSD
suite uses a checksum-pinned official VM image and repository-owned provisioning
under `tests/network/`. Both can be recreated after local Docker images and
caches are deleted; no required script exists only inside a container.

The four-endpoint gate coordinates macOS, Debian 13, FreeBSD 15.1, and the
remote Intel Debian/QEMU endpoint when explicitly configured. Credentials are
runtime inputs and must never be stored in the repository.

## Evidence policy

- QEMU and VMware results are correctness and ABI evidence.
- Sparse files prove address width and bounded memory, not storage throughput.
- High virtual CPU counts prove dynamic metadata sizing, not server speed.
- Performance claims require physical hardware and immutable artifacts meeting
  the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).
- Generated reports, logs, packet captures, and images belong under ignored
  output directories unless an evidence process explicitly publishes them.

See [[Current Limitations|Current-Limitations]] for tests that still require
physical hardware or real model checkpoints.

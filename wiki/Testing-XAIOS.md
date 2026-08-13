# Testing XAIOS

All maintained test runners, fixtures, client scripts, and Docker definitions
are versioned under [`tests/`](https://github.com/Pummelchen/XAIOS/tree/main/tests).
The `scripts/` directory contains product build, image, launch, and bridge tools,
not test runners.

Gate orchestration is under `tests/scripts/`; protocol clients and reproducible
Debian/FreeBSD environments are under `tests/network/`.

Host prerequisites are Clang, LLD, Python 3, mtools, QEMU, and the applicable
AArch64 or x86_64 UEFI firmware. Setup details are in
[[Getting Started|Getting-Started]].

## Core validation

| Command | Purpose |
|---|---|
| `make docs-check` | Wiki/catalog/status and test-layout contracts. |
| `make compile-check` | Freestanding C compile checks with warnings treated as failures. |
| `make hosted-test` | Hosted model-v2, engine, parser, kernel, and utility tests. |
| `make libc-check` | Strict hosted C99 headers, 464-function namespace/link, ELF layout, source pin, non-POSIX surface, and syscall-budget contract. |
| `make qemu-libc-gate` | Complete libc contract plus AArch64/x86_64 runtime and termination probes; emits the conformance report. |
| `make xapt-test` | Host-side signed package/catalog/system-image construction, verification, tamper, and malformed-input tests. |
| `make qemu-xapt-gate` | AArch64 and x86_64 install, execute, upgrade, rollback, corruption rejection, OS-slot update, reboot persistence, and removal through real SSH. |
| `make code-scanning-contract` | Read-only workflow permissions, loopback-only test port reservation, bounded diagnostics, and integer-width regression checks for resolved CodeQL findings. |
| `make qemu-abi-contract` | Syscall, image, service, telemetry, and fixture ABI contract. |
| `make qemu-smoke` | Primary AArch64 boot and deterministic self-test gate. |
| `make qemu-regression-suite` | Broader process, filesystem, network, and runtime regression suite. |
| `make qemu-network-adversarial-gate` | N-F3Q parser fuzzing, packet-fault handling, concurrent load/recovery, and 20 fresh ARM64 plus 20 fresh x86_64 QEMU boots. Set `XAIOS_NF3Q_BOOTS` only for bounded development reruns. |
| `make qemu-nvme-gate` | AArch64/x86_64 async four-queue PRP/SGL, direct-buffer, cancellation, malformed-completion, stress, and backing-byte checks; x86_64 also requires MSI-X delivery. |
| `make qemu-x86_64-numa-gate` | Two-node x86 SRAT/SLIT discovery, range ownership, node-local allocation and local/remote byte accounting. |
| `make qemu-aarch64-sve2-gate` | SVE2 arithmetic canary under QEMU TCG; it does not qualify scalable scheduler state, a backend, or physical SVE hardware. |
| `make qemu-operations-closure` | Both-architecture abrupt-stop, power, recovery, diagnostics, clock, pressure, update/config, support, and Debian-client gate. |
| `make qemu-qualification-readiness` | Consolidated QEMU evidence packet for SSH/network, NVMe, storage recovery, diagnostics, high-core topology, x86 parity, and repeated soak; physical qualification remains open. |
| `make qemu-full-os-rc` | Aggregate mandatory QEMU core-OS release-candidate gate. |

Focused gates cover boot loops, faults, security, local console, storage,
ModelFS, SMMUv3, NVMe, CPU-count/topology, x86_64, VMware Fusion, and developer
UX. The exact current inventory and prerequisites are maintained in
[`tests/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md).

## Complete validation command set

```sh
make bootstrap
make engine-cli
make compile-check
make hosted-test
make hosted-sanitizer-test
make qemu-libc-gate
make xapt-test
make qemu-xapt-gate
make code-scanning-contract
make production-source-audit
make qemu-abi-contract
make image
make qemu-smoke
make qemu-storage-crash-test
make qemu-smmu-gate
make qemu-nvme-gate
make qemu-x86_64-numa-gate
make qemu-aarch64-sve2-gate
make qemu-outbound-fragmentation-gate
make qemu-model-sftp-gate
make qemu-network-adversarial-gate
make qemu-freebsd-network-suite
make qemu-freebsd-bidirectional-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-core-os-rc
make qemu-high-core-gate
make qemu-x86_64-smoke
make qemu-x86_64-cpu-matrix
make qemu-x86_64-platform-matrix
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-docker-network-suite
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-freebsd-bidirectional-suite
XAIOS_INTEL_VPS=root@VPS make qemu-four-endpoint-network-suite
make vmware-fusion-smoke
```

The ModelFS and parallel-network gates require macOS plus Docker because they
run native macOS and Debian 13 clients against one guest. The focused high-core
gate validates runtime-sized SMP/NUMA metadata; it is not a scalability test.

The translated SMMUv3 gate requires QEMU's test-only `iommu-testdev`. Aggregate
CI builds and caches upstream QEMU commit
`6ce361b02c825b4a12a9684c47342859ee967cb2`; the gate does not silently skip
when a distribution QEMU lacks that device. Platform recommendation IDs are
registered in
[`docs/PLATFORM-SUPPORT.json`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-SUPPORT.json),
while their sole human-maintained status is in [[Project Tracker|Project-Tracker]].

The evidence boundary and the physical measurements required after QEMU are
documented in
[`docs/PHYSICAL-QUALIFICATION-READINESS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PHYSICAL-QUALIFICATION-READINESS.md).

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

## Update repository validation

`make xapt-repository` creates a deterministic OS-update repository for both
architectures under `build/xapt/repository`. It packages current AArch64 and
x86_64 kernel images and signs architecture-specific catalogs. It does not
invent product applications. `make qemu-xapt-gate` separately compiles the
`tests/fixtures/xapt-test-app.c` package and serves an isolated copy over
HTTP/1.1 to verify discovery, arguments, install, upgrade, rollback, corruption
rejection, persistence, and removal.

The Caddy deployment and live-origin checks are documented in
[[xapt Package Updates|Xapt-Package-Updates]]. The repository test key is a
public fixture and is not production trust evidence.

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

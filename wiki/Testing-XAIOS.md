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
| `make qemu-riscv64-gate` | RISC-V rv64gc on the QEMU `virt` board: boots the shared kernel to 100% across four harts and requires PCI and MMIO virtio both carrying a disk, xaiFS mounted at /models, the initial filesystem mounted, `/init` and the service manager run and returned from, the hosted C99 termination probes passed, every control command rendered, a `xaios login:` prompt, sshd listening, and at least 78 self-tests, with no assertion or panic anywhere. Four harts deliberately: firmware picks its own boot hart and it is not always hart 0. Negative control run -- zeroing the filesystem header fails it on six markers. |
| `make qemu-riscv64-boot-media-gate` | The same machine, booted from its own disk instead of from a kernel handed to QEMU: EDK2 firmware with no `-kernel`, requiring that firmware find the loader at the removable-media path, that the loader read the kernel off that same disk, and that the boot reach a login prompt with sshd listening. Needs `acpi=off`, or this EDK2 build publishes no device tree. Negative control run -- deleting the loader from the medium fails it on the loader markers. |
| `make qemu-riscv64-matrix-gate` | RISC-V at 1, 2, 4 and 8 harts: every boot must reach a login prompt, report exactly the harts it was given as scheduling, and answer an SSH login asking for its service state. Four independent boots with fresh firmware variables and fresh volumes each, so none can pass on state a previous run left behind. Hart count is the dimension swept because firmware picks its own boot hart and it is not always hart 0. |
| `make vmware-fusion-snapshot-gate` | Fusion snapshot and resume semantics: a snapshot is a point in time (pre-snapshot data survives a revert, post-snapshot data does not), a revert boots onto a filesystem the guest trusts, and a suspend is not counted as an unclean boot. Reads files over SFTP rather than the shell, because of B-25. |
| `make xapt-test` | Host-side signed package/catalog/system-image construction, verification, tamper, and malformed-input tests. |
| `make qemu-xapt-gate` | AArch64/x86_64 pinned TLS, trust rotation/revocation/recovery, install, execute, upgrade, rollback, corruption rejection, OS-slot update, reboot persistence, and removal. |
| `make code-scanning-contract` | Read-only workflow permissions, loopback-only test port reservation, bounded diagnostics, and integer-width regression checks for resolved CodeQL findings. |
| `make qemu-abi-contract` | Syscall, image, service, telemetry, and fixture ABI contract. |
| `make qemu-smoke` | Primary AArch64 boot and deterministic self-test gate. |
| `make qemu-keyboard-input-gate` | QMP-injected USB HID boot-keyboard login through the local console on both ARM64 and x86_64 QEMU. |
| `make qemu-regression-suite` | Broader process, filesystem, network, and runtime regression suite. |
| `make qemu-network-adversarial-gate` | N-F3Q parser fuzzing, packet-fault handling, concurrent load/recovery, and 20 fresh ARM64 plus 20 fresh x86_64 QEMU boots. Set `XAIOS_NF3Q_BOOTS` only for bounded development reruns. |
| `make qemu-nvme-gate` | AArch64/x86_64 async four-queue PRP/SGL, direct-buffer, cancellation, malformed-completion, stress, backing-byte, and every-queue MSI-X/LPI delivery checks. |
| `make qemu-x86_64-numa-gate` | Two-node x86 SRAT/SLIT/HMAT, 2 MiB/1 GiB mappings, targeted SMP TLB invalidation, placement, and byte accounting. |
| `make qemu-aarch64-sve2-gate` | SVE2 arithmetic plus per-task Z/P/FFR scheduler/interrupt preservation under QEMU TCG; it does not qualify an inference backend or physical hardware. |
| `make qemu-operations-closure` | Both-architecture abrupt-stop, power, recovery, diagnostics, clock, pressure, update/config, support, and Debian-client gate. |
| `make qemu-qualification-readiness` | Consolidated QEMU evidence packet for SSH/network, NVMe, storage recovery, diagnostics, high-core topology, x86 parity, and repeated soak; physical qualification remains open. |
| `make qemu-full-os-rc` | Aggregate mandatory QEMU core-OS release-candidate gate. |

Focused gates cover boot loops, faults, security, local console, storage,
xaiFS, SMMUv3, NVMe, CPU-count/topology, x86_64, VMware Fusion, and developer
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
make qemu-keyboard-input-gate
make qemu-storage-crash-test
make qemu-cluster-two-node-gate
make qemu-crash-safety-gate
make qemu-write-ordering-gate
make qemu-storage-bench
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

RISC-V is held to its own set, listed in full on [[RISC-V]]; the short form is:

```sh
make riscv64
make qemu-riscv64-gate
make qemu-riscv64-isa-gate
make qemu-riscv64-boot-media-gate
make qemu-riscv64-matrix-gate
make qemu-riscv64-durability-gate
make qemu-riscv64-release-gate
make qemu-riscv64-smoke
make qemu-riscv64-regression-suite
make qemu-riscv64-storage-crash-test
make qemu-riscv64-crash-safety-gate
make qemu-riscv64-framebuffer-gate
make qemu-riscv64-keyboard-input-gate
make qemu-riscv64-routing-prefix-gate
make qemu-riscv64-storage-bench
make qemu-riscv64-instruction-cost-gate
make qemu-riscv64-dhcpv6-gate
make qemu-riscv64-outbound-fragmentation-gate
make qemu-riscv64-model-sftp-gate
make qemu-riscv64-boot-loop
make qemu-riscv64-benchmark
make qemu-riscv64-preview
make qemu-riscv64-libc-gate
make qemu-riscv64-fault-matrix
make qemu-riscv64-nvme-gate
make qemu-riscv64-soak-gate
make qemu-riscv64-write-ordering-gate
make qemu-riscv64-local-console-gate
make qemu-console-xtop-gate-riscv64
```

The xaiFS and parallel-network gates require macOS plus Docker because they
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

## Manual host-platform runs

Two targets have no automated gate and are exercised by hand. Neither produces
qualification evidence.

```sh
make vmware-fusion-smoke
```

```sh
make vz-gate
```

The Virtualization.framework gate boots the current image, waits for the kernel,
the virtio console, a mounted and checked durable volume, a DHCP lease, an IPv6
address and a listening SSH server, and fails on a panic or a missing check. It
writes `build/vz-gate.json`, refreshes every attached volume from the current
build first -- the loader prefers the kernel on the A/B system volume over the
one on the ESP, so a stale copy boots a stale kernel and the run tests nothing
-- and needs macOS on Apple Silicon with a signed harness. It boots four vCPUs
and requires all four, because the defects a secondary CPU can have are
invisible on a single-core boot.

```sh
make vz-stress-gate
```

The stress gate is the same platform under sustained load rather than a single
pass. It boots repeatedly with `/bin/smpstress`, which pins threads across the
cores and runs them to a deadline, then checks invariants that admit no
tolerance: a contended counter against tallies each thread kept privately, and
per-thread words against the neighbours sharing their cache line. It repeats
because the defects it finds are intermittent -- the first one appeared on one
boot in six. See [[Virtualization Framework|Virtualization-Framework]].

## Update repository validation

`make xapt-repository` creates a deterministic OS-update repository for both
architectures under `build/xapt/repository`. It packages current AArch64 and
x86_64 kernel images and signs architecture-specific catalogs. It does not
invent product applications. `make qemu-xapt-gate` separately compiles the
`tests/fixtures/xapt-test-app.c` package and serves an isolated copy over pinned
TLS 1.2 to verify trust rotation/revocation/recovery, discovery, arguments,
install, upgrade, rollback, corruption rejection, persistence, and removal.

The Caddy deployment and live-origin checks are documented in
[[xapt Package Updates|Xapt-Package-Updates]]. The repository test key is a
public fixture and is not production trust evidence.

## Evidence policy

- QEMU and VMware results are correctness and ABI evidence.
- `make qemu-cluster-two-node-gate` is cluster evidence between two XAIOS
  machines rather than between XAIOS and a program written from the wire
  format. One image is built to listen and one to dial, each guest gets its
  own copy of every volume, and the gate requires the lines only a listening
  XAIOS produces. The same pair has been run across a real network with the
  dialling machine on the Intel VPS; that run is manual, because it needs a
  second host and a tunnel between them.
- `make qemu-crash-safety-gate` is power-loss evidence for ordering and
  tearing: it kills the emulator outright at random points while a package is
  being ingested, then hashes every chunk the surviving catalog still calls
  complete. It also constructs two states directly, because a kill almost
  never lands on either: a superblock caught half-written, and a superblock
  that is whole while the catalog it points at was never written — which is
  what a device with a volatile write cache leaves behind if it persists the
  publish before the thing it publishes. Both must be rejected by the slot's
  own hash and the volume must come back from the other slot, a commit lost.
  What it still does not do is run against a device that actually acknowledges
  a write and then loses it: the emulator never loses an acknowledged write,
  so the state is constructed rather than provoked.
- `make qemu-write-ordering-gate` covers the half the crash gate cannot: it
  has the block driver log every write and every flush, then checks that no
  superblock write — the write that publishes a commit — is issued without a
  flush since the previous write. That ordering is what keeps a device with a
  volatile write cache from persisting a superblock before the catalog it
  points at. Removing the flush makes the gate fail on every commit, which is
  how it was checked to be capable of failing.
- `make qemu-storage-bench` reports throughput rather than asserting it — these
  are emulator figures. What it does assert is that a warm read beats a cold
  one, which is the claim the read cache exists to make and the one that would
  silently stop being true if the cache were bypassed or invalidated on every
  access.
- Sparse files prove address width and bounded memory, not storage throughput.
- High virtual CPU counts prove dynamic metadata sizing, not server speed.
- Performance claims require physical hardware and immutable artifacts meeting
  the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).
- Generated reports, logs, packet captures, and images belong under ignored
  output directories unless an evidence process explicitly publishes them.

See [[Current Limitations|Current-Limitations]] for tests that still require
physical hardware or real model checkpoints.

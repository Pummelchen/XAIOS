# Hardware Support

## Current virtual targets

| Target | Current status |
|---|---|
| QEMU AArch64 `virt` | Complete core-OS correctness target with UEFI, SMP, GIC, VirtIO, SMMUv3 gates, filesystems, network, SSH/SFTP, and userspace. |
| QEMU x86_64 `q35` | Common kernel/userspace service parity with AArch64, including ACPI/MADT AP startup, xAPIC, XSAVE/FXSAVE, PCI VirtIO, network, SSH/SFTP, storage, and userspace. Block MSI-X setup is exercised, with bounded polling when a post-reset edge is not delivered. |
| VMware Fusion ARM64 | Limited boot path through the UEFI/GRUB compatibility stage to `/init`; no VMware NIC, persistent-disk driver, or multi-vCPU discovery. |

QEMU CPU-count gates cover 1 through 256 emulated CPUs and a focused 130-CPU
NUMA case. Hosted cpuset tests cover CPU IDs beyond 4,096. These checks prove
dynamic sizing and ABI behavior, not physical scaling or performance.

The x86_64 path starts MADT-discovered application processors. QEMU service parity with AArch64
is complete for the declared common core-OS scope.

## CPU feature foundations

- AArch64: scalar baseline, NEON context handling, experimental packed NEON
  interfaces, and an SVE2 QEMU arithmetic canary. SVE/SVE2 backends remain
  disabled because scalable Z/P/FFR scheduler state is not preserved yet.
- x86_64: CPUID/topology discovery, AVX2 packed-kernel interfaces, XSAVE state,
  and conservative FXSAVE fallback. AVX-512, VNNI, and AMX production backends
  remain incomplete.
- NUMA: runtime-sized node and CPU metadata exists. A two-node x86 QEMU gate
  parses SRAT/SLIT, allocates from each firmware range, and reports deterministic
  local/remote accounting. HMAT policy and physical locality/bandwidth remain
  open.

Both architecture VMMs expose collision-safe kernel 2 MiB map/unmap operations
and validate translation across the full extent during boot. Sparse model
packages beyond 100 GiB are covered in hosted tests. Neither result proves
multi-terabyte physical capacity or large-page performance.

## Physical hardware boundary

No current QEMU or VMware result establishes physical Apple Silicon, Intel
desktop, Xeon, NVMe, NIC, SMMU/IOMMU, thermal, power, or performance support.
Physical qualification requires boot logs, device inventory, correctness gates,
and immutable benchmark artifacts from the actual machine.

No physical Apple or Xeon benchmark artifact currently exists in the
repository. Performance numbers that do not satisfy the
[benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
are targets, not results, and independent microbenchmark improvements must not
be multiplied into an end-to-end claim.

## Qualification readiness packet

`make qemu-qualification-readiness` is the consolidated QEMU pre-physical
gate. It runs both architecture boot/readiness checks, network and SSH
operations, fragmentation, NVMe queue/flush, storage crash recovery, dynamic
high-core metadata, benchmark telemetry, and repeated smoke boots. A passing
`build/qemu-qualification-readiness-report.json` is still marked
`qemu_evidence_pass_physical_open`.

The report deliberately marks real NUMA-local/remote bytes, memory bandwidth,
PMU counters, frequency/power/thermal behavior, physical NIC behavior, and
physical NVMe durability as unavailable under QEMU. The required physical
artifact fields are defined in
[`docs/PHYSICAL-QUALIFICATION-READINESS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PHYSICAL-QUALIFICATION-READINESS.md).

See [[VMware Fusion|VMware-Fusion]], [[Testing XAIOS|Testing-XAIOS]], and the
single [[Project Tracker|Project-Tracker]].

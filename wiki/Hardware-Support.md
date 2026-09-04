# Hardware Support

## Current virtual targets

| Target | Current status |
|---|---|
| QEMU AArch64 `virt` | Complete core-OS correctness target with UEFI, SMP, GICv3/ITS, VirtIO, SMMUv3 gates, filesystems, network, SSH/SFTP, and userspace. NVMe requires LPI delivery on every negotiated queue. |
| QEMU x86_64 `q35` | Common kernel/userspace service parity with AArch64, including ACPI/MADT AP startup, xAPIC, XSAVE/FXSAVE, PCI VirtIO, network, SSH/SFTP, storage, and userspace. NVMe requires APIC/MSI-X delivery on every negotiated queue. |
| QEMU RISC-V `virt` (rv64gc) | Boots to 100% on four harts with 81 self-tests and no errors, a login prompt and sshd answering; also boots from its own disk through EDK2 from the verified signed A/B system slot, and at 1, 2, 4 and 8 harts with an SSH login each. Sv48 with per-section kernel permissions, ecall syscalls with the user-access window closed except across dispatch, PLIC, PCI through ECAM with base addresses assigned by the kernel because SBI firmware assigns none, both virtio transports, xaiFS at /models, a Goldfish clock, IPv6, the hosted ISO C99 library, xapt, and secondaries woken by SBI IPI. Run with `platform/qemu/run-qemu-riscv64.sh`; the disk layout and `virtio-mmio.force-legacy=false` both matter, and the UEFI path needs `acpi=off`. virtio still polls rather than taking interrupts. Not qualified on hardware: one emulated board is the whole evidence, against three gates where the other two have roughly seventy. QEMU 11.1.1 (macOS/arm64). |
| Apple Virtualization.framework ARM64 | Development target, not a qualification profile and not gated. Boots to a login: virtio-PCI console, xaibootFS on a durable volume, DHCP IPv4, SLAAC IPv6 and SSH. No PL011, no linear framebuffer (`PixelBltOnly` GOP) and no GIC ITS, so every virtio queue runs polled. See [[Virtualization Framework|Virtualization-Framework]]. |
| VMware Fusion ARM64 | Qualified four-vCPU guest profile tested only on Fusion 26H1 (26.0.0): PCI-discovered E1000E DHCP, AHCI xaibootFS persistence/recovery, public-key SSH, SFTP, reboot, shutdown and repeat boot. VMXNET3, IPv6, outbound-client and physical qualification remain open. |

QEMU CPU-count gates cover 1 through 256 emulated CPUs and a focused 130-CPU
NUMA case. Hosted cpuset tests cover CPU IDs beyond 4,096. These checks prove
dynamic sizing and ABI behavior, not physical scaling or performance.

The x86_64 path starts MADT-discovered application processors. QEMU service parity with AArch64
is complete for the declared common core-OS scope.

## CPU feature foundations

- AArch64: scalar baseline, NEON context handling, experimental packed NEON
  interfaces, and an SVE2 QEMU arithmetic canary. EL0 SVE is enabled only when
  supported, and scheduler/interrupt gates preserve scalable Z/P/FFR state per
  task. A production SVE inference backend and physical qualification remain.
- RISC-V: rv64gc with the compressed extension, which the trap path has to
  account for -- resuming from a trap reads the faulting instruction's width
  from its low two bits rather than assuming four bytes, because the assembler
  encodes a bare `ebreak` as the 16-bit `c.ebreak`. No vector extension work.
- x86_64: CPUID/topology discovery, AVX2 packed-kernel interfaces, XSAVE state,
  and conservative FXSAVE fallback. AVX-512, VNNI, and AMX production backends
  remain incomplete.
- NUMA: runtime-sized node and CPU metadata exists. A two-node x86 QEMU gate
  parses SRAT/SLIT/HMAT, allocates from each firmware range, selects a preferred
  memory node from checked latency/bandwidth records, and reports deterministic
  local/remote accounting. Physical locality and bandwidth remain open.

Both architecture VMMs expose collision-safe kernel 2 MiB map/unmap operations
and validate translation across the full extent during boot. x86_64 additionally
validates a 1 GiB leaf and address-specific SMP TLB invalidation; AArch64
reports 1 GiB mappings as unsupported. Sparse model packages beyond 100 GiB are
covered in hosted tests. None of these results proves multi-terabyte physical
capacity or large-page performance.

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

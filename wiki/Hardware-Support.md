# Hardware Support

## Current virtual targets

| Target | Current status |
|---|---|
| QEMU AArch64 `virt` | Complete core-OS correctness target with UEFI, SMP, GICv3/ITS, VirtIO, SMMUv3 gates, filesystems, network, SSH/SFTP, and userspace. NVMe requires LPI delivery on every negotiated queue. |
| QEMU x86_64 `q35` | Common kernel/userspace service parity with AArch64, including ACPI/MADT AP startup, xAPIC, XSAVE/FXSAVE, PCI VirtIO, network, SSH/SFTP, storage, and userspace. NVMe requires APIC/MSI-X delivery on every negotiated queue. |
| QEMU RISC-V `virt` (rv64gc) | Boots the shared kernel to the first-run setup prompt on four harts, with 75 self-tests passing and no errors: Sv48 paging with per-section kernel permissions, SBI console and power, a full trap frame with ecall syscalls and user faults, PLIC interrupts, PCI enumerated through ECAM with base addresses assigned by the kernel because SBI firmware assigns none, two virtio-blk disks, the initial filesystem, IPv6, and fifteen user applications built by `scripts/build-riscv64-image.sh`. Not qualified on hardware: this is one emulated board and nothing else. `xapt` and the C99 libc are not built for it. Run on QEMU 11.1.1 (macOS/arm64). |
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

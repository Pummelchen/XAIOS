# Hardware Support

## Current virtual targets

| Target | Current status |
|---|---|
| QEMU AArch64 `virt` | Complete core-OS correctness target with UEFI, SMP, GICv3/ITS, VirtIO, SMMUv3 gates, filesystems, network, SSH/SFTP, and userspace. NVMe requires LPI delivery on every negotiated queue. |
| QEMU x86_64 `q35` | Common kernel/userspace service parity with AArch64, including ACPI/MADT AP startup, xAPIC, XSAVE/FXSAVE, PCI VirtIO, network, SSH/SFTP, storage, and userspace. NVMe requires APIC/MSI-X delivery on every negotiated queue. |
| QEMU RISC-V `virt` (rv64gc) | Boots to 100% on four harts with 87 self-tests and no errors, a login prompt and sshd answering; also boots from its own disk through EDK2 from the verified signed A/B system slot, and at 1, 2, 4 and 8 harts with an SSH login each. Sv48 or Sv39 chosen at run time, with per-section kernel permissions, ecall syscalls with the user-access window closed except across dispatch, PLIC on the default board and an APLIC/IMSIC pair on `virt,aia=aplic-imsic`, PCI through ECAM with base addresses assigned by the kernel because SBI firmware assigns none, both virtio transports, xaiFS at /models, a Goldfish clock, IPv6, the hosted ISO C99 library, xapt, and secondaries woken by SBI IPI. Run with `platform/qemu/run-qemu-riscv64.sh`; the disk layout and `virtio-mmio.force-legacy=false` both matter, and the UEFI path needs `acpi=off`. On the default board virtio takes its interrupt through the PLIC, and the interrupt ends the waiting process's sleep rather than being polled for; the frame is still drained by that process rather than in the handler, because handing one to the stack takes a lock a thread on the same hart may hold. On the AIA board the same kernel is delivered message-signalled interrupts instead, so NVMe reports `controller=aia-imsic` with an MSI-X vector on its queue (`make qemu-riscv64-aia-gate`). Not qualified on hardware: one emulated board is the whole evidence, and fifty-seven gate targets on one board are still one board. QEMU 11.1.1 (macOS/arm64). |
| Apple Virtualization.framework ARM64 | Development target, not a qualification profile. Its gates -- `vz-gate`, `vz-stress-gate`, `vz-bridged-gate`, `vz-framebuffer-gate` -- all need macOS on Apple Silicon and a signed harness, so none of them runs in CI. Boots to a login: virtio-PCI console, xaibootFS on a durable volume, DHCP IPv4, SLAAC IPv6 and SSH. No PL011 and no GIC ITS, so every virtio queue runs polled. Firmware leaves no linear framebuffer (`PixelBltOnly` GOP), so the kernel drives the virtio-GPU on the PCI bus to get one, and the resulting display is captured from the host through ScreenCaptureKit. See [[Virtualization Framework\|Virtualization-Framework]]. |
| VMware Fusion ARM64 | Qualified four-vCPU guest profile tested only on Fusion 26H1 (26.0.0): PCI-discovered E1000E DHCP, AHCI xaibootFS persistence/recovery, public-key SSH, SFTP, reboot, shutdown and repeat boot; the smoke gate requires as many CPUs online as the VMX asks for (`F-01`). VMXNET3 carries traffic end to end (`F-02`) and a bridged guest configures and answers on a globally routable IPv6 address (`F-03`), both gated, but the qualified profile stays on E1000E by choice. Live DNSSEC interoperability, outbound-client coverage inside a gate, and physical qualification remain open. |

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
- NUMA: runtime-sized node and CPU metadata exists. `make qemu-x86_64-numa-gate`
  boots two machines. The two-node one parses SRAT, SLIT and HMAT together,
  allocates from each firmware range, selects a preferred memory node from
  checked latency/bandwidth records, reports deterministic local/remote
  accounting in bytes, leases cores with the requesting node preferred and
  spills to the node the SLIT calls nearest, and steals work only from a
  victim on the stealer's own node. The four-node one has no HMAT at all, so
  the SLIT stands on its own, and its distances are arranged so that the
  fallback order seen from node 3 is the reverse of the node-id order -- the
  only arrangement here that can tell a distance-ordered walk from a walk that
  merely counts upwards. Physical locality and bandwidth remain open, and
  there is no AArch64 or RISC-V equivalent: this is a firmware-table gate.

All three architecture VMMs expose collision-safe kernel 2 MiB map/unmap
operations and validate translation across the full extent during boot. x86_64
and RISC-V additionally validate a 1 GiB leaf; AArch64 reports 1 GiB mappings
as unsupported. RISC-V validates both of its paging modes, which differ in
where a gigantic leaf sits: Sv39 holds it in the root table the hardware walks
and Sv48 one level below, so the Sv48 boots alone would not have covered it.
Each RISC-V leaf is also dereferenced through an alias of memory the kernel
owns, so the hardware's own walker is a witness and not only the kernel's.
Separately, RISC-V maps the kernel *image* in 4 KiB pages, so that a leaf never
spans two sections with different permissions.

All three architectures now withdraw a mapping from every online CPU's TLB,
and each validates it. x86_64 validates address-specific SMP TLB invalidation
through its own inter-processor interrupt; AArch64 relies on hardware-broadcast
TLBI. RISC-V had neither and no remote fence of any kind -- its `sfence.vma`
is hart-local by definition, so a kernel mapping withdrawn on one hart stayed
live in every other hart's TLB. It now issues an SBI RFENCE
(REMOTE_SFENCE_VMA) from its unmap and remap paths, with the hart mask built
from firmware's hart ids rather than from the kernel's CPU numbers, because
those are not the same sequence on every boot.

What the RISC-V self-test measures is stronger than a call count: a *remote*
hart is made to read the address, the mapping is then withdrawn, and that hart
must fault. In the same boot the withdrawal is first performed with the remote
fence suppressed, and the boot log records whether the remote hart was still
reading through the cleared entry at that point -- which is what makes the
subsequent fault attributable to the fence rather than to the machine. On
QEMU (rv64/Sv48 and thead-c906/Sv39, four harts) all three remote harts are
observed stale before the fence and faulting after it. This has not been run
on RISC-V silicon.

Sparse model packages beyond 100 GiB are covered in hosted tests. None of these
results proves multi-terabyte physical capacity or large-page performance.

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

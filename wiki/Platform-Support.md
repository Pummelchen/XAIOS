# Platform Support

Last updated: 2026-08-10.

The authoritative status for the 20 ARM, Intel and portable-engine
recommendations is
[`docs/PLATFORM-SUPPORT.json`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-SUPPORT.json).
This page summarizes that machine-checked source. QEMU results are correctness
and ABI evidence only.

## Recommendation Status

| # | Recommendation | Status |
|---:|---|---|
| 1 | Restore green CI | `ci-tested` |
| 2 | ARM SMP worker dispatch | `qemu-tested` |
| 3 | ARM FP and NEON context preservation | `qemu-tested` |
| 4 | Native macOS and Linux engine executable | `hosted-tested` |
| 5 | Physical Apple NEON evidence | `physical-gate` |
| 6 | Generic ARM server scope | `scope-defined` |
| 7 | SVE and SVE2 | `interface-only` |
| 8 | x86 AP startup and worker participation | `qemu-tested` |
| 9 | x86 ring 3, syscalls and user threads | `qemu-tested` |
| 10 | x86 PCI storage, network, NVMe and interrupts | `qemu-tested` |
| 11 | x86 full platform services | `qemu-tested` |
| 12 | MADT, SRAT, SLIT and HMAT | `parser-tested` |
| 13 | XSAVE and XRSTOR state management | `qemu-tested` |
| 14 | Physical Intel and Xeon evidence | `physical-gate` |
| 15 | Inference engine service ownership boundary | `hosted-tested` |
| 16 | Immutable 64-bit model mappings | `qemu-tested` |
| 17 | Async direct model range I/O | `hosted-tested` |
| 18 | Lifecycle-safe sessions | `interface-tested` |
| 19 | Documentation reconciliation | `synchronized` |
| 20 | GitHub milestone reconciliation | `synchronized` |

The exact evidence for each row remains in the authoritative JSON source.

## Implemented QEMU And Hosted Foundations

- AArch64 starts runtime-discovered CPUs, dispatches joinable workers, and
  preserves q0-q31, FPCR and FPSR across live timer interrupts.
- VMware Fusion 25.0.1 on Apple Silicon boots the ARM64 package through a GRUB
  UEFI compatibility stage and reaches `/init`; this limited gate has no VMware
  NIC/persistent-disk driver or multi-vCPU platform discovery.
- The native macOS/Linux engine executable exposes probe/inspect and a
  fail-closed serve command through caller-owned model/session registries.
- x86 starts all MADT-discovered application processors through an OS-owned
  trampoline and dispatches deterministic IPI work without a project-level CPU
  count limit.
- x86 executes the complete shared ELF/syscall/process/thread ABI with per-CPU
  page-table roots and AP worker threads. Runtime-sized XSAVE/XRSTOR or
  FXSAVE/FXRSTOR preserves FP/SIMD state across live interrupts. The common
  filesystems, security, AI Cell, telemetry, control and SSH/SFTP services run
  over PCI VirtIO block/network, and emulated NVMe passes identify/write/flush/read.
- The x86 platform matrix passes 1, 4, 8, 128 and 256 vCPUs including x2APIC;
  every required CPU-family tier and the Debian 13 interoperability suite pass.
- Production model registration retains immutable readers or no-copy 64-bit
  mappings. Direct aligned range I/O and lifecycle-safe 64-bit session metadata
  pass hosted tests. The copied model arena remains fixture-only.
- Aggregate CI pins upstream QEMU commit
  `6ce361b02c825b4a12a9684c47342859ee967cb2` for the translated SMMUv3 gate,
  verifies its test-only `iommu-testdev`, and fails rather than skipping when
  that device is unavailable.

## Deliberate Open Boundaries

- QEMU service parity with AArch64 is complete. Physical Intel firmware,
  storage, NIC, NUMA, ISA-state, security and performance validation remains
  open and cannot be inferred from emulation.
- SVE/SVE2, Metal, AVX-512/VNNI and AMX are capability/roadmap entries, not
  executing production backends.
- Typed model state, ragged batching, exact speculation, tokenizer parity,
  logits parity and real-model decode are not implemented.
- Physical Apple, Intel Desktop and Xeon validation cannot be established by
  QEMU and remains a separate required gate.
- VMware Fusion is virtual ARM64 correctness evidence only. See
  [[VMware Fusion|VMware-Fusion]] for the exact scope and commands.

The repository tracker and hardware-readiness document retain these open items;
an interface, parser, or QEMU canary is not a production-support claim.

The completed QEMU x86 service-parity work is tracked in
[issue #18](https://github.com/Pummelchen/XAIOS/issues/18). Physical Apple, ARM,
Intel and Xeon validation remains tracked separately in
[issue #19](https://github.com/Pummelchen/XAIOS/issues/19).

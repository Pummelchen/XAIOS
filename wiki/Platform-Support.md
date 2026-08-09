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
| 9 | x86 ring 3, syscalls and user threads | `partial` |
| 10 | x86 PCI storage, network, NVMe and interrupts | `partial` |
| 11 | x86 full platform services | `pending` |
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
- x86 validates GDT/TSS ring-3 syscall entry by executing a real `/bin/hello`
  ELF built from the shared userspace runtime, plus common security and scalar
  kernel self-tests. It also validates runtime-sized XSAVE/XRSTOR with
  FXSAVE/FXRSTOR fallback, ACPI MADT/SRAT/SLIT/HMAT parsing, modern VirtIO block
  DMA, MSI-X completion, and VirtIO network TX.
- Production model registration retains immutable readers or no-copy 64-bit
  mappings. Direct aligned range I/O and lifecycle-safe 64-bit session metadata
  pass hosted tests. The copied model arena remains fixture-only.
- Aggregate CI pins upstream QEMU commit
  `6ce361b02c825b4a12a9684c47342859ee967cb2` for the translated SMMUv3 gate,
  verifies its test-only `iommu-testdev`, and fails rather than skipping when
  that device is unavailable.

## Deliberate Open Boundaries

- Full ARM-service parity on x86 remains open: the complete EL0 process/thread
  ABI, receive networking, SSH/control, mounted filesystems, x86 NVMe operation,
  security, AI Cell and telemetry are not linked as one x86 service image.
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

The remaining implementation blocker for full x86 service parity is tracked in
[issue #18](https://github.com/Pummelchen/XAIOS/issues/18). Physical Apple, ARM,
Intel and Xeon validation is tracked separately in
[issue #19](https://github.com/Pummelchen/XAIOS/issues/19).

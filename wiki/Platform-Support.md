# Platform Support

Last updated: 2026-08-04.

The authoritative status for the 20 ARM, Intel and portable-engine
recommendations is
[`docs/PLATFORM-SUPPORT.json`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-SUPPORT.json).
This page summarizes that machine-checked source. QEMU results are correctness
and ABI evidence only.

## Implemented QEMU And Hosted Foundations

- AArch64 starts runtime-discovered CPUs, dispatches joinable workers, and
  preserves q0-q31, FPCR and FPSR across live timer interrupts.
- The native macOS/Linux engine executable exposes probe/inspect and a
  fail-closed serve command through caller-owned model/session registries.
- x86 starts all MADT-discovered application processors through an OS-owned
  trampoline and dispatches deterministic IPI work without a project-level CPU
  count limit.
- x86 validates GDT/TSS ring-3 syscall entry, runtime-sized XSAVE/XRSTOR with
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

The repository tracker and hardware-readiness document retain these open items;
an interface, parser, or QEMU canary is not a production-support claim.

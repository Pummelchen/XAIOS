# Hardware Readiness Gate

XAIOS is not ready for physical Apple, Intel Desktop, or Xeon deployment. QEMU
gates establish architecture and ABI correctness only. The current 20-item
platform status is authoritative in `docs/PLATFORM-SUPPORT.json`.

No current repository artifact proves physical-hardware model performance or
real-model parity. Model status is checked against `docs/MODEL-SUPPORT.json`:

| Model or path | Status | Hardware meaning |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | QEMU correctness and ABI evidence only. |
| xaios.model.v2 tooling | Interface only | Package structure is tested; no model executes from it. |
| Qwen 3.6 27B | Interface only | No physical Qwen logits/token parity artifact. |
| Kimi K3 text | Interface only | No physical K3 text execution artifact. |
| Kimi K3 multimodal | Roadmap only | No multimodal implementation or artifact. |
| DeepSeek V4 Flash 0731 | Roadmap only | No verified source revision, implementation or physical execution artifact. |
| GLM 5.2 | Roadmap only | No importer, adapter, parity result or physical execution artifact. |

The benchmark evidence required for future hardware claims is defined in
`docs/BENCHMARK-CONTRACT.md`.

## Current Gates

The milestone 33 QEMU hardware-readiness gate is:

- `make qemu-readiness-gate`

That command runs the full local QEMU matrix and then validates the generated
artifacts. It writes:

- `build/qemu-benchmark-report.json`
- `build/qemu-preview-manifest.json`
- `build/qemu-cpu-matrix-report.json`
- `build/qemu-readiness-report.json`

The readiness report schema is `xaios.qemu.hardware_readiness_gate.v1`.
The frozen release-candidate contract schema is
`xaios.qemu.release_candidate_contract.v1` and lives at
`contracts/qemu-rc-v1.json`.

The benchmark harness is a correctness benchmark only. It does not authorize
performance claims against Linux, BSD, or hardware targets.

The milestone 42 QEMU full OS release-candidate gate is:

- `make qemu-full-os-rc`

That command runs `make qemu-readiness-gate`, validates the generated reports,
checks the source syscall/capability ABI against `contracts/qemu-rc-v1.json`,
and writes:

- `build/qemu-full-os-rc-report.json`

The full OS RC report schema is
`xaios.qemu.full_os_release_candidate.v1`. The AArch64 report and x86_64
bring-up report remain separate because the x86 image does not yet host all
ARM platform services.

The post-51 QEMU-only hardening gate is:

- `make qemu-post51-gate`

That command runs milestones 52-59 for regression coverage, fault injection,
ABI contract checks, deterministic boot loops, userspace control-plane checks,
network stack checks, CPU-only AI runtime simulator checks, and developer UX
checks. It writes `build/qemu-post51-gate-report.json` and remains QEMU
correctness evidence only.

## Frozen QEMU Contracts

Before moving to Intel Desktop bring-up, these contracts must remain stable:

- AArch64 UEFI loader can load and transfer control to the kernel.
- Kernel parses the UEFI memory map and initializes PMM/VMM.
- Controlled page, read-only write, and NX execute faults are reported through
  the exception path.
- Real EL0 `/init` ELF is loaded from the VirtIO-backed read-only filesystem.
- Syscalls enforce process capabilities and user pointer validation.
- Syscall ABI, telemetry schema, read-only initramfs format, persistence record
  format, and service descriptor format are frozen in
  `contracts/qemu-rc-v1.json`.
- Security policy enforces capabilities, filesystem boundaries, workspace and
  sandbox ownership, rollback authorization, credential rejection, and
  signed-update format validation.
- Persistence metadata can snapshot and roll back boot, service, workspace, and
  sandbox records.
- VirtIO block and VirtIO net self-tests pass.
- AI Cell resource enforcement, fixture model arena, immutable production
  mapping registry, private KV/cache, source index, Git workspace, sandbox,
  CPU-AI runtime, and low-latency network smoke paths all emit telemetry.
- Hot AI core telemetry reports zero migration and zero involuntary context
  switches in the QEMU gate.
- CPU matrix tiers validate the mandatory ARM64 TCG correctness path and TCG
  boot probes for `cortex-a53`, `cortex-a72`, `cortex-a76`, `cortex-a710`,
  `neoverse-n1`, `neoverse-n2`, `neoverse-v1`, and `max`, plus x86_64 early
  boot profiles for Intel, Xeon, Atom server-edge, and AMD CPU models.
- The macOS host/HVF tier is an optional local acceleration check. It runs only
  with `XAIOS_QEMU_RUN_OPTIONAL_HVF=1`, is reported as skipped otherwise, and
  never replaces or blocks the TCG correctness contract.

## Remaining Physical And Platform Gates

The QEMU release-candidate gate intentionally does not claim:

- performance wins against Linux or BSD;
- measured x86_64 hardware performance evidence beyond the milestone 43-51
  QEMU correctness gate;
- full x86 ARM-parity services, including the complete userspace/thread ABI,
  RX networking and SSH, mounted filesystems, x86 NVMe operation, security,
  AI Cell and telemetry integration; equivalently, the full ARM
  userspace/service stack is not yet present in the x86 image;
- production update signing and key management;
- a production mutable filesystem;
- production tokenizer/model runtimes beyond the QEMU CPU-only deterministic
  model format;
- network throughput benchmarking;
- multi-user security policy and remote administration hardening.

## Physical Hardware Entry Criteria

Intel Desktop work can begin only after:

- `make qemu-full-os-rc` passes locally.
- The QEMU full OS RC report exists at
  `build/qemu-full-os-rc-report.json`.
- The full OS RC report status is `pass`.
- The full OS RC report has `qemu_full_os_complete=true`.
- `make qemu-readiness-gate` passes locally.
- The QEMU preview manifest exists at `build/qemu-preview-manifest.json`.
- The QEMU benchmark report exists at `build/qemu-benchmark-report.json`.
- The QEMU CPU matrix report exists at `build/qemu-cpu-matrix-report.json`.
- The QEMU readiness report exists at `build/qemu-readiness-report.json`.
- The readiness report status is `pass`.
- The release-candidate contract exists at `contracts/qemu-rc-v1.json` and
  remains frozen.
- No QEMU benchmark result is represented as a hardware performance claim.
- The GitHub Wiki platform pages are updated for the current gate.

## Intel QEMU Deliverables

- UEFI x86_64 boot path: milestone 43 gate is `make qemu-x86_64-smoke`.
- Serial console and early exception reporting: milestone 44 gate is
  `make qemu-x86_64-smoke`.
- PMM/VMM initialization from the x86_64 firmware memory map: milestones 45
  and 46 gate through `make qemu-x86_64-smoke`.
- Controlled exception delivery, a real local-APIC one-shot timer interrupt,
  OS-owned GDT/TSS, ring-3 syscall transition, runtime-sized XSAVE/XRSTOR, and
  MADT-driven AP startup with IPI worker dispatch pass. The x86 AP trampoline
  is reserved by UEFI and owned by the kernel; these paths pass
  `make qemu-x86_64-smoke`.
- PCI discovery includes MSI, MSI-X and modern VirtIO capabilities. The same
  gate maps the high MMIO aperture, performs a modern VirtIO boot-sector DMA
  read, receives a queue MSI-X interrupt, and completes VirtIO network TX.
  Full RX/network-stack integration and x86 NVMe operation remain incomplete.
- P-core/E-core placement policy metadata: milestone 49 gate is
  `make intel-desktop-gate`.
- x86_64 links and executes a portable common-runtime subset, while its emitted
  OS contract explicitly reports EL0, networking, AI Cell, security and
  telemetry parity as unavailable. Milestone 50 remains incomplete rather than
  treating linked shared code as full platform support. The full ARM userspace/service stack is not yet linked into the x86 image.
- Hosted tests validate MADT/SRAT/SLIT/HMAT checksums, malformed data, dynamic
  CPU counts and xAPIC/x2APIC identifiers; the default QEMU machine exposes
  MADT but does not expose SRAT, SLIT or HMAT.
- The milestone 51 Intel Desktop hardware assessment reports `blocked` until
  the remaining platform services and qualifying physical evidence exist.
- Initial tuned Linux/BSD baseline plan for later measured comparisons remains
  required before hardware performance claims.

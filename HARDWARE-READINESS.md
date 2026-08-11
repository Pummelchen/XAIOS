# Hardware readiness contract

Hardware progress is tracked only in
[`wiki/Project-Tracker.md`](./wiki/Project-Tracker.md). This document defines
the evidence boundary retained by release gates; it is not a second tracker.

`make qemu-readiness-gate` emits
`build/qemu-readiness-report.json` using
`xaios.qemu.hardware_readiness_gate.v1`. The frozen contract is
`xaios.qemu.release_candidate_contract.v1` in `contracts/qemu-rc-v1.json`.
Its benchmark is a correctness benchmark only.

`make qemu-full-os-rc` emits `build/qemu-full-os-rc-report.json` using
`xaios.qemu.full_os_release_candidate.v1`. It is a QEMU correctness gate, not
physical hardware qualification.

`make qemu-post51-gate` retains regression, fault, ABI, boot-loop, userspace,
network, CPU fixture, and developer-UX coverage.

Current emulated evidence includes the x86 AP trampoline, a real local-APIC
one-shot timer interrupt, MSI, MSI-X and modern VirtIO capabilities, and
runtime-sized XSAVE/XRSTOR state. None of this establishes physical Apple,
ARM-server, Intel-desktop, or Xeon performance, firmware compatibility, NIC,
NVMe durability, NUMA locality, thermal behavior, or production security.

Physical claims require named machines, immutable raw artifacts, repeated
measurements, and the full `docs/BENCHMARK-CONTRACT.md` contract.

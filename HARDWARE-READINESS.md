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

## Physical qualification is deferred, by decision

This is stated rather than left to be inferred, because "not yet" and "not being
worked on" are different claims and a reader should not have to guess which one
this is.

**It is a deferral, not a queue.** There is no physical hardware in this
project -- on any architecture -- and no physical result is being waited on to
complete the current work. Every result in this tree comes from QEMU or from a
hypervisor, and that is the intended state of the project at this point rather
than a gap something is closing. The engineering that a physical machine would
exercise is finished as far as it can be here; what is missing is the machine.

**What the deferral does not do.** It does not weaken a gate. The emulated gates
are held to the same standard they were, `physical_qualification=false` stays
retained in the reports that carry it, and no emulated result is promoted by
being the only one available. It also does not license a physical claim: the
vocabulary is unchanged, so a QEMU result is *correctness and ABI only*, an
Apple Virtualization.framework result is *not qualification evidence*, and the
items that can only be settled by hardware keep the status `NEEDS HARDWARE`
and stay off the active work list instead of reading as further behind than they
are.

**The three targets, and what each one's evidence actually is.**

| Target | Emulated evidence | Physical evidence |
|---|---|---|
| AArch64 | QEMU ARM64, and VMware Fusion and Virtualization.framework on Apple Silicon | none |
| x86-64 | QEMU x86_64, on an ARM host through QEMU's interpreter | none -- it has never executed on an Intel or AMD processor |
| RISC-V (rv64gc) | one emulated board, QEMU's `virt` | none, and no RISC-V machine or hypervisor is in the test set at all, so one board is this port's entire evidence |

**What closes it, in order.** A named machine per target -- the selections
`OD-001`, `OD-002` and `OD-003` in the project tracker, all still `NOT STARTED`
and all blocked on nothing but the choice -- passing the firmware, device,
durability, security, ISA-state, NUMA, soak and benchmark contracts above. That
is delivery order 1b, and it is the only entry in that table that no work on
this repository can advance.

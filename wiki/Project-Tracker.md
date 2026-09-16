# Project Tracker

Last reviewed: 2026-09-17.

This is the only human-maintained XAIOS project tracker. Roadmaps, milestones,
phase plans, open decisions and risks are consolidated here, and the Wiki keeps
no other planning page. It records what each item's state is and what would
change it -- not how the work was done. That reasoning belongs in the commit
that did it and in the comments beside the code.

**A numbering collision, and what was done about it.** Item numbers are assigned
on whichever branch the work happens on, and two branches allocated the same
range at the same time without seeing each other: the RISC-V and CI work on
`main` and the WebTransport C99 port each took a block of numbers for entirely
different things. The rule on this page is that a number is never reused and
never renumbered, and that rule cannot hold for both sides, so the published
branch won and the port's rows were renumbered after it. The port's commits were
already pushed when this was found and still cite the old numbers, which is why
this paragraph exists rather than a silent edit; its branch has since been
merged and deleted. Anything assigned from now on starts at `B-84`.

**Closed rows are removed, not kept.** At the maintainer's direction on
2026-09-17 every resolved row was deleted, including the tables that held them.
The identifiers are therefore holes, and a number that a gate, a comment or a
release note cites is a pointer into `CHANGELOG.md`, the commit history and the
[closed-identifier index](#closed-identifiers) at the end of this page. The reasoning behind each fix was always in the
commit that made it and in the comments beside the code; that is now the only
place it lives.

## Where the tree stands

The ten aggregate targets -- `qemu-core-os-rc`, `qemu-full-os-rc`,
`qemu-developer-ux`, `qemu-operations-closure`, `qemu-network-adversarial-gate`,
`qemu-readiness-gate`, `qemu-post51-gate`, `qemu-qualification-readiness`,
`qemu-100-gate` and `qemu-release` -- were re-run serially on 2026-09-12. Eight
passed. `qemu-readiness-gate` and `qemu-full-os-rc` both failed on the same leg,
`qemu-fault-matrix`, and that failure was this machine's accumulated durable
volume rather than the guest: the three controlled-fault scenarios never ran,
because the boot died first in an unrelated self-test. It is fixed, and
`qemu-fault-matrix` passes in isolation on the same commit that
failed. **Both have since been asked again, serially, on a second Mac at
`0fba4de`, and both pass:** `qemu-readiness-gate` reports `matrix_exit_code=0`
with an empty `failures` list, and `qemu-full-os-rc` reports `status=pass`,
`milestone=42`, `qemu_full_os_complete=true`, `release_candidate=qemu-rc-1` and
thirteen validated subsystems. That answers the question the paragraph above
left open and answers nothing wider: the other eight aggregates were not re-run
in the same sitting, and these two are both QEMU gates, so the two that include
Fusion and VZ are exactly as current as they were.

They are run serially deliberately: these assert on boot markers and timings,
and this machine cut a `qemu-smoke` boot short at load average 30 and passed it
at load 9 with no change in between. The consolidated report deliberately
retains `physical_qualification=false`.

What *is* current, against `7df4fc8`, the commit build 6 was cut from:
`make release-check` passes, which requires `docs-check`, a
`check-release-package` run against the published note, and a `local-gates`
record naming that exact commit. It now also requires that CI passed on that
commit: it did not when build 6 was cut, and it could not, because the check
did not exist and the sentence it printed was about this Mac's four
environments only. The runner is a fifth and it is the one that finds what none
of the four can -- every defect in the nine red days was invisible here and
immediate there -- so `check-ci-status` asks, and says INCONCLUSIVE rather than
passing when it cannot get an answer. That record covers six gates including both
hypervisors -- `vmware-fusion-smoke`, `vmware-fusion-framebuffer-gate`,
`vz-gate`, `hypervisor-memory-matrix`, `release-image-gate` and
`vz-stress-gate`. `boot-media-gate` (72 checks) and `vm-package-gate` (five
kits) also pass on the released files.

That is emulated evidence and nothing more. **No result on this page is
physical-hardware evidence, and no released build has been booted on physical
hardware.**

### What is open

**No open defects.** Every defect this tracker recorded has been closed, and
closed rows are no longer listed; see the note at the top of this page for where
their identifiers and their accounts live now.

Two things are open that are not defects:

- **No physical hardware, on any architecture.** Every result on this page comes
  from an emulator or a hypervisor. `D1` is the USB route and needs a stick in a
  machine; RISC-V has never run on anything but QEMU's `virt` board; and
  `serve-netboot.sh` has never served a real machine on any architecture.
- **Two external decisions block their own work** and nothing here moves them:
  `OD-004` (production trust-root custody) and `OD-008` (pinning an official
  DeepSeek source, whose exact release label is unresolved).

## Current tasks

**The WebTransport C99 port is paused, with its TLS 1.3 client handshake written,
tested and merged on `main`.** It completes a QUIC handshake against a server
flight built by an independent Python implementation, and 1487 host checks pin it
against RFC 8446, 8448, 9001, 7301 and 7748 in CI and under AddressSanitizer and
UndefinedBehaviorSanitizer. The tasks below are what is left of the port, in the
order they unblock each other. They are numbered from `B-84` because that is
where the tracker's sequence had reached; they are work not yet done rather than
defects, and the numbering rule on this page does not care which it is.

| # | Task | Status | Exit criterion |
|---|---|---|---|
| `B-84` | Nothing on the target drives the handshake from a socket | `NOT STARTED` | A guest opens a datagram socket, sends a real QUIC Initial, receives a ServerHello and completes a handshake. The module is exercised only from the host today, and the only on-target evidence for the syscall under it is `netsocktest` and `make qemu-datagram-ephemeral-port-gate`. **Exit gate:** `make qemu-quic-handshake-gate` boots a guest that completes a handshake and says so on the console. |
| `B-85` | QUIC transport parameters are carried as opaque bytes | `NOT STARTED` | The client's own parameters are encoded and the server's are parsed and checked against RFC 9000's rules. Today `userspace/wt/` requires only that the extension is present, so no flow-control limit, idle timeout or connection ID the peer set is actually known -- and an unchecked parameter is one a peer can make unreasonable. |
| `B-86` | There is no QUIC connection runtime | `NOT STARTED` | Packet number spaces, CRYPTO stream reassembly, ACK and loss recovery, connection IDs, Retry and Version Negotiation. The TLS module is handed messages that have already been reassembled and in order; nothing does the reassembling, so nothing yet turns the handshake into a connection. |
| `B-87` | 0-RTT is not implemented, and neither is what it needs | `NOT STARTED` | Early data: the `c e traffic` and binder branches of the key schedule, a session-ticket store for the PSK they come from, and an early-data encryption level. The level enum deliberately has no member for it, because a member that is always unavailable is worse than an absence. |
| `B-88` | A HelloRetryRequest is refused by name rather than handled | `NOT STARTED` | A server that wants a different group can be talked to. This means rewriting the transcript with the synthetic `message_hash` (RFC 8446 section 4.4.1), sending a second ClientHello and refusing a second retry. Refusing by name is honest and is a server this client cannot reach. |
| `B-89` | A CertificateRequest is answered with an empty Certificate and no CertificateVerify | `NOT STARTED` | Client certificates, if XAIOS ever has a use for them. RFC 8446 section 4.4.2 requires the empty answer a client with no certificate sends, which is what is implemented and is conformant. |
| `B-91` | The module has never been built or booted for RISC-V | `IN PROGRESS` | **The premise originally written into this row was wrong and is corrected in place.** There is no missing RISC-V cross-compiler: `compile-check` has always compiled `kernel/arch/riscv64/` with `clang --target=riscv64-unknown-elf`, and clang and lld target rv64. What was missing was the **hosted RISC-V libc sysroot**, because `scripts/build-libc.sh` defaulted `XAIOS_LIBC_ARCHES` to `aarch64 x86_64` while every kernel leg of `compile-check` covered three architectures -- so the tree built the hosted library for two of the three machines it ships on, and the userspace legs had no riscv64 sysroot to point at. **Half of this is now closed, and the two halves had to move together:** the libc default names all three architectures, and `compile-check` gained a riscv64 userspace leg beside the aarch64 and x86_64 ones. All eight `userspace/wt/src/*.c` now compile to RISC-V objects on every run -- `ELF 64-bit LSB relocatable, UCB RISC-V, RVC, double-float ABI`, 56 objects in the leg -- so a regression in this module for RISC-V is a build failure rather than a discovery. **Still open:** it has never *run* there. **To close:** a guest that completes a handshake, which is `B-84`. |
| `B-129` | RISC-V had no tick, x86-64's tick applied nothing, and neither port has a task to preempt | `IN PROGRESS` | **The gap is real, and reading x86-64 for the same question found its sibling.** On RISC-V `scheduler_tick` is called from the AArch64 and x86-64 timer handlers and from nothing under `kernel/arch/riscv64/`: the timer branch rearms the comparator and returns, so an EL0 process there runs until it yields or exits, which `wiki/Current-Limitations.md` records. On x86-64 the tick exists but cannot switch anything: `g_irq_frame` has exactly two references in the tree -- its declaration and one `scheduler_tick(&g_irq_frame, 0)` -- so the scheduler is handed a context frame nobody filled (the preempted task's saved context becomes zeros) and the frame it hands back is never applied, because the vector-32 branch returns 0 and resumes the interrupted instruction. **AArch64 is the one that works, and it is the design to follow:** its IRQ handler takes `xaios_context_frame_t *` directly, so its trap frame *is* the scheduler's frame. **Exit criterion:** each architecture fills the scheduler's frame from its own trap frame, calls the tick from its timer interrupt unless that CPU carries the network tick, and writes the returned frame back so the trap return resumes whichever task the scheduler chose; a self-test on each architecture shows a spinning EL0 process being preempted rather than running until it yields; and the riscv64 idle loop's `timer_mask_local()` workaround is removed or explained. **Landed so far:** the RISC-V timer interrupt now ticks the scheduler. Its trap frame is mapped to `xaios_context_frame_t` in both directions -- the 31 general-purpose registers the stub saves are exactly `regs[31]` in that order, `sepc`/`sstatus` are the program counter and processor state, and the stack follows one rule: `regs[1]` is the stack a trap saved, while a task that has never run (every register zero, `sp_el0` set by `user.c`) resumes on `sp_el0`. The mapping has its own round-trip self-test, which the RISC-V smoke requires by name (`sched-tick: riscv64 trap-frame mapping self-test passed`); `scheduler_self_test` now also asserts that the frame it passes comes back as the chosen task's, which is the invariant AArch64's working path rests on; and the two ports that cannot yet do this say so in their own self-tests rather than passing -- x86-64 names the unfilled `g_irq_frame`, and AArch64 reports that it has nothing to map because its IRQ handler takes the scheduler's frame itself. **Measured on the machine, and it changed what this row is about.** The tick is instrumented to count what it actually does -- `sstatus.SPP` says whether the trap came from user mode, and the scheduler's current task before and after says whether the frame it returns belongs to another one -- and a boot with the worker gate prints `sched-tick: riscv64 user-context tick pid=0 -> pid=0 ticks=854 user_ticks=1 switches=0`. **So the tick now arrives from EL0 and the scheduler has nothing to switch to, because no user process is ever registered with it.** `user_process_run`, the only path this kernel runs a process through, never calls `scheduler_register`, and the one function that does, `user_process_run_concurrent`, has no callers -- on any of the three architectures, which is why AArch64's path was only ever exercised by the scheduler's own self-test. The worker gate's three processes then run to completion one after another on the same user stack, which is the second half of the same measurement. **What that leaves for this row and for `B-132`:** the mechanism half is landed and tested here (and on x86-64 the tick that could not apply a switch was **removed rather than left half-working** -- it filled the scheduler's frame with nothing, saved zeros as the preempted task's context and moved `current` without moving the CPU, so the honest state was no tick at all; the port's `platform_scheduler_tick_self_test()` now says why by name, and a comment at the tick records the per-CPU continuation and floating-point slots a real switch needs). **Progress (round 3): the mechanism has a behavioural proof on RISC-V, and it is the first behavioural one in this tree.** The log of a boot is two switches and a count: `scheduler[cpu0]: switch 30001 -> 30000 ticks=2 switches=2`, then `switch 30000 -> 30001 ticks=3 switches=3`, then `sched-preempt: riscv64 kernel-context switch registered=1 ran=1 runs=1 switches=3` and `... preemption self-test passed`. **The ordering that makes it work is a design constraint the next piece must respect, and it was found by getting it wrong:** the first version made the new task runnable at registration, and a tick landed between that and the adoption of the caller's own context -- so the CPU left a context whose frame had never been saved and could never be resumed, and the boot died at program counter zero with the abandoned stack still in `sp`. `scheduler_register_kernel_task()` therefore leaves its task registered and *not* runnable, the caller adopts the context that will hand the CPU over, and only then is the task made runnable. **Progress (round 3): the mechanism has a behavioural proof on RISC-V.** `scheduler_register_kernel_task()` builds a frame that starts a task in kernel mode on a stack of its own, `scheduler_adopt_this_context()` registers the context that is running *now* so a tick can save it and hand the CPU over, and `platform_kernel_preemption_self_test()` uses both: the boot context blocks itself, the timer switches to a second kernel task on its own stack, that task makes the first runnable again and blocks itself, and the next tick brings the first back -- with runs and switches printed and asserted. The architecture helper that builds such a frame, `xaios_context_frame_kernel_entry()`, refuses by name where it cannot: AArch64's exception return keeps the CPU's `SP_EL1` rather than loading a kernel stack from the frame, and x86-64 does not tick the scheduler from a trap at all. **Progress (round 4): per-task floating-point state, asserted across a real switch.** The RISC-V trap stub now saves and restores `f0`-`f31` and `fcsr` with the rest of the context, the mapping carries them through the shared frame's SIMD area and `fpcr`, and the preemption self-test writes a value into `f0`, gives the CPU away, and requires *its own* value back after the other task has written a different one: `sched-preempt: riscv64 kernel-context switch registered=1 ran=1 runs=1 switches=3 fp_kept=1`. Two details are the port's rather than the mechanism's: the stub switches `sstatus.FS` on for its own duration (an `fsd` with the unit off is an illegal instruction taken inside the trap entry) while the frame keeps the interrupted `sstatus`, and the restore is skipped for a frame whose `FS` says the unit was off, because those values are not live. A kernel-entry frame now sets `FS = Initial` so the task it starts may use the unit at all. **Attempted, and blocked by a defect it found (round 5): a user process dispatched as a task.** The pieces were written -- a task entry that runs on a kernel stack of its own, binds the process and calls `xaios_enter_user`; a dispatcher that registers the process on this CPU, adopts the calling context as a task, then blocks and waits; and the scheduler re-establishing the per-CPU process binding on every switch. **The entry and the exit both worked and the hand-back did not:** a boot recorded `switch 20006 -> 6`, `/bin/hello` entering EL0 from the task entry, its exit status, and `user: scheduled task exited pid=6 exit_code=0`, then stopped -- no switch back and no dispatcher summary. **The cause is found, and it is a defect in the existing path rather than in the dispatcher.** RISC-V's user-exit return (`riscv64_return_from_user_exit`) leaves through `ret`, not `sret`, so the kernel continuation it returns into kept the `sstatus.SIE = 0` that the trap from user mode had set: **interrupts were off for the rest of that context's life**, and the context waiting for a tick to hand it the CPU back never got one. The same path also left the *user* stack pointer in `sscratch`, which the next trap entry reads as "this came from user mode" (`B-108`'s misread). Both are fixed in the exit path, and the boot gate now records and asserts the property on this port: `kernel: /bin/xaios-worker pid=3 returned to kernel exit_code=0 interrupts=1`. **This is why round 4's stall looked like a lost trap rather than a lost interrupt**, and why nothing had noticed before: the sequential path's kernel continuation is a few instructions from `timer_disable()`, so interrupts being off there changed nothing that a gate could see. **Landed (round 6): a user process is a scheduled task on RISC-V, and it hands the CPU back.** With the exit path fixed, the same dispatch runs end to end: `user: dispatcher waiting pid=6 runner=20006 cpu=0`, `scheduler[cpu0]: switch 20006 -> 6`, `/bin/hello` entering EL0 from a task entry on its own kernel stack, its exit, `user: scheduled task handed the CPU back pid=6 runner=20006`, `scheduler[cpu0]: switch 6 -> 20006`, and `user: scheduled dispatch pid=6 switches=2 exit_code=0 waited_ns=22584000` -- asserted, and required by the riscv64 smoke. The dispatcher adopts the calling context, blocks it and waits; the process owns a kernel stack allocated for it; and the scheduler now re-establishes the per-CPU process binding on every switch, so a preempted process's next syscall is checked against its own capabilities rather than the task it displaced. **The round-7 measurement is explained, and it was the test's design rather than the port (round 12).** The spinner ran 1.2 seconds in EL0 and the switch count stayed at 2 (`scheduler[cpu0]: switch 20006 -> 7` and back), which I first read as "EL0 is not preempted". **It is not: the tick had nothing to switch to.** `user_process_run_scheduled` blocks the dispatching context while it waits, and the spinner was the only runnable task, so `scheduler_tick`'s reschedule path picks it again, hits `next_pid == current_pid` and returns without a switch -- correctly. `switches=2` is exactly what a correct scheduler does when one task is runnable, and the three eliminations that followed (slices, user-entry enablement, sscratch routing) were each consistent with the port being fine, which is what made them all succeed. **The measurement needs a competitor, and the scheduler's own shape says which one.** `rq_pick_best` takes the highest priority and then the first entry in the run queue, and the expiry path re-adds the task that just lost the CPU, so two tasks at the *same* priority alternate only if the first pick is not the one that is already running: with the spinner HIGH and the runner NORMAL the pick always prefers the spinner and it is never switched away from; with the runner HIGH and the spinner NORMAL the runner is preferred, and after its own slice expires it is re-added and picked again, so the spinner starves. **Only one of the two designs can work, and the other is a dead end -- recorded here so it is not tried.** The competitor task blocks itself after its turn and *nothing re-arms it*: once it has run, the spinner is again the only runnable task, so it runs to completion and the count stops at about three. A competitor that has to be re-armed by the very process it is competing with is not a competitor. **The design that works is queue order, not priorities.** Both the process and the dispatching context stay `RUNNABLE` at the *same* priority, and the process is placed **ahead** of the dispatcher in the run queue. Then: the dispatcher is current and its slice expires, the expiry path re-adds it at the back, `rq_pick_best` takes the first entry -- the process -- so the CPU is handed over (switch one); the process's slice expires, it is re-added behind the dispatcher, and the pick takes the dispatcher (switch two); and the two alternate from there, which is exactly what a switch count above the dispatch and the hand-back measures. In code that is `scheduler_adopt_this_context(runner, NORMAL)`, `scheduler_set_runnable(process)`, then `scheduler_set_blocked(runner)` and `scheduler_set_runnable(runner)` to move the dispatcher behind the process -- both stay runnable, and only the order changes. The registration must still leave the process non-runnable until the dispatcher has been adopted, which is the ordering rule this work already established. The blocked-dispatcher run already in the log remains the negative control. **Landed (round 13):** the queue-order design above works, and the exit criterion's spinning-EL0 half is met on RISC-V. `/bin/spin` never yields and the boot gate measures the timer taking the CPU away from it more than once (`kernel: /bin/spin preempted pid=7 switches=86`), with the blocked-dispatcher run as the control (`kernel: /bin/spin blocked dispatcher pid=8 switches=2`, strictly fewer). Getting there found a defect the design description had not accounted for -- the tick reschedules a `RUNNING` current task, which the pick had already removed from the queue, so two runnable tasks lost each other after two ticks -- and `scheduler_tick` now re-queues the running task before choosing; the mechanism, the measurements and what `B-132` still owes are recorded in that row. The other two ports still name their own missing half in their self-tests rather than passing: x86-64 has no kernel-context trap frame and AArch64's exception return keeps `SP_EL1`, so this row stays open for those two. |
| `B-130` | The RISC-V board has no IOMMU path, although QEMU provides one | `IN PROGRESS` | `wiki/Current-Limitations.md` says this board has no IOMMU and that DMA is unmediated, and the riscv64 smoke *requires* that sentence as a marker. QEMU 11.1.1 attaches one: `-device riscv-iommu-pci`, the RISC-V IOMMU over PCI. **Exit criterion:** `kernel/arch/riscv64/` drives it -- capabilities, device directory table, command and fault queues, its page-table formats, invalidation -- the virtio DMA path translates through it, and a gate boots with the device attached and proves isolation the way the AArch64 SMMU gate does: an authorized stream translating, a device with no mapping refused rather than translated, and a stale mapping blocked. The smoke's no-IOMMU marker then becomes an assertion about the board it actually boots. **The contract is written down and no driver code exists yet (2026-09-16).** `docs/RISCV-IOMMU.md` records what QEMU 11.1.1 actually implements -- vendor `0x1b36` device `0x0014`, requestor id 8 with the device tree's `iommu-map` excluding it, `CAP`/`FCTL`/`DDTP`/queue registers, 1LVL device directory and 32/64-byte contexts, Sv39/48/57 tables bit-identical to the port's, the four command opcodes and the fault causes -- and the three findings that change the plan. **First, the device attaches to the PCI bus and to nothing else** in both QEMU variants, so the runner's `virtio-blk-device` root filesystem, models volume and persistent disks, which are all on `virtio-mmio-bus`, **cannot be mediated on this board at all**; the exit criterion's "the virtio DMA path translates through it" is reachable for the PCI transports and must be written that way. **Second, the failure mode is a machine with no DMA:** as soon as `DDTP` leaves Bare, every PCI function without a valid context stops, which on the riscv64 runner takes the entropy source (`entropy: source=device-rng`) and the PCI disks with it, so the identity context for every enumerated function lands in the same step that programs `DDTP`, with a bail-out to Bare and the honest marker if the capability read or the first command fails. **Third, fault evidence does not need interrupts:** faults are written to the queue however they are notified, and on the default board the PCI IOMMU has no usable MSI-X and no wire IRQ, so polling `FQH`/`FQT` is both the only option and the stronger evidence. The model is `kernel/arch/aarch64/smmu.c`, and none of its register or encoding detail may be copied -- only the PCI helpers, the MMIO fault-containment probe, `xaios_cpu_io_barrier()` (a copied `dsb sy` would be an AArch64 instruction) and the gate's shape are reusable. One latent mismatch must be fixed rather than preserved: `smmu_init` is declared with a `boot` parameter and called that way from `kmain`, and defined without one in `kernel/arch/riscv64/platform.c`. **Next:** milestone 1, a PCI probe that reads `CAP` and reports what it found, which is safe because `off=off` leaves the device in Bare and changes no DMA. **Milestone 1 is landed and measured (2026-09-16).** `kernel/arch/riscv64/platform.c` now looks for the device over PCI instead of asserting its absence: it finds `0x1b36:0x0014`, reads BAR0 and names it -- `riscv-iommu: found device=N base=0x400010000 (BAR0 not yet mapped; CAP read deferred to the milestone that maps it)` -- **and the `CAP` read needed the BAR mapped first:** QEMU places this 64-bit BAR above 4 GiB, this port identity-maps its device window far below that, and the read taken without a mapping produced `ERROR: controlled page fault reported`, `class=load-page-fault cause=13 stval=0x400010000` with `sepc` inside the probe. With `vmm_map_page(base, base, XAIOS_VMM_DEVICE)` in front of it the register answers: a guest booted with the device attached reports `riscv-iommu: found device=5 base=0x400010000 cap=0x78c2cf4f10 version=0x10 sv39=1 sv48=1 sv57=1 igs=0` -- version 1.0, every page-table format available, and **`IGS = 0`, MSI only**, which is why the gate must assert fault-queue evidence by polling on a board whose MSI-X is unusable; on a board without it the sentence is now the result of a look, preceded by the evidence -- `smmu: riscv64 pci inventory has no 0x1b36:0x0014 and the tree has no riscv,iommu node`. **Where the look happens is itself a finding:** the shared `smmu_init(boot)` runs before `pci_init()`, so a probe there searched an inventory that did not exist yet and reported that a QEMU command line *with* the device attached had none; the probe is in `smmu_self_test()`, which `kmain` calls after `pci_init()`. Nothing is programmed: QEMU leaves the device with its device directory table Off, so an unprogrammed IOMMU refuses PCI DMA, and milestone 2 must install the identity contexts in the same step that first programs `DDTP`. Also fixed here: the port's `smmu_init` was defined with no parameters while the shared header declares and `kmain` calls it with the boot info. **Verified both ways:** `make qemu-riscv64-smoke` passes with the new evidence line, and a guest booted with `-device riscv-iommu-pci` attached reports `riscv-iommu: found device=5 base=0x400010000 cap=0x78c2cf4f10 version=0x10 sv39=1 sv48=1 sv57=1 igs=0` and then **boots normally to the login prompt with SSH sessions**, which is the contract's prediction and not a coincidence: the runner's storage, entropy and network are all virtio-mmio, so a device reset with `DDTP` Off refuses PCI DMA without touching this machine's boot. That boot also fails the riscv64 smoke by design -- the smoke requires the no-IOMMU sentence -- which is the assertion becoming a statement about the board it boots, and the new gate is where the enabled branch is claimed.  **Landed (2026-09-17): milestones 2-5 and the gate.** `kernel/arch/riscv64/iommu.c` now programs the device: a 1LVL device directory of 64 extended contexts -- the format QEMU's `intremap` reset selects, which is also what fixes the 1LVL device-id width at six bits, one page -- 16-entry command and fault queues, an `IOFENCE.C` round trip and an `IODIR.INVAL_DDT`, with a pass-through context for every enumerated PCI function installed in the same step that leaves `Bare`. The ordering guarantee held: `riscv-iommu: queues and ddt enabled commands=2 contexts=7 fence=1 invalidate_ddt=1 faults=0`, and the machine still boots to the login prompt with SSH. It then builds Sv39 and Sv48 first-stage tables (one tree read at two depths: identity over the low RAM with 1 GiB leaves, the test IOVA through a full walk, every leaf R/W/U with software A/D), translates an `iommu-testdev`'s DMA under both -- `riscv-iommu: sv39 translated DMA result=0x0 target=0x12345678 iova=0x100000000 did=48` and the same under Sv48 -- and proves isolation: clearing the leaf and issuing `IOTINVAL.VMA` gives `result=0xdead0002 target=0x0` with `cause=15` (first-stage write fault), and the second `iommu-testdev`, deliberately left out of the directory, gives `cause=258` (`DDT_INVALID`) rather than a translation. `make qemu-riscv64-iommu-gate` boots exactly that board and requires both refusals in the fault total so a summary with no faults cannot pass, and `translated_riscv_iommu_isolation` moved into `contracts/qemu-rc-v1.json`, `tests/repository/check-core-os-status.py` and `tests/scripts/qemu-core-os-rc.py` with it. **One finding worth keeping:** a leaf PTE's physical address is the PPN field at bits 53:10, so `address & ~0xfff` puts the address where the page number belongs and the walk lands at `address >> 2`; the first version translated the test IOVA to `0x20177c000` for a target of `0x805df000`, and QEMU's `riscv_iommu_dma` trace showed it before any kernel log did. **The virtio half landed 2026-09-17.** `virtio_transport_setup_queue` now calls `riscv64_iommu_mediate_dma` for the descriptor, available and used rings before the device is told where they are, and the driver installs an Sv39 first-stage context whose table identity-maps three gigabytes with 1 GiB leaves -- identity because a driver allocates a device's buffers wherever physical memory is, and the point of the step is that the walk happens. Each ring address is then resolved back OUT of the table and only a resolution that returns the same page is claimed (`riscv-iommu: mediated dma stream_id=32 region=0x... pte_ok=1`, three times), and the entropy source's two self-test reads afterwards are DMA that could only have reached its rings through the walk. The gate asserts both. **What this row still owes:** isolation between mediated functions -- they share one identity-mapped table, so the walk happens without keeping them out of each other's memory -- a transport whose buffers map to different addresses rather than the same ones, and the same isolation proof on a second board. `virtio-mmio` remains impossible to mediate on this board and that is stated in `docs/RISCV-IOMMU.md` rather than implied. |
| `B-132` | A user process is not a scheduled task, so nothing on any port preempts it | `IN PROGRESS` | **Found by measuring `B-129` rather than by reading for it.** `user_process_run` (`kernel/user/user.c:936-971`) is the only path this kernel runs a process through, and it never registers the process with the scheduler; the single registration site in the tree, `user_process_run_concurrent` (`kernel/user/user.c:973-1023`), has no callers. The scheduler's current task is therefore process 0 -- the idle task -- for the whole of userspace, so the timer tick every port now has arrives, finds nothing to switch to and returns. Measured on RISC-V: `sched-tick: riscv64 user-context tick pid=0 -> pid=0 ticks=854 user_ticks=1 switches=0`, and the boot worker gate's three processes run to completion one after another on the same user stack (`user: entering EL0 /bin/xaios-worker pid=3`, then `pid=4`, then `pid=5`). **Exit criterion:** a running process is registered on the CPU running it and adopted as that CPU's current task (`scheduler_register_on_cpu` is static today, so the registration must be exported or the placement must stop going through `find_least_loaded_cpu`, which would put the slot on a CPU that is not running the task and defeat the tick's own lookup); each task owns its kernel context -- on x86-64 a per-task `user_resume_rsp`/`user_previous_rsp0` record and TSS `rsp0` (`kernel/arch/x86_64/early.c:228-230`, `:836-874`) and a per-task floating-point area (`:967-980`), on RISC-V a per-task kernel stack and the `sscratch` that names it (`kernel/arch/riscv64/entry.S:136-218`, `:300-340`); a trap taken in kernel mode is either refused by name or given a frame shape that can carry a switch, since x86-64's has no `RSP`/`SS` words for that origin; and the port then proves what `B-129` could not -- a spinning EL0 process is preempted, with today's tree as the negative control (`switches=0`). **The mask is the same work, not a separate one:** RISC-V's idle loop keeps `timer_mask_local()` around `xaios_thread_run_pending` because a user thread there runs nested inside the joiner's syscall with its continuation on that CPU's stack, so removing it before this row lands  **Landed (round 13): the EL0 preemption proof, with its control, on RISC-V.** `/bin/spin` is a process that never yields -- it loops in EL0 for a fixed wall-clock span, reading the clock once per burst so nearly all of it is spent executing with the timer as the only thing that can take the CPU away -- and the boot gate dispatches it twice. `user_process_run_scheduled` now takes the dispatcher's design as an argument and reports what the dispatch did (`as_task`, `dispatcher_blocked`, `switches`, `exit_code`), so a caller can assert on the measurement instead of re-deriving it, and `user_process_scheduled_dispatch_supported()` answers before a run whether this port can start a task in kernel mode at all. In the positive run the dispatching context stays `RUNNABLE` at the process's priority and is moved behind it with `scheduler_set_blocked(runner)` then `scheduler_set_runnable(runner)`, and the two alternate: `user: dispatcher waiting pid=7 runner=20007 cpu=0 blocked=0`, `kernel: /bin/spin preempted pid=7 switches=86 exit_code=0 as_task=1`, the boot asserting `switches >= 4` because two are the dispatch and the hand-back and nothing else in that window can add a third. The control is the same process over the same span with the dispatcher blocked -- `kernel: /bin/spin blocked dispatcher pid=8 switches=2 exit_code=0 as_task=1`, asserted strictly fewer -- and both markers are required by the riscv64 smoke. **The first attempt stalled, and the stall was a defect in the shared scheduler rather than in the design.** The positive run preempted the process exactly once and then never again, and the dispatcher timed out at `switches=2`: `rq_pick_best` removes the task it picks, the tick treats a `RUNNING` current task as needing a reschedule, and the outgoing task was not put back -- so after two ticks neither the process nor the dispatcher was in any run queue, `current_pid` became 0 on the next tick, and the abandoned runner kept executing on a frame the scheduler had stopped saving until its deadline. One runnable task hides it, because the pick then returns the task it just removed and no switch happens, which is why nothing had found it before. `scheduler_tick` now re-queues a current task in `XAIOS_TASK_STATE_RUNNING` before choosing (leaving its remaining slice alone), `scheduler_self_test` ticks two equal-priority tasks twice and requires whichever is not current to still be in the queue -- the check fails without the fix -- and the two spinner runs are the behavioural pair. **What this row still owes:** the same proof on x86-64 and AArch64, each with its own per-task kernel context (a per-task `user_resume_rsp`/TSS `rsp0` record and floating-point area on x86-64; `SP_EL1` loaded from the frame on AArch64), and the `timer_mask_local()` question, which stays until a user thread's continuation is no longer on that CPU's stack. |
| `B-133` | A stolen task is given another CPU's name without its slot moving | `NOT STARTED` | `try_steal_from_cpu` (`kernel/sched/scheduler.c:346-381`) sets a task's `assigned_cpu` without moving the task out of the slot that CPU's run queue holds it in, so the stealing CPU's `find_task_local` never finds it. Today that is why a stolen task cannot be corrupted by a resume -- the tick looks the task up locally and does not find it -- which is luck rather than design, and it becomes a correctness bug the moment `B-132` makes a task preemptible. **Exit criterion:** the steal moves the slot with the assignment, or the queue is searched by assignment rather than by slot; the scheduler's own self-test exercises a steal and shows the task found on the CPU that owns it. |
| `B-136` | Source files run to thousands of lines, and the 500-line rule is not enforced | `IN PROGRESS` | 120 tracked files exceed 500 lines and 44 exceed 1000; the largest is `kernel/runtime/network_stack.c` at 5900. The limit is stated in `AGENTS.md` and on this page, and nothing measured it until `check-file-size-budget.py` joined `docs-check`: it fails when a new file crosses 500 lines and when an existing one grows past the size recorded for it, and it reports entries that have come back under the limit so the baseline can be cut. First module landed: `kernel/runtime/network_stack_wire.c` (431 lines) takes the wire-format helpers out of `kernel/runtime/network_stack.c`, which drops from 5900 to 5488. These are the functions that touch none of the stack's tables or counters -- the byte-order readers, the Ethernet/IPv4/IPv6/UDP/TCP parsers and the TCP option parse/build -- so the split moves no state and crosses one type (`network_tcp_flow_t`), which is why `build_tcp_options` stayed behind. Second module landed: `kernel/dev/nvme_completion.c` (122 lines) takes the NVMe completion path out of `kernel/dev/nvme.c`, which drops from 1701 to 1516. It touches no controller state, so only the queue and completion types crossed, into `nvme_completion.h`. Verified by `make compile-check` and `make qemu-nvme-gate` on all four configurations. Verified by `make compile-check` (all three architectures) and `make qemu-network-full-gate`. The rest of that file needs its state behind accessors first, as its own header note says. **Exit criterion:** the baseline is empty -- every source file is at or under 500 lines -- with each split landing on its own and verified by `make compile-check` plus the gates for its area (hosted tests for `userspace/` and `engine/`, the QEMU gates for `kernel/`), while the ratchet stays in place so the debt can only shrink. Split order, largest first by area: `kernel/runtime/` (`network_stack.c`, `remote_login.c`), `kernel/fs/`, `userspace/lib/`, `userspace/sshd/`, `tests/`, then the rest. |

The corresponding rows in the WebTransport repository's own tracker are `WT-44`
to `WT-53`, in the same order, and that page is where the protocol-level work
that is not XAIOS-specific is recorded.

**Five larger pieces belong here rather than in the bug table**, because they
are capability and integration work rather than defects: `B-129` (the tick on
every architecture, and what measuring it found), `B-132` (a user process is
not a scheduled task on any port, so nothing preempts it -- the prerequisite
`B-129` turned out to need), `B-133` (a stolen task changes CPU without its
queue slot moving) and `B-130` (the RISC-V board's IOMMU).

### Firmware profile results

Three profiles carry firmware evidence. **Two of them are current at
`58bd1fe`, re-collected by the targets that produce them from a clean tree:**
the macOS QEMU ARM64 profile on `node4` and the macOS VMware Fusion ARM64 one
on `node2`, each passing every gate it defines. **The third is still behind the
tree and must be re-run before it is quoted:** shared code that every profile
compiles has changed since it was collected -- the scheduler and page
allocator, the network stack, the cluster engine, and the RISC-V memory and
interrupt path -- and it needs its designated host rather than one of these.

One thing about collecting them is worth knowing before the next attempt,
because it cost a run here: the collector does not discover the firmware. It
reports `set XAIOS_AAVMF_CODE to the qualified firmware file` and refuses, even
when the file it wants is the very one the QEMU runner would have defaulted to,
so the variable has to be set explicitly and the check is on the file's
identity rather than its location.

| Profile | Collected at | Firmware | Covers |
|---|---|---|---|
| macOS QEMU ARM64 | `58bd1fe` | AAVMF/EDK2 `47765fe344818cbc464b1c14ae658fb4b854f5c2ceffa982411731eb4865594d` | boot, CPU, network, SSH, USB keyboard console, SVE2 per-task context, storage recovery, operations, shutdown, repeat boot |
| macOS VMware Fusion ARM64 | `58bd1fe` | Fusion 26.0.0, chainloader `b7fb993edf80e301b148a2076f8a9919c3d31936d2273f592d19c06b5ec1d3a5` | four-vCPU boot, storage, network, SSH lifecycle |
| Intel VPS QEMU x86_64 | `ee9c621edde5315e0da37fb3ae328baf717318ee` | OVMF/EDK2 `624e06de18b4fa535e90db7160d00d3d07d206422b89999bf1e27d920264e4e0`, QEMU 10.0.11 under TCG | all eight profile gates: boot/network/SSH, USB keyboard console, CPU matrix, platform inventory, NUMA firmware, NVMe storage, operations/shutdown, repeat boot |

The Intel profile needs its designated host (`deltasona`, Linux x86_64); no ARM
result stands in for it. Collecting it found nothing wrong with XAIOS and one
thing wrong with a gate: `q35-high-core-256-x2apic` needs about 517 seconds to
boot 256 vCPUs under TCG against a hardcoded 480, so the matrix killed a machine
that was booting correctly. Budgets now scale by
`XAIOS_QEMU_MATRIX_TIMEOUT_SCALE`; unset, nothing changes, and nothing the
scenario asserts was relaxed.

## Physical qualification: deferred, and said so

**This is a position rather than a queue, and it is written down here because
the objective it belongs to is a single-node, self-hosting, SSH-administered OS
with physical qualification explicitly deferred rather than silently assumed.**
There is no physical hardware in this project on any architecture, no physical
result is being waited on to complete any current work, and the three targets
that would need one are `OD-001`, `OD-002` and `OD-003` -- all `NOT STARTED`,
all blocked on nothing but the choice of machine.

What follows from it, and what does not:

- **Nothing is promoted for being the only evidence available.** A QEMU result
  stays *correctness and ABI only*, an Apple Virtualization.framework result
  stays *not qualification evidence*, and the rows that only hardware can settle
  keep `NEEDS HARDWARE` and stay off the active list.
- **No physical claim is made anywhere.** No physical Apple, ARM-server,
  Intel-desktop or Xeon performance, firmware compatibility, NIC behaviour, NVMe
  durability, NUMA locality, thermal behaviour or production security is
  asserted by anything in this tree. x86-64 in particular has never executed on
  an Intel or AMD processor: its evidence is QEMU on an ARM host through an
  interpreter. RISC-V's evidence is one emulated board and nothing else.
- **The deferral does not weaken an emulated gate.** They are held to the
  standard they were written to, and `physical_qualification=false` stays in the
  reports that carry it.
- **It closes only one way:** delivery order 1b -- a named machine per target
  passing the firmware, device, durability, security, ISA-state, NUMA, soak and
  benchmark contracts. `HARDWARE-READINESS.md` states the boundary and the
  contracts; this page owns the status.

## Released builds

Builds are published on the
[releases page](https://github.com/Pummelchen/XAIOS/releases); each carries a
note recording the hypervisors and firmware it was booted on and what was not
tested. What changed between them is in
[`CHANGELOG.md`](https://github.com/Pummelchen/XAIOS/blob/main/CHANGELOG.md);
this page does not repeat it.

| Build | State | Note |
|---|---|---|
| `b6` | **current** | One image per architecture instead of one image for all three, and eleven kits built for one machine each. RISC-V gets a launcher, a USB kit and a network-boot binary for the first time. Cut with `make release-check` green against `7df4fc8`. |
| `b5` | superseded | A RISC-V kernel in the shipped image, `xtop`, the screen framework, and a machine that is idle when nothing is happening. The last build to ship a single unified image. |
| `b4` | superseded | Cut from a green CI run. Adds first-boot setup, and an account and machine name a person chooses. |
| `b3` | superseded — do not use | A machine configured with SSH keys and no password account refused every key login, and it was cut while CI was red. |
| `b2` | superseded | First build to ship USB and network-boot kits. |
| `b1` | superseded | First released build. |

No released build has been booted on physical hardware.

## Status codes

| Code | Meaning |
|---|---|
| `TESTING` | Implemented, but the current acceptance run or physical qualification is still underway. |
| `IN PROGRESS` | Active implementation is incomplete. |
| `NOT STARTED` | No qualifying implementation has begun. An interface or fixture alone does not count. |
| `BLOCKED` | Work cannot proceed until the stated external decision or dependency is resolved. |
| `FAILED` | The latest required acceptance gate failed; the failure evidence must be linked in the item. |
| `DEFERRED` | Postponed on purpose. Not blocked by anything external and not abandoned -- it is simply not being worked on now, and saying so is more honest than leaving it among the open items. |
| `NEEDS HARDWARE` | Implemented as far as it can be here, and the remaining evidence can only come from physical machines. Not on the active work list: no amount of effort in this environment moves it, and leaving it among the open items makes the list read as further behind than it is. |

Resolved items carry no status code and are not listed: a resolved row is
deleted, and its identifier becomes a hole that `CHANGELOG.md` and the commit
history answer for.

QEMU status proves correctness and ABI behavior only. Physical support and
performance require immutable evidence under the
[benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).

## Supported environments

XAIOS runs on three hypervisors. QEMU covers three architectures, so five
targets exist, but the platform contract is per hypervisor.

Firmware differences below are the hypervisor's, not XAIOS's: the system
behaves identically wherever a capability exists, and where one is absent it
degrades the same way everywhere. See
[Platform neutrality](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-NEUTRALITY.md),
which the build enforces.

| Function | QEMU ARM64 | QEMU RISC-V64 | QEMU x86_64 | VMware Fusion ARM64 | Virtualization.framework |
|---|---|---|---|---|---|
| Boots to a login | yes | yes | yes | yes | yes |
| Durable xaibootFS volume | yes | yes | yes | yes | yes |
| IPv4 by DHCP | yes | yes | yes | yes | yes |
| IPv6 by SLAAC | yes (`qemu-slaac-gate`) | yes (`qemu-slaac-gate`) | yes (`qemu-slaac-gate`) | yes, global, from a real router advertisement (`make vmware-fusion-network-gate`) | yes, unique-local only (`V-03`) |
| IPv6 by DHCPv6 | client present, gated | client present, gated | client present | client present | client present |
| SSH server | yes | yes | yes | yes | yes |
| SSH client, SFTP | yes | yes | yes | yes | yes |
| Reachable from the host | yes | yes | yes | yes | vmnet helper only, one direction at a time |
| Boots at 1, 2 and 4 GiB | yes (`qemu-memory-matrix`) | yes (`qemu-memory-matrix`) | yes (`qemu-memory-matrix`) | yes, all three run | yes, all three run |
| Multiple vCPUs | yes, 130 gated | yes, 1/2/4/8 gated | yes, 128/256 scenarios | yes, 4/4 | yes, 8/8 |
| Message-signalled interrupts | distributor | board-dependent: none on the default `virt` (PLIC, everything polls), APLIC+IMSIC on `virt,aia=aplic-imsic` (`qemu-riscv64-aia-gate`) (`P-16`) | yes | PCI | none; every queue polls (`V-02`) |
| Framebuffer console | no, serial | yes with a virtio-GPU attached, gated; serial otherwise | no, serial | yes | yes when a display device is attached (`--gui`), driven directly over virtio-GPU because firmware publishes none; serial otherwise |
| USB keyboard input | yes | yes, gated | yes | provisioned, not gated | console input over virtio |
| Entropy protocol | virtio-rng | virtio-rng (`source=device-rng`) | virtio-rng | `F-05` none exposed | yes |
| Storage transport | virtio-MMIO | virtio-MMIO; NVMe over PCIe in its own gate | virtio-PCI, NVMe | AHCI | virtio-PCI |
| Network transport | virtio-MMIO | virtio-MMIO | virtio-PCI | E1000E qualified; VMXNET3 works (`F-02`) | virtio-PCI |
| Applications gated | yes, by name | yes, by name | yes, by name | yes, by name | yes, by name |
| Boots its release image | yes, gated | yes, gated | yes, gated | yes, gated | yes, gated |
| Automated gate | full CI | full CI (`riscv-bring-up`: smoke, release configuration, CPU tiers) | full CI | `make vmware-fusion-smoke` | `make vz-gate`, `make vz-stress-gate` |
| Release-image gate | `make release-image-gate` covers all five, each booting its own architecture's image; CI runs the three QEMU rows and reports the hypervisors as skipped |  | | | |
| Verified by | CI, every push | CI, every push | CI, every push | `make local-gates`, required by `make release-check` | `make local-gates`, required by `make release-check` |
| Evidence class | correctness only | correctness only | correctness only | Fusion 26H1 lifecycle | development target, not evidence |

Device inventory differs because the hypervisors differ; the kernel discovers
what is present rather than assuming a platform, so those rows are not defects.
The rows carrying an item identifier are.

## Bugs

No defect is open, and no closed defect is listed. A defect identifier cited
from a gate, a comment or a release note resolves through `CHANGELOG.md` and the
commit that made the fix, which is where the account of it has always lived.

## Open problems and recommended refactors

Two problems are open and one is closed. Each is written here with what was
tried, what did not work, and what would actually close it, because two of the
three have already cost more in method than in engineering. **`P-1` is the one
that closed**, and it closed by the refactor it recommended: the network-poll
decision chose the timer, stage three-b landed it, and the worst gap between
polls fell from 55-93 ms idle and 164-297 ms under load to 24 ms idle and 29 ms
under load.

### P-1 — A connection is dropped whenever sshd's loop blocks

Covers `B-43`, `B-63`, and the structural half of `B-44`.

**Mechanism, established, and since closed.** The network stack was polled only
from sshd's service loop. While that loop is inside any blocking call, nothing processes packets:
the peer waits, gives up at its own patience (about 18s for the macOS client),
and the connection surfaces much later as `packet-read-failed` or
`auth-timeout`. Three independent clocks agree on each outage -- `network:
longest gap between polls us=9069149` from the stack, `service loop stalled
ms=9101 phase=connections` from sshd, and `held_ms=9333` from the connection --
against a next-largest gap of 143 ms in the same run.

**What blocked the loop.** `ssh_log()` wrote every line straight to the durable
volume, and a xaibootfs append carries `blk_flush()`, which is a virtio flush and
therefore a host fsync. A connection produces about five log lines, so sshd paid
five host fsyncs per connection inside the only loop that moves packets.

**What was tried, and what it was worth:**

| Attempt | Outcome |
|---|---|
| Three Fusion load soaks, ~26,000 round trips | Soak 1 reproduced three times; soaks 2 and 3 reproduced nothing. As a *diagnostic* this failed -- the mechanism was stated in a comment directly above the offending lines. |
| Following stranded sockets by number rather than by clock | Worked. The close lands 30-120s late, so a per-round window attributes it to the wrong round. This is why the row read "the guest never saw it" for so long. |
| A kernel line at flow release when `rx_unread > 0` or `packets_rx == 0` | Worked, and fired on CI rather than in the soak. Silent on healthy traffic: 0 of 280 releases printed. |
| `durable_ms` on the stall line, per pass | Worked. At millisecond scale the durable write is ~90% of every stall this machine produces. |
| Buffering audit records; draining only when half full | Worked. Five fsyncs per connection became **0.041**, and blocking time for 121 connections fell from 1324 ms to 89 ms. |

**Ruled out, each of which would have been a reasonable place to start:** the
socket-to-flow map never ran out (`B-47`'s mechanism -- the one exhaustion line
in a 33 MB console is its own self-test); sshd's loop was not asleep (it waits at
most 50 ms and accepts four per pass); the server was not wedged (a `DEBUG3`
probe connected in 0.08s immediately after each failure); there was no drop or
retransmit storm (one `retransmit=6` line in the whole console, early, nowhere
near a failure); and the guest was not being descheduled by a loaded host (zero
wait overruns in a run with three multi-second stalls, and that wait is the
longest single call in the loop).

**Closed, by the refactor this section asked for.** Everything above narrowed
the window and none of it closed it, so the poll was made independent of sshd's
loop: the network-poll decision chose the timer and stage three-b landed it, and
the worst gap between polls fell from **55-93 ms idle and 164-297 ms under load
to 24 ms idle and 29 ms under load**, with several thousand polls per run now
taken from the timer interrupt instead of from a syscall. One fsync can still
stall for
seconds, but it no longer takes the network with it. **What that does not
settle:** a stall long enough to outlast the peer's own patience still ends the
connection, and `B-43` and `B-63` were never reproduced on demand, so this
records a window that is bounded rather than one that is gone. The full finding,
including the three separate causes that had to be fixed and the six candidate
mechanisms ruled out by measurement, is in the commit history for the
poll-carrier decision.

**Reproduction, for whoever takes it:** CI is far better at this than the local
soak -- roughly one run in six to eight against three in 7138 rounds on Fusion,
none in 7235, none in 11690. The Debian 13 interoperability job is where it
lands. Running the soak again is the least likely thing to work.

### P-2 — A gate that outlasts its budget cannot report its own failure

Covers `B-39`, and retrospectively explains `B-72`.

`qemu-core-os-rc` kills each step at its budget; the gates it runs have budgets
of their own, and `smoke_timeout` multiplies the RISC-V ones by four. Where the
gate's wait was longer than the step's budget, the aggregate killed it first and
printed `exited 124` with no architecture, no phase and no reason.

Two steps had it. `fragmentation` waited 720s for a RISC-V boot inside 360 --
that is B-39, whose only evidence is one run that took at least 3.7x its usual
time and could be recorded as nothing but a timeout. `nvme` waited 1440s inside
900, which is why B-72 read as an anonymous timeout for two runs and why raising
its budget worked: it gave the gate back the ability to name the row.

Fixed in both, and `check-aggregate-budgets.py` now fails on either -- exercised
in both directions before it was wired in. **Residual worth knowing:** that check
reads two spellings of a wait out of gate source and cannot see a wait built any
other way, which its own docstring states. **Recommended refactor:** gates should
derive their wait from the budget they are given rather than choosing one
independently, at which point the inversion becomes unrepresentable and the check
becomes unnecessary.

### P-3 — This Mac cannot see what the runner sees

Nine defects (`B-65` through `B-73`) were invisible here and immediate on Linux:
a firmware path defaulting to `/opt/homebrew` and nothing else, `dd bs=1m`,
mtools missing from a job, a job with no RISC-V emulator, small-data sections
clang 18 emits and clang 23 does not, an argument silently discarded, a make
target that built half a machine, a truncated number read mid-arrival, and an
MSI-X interrupt QEMU 8.2.2 never delivers.

**What worked:** `tests/linux-parity` reproduces in about a minute what used to
take a push and a wait. Better still, three of the nine now have static checks --
`check-riscv-firmware-paths.py`, `check-portable-dd.py`,
`check-aggregate-budgets.py` -- which catch the whole class without booting
anything.

**What did not work, and is a real limit:** the parity container is arm64 and the
runner is x86_64. It cannot build an x86-64 userland at all (picolibc asks gcc
for `-m64`), and running it under emulated amd64 produces timings slower than any
real runner, so it predicts nothing. Three gates were once "reproduced" failing
there and all three had died on that build, saying nothing about CI. Every run
now prints the platform it ran on.

**Recommended:** an x86_64 Linux host for parity. One already exists -- the Intel
qualification host in `Platform recommendations` -- and pointing
`tests/linux-parity` at it would close the gap that `nvme-budget.sh` currently
refuses to guess at.

## What ships, and how far along it is

Three bootable deliveries, and the engineering each one waits on. Status is
what has been demonstrated, not what has been designed: `PARTIAL` means some of
it runs and the rest has not been tried, and is never a way of saying nearly
done.

| # | Deliverable | Status | Where it actually stands |
|---:|---|---|---|
| D1 | USB image, every architecture | `NEEDS HARDWARE` | Off the active work list: what remains is a physical test, not an implementation. Build 6 ships three USB kits, one per architecture, each carrying a hybrid ISO 9660 and GPT disk for that machine, so `dd` should produce a bootable stick on all three. Everything except the stick is exercised: `make release-image-gate` boots each of those images as a disk across five environments, and the installed-disk gate boots the partition layout they rely on twice a run. The unproven step is a stick in a machine, and `write-usb.sh` itself has never been run against a real device. |
| D2 | Network boot for blank machines | `TESTING` | A blank machine boots over the network and installs itself. `make qemu-netboot-gate` runs four stages: firmware asks DHCP for a boot filename and fetches it over TFTP; a medium holding the loader and nothing else boots the same way; that machine installs onto a blank disk; and that disk boots alone to a login prompt with SSH listening. Only the last two are evidence of an install. **Remaining:** the same sequence on physical hardware. |
| D3 | Ready-to-run images per environment | `TESTING` | Eleven kits from `scripts/build-vm-packages.sh` and `scripts/build-boot-media.sh`: QEMU, USB and netboot for each of the three architectures, plus VMware Fusion and Virtualization.framework for AArch64, which is the only architecture those two run natively on this host. Each kit carries the image for its own machine -- since build 6 there is no shared image to carry, and a kit that contained another architecture's would be a kit that boots nothing. `make vm-package-gate` boots all five VM kits out of their own archives and `make boot-media-gate` boots all three shipped netboot binaries. Kits are release assets, not committed. **Remaining:** physical media (D1). |

## Engineering these wait on

| # | Work | Status | Where it actually stands |
|---:|---|---|---|
| E1 | Disk partitioning, formatting and install tooling | `TESTING` | Works end to end: a running XAIOS partitions a blank disk, formats an EFI System Partition, copies its own loader, kernel, initial filesystem and entropy seed across, and the result boots on its own to a login prompt with SSH up. `kernel/fs/fat.c` is a FAT16 writer with long-name support, chosen over FAT32 because Fusion silently boots nothing from FAT32. `make qemu-installed-disk-gate` boots the installed disk, which is the only evidence that counts -- everything before it is the installer describing its own work. **Remaining:** the same run on physical media (D1). |
| E2 | Instruction-cost metric | `TESTING` | Recorded, committed and checked. Under `-icount shift=0` the guest clock counts instructions, and `make qemu-instruction-cost-gate` compares three single-threaded figures against `tests/fixtures/instruction-cost-baseline.json`. The four-thread figure is printed and never pinned, because under `-icount` the virtual clock advances for every vCPU. **Not a performance measurement:** see the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md). |
| E3 | NUMA correctness | `TESTING` | The self-test proved node-0 placement and never checked node 1, so an allocator ignoring its node argument would have passed. It now asserts placement inside node 1's range and that every CPU maps to exactly one node through both lookups, held by `make qemu-x86_64-numa-gate` across a two-node and a four-node machine. **Remaining:** physical NUMA hardware. |
| E4 | Multiqueue and RSS networking | `TESTING` | Per-queue driver state, every advertised pair allocated and polled round-robin so a busy pair cannot starve the others, and `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` sent only after the buffers exist. RSS is now negotiated and configured from the device's own config -- supported hash types, table length and key size read rather than assumed -- and steering is measured by `make qemu-rss-steering-gate` on a four-queue tap: sixteen buckets across four pairs spread `[64, 62, 66, 64]`, and a one-bucket control collapses to `[256, 0, 0, 0]` and fails the same assertion. Two defects were found by insisting on real counts: the hash key's byte 13 was zero, which pinned the low bit of every flow's hash so only even buckets were reachable (512 frames landed `[37, 0, 27, 0]` -- enough spread to pass a gate that asked for "more than one queue"), and `max_tx_vq` was sent as an index where the device reads a count, cutting a four-pair device to three with pair 3 set up, polled and unreachable. **Remaining:** the gate needs Linux, root and a multi-queue tap, so it runs on the Intel host only -- macOS offers the feature bits on both transports and has no multi-queue backend for either, and virtio-mmio multiqueue is unexercised anywhere. Hash report is offered but deliberately not negotiated: it grows every frame's header and forces software hashing for a per-packet value nothing here reads. |
| E5 | xaibootFS and xaiFS at scale | `TESTING` | xaibootFS v6 records a file as extents rather than a block list, which lifts both limits at once and makes a node smaller: 1 GiB per volume against v5's 4 MiB, 1024 nodes against 256, and a format limit of a gibibyte per file. The write path still refuses at 256 KiB, because it stages a whole file through a static buffer that was never raised with the format -- refusing is deliberate until it streams. Resident cost is about 850 KiB for 256 times the capacity. Which version a new volume gets follows the disk rather than a flag day. **Remaining:** scale evidence on physical storage. |
| E6 | Cluster data plane | `TESTING` | A sealed frame crosses a real network between two guests. `make qemu-cluster-two-node-gate` and `-three-node-gate` run join, partition, recovery and ownership, each phase on its own TCP connection so each machine has to be ready on its own schedule. `engine/src/cluster.c` had framing, sealing and peer state since it was written and had never opened a socket. **Remaining:** distributed execution, which waits on D-05. |
| E8 | WebTransport C99 port | `IN PROGRESS` | The TLS 1.3 client handshake is written, tested and merged: it completes a QUIC handshake against a server flight from an independent Python implementation, and 1487 host checks run in CI and under the sanitizers. `userspace/wt/` carries the key schedule, packet protection, framing and transcript, the message parsers, the signature check, the pinned-key policy and the state machine. **Remaining:** seven tasks -- `B-84` to `B-89` and `B-91` -- with `B-90`, `B-92` and `B-93` fixed, under [Current tasks](#current-tasks) -- the largest is that nothing on the target drives the handshake from a socket yet, and there is no QUIC connection runtime under it. |
| E7 | Storage throughput, caching and power-loss evidence | `TESTING` | The block path moved 512 bytes per virtqueue round trip -- `buffer_size` had always been validated and then ignored. Raising it to a mebibyte and reading each byte once rather than twice changed the figures by orders of magnitude, against a baseline rebuilt from the same tree rather than remembered. Power loss is real: `make qemu-power-loss-gate` replays QEMU's `blklogwrites` journal through `tools/xaios_write_log.py`, because no emulator option loses an acknowledged write on its own. **Remaining:** physical storage; emulator figures are not throughput evidence. |

## Delivery order

| Order | Workstream | Status | Current boundary / exit gate |
|---:|---|---|---|
| 1b | Physical Apple/ARM, Intel desktop, and Xeon qualification | `NOT STARTED` | Named hardware must pass firmware, device, durability, security, ISA-state, NUMA, soak, and benchmark contracts. |
| 1c | Disk partitioning, formatting and install tooling | `TESTING` | A tool set that partitions a disk, formats xaibootFS and xaiFS on it, and makes it bootable with XAIOS as the only operating system on the machine. The tooling exists and installs -- see `E1` for what it is. The gates that prove it, `make qemu-installed-disk-gate` and `make qemu-setup-gate`, began as AArch64 QEMU only, which is why this row read "x86-64 has no install evidence at all" for so long. **That is now three architecture-specific variants rather than one:** `qemu-riscv64-setup-gate` already existed, and `qemu-x86_64-installed-disk-gate` is new; a `qemu-riscv64-installed-disk-gate` target was listed beside it, but it could not run at all -- see `B-103` -- it took adding x86_64 to the disk builder, which refused the architecture outright, and a per-architecture profile in the gate. The installed-disk boots pass on x86-64 (kernel, ordinal, state partition found by type, fsck, four vCPUs, shell, systest, ESP readable, kernel on the ESP, and the second boot seeing what the first wrote). **That phase now runs on all three architectures.** It is the first time the row can say that: a running machine installing onto a blank disk is exercised on AArch64, x86-64 and RISC-V, and on x86-64 the disk XAIOS wrote was then booted on its own with an SSH server running on it. What held it back was that the storage-administration window was a device's *position in the test bench's disk order* -- see `B-113`, which also records how it was fixed and what the fallback needed before it was safe to scan for a device at all -- and, once that was fixed, a byte floor in the install check that only AArch64's ESP could satisfy, which is `B-114`. **Exit gate:** a blank disk partitioned, formatted and booted on all four environments and on one physical machine. |
| 2 | Qwen 3.8 support | `NOT STARTED` | Begins after physical platform qualification is accepted or explicitly deferred; official tokenizer, layer, logits, 32-step decode, session, and physical gates must pass. |
| 3 | Kimi K3 text support | `NOT STARTED` | Begins after Qwen unless reprioritized; KDA, Gated MLA, exact top-16 MoE, MXFP4, and token parity are mandatory. |
| 4 | Kimi K3 multimodal support | `NOT STARTED` | Separate vision preprocessing/tower/projection/position and golden image gates. |
| 5 | DeepSeek V4 Flash 0731 support | `BLOCKED` | The exact official release label and immutable source must be verified first. |

## Model support boundary

| Model or format | Progress | Support boundary | Completion gate |
|---|---|---|---|
| Qwen 3.8 | `NOT STARTED` | Roadmap target; no architecture adapter is claimed | Pin an immutable official configuration before tokenizer, tensor, layer, prefill-logit, decode, session, backend, and physical parity work. |
| Kimi K3 text | `NOT STARTED` | Interface only | KDA/MLA/MoE/MXFP4/operator and target-token parity on a real checkpoint. |
| Kimi K3 multimodal | `NOT STARTED` | Roadmap only | Separate official vision and multimodal golden acceptance. |
| DeepSeek V4 Flash 0731 | `BLOCKED` | Roadmap only | Verify exact official source before architecture work. |

## Platform recommendations

Only open ARM/Intel/platform recommendations remain here. The complete numbered
catalog stays in `docs/PLATFORM-SUPPORT.json`; no secondary page owns progress
status.

| # | Recommendation | Status | Evidence / remaining gate |
|---:|---|---|---|
| P-05 | Physical Apple NEON evidence | `NOT STARTED` | QEMU cannot satisfy this physical gate. |
| P-07 | SVE/SVE2 backend | `TESTING` | `make qemu-aarch64-sve2-gate` executes the SVE2 canary and preserves per-task Z/P/FFR across scheduling and interrupts. A packed SVE inference kernel exists -- `xaios_packed_gemv_sve`, runtime-length vectors with `svwhilelt` predicating the final partial vector rather than a hand-written tail -- and is verified against the scalar reference before use (`packed=verified against scalar` on `-cpu max,sve=on`). It is selected ahead of NEON because SVE's width is the machine's. **Remaining:** physical Apple silicon; nothing here is performance evidence. |
| P-15 | RISC-V (rv64gc) as a third architecture | `TESTING` | Functional parity on the QEMU `virt` board, in the release image, gated three ways: `qemu-riscv64-gate`, `qemu-riscv64-boot-media-gate` and `qemu-riscv64-matrix-gate` at 1, 2, 4 and 8 harts. Boots from a kernel handed to QEMU and from its own disk through EDK2 via the signed A/B slot, and the unified release ISO carries it. Sv48 and Sv39, ecall syscalls over a full trap frame, PLIC, PCI over ECAM, both virtio transports, xaiFS at `/models`, IPv6, the hosted C99 library and xapt. **Remaining:** hardware. See [[RISC-V\|RISC-V]]. |
| P-16 | RISC-V message-signalled interrupts | `TESTING` | Implemented and gated on QEMU; not qualified on hardware. `kernel/arch/riscv64/aia.c` drives APLIC and IMSIC, discovered from the device tree and selected at run time, so `-machine virt,aia=aplic-imsic` works and the default PLIC board is unchanged. The supervisor-level pair is identified by the interrupt cause an IMSIC raises (9, not 11) and by `msi-parent`, because the machine-level devices carry the same compatible strings. Held by `make qemu-riscv64-aia-gate`, which requires markers that can only be printed after something was delivered. **Remaining:** hardware. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |

## VMware Fusion ARM64 remaining work

The qualified Fusion boundary is Apple Silicon VMware Fusion 26H1 (26.0.0),
four vCPUs, E1000E, AHCI, DHCP IPv4, and public-key SSH/SFTP. The items below
are intentionally not implied by that passing profile.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| F-06 | Fusion release-version coverage | `DEFERRED` | Postponed deliberately; nothing external blocks it. Fusion 26H1 evidence is not a compatibility claim for earlier or later releases, x86_64 guests, or physical Apple hardware. |

## Apple Virtualization.framework ARM64 remaining work

XAIOS boots to a login on this platform with xaibootFS on a durable volume,
DHCP IPv4, SLAAC IPv6, SSH and all four vCPUs online, and the Mac can ssh into
the guest over vmnet
through `platform/virtualization-framework/vmnet-helper`, which is the only route in: the built-in NAT
attachment delivers no host-initiated frame, and bridging needs an entitlement
V-03 also waits on. `make vz-gate` checks that boot and writes
`build/vz-gate.json`. It is a development target: the gate needs macOS on Apple
Silicon and a signed harness, so it cannot run in CI and its result is not
qualification evidence.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| V-02 | MSI-X delivery for virtio on PCI | `TESTING` | Exercised by attaching QEMU's virtio devices on PCI against a real translation service: every device on the bus receives a distinct vector. Three defects were fixed to get there -- one translation table shared by all devices, identifiers reissued to a device whose predecessor polls and never registers a handler, and an assertion on any BAR above 512 GiB. **Remaining:** physical ARM PCIe. Virtualization.framework has no ITS, so its queues stay polled. |
| V-03 | Globally routable IPv6 | `TESTING` | The NAT attachment advertises only the unique-local prefix `fd4a:25c::/64`. A bridged attachment needs the `com.apple.vm.networking` entitlement, which Apple issues only with a provisioning profile; ad-hoc signing cannot provide it. **The blocker is now known to be only the entitlement:** the guest half was never proven while `e1000e` discarded every multicast frame, and with that fixed a bridged Fusion guest on the same LAN autoconfigures a routable address from a real advertisement (F-03). |
| V-04 | Multi-vCPU qualification | `IN PROGRESS` | Secondaries genuinely run: PSCI starts them with translation off, where exclusives are unsupported, so the atomic each one used to announce itself aborted and every boot reported `online cpus=1/4`. With that window made coherent, boots come up 1/1, 4/4 and 8/8, and ten consecutive eight-vCPU boots produce byte-identical `smptest` signatures. `make vz-gate` requires 4/4 and `make vz-stress-gate` covers sustained load. **Remaining:** this host has eight cores against a 128-256 core target and the platform offers no interrupt-affinity control. |
| V-06 | Graphical console | `TESTING` | Implemented. The platform's GOP reports `PixelBltOnly` with a zero framebuffer base, so firmware leaves nothing to draw into, but the display device is on the PCI bus regardless and `kernel/dev/virtio/virtio_gpu.c` claims it: resource created, framebuffer attached page by page, scanout pointed at it, transfer-and-flush after each draw. `boot_ui` accumulates a dirty bounding box and presents only that region. `make vz-framebuffer-gate` captures the guest's display through ScreenCaptureKit and requires the boot bar; it needs Screen Recording permission, cached per process at launch. |
| C-01 | Shared kernel state under genuine parallelism | `TESTING` | Addressed per subsystem, because the right fix differed per file. The network stack, service records and CPU-AI runtime took reentrant guards on their syscall-reachable entry points -- reentrant because ten of the network stack's exported functions call other exported ones. The resolver shares the network guard rather than holding its own; a separate one was a lock-order inversion, caught before it could bite. `security.c` and `agent_protocol.c` hold no tables, so their counters became atomics. **Remaining:** sustained multi-core evidence on a machine with more cores than this one. |
| C-02 | `network_stack.c` state escapes its module | `TESTING` | The obstacle to finer locking was never the lock: tables handed out their rows. The socket map returned interior pointers across the syscall boundary, where callers dereferenced them after the guard was released -- a live race once secondary CPUs ran -- and now returns a copy. No exported function returns a pointer into module state. Splitting the tables further was left open pending C-03, which then measured it as worthless. |
| C-03 | The socket path scales; the finding that said otherwise was noise | `TESTING` | Socket bind/close costs about 40 us per operation at four threads and the same at eight, three runs per configuration, so throughput rises with cores. Giving the listener registry its own guard made no measurable difference and that split was removed. The 437 us that opened this item was recorded while `vmnet-helper` held a core busy (B-03) -- contention with the host, not serialisation in the stack. **Nothing here is performance evidence:** see the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md). |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| N-F3P | Physical SSH/network security qualification | `IN PROGRESS` | Consolidated QEMU network/SSH readiness evidence is available through `make qemu-qualification-readiness`; physical lossy-link, sustained-load, side-channel analysis, and independent SSH/cryptography review remain open. QEMU evidence cannot close this item. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-11P Physical production NVMe qualification | `IN PROGRESS` | Consolidated QEMU NVMe and crash-recovery evidence is available through `make qemu-qualification-readiness`; named physical devices must still pass queue scaling, interrupt affinity, FUA/flush/discard semantics, reset recovery, power-loss durability, sustained-load, and performance gates. QEMU evidence cannot close this item. |
| S-12 Production xaiFS trust-root and signing-key custody | `BLOCKED` | Offline trusted-replica payload repair is implemented and QEMU/hosted-tested. Production trust-root enrollment, private-key custody, replica authorization, and rotation decisions require named operators and deployment credentials. |

## Distributed AI server phases

| Phase | Status | Exit gate |
|---|---|---|
| D-05 Real local inference | `NOT STARTED` | Real Qwen correctness, typed state, scheduling, cancellation, backpressure, and metrics. |
| D-06 Authenticated cluster control | `TESTING` | The QEMU-testable tranche is done. `make qemu-cluster-two-node-gate` runs join, partition, recovery and ownership across two guests; `-three-node-gate` runs three that heartbeat every 500 ms and kills one emulator outright, so the survivors must notice from silence rather than from a `LEAVE`; `-partition-gate` breaks links instead of machines through `tests/scripts/cluster_fault_relay.py`, so one-way and two-way partitions can be arranged while every machine keeps running. Quorum is what could not exist at two nodes: a minority reports `owners=withheld` rather than deciding, because one expert with two owners is work done twice that nobody reconciles. Each gate carries its own control -- a healthy window longer than the detector's deadline that must declare no death, and a skip-kill mode in which every failure-detection check must go red. **Remaining:** execution across nodes, which waits on D-05. |
| D-07 Distributed placement/execution | `IN PROGRESS` | Hosted tests cover deterministic expert ownership, grouped routing, simulated node-loss rerouting, and stable node/expert reduction. End-to-end distributed activation execution depends on D-05 and D-06 and cannot be closed by hosted placement tests alone. |
| D-08 Benchmarks/diagnostics | `IN PROGRESS` | QEMU benchmark telemetry and a hashed qualification-readiness report are implemented; physical metadata-rich NUMA, bandwidth, PMU, thermal, storage, network, and redacted support-bundle evidence remain. |
| D-09 Production inference service | `NOT STARTED` | Authenticated API, streaming, cancellation, saturation, loss, and long-lived tests. |
| D-10 Support qualification/cleanup | `IN PROGRESS` | Documentation contracts and the consolidated QEMU qualification-readiness gate exist; physical, model, cluster, thermal, PMU, and durability qualifications remain. |

## Qwen 3.8 implementation

| Item | Status | Acceptance |
|---|---|---|
| Pin immutable official config/tokenizer/SafeTensors and parity corpus | `NOT STARTED` | Hashes and source revisions recorded. |
| Streaming SafeTensors/config/tokenizer importer | `NOT STARTED` | Bounded RSS and deterministic package output. |
| Package-owned tokenizer | `NOT STARTED` | Trusted tokenizer IDs match. |
| Official architecture probe and ordered configuration-derived layer plan | `NOT STARTED` | Unknown fields fail closed. |
| Scalar embedding, RMSNorm, and first projection | `NOT STARTED` | Python reference parity. |
| Every configured attention/recurrent/convolution operator, position encoding, FFN, residual, norm/head | `NOT STARTED` | Complete-layer and prefill-logit parity. |
| Separate prefill/decode plans and real per-layer state | `NOT STARTED` | State and reload continuity. |
| 32-step deterministic decode | `NOT STARTED` | Exact trusted continuation within documented tolerance. |
| Physical AVX2 and tiled prefill/verification kernels | `NOT STARTED` | Physical differential and performance artifacts. |
| Native model-executing macOS process and optional Metal | `NOT STARTED` | Real model plan runs end to end; CPU fallback remains authoritative. |
| AVX-512/VNNI/AMX, SVE/SVE2, persistent worker gangs, NUMA autotuning | `NOT STARTED` | Capability canaries, scalar differential, and physical evidence. |
| Typed paged state, prefix COW, ragged batching, exact speculation | `NOT STARTED` | Target-only and speculative deterministic outputs match. |

## Later model work

| Item | Status | Acceptance |
|---|---|---|
| Separate `kimi_k3` adapter from immutable official config | `NOT STARTED` | Config/tensor roles reject unsupported fields. |
| K3 KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts, SiTU, MXFP4 | `NOT STARTED` | Scalar operator/router/expert parity. |
| K3 independently addressable expert shards and async residency/prefetch | `NOT STARTED` | Authoritative routing is unchanged by prediction. |
| Real K3 text checkpoint | `NOT STARTED` | Tokenizer/operator/router/target-token and production-width physical gates. |
| K3 MoonViT-V2 and multimodal pipeline | `NOT STARTED` | Separate golden image/text cases. |
| DeepSeek V4 Flash 0731 source verification | `BLOCKED` | Maintainer-approved immutable official source. |
| DeepSeek adapter and parity suite | `BLOCKED` | Depends on verified source. |
| Multi-terabyte sparse allocators and large pages | `IN PROGRESS` | Hosted model packages represent sparse offsets above 100 GiB; both QEMU targets cover 2 MiB mappings and x86_64 covers a 1 GiB leaf plus targeted SMP TLB invalidation. Physical capacity and performance qualification remain. |
| SRAT/SLIT/HMAT placement policy and local/remote byte telemetry | `IN PROGRESS` | The two-node x86_64 QEMU gate validates SRAT/SLIT/HMAT parsing, usable-memory intersection, deterministic preferred-node policy, node-local allocation, and local/remote byte accounting. Physical locality/performance qualification remains. |
| AI Cell/secondary-CPU real inference dispatch | `NOT STARTED` | Real model work executes on leased workers. |
| NUMA/machine expert ownership and stable failure-aware reduction | `IN PROGRESS` | Hosted tests validate deterministic owner selection, grouping, simulated owner failure, and stable reduction. Real NUMA/machine transport, remote activation execution, and multi-QEMU exactness remain. |

## Open decisions

| ID | Decision | Status | Required before |
|---|---|---|---|
| OD-001 | Select first physical Apple/ARM target and firmware/storage/NIC boundary | `NOT STARTED` | Physical ARM support. |
| OD-002 | Select representative AVX2 Intel desktop and hybrid-core/device baseline | `NOT STARTED` | Intel desktop support. |
| OD-003 | Select Xeon generation, sockets/NUMA, memory, NIC, and NVMe | `NOT STARTED` | Xeon support. |
| OD-004 | Provision production update/xaiFS trust roots and define custody/authorization procedures | `BLOCKED` | Rotation, revocation, offline recovery, and interrupted-activation rollback are implemented; private operator keys and process are required before untrusted deployment. |
| OD-005 | Define SSH fleet limits, identity, audit retention, lockout, recovery | `NOT STARTED` | Production SSH exposure. |
| OD-006 | Define supported NVMe/FUA/flush/discard/repair/power-loss contract | `NOT STARTED` | Physical persistent deployment. |
| OD-007 | Pin official immutable Qwen 3.8 fixtures | `NOT STARTED` | Qwen implementation. |
| OD-008 | Pin official Kimi/DeepSeek sources | `BLOCKED` | Corresponding adapters; DeepSeek exact label is unresolved. |
| OD-009 | Select expert-parallel interconnect and failure/ownership model | `NOT STARTED` | Cluster inference. |
| OD-010 | Define names, quality reporting, telemetry, and acceptance for opt-in approximate modes | `NOT STARTED` | Any approximate mode. |

**This is the decision analysis as it was written, and the outcome is recorded
under the network-poll decision: the timer was chosen, it is landed, and three
of the costs named here turned out to be removable rather than payable. It is
kept because the analysis is what made the third cause findable.**

**The network-poll decision is the one on this list most likely to be
under-costed, so the two options are set out with what each actually needs.**
The timer option is not a small change. There is no interrupt-mask primitive in
the tree to build on:
`kernel/include/xaios/arch_cpu.h` carries barriers, `relax`, `notify`, `wait`, a
counter and a stack pointer, and nothing that saves and disables interrupts, and
no `interrupts_save`-shaped helper exists anywhere in `kernel/`. So it needs one
per architecture -- the instructions are already used in isolation, aarch64's
`msr daifset, #2` in `gic.c` and riscv64's `csrrc sstatus` in `aia.c` -- and then
a change to `xaios_reentrant_lock`'s contract with an audit of its four users
(service, network, the resolver and the CPU-AI runtime, whose lock order the
header fixes), and then preemption, which the scheduler does not provide today
because it runs one thread to completion per worker. It also puts the whole poll
path -- the device drain and the packet processing, whose cost is set by how much
traffic arrived -- inside interrupt context, where its latency is everyone's.

The thread option is the opposite trade. A kernel thread on a CPU of its own
needs no lock change, no preemption and no new primitive, and it keeps the work
in thread context where it can be bounded; it costs one of the three worker CPUs
permanently, which is a quarter of a four-CPU machine.

**A third shape exists that neither option in the row names, and it may be the
cheapest correct one:** the timer interrupt drains the device into a ring and
sends only what a peer needs to keep waiting, leaving the rest of the stack to
the loop. That bounds the interrupt's work and removes the total-outage property
without a dedicated CPU, at the cost of splitting the poll path in two and having
to say which half may do what.

**And a measurement that changes what the timer option has to include.** The
first piece of it is now in the tree: `arch_cpu.h` carries
`xaios_interrupts_disable` / `xaios_interrupts_restore` /
`xaios_interrupts_enabled` for all three architectures, built on the
instructions each already used in isolation, with a self-test beside the other
boot self-tests. **That self-test reports `inconclusive`, not `passed`:**
`before=0 masked=0 after=0` at the end of boot, just before sshd starts, so the
enabling direction is never exercised because there is nothing enabled to mask.
The first version of it asserted `before == 1` and halted the machine, which is
how the masked state was found rather than assumed. **The boot CPU runs with
interrupts masked**, and the only unmask paths in the tree are
`gic_secondary_init`, which `smp.c` runs on the secondary CPUs, and
`kernel/sched/context.S`. A timer that polls the network therefore cannot be
built on "add a timer" alone: it has to establish where and why the boot CPU
enables interrupts, which is the same question as the preemption this row
already names. The primitive is landed and the self-test is honest about what it
did not test, because a test that reports a round trip it did not perform is
exactly the thing this page exists to prevent.

**The execution model is now established rather than assumed, and it is not
uniform across CPUs.** Both EL0 entry paths in `kernel/arch/aarch64/entry.S` set
`spsr_el1` to zero, so userspace runs with interrupts enabled; the boot CPU runs
kernel code with them masked; and the secondary CPUs unmask in `smp.c` and then
run kernel work interruptible, having first masked the scheduler timer on
purpose -- *"Keep the local scheduler timer masked until this CPU owns a
preemptible userspace run queue"*. That line is the shape of the whole problem:
the machine **already** takes interrupts in kernel context on three of its four
CPUs, so a network timer would fire there and call `network_poll_tick` from a
handler, which is exactly what the reentrant lock forbade.

**So stage two landed with stage one: the guard now masks interrupts for as long
as it is held and restores the state on release.** The prohibition is gone
because the condition it guarded against can no longer happen, the same guard
may now be taken from a handler, and the saved state is kept per guard because
the depth counter already says that only the outermost release undoes the
outermost acquire -- read before the guard is released, so a CPU that takes it
next cannot overwrite the state being restored. Verified by `make compile-check`
in every configuration and a full `make qemu-smoke` boot that passes its lock,
network and sshd markers with no halt. **What is left for the timer itself** is
deciding where the network tick is allowed to run, since the boot CPU takes no
kernel-context interrupts today while the secondaries already do.

**Stage three-a landed, and it is a race fix that was already there.** Putting
the tick into interrupt context needs `network_poll_tick` to be safe to
re-enter, and reading it for that found a live defect: `dns_transport_tick` was
called *after* `network_unlock()`, so it mutated the pending query and drove the
TCP flow carrying it without the guard that `dns.c`'s own comment says the
resolver shares -- racing every `dns_resolve_address` on another CPU, and
re-entering one on this CPU as soon as a tick could arrive in interrupt
context. It is now inside the guard, which is where that comment always said it
belonged. Verified by `make compile-check` in every configuration and a full
`make qemu-smoke` boot on node4 with the DNS and network markers passing.

**Done, and the two sessions together are the record of why it took three
passes.** The network-poll decision chose the timer; stage three-b landed it:
one secondary CPU arms its own timer after `kmain` stops the shared periodic
tick, and on that CPU the timer interrupt does not tick the scheduler, which
stays masked there exactly
as the port left it. The tick wakes the CPU; the idle loop polls the stack in
thread context through `network_poll_tick_from_carrier()`, which is the whole
poll including the power path -- safe there because thread context is where
`operations_tick()` quiesces storage, and it can stop the machine.
**No CPU gains or loses a preemption.**

**What the first attempt got wrong, because it is the useful part.** It read
"the tick stops when the carrier is given work", which was coincidence: in the
run instrumented to test that, no thread was dispatched to the carrier and the
tick still died. Three separate causes had to be removed, and only the third was
the timer:

1. **The hook point never ran.** `kmain` clears the *global* period before sshd
   starts, so no CPU takes a periodic timer interrupt afterwards and a poll in
   `intid == TIMER_PPI_INTID` is unreachable code. The tick has to be armed, not
   merely hooked.
2. **The idle loop could not take an interrupt at all.** `vector_entry` masks
   `DAIF` on every trap, and a secondary's loop could be re-entered with `I` set
   -- measured spinning with a pending timer *visible* in its CPU interface
   (`hppir1=27`) and `DAIF=0x3c0`, so it never took another one. A CPU that
   cannot take an interrupt cannot be woken by one either, which is how the
   scheduler moves work between CPUs. The loop now clears `I` every turn instead
   of once before it, and `wfe` sleeps again rather than spinning: the same run
   had turned 134 million times. **This is a defect in its own right and has
   nothing to do with the network.**
3. **The keepalive starved the timer it was keeping alive.** Re-pointing the
   comparator on every idle turn postpones the deadline indefinitely when the
   loop iterates faster than the period, which is exactly what a pending
   interrupt makes it do. The count froze at 18, then at 50. The keepalive now
   re-arms **only when the tick is not running** -- which is what it is for: a
   mask taken while this CPU ran a task -- and the count then tracked the loop
   one-for-one to 8000.
4. **RISC-V could not take the trap at all, so the poll moved out of the
   handler.** Polling from the timer handler worked on AArch64 and x86-64 and
   corrupted a trap frame on RISC-V (`/bin/c99-thread-context` returned to
   program counter zero), because that port's trap entry cannot yet take
   arbitrary kernel-context traps. The tick now only *wakes* the carrier and the
   poll runs from its idle loop, in thread context: no port has to be more
   interrupt-safe than it already is, none is special-cased, and the power path
   stays out of handlers. RISC-V was measured carrying it -- `network tick armed
   on cpu=2`, `tick=783` rising to `3625` polls, worst gap 15 ms.

Ruled out along the way, each by measurement rather than argument, so the next
person does not repeat them: a mask by this kernel (`timer_mask_local` is never
reached on the carrier); `g_cpu_states` being reused (the bootstrap region is
reserved from the NUMA allocator); the redistributor being asleep
(`GICR_WAKER=0x0`, both `ProcessorSleep` and `ChildrenAsleep`); PPI 27 being
disabled (`GICR_ISENABLER0=0x08000002`); the interrupt stuck active
(`GICR_ISACTIVER0=0`, and `ICC_CTLR_EL1=0x8c00` means `EOImode=0`, so the
unconditional `ICC_EOIR1_EL1` does deactivate); and the priority mask
(`ICC_PMR_EL1=0xf8` admits the timer's `0xa0`).

**Verified, and the numbers are the claim.** `make compile-check` clean on
aarch64, x86_64 and riscv64; `make qemu-smoke` passes; and
`make qemu-network-poll-cadence-gate` reports **24 ms idle, 25 ms across three
256 KiB SFTP round trips and 29 ms after ninety rejected connections, with 2890
of those polls taken from the timer interrupt** -- against 55-93 ms idle and
164-297 ms under load before. The gate's assertion that an announced tick must
actually advance the interrupt count is what caught causes 2 and 3, and it is
green. `make qemu-x86_64-smoke` and `make qemu-riscv64-smoke` also pass, and the cadence gate reports the tick firing on AArch64 and RISC-V.

**One latent deviation found on the way is now fixed.** Neither `gic_init` nor
`gic_secondary_init` waited for `ChildrenAsleep` to clear after clearing
`ProcessorSleep`, which the GICv3 specification requires before the rest of the
redistributor is used. Both paths omitted it, and neither was this defect -- the
boot CPU's timer works for thousands of ticks regardless -- but a mandatory
sequence was not being performed, and it had gone missing in two places at once
because the same three lines were written out twice. It is one
`wake_redistributor()` now, which polls until the redistributor reports itself
awake and is bounded rather than open-ended: a frame that never wakes logs
`gic: cpu<N> redistributor never reported awake` and lets the probe that follows
fail visibly, instead of hanging the machine with no output at all. Verified by
`make qemu-smoke`: the boot completes with no such line, so both paths take the
poll and pass it.
is a choice about the machine's execution model rather than a refactor to make
quietly.

## Risk register

Risk status `TESTING` means mitigations exist but the risk remains open and is
checked continuously.

| ID | Risk | Status | Mitigation / closure gate |
|---|---|---|---|
| R-001 | QEMU timing presented as hardware performance | `TESTING` | Evidence vocabulary and benchmark contract; close only with continued claim audits. |
| R-002 | Documentation drift | `TESTING` | One tracker, `make docs-check`, and live-Wiki parity. `check-doc-freshness.py` now also fails the build on the two claims that expire quietly: an evidence commit of ours that has fallen far behind `HEAD` without saying so, and a review date on a page that git shows was edited afterwards. Three such claims were found expired in a single session -- a page saying a target had no automated gate months after two were added, a stale review date, and an evidence commit quoted as current from a hundred commits back -- so the residual risk is prose that is wrong in ways no pattern can see. |
| R-004 | Unreviewed SSH exposure | `TESTING` | Passwords off by default, bounded limits, OpenSSH/FreeBSD gates; independent review remains. |
| R-005 | Fixture keys used as production trust | `TESTING` | Fixtures are labeled; OD-004 blocks production trust. |
| R-006 | Storage durability inferred from sparse/QEMU tests | `TESTING` | Passing emulated async-NVMe and crash-recovery gates remain separate from physical S-11P and trust/repair S-12; only physical evidence can establish durability. |
| R-007 | Parser arithmetic or ownership error | `TESTING` | Checked arithmetic, malformed tests, sanitizers, immutable readers, fuzzing. |
| R-008 | Interfaces advertised as model support | `TESTING` | Separate progress and support-boundary columns plus golden gates. |
| R-009 | SIMD selected from CPUID alone | `TESTING` | OS-state checks, known-answer canaries, and scalar differential tests. |
| R-010 | Bounded fixture limits treated as server-scale targets | `TESTING` | Runtime-sized CPU/NUMA structures and explicit remaining bounded stores. |
| R-012 | Repository Wiki diverges from live Wiki | `TESTING` | Versioned Wiki source in `wiki/`, `make wiki-parity-check` reading the published pages back and comparing them byte for byte, and the layout and link gates in `docs-check`. **The middle one was claimed for months and did not exist** — every check read the in-repo copy, and `publish-wiki` pushed without reading anything back, so the risk was recorded as mitigated while nothing mitigated it. It was not theoretical: see `B-101`. The parity check is deliberately outside `docs-check`, which runs inside `qemu-core-os-rc` under a 120-second budget and must work with no network. **The mitigation has now been exercised in both directions on the live Wiki**, which is the part R-012 never had: against the state as found it failed naming the one page that had gone backwards (`Project-Tracker.md`, 186,340 bytes against 179,190, first difference at line 186), and after the publish fix it passes with all 26 pages byte-identical to the pushed tree -- the tracker restored from 179,190 bytes to 193,568, and two consecutive pushes both published from the correct commit. **Untested by that:** a divergence introduced by a publish run that fails, which the red run reports rather than this check, and a divergence older than the last push, which `publish-wiki` would overwrite without this check ever seeing it. |
| R-013 | A static-analysis finding is published and never triaged | `TESTING` | CodeQL runs on every push and its alerts are a backlog unless someone closes them. Thirty were open and every one has now been read: ten were real kernel defects (`B-95`), ten are BearSSL's DES, which is vendored, unmodified, and linked rather than called (`B-96`), and the remaining ten are test tooling whose weak fixture key, ECB against RFC 9001's own vectors, public per-run passphrase and QEMU-facing listener are the point of the gate rather than a defect in it. **The rule is that a finding is fixed, tracked, or dismissed with a reason on the alert -- not left open.** `check-code-scanning-contract.py` gates the workflow's permissions and job elevations, not its findings, so nothing enforces this but the practice. |

## Evidence gates

The default status-changing evidence set is documented in
[[Testing XAIOS|Testing-XAIOS]]. At minimum, source changes require the smallest
relevant compile/hosted/QEMU gates; documentation changes require layout,
status, JSON, link, and live-Wiki checks. A failed required gate changes the
affected item to `FAILED` until a passing rerun is recorded.

GitHub issues and milestones may provide discussion and execution history, but
their descriptive status must link back here rather than becoming another
independent tracker.

## Closed identifiers

Closed rows are removed from this tracker; this is the index that keeps their
identifiers resolvable. One line per identifier, naming what the item was and
the commit that first recorded the row as closed -- which for a row this tracker
inherited already closed is the commit that first wrote it. The account of the
fix itself is in that commit, in `CHANGELOG.md` and in the comments beside the
code; the numbers here are holes that are never reused.

| ID | What it was | Recorded closed in |
|---|---|---|
| `B-01` | Outbound ProxyJump failed host key verification | `1fdb810` Tracker: F-02, B-01 and B-04 say what was found |
| `B-02` | Thread join failed under load, twice | `2c68000` B-02: the join window, entered on purpose |
| `B-03` | `vmnet-helper` spun a core while idle | `4f1ab4e` B-03: verified on the fixed binary, which the V-03 run happened to start |
| `B-04` | Fusion intermittently got no DHCP offer | `6da8f0b` B-04: a hundred Fusion boots, and the retry count explains the defect |
| `B-05` | One fixed kernel link address blocked a 1 GiB profile | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-06` | Virtualization.framework booted to nothing below ~3.5 GiB | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-07` | Applications were never run on two of the four images | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-08` | An unclean-boot marker put the guest into rescue mode | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-11` | Userspace and the identity map were the same addresses | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-12` | Fusion faulted on the firmware framebuffer at 4 GiB | `a1f2f61` Six acceptance runs, and why five rows were never actually tested |
| `B-14` | The x86_64 guest wrote to the medium it booted from | `d7175bd` B-14: the read-only branch runs for the first time, and fails |
| `B-15` | An intermittent fatal assertion on VMware Fusion | `3d98a26` The tracker was an implementation diary in a table |
| `B-19` | The relocated kernel was placed without its required alignment | `d7175bd` B-14: the read-only branch runs for the first time, and fails |
| `B-23` | A v6 volume sometimes did not come back from a power cut | `e3a2974` xaibootfs: probe the mirror at the right sector on v6, and stop the rename overflow |
| `B-24` | Renaming a directory on a v6 volume wrote 191 KiB past a static array | `e3a2974` xaibootfs: probe the mirror at the right sector on v6, and stop the rename overflow |
| `B-25` | After reverting a Fusion snapshot the guest refused every command | `b27c507` B-25: sshd leaked a kernel session per connection whose command failed |
| `B-26` | `qemu-docker-network-suite` failed its native xtop check | `aa1ce44` B-26: the external client suite described an xtop that no longer exists |
| `B-27` | A full-screen program's terminal restore was truncated | `3ac5c06` B-27: five bytes of a terminal restore that never left the program |
| `B-28` | An SSH session is refused once in several hundred under sustained load | `166b980` The Fusion soak: B-28's fix holds, and its second signature is a separate defect |
| `B-29` | A userspace UDP socket could not send | `2fdbb00` B-29: a UDP socket could reply but never speak first |
| `B-30` | `operations-closure` blamed the wrong boot for a missing unclean record | `1d1787d` B-30: the gate blamed the wrong boot, and so did this tracker |
| `B-31` | `qemu-libc-gate` booted a RISC-V image its dependency never built | `b13f431` B-31: the libc gate reported PASS about a kernel that no longer existed |
| `B-32` | The CI permissions check could not see a job-level override | `b13f431` B-31: the libc gate reported PASS about a kernel that no longer existed |
| `B-33` | Two aggregate gates certified a `printf` for the DNSSEC path | `5e6661e` B-33: two aggregate gates were certifying a printf |
| `B-34` | `dns_self_test` reported three things it did not test | `49fe1b8` B-34, B-35, B-36: the DNSSEC cluster, and a gate that keyed on the symptom |
| `B-35` | One deadline covered a whole DNSSEC chain | `49fe1b8` B-34, B-35, B-36: the DNSSEC cluster, and a gate that keyed on the symptom |
| `B-36` | A malformed argument was reported as a DNSSEC failure | `49fe1b8` B-34, B-35, B-36: the DNSSEC cluster, and a gate that keyed on the symptom |
| `B-37` | The outbound SSH client could not run without a terminal | `e42b32a` B-37: the outbound client asked for a passphrase that did not exist |
| `B-38` | An SFTP session stalls when the file contains the alternate-screen sequence | `75e1fc7` The soak now counts what it used to glimpse, and B-38's leak does not exist |
| `B-39` | `core-os-rc`'s fragmentation step timed out once here, and timed out on CI | `720a580` B-39 was two causes and a reporting inversion, and the step now completes at 13% of budget |
| `B-40` | `send_all` could freeze the whole server for as long as a peer trickled | `24bb31e` B-40 and B-41: the two ways one peer could stop the server serving everyone |
| `B-41` | A failing channel was logged, never closed, and starved the ones behind it | `24bb31e` B-40 and B-41: the two ways one peer could stop the server serving everyone |
| `B-42` | The DNSSEC self-test fixture and its anchors ship in release images | `9bf7bdf` B-42: the fixture stays, and the claim about the anchors became checkable |
| `B-43` | A session stalls ~19 s and the guest says nothing about it | `7505946` The tracker has no open defect left, and none of the last four needed a code change |
| `B-44` | sshd is the machine's network thread, and nothing said so | `068903f` B-47 was reachable, and B-44 keeps its arrangement with the silence removed |
| `B-45` | Every 32-byte audit append rewrote the whole log file | `9b82034` B-45: the append stops rewriting the file, and the real cost turns out to be elsewhere |
| `B-46` | A full-size SSH packet would be refused rather than short-written | `c0b93a6` B-46: two numbers that had to agree, and nothing made them |
| `B-47` | A full socket map accepted the connection and dropped it silently | `068903f` B-47 was reachable, and B-44 keeps its arrangement with the silence removed |
| `B-48` | Every file write committed the whole metadata region | `201b6e0` A 32-byte append cost 640 KiB, and now costs 2 |
| `B-49` | A data sector number truncated above 32 MiB | `785f83c` A data sector number truncated above 32 MiB |
| `B-50` | The gate stopped reading the guest's console and then blamed the guest | `30f577e` The gate stopped reading the console and then blamed the guest |
| `B-51` | `qemu-fault-matrix` booted the machine's accumulated state, and said the wrong thing when that state failed it | `483625e` One architecture, one set of images |
| `B-52` | A machine that had run long enough stopped booting | `33af3f8` A machine that had run long enough stopped booting |
| `B-53` | Nothing stopped a packaging script from shipping a kernel built to fault on purpose | `483625e` One architecture, one set of images |
| `B-54` | The release-image gate passed a row that booted a kernel from the previous build | `52e5ed5` The gate said five environments booted the image; one booted the last build |
| `B-55` | Sixteen extents was a reachable ceiling; it is now sixty-four | `6ff063b` B-55 rested on arithmetic; here is the test |
| `B-56` | Every RISC-V boot in CI failed at a missing AArch64 artifact, and was reported as a guest that would not boot | `214d422` Every RISC-V boot in CI failed before QEMU started |
| `B-57` | `dd bs=1m` works on a Mac and fails on Linux, and CI is Linux | `fba3df3` dd bs=1m works on a Mac and fails on Linux, and CI is Linux |
| `B-58` | Two CI jobs were missing packages the work they run requires | `493894e` Two CI jobs were missing packages the work they run requires |
| `B-59` | A machine with no entropy source panicked at boot, in the self-test that exists to prove it refuses gracefully | `ee66efc` A machine with no entropy source panicked at boot |
| `B-60` | `qemu-operations-closure` required `ssh reboot` to exit cleanly over the connection the reboot destroys | `c742c0a` B-60 is settled: the operations closure passes on the runner |
| `B-61` | Two userspace linker scripts never collected RISC-V's small-data sections | `cdc6f74` Two userspace linker scripts never collected RISC-V small data |
| `B-62` | The Fusion soak's session tally counted closes it never counted accepts for | `4ddd7d8` Open a datagram socket on a port the kernel chooses |
| `B-63` | A session is accepted, receives nothing, and both ends time out separately | `4ddd7d8` Open a datagram socket on a port the kernel chooses |
| `B-64` | `qemu-cpu-matrix` accepted `--arch` and ignored it | `6c34115` qemu-cpu-matrix accepted --arch and ignored it |
| `B-65` | Seven required CPU tiers need a QEMU newer than the runner's | `0fe5ada` Seven RISC-V CPU tiers could not be tested on the runner |
| `B-66` | A three-architecture gate ran on a two-architecture runner | `dd9a88a` A three-architecture gate ran on a two-architecture runner |
| `B-67` | The RISC-V release image boots on macOS and not on the runner | `cdf3616` The RISC-V release image booted here and nowhere else |
| `B-68` | Eight RISC-V gates took a prerequisite that built half a machine | `6b63f8a` A prerequisite that built half a machine |
| `B-69` | The memory matrix believed a number that had not finished arriving | `4d1f2c4` The memory matrix believed a number that had not finished arriving |
| `B-70` | Whether other gates stall the guest the way B-50 did | `371c174` None of the other gates have B-50's fault, and reading them is how that is known |
| `B-71` | The operations closure waited 60s for a guest the runner interprets | `ba9d59f` The operations closure passes on the runner; nvme now fails on its merits |
| `B-72` | Fixing the nvme gate's RISC-V legs made it outgrow its budget | `ba9d59f` The operations closure passes on the runner; nvme now fails on its merits |
| `B-73` | The AIA board waits for an MSI-X interrupt that never arrives on the runner | `4d05a36` The AIA row costs 175 seconds, not 1643 |
| `B-75` | The kernel's answer to `net_open_udp` reached every field except the one that carried it | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-76` | XAIOS had no way to open a datagram socket with a port the kernel chose | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-77` | The kernel's ephemeral ports overlap the DNS resolver's and NTP's | `cb0a615` Three subsystems each believed the dynamic port range was theirs |
| `B-78` | A socket refused a listener row still reports a port that cannot receive | `94c709c` A listener row that was refused is now a refused call, and the ceiling is measured |
| `B-79` | The TLS 1.3 handshake has its pieces and a state machine, and no 0-RTT | `7505946` The tracker has no open defect left, and none of the last four needed a code change |
| `B-80` | Nothing on XAIOS could verify a server certificate | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-81` | The CertificateVerify verifier hashed into a buffer sized for SHA-256 | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-82` | The public key read out of a certificate pointed into a dead stack frame | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-83` | The EncryptedExtensions ALPN answer was read in a format RFC 7301 does not define | `fcd43d6` Renumber the port's tracker rows: main had taken B-61 to B-73 first |
| `B-90` | No P-384 or P-521 certificate has been through the verifier | `165e822` Two of the verifier's three ECDSA branches had never run |
| `B-92` | Two views outlived the buffers they point into, by contract rather than by construction | `a4e7271` B-92: the client owns the bytes it keeps, by construction |
| `B-93` | The client's flight was valid only until the next call | `58bd1fe` B-93: the flight can be asked for again, and says how long it lives |
| `B-94` | `qemu-readonly-medium-gate` fails on the runner about one run in four | `95ecdf0` The read-only-medium gate was racing itself, and B-94's premise was wrong |
| `B-95` | Twelve kernel calls printed a 64-bit value through a 32-bit specifier, or the reverse | `2510321` Nothing was checking klog's format strings, and thirteen of them were wrong |
| `B-96` | The kernel links every BearSSL source, including algorithms nothing calls | `a90b8ba` Stop linking the BearSSL ciphers XAIOS cannot negotiate, and run the xapt tests |
| `B-97` | `compile-check` compiled one configuration and every image ships another | `185d60f` Record B-97: the compile check compiled one configuration and the images ship another |
| `B-98` | `make xapt-test` had been failing and nothing ran it | `a90b8ba` Stop linking the BearSSL ciphers XAIOS cannot negotiate, and run the xapt tests |
| `B-99` | The Fusion load soak fails on node2 about one round in 64, and the guest is provably not the cause | `7505946` The tracker has no open defect left, and none of the last four needed a code change |
| `B-100` | The NVMe driver could read a completion while the device was still writing it | `9271e1d` The NVMe completion is read in one access, with the phase checked first |
| `B-101` | The published Wiki silently went backwards, and nothing failed | `212de96` Fix the Wiki publish race, and compare what is published |
| `B-102` | One format, two chunk-size caps, and the writer had the smaller one | `9eebf88` One format had two chunk-size caps, and the writer had the smaller one |
| `B-103` | The RISC-V installed-disk gate never ran, and nothing could make it | `ffb4a50` The RISC-V installed-disk gate could not run, and nothing said so |
| `B-104` | RISC-V could not boot an XAIOS-installed disk: a five-second join that was a speed assertion, and a kernel fault behind it | `6f4d16d` RISC-V boots an installed disk: close B-104 and B-108, open B-113 |
| `B-105` | The recorded cause of the x86-64 install skip was wrong, and it was recorded as established | `ffb4a50` The RISC-V installed-disk gate could not run, and nothing said so |
| `B-106` | The RISC-V libc leg's deadline was the one budget in the tree that ignored the declared host scale | `c5bab2d` Record the RISC-V leg's budget defect, its kernel fault, and a resolver that lied |
| `B-107` | A RISC-V panic said it was an AArch64 panic, and the resolver believed it | `c5bab2d` Record the RISC-V leg's budget defect, its kernel fault, and a resolver that lied |
| `B-108` | RISC-V could not boot an installed disk: the secondary hart stacks were a quarter of the size already proven too small, with no guard under them | `6f4d16d` RISC-V boots an installed disk: close B-104 and B-108, open B-113 |
| `B-109` | Every port's user-entry symbols were named after AArch64 | `e81e5f6` Close the symbol-naming defect and narrow the unrun-gate row to what is left |
| `B-110` | A panic dump was shredded by the other harts' logging, and on RISC-V it was not even given a quiet machine | `2b2d87c` Record a mask experiment that failed, and a symbol name that lied |
| `B-111` | The RISC-V panic dump printed every register under the wrong name, and ten of them from memory it never wrote | `f9fdd78` Correct the "frame sp=0" in B-108 and record the register mislabelling |
| `B-112` | The fault matrix and the update gates were gates that no CI job ran, on any architecture | `f09ccb7` Close the last unrun gate: the fault matrix runs on all three architectures |
| `B-113` | The storage-administration window was a device's position in one test bench's enumeration, so installing onto a blank disk could not work on a machine with fewer disks | `2bfee22` Record that all three architectures install, and the check that said otherwise |
| `B-114` | The install check could not pass on x86-64, and the first successful install there was reported as a failure | `2bfee22` Record that all three architectures install, and the check that said otherwise |
| `B-115` | The shared smoke booted a machine it had not asked for, so x86-64 had no milestone gate | `ffbbc5d` x86-64 has update evidence, and two defects that hid each other are closed |
| `B-116` | The x86-64 build was not the machine the test was written for: a control self-test asserted an AArch64 answer | `ffbbc5d` x86-64 has update evidence, and two defects that hid each other are closed |
| `B-117` | `klog` threw log lines away when the console lock was held, and said nothing | `1c48cb5` Record that the console was lossy, and what that means for old failures |
| `B-118` | The fault matrix had no x86-64 target, and would not have worked if it had | `f25c0bf` Record the three faults behind the missing x86-64 fault matrix |
| `B-119` | The console lock drops lines, so a gate can fail on a marker the kernel did print | `dbca02e` The console lock now waits in the context that can afford it |
| `B-120` | A wakeup consumed between an idle CPU's check for work and its halt left the thread pending | `d23f1f7` B-120 closed: the runner's own job passes the step that lost threads |
| `B-121` | The operations closure waits for a third durable lifecycle record that never arrives | `4203ffc` The administration window was seizing the machine's own disk, and that is why it could not reboot |
| `B-122` | The x86-64 time base was a guess of 1 GHz, so every timeout, sleep and clock reading on that architecture was scaled by the machine's real TSC over that guess | `2614c5a` The tick frequency is measured, not the host's interrupt latency |
| `B-123` | A CPU spinning with interrupts masked could not answer a TLB shootdown, and the x86-64 operations closure panicked on it | `0a25ffe` A CPU that cannot take the interrupt answers the TLB shootdown itself |
| `B-124` | The operations closure could not tell a refused reboot from a machine going down | `71d7f55` The closure reads the guest's answer to reboot instead of discarding it |
| `B-125` | The aggregate gate asked for an NVMe completion count the system never promised | `07db335` The aggregate asks for the NVMe phase's shape, not one host's count |
| `B-126` | The RISC-V image could not carry an SSH authorized-keys file, so the machine could not be key-administered | `73a434b` The administrative lifecycle runs on RISC-V, and found two defects doing it |
| `B-127` | `reboot` on RISC-V powered the machine off | `73a434b` The administrative lifecycle runs on RISC-V, and found two defects doing it |
| `B-128` | The lifecycle gate reported a probe that produced no output as a resolver verdict | `1ed58b8` A DNS probe that produced no output is not a resolver verdict |
| `B-131` | The completed WebTransport C99 tree is not in this repository | `37ca33d` Close B-131: the port's handshake gate is green on a booted guest |
| `B-134` | A real timer interrupt inside `scheduler_self_test` resumed the CPU at program counter zero | `04802bf` Record the IOMMU look, the deferred CAP read, and the self-test mask |
| `B-135` | A timer interrupt that arrived before the scheduler existed took the machine down | `21895a3` Record the CAP read, the kernel-stack carrier and the early-tick crash |
| `F-01` | Fusion multi-vCPU startup | `dd92da8` F-01 closes; V-06's Fusion boundary is blocked, and by what |
| `F-02` | VMXNET3 networking | `0be357e` F-02: the VMXNET3 fix, confirmed on the machine the row is about |
| `F-03` | Fusion network feature qualification | `44d9873` F-03: the chain this gate said it could not stage |
| `F-04` | Fusion snapshot and sustained-load qualification | `75e1fc7` The soak now counts what it used to glimpse, and B-38's leak does not exist |
| `F-05` | Fusion entropy and production-credential boundary | `3d98a26` The tracker was an implementation diary in a table |
| `OD-011` | Choose how the network is polled when sshd's loop is busy | `e288cf6` OD-011 stage three-b: the network tick, on AArch64 and x86-64 |

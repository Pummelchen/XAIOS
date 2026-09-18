# Changelog

XAIOS is identified by build number, single-sourced from
[`BUILD_NUMBER`](./BUILD_NUMBER). A build refuses to proceed if that file is
not a whole number, the running system reports the same number on its first
boot line and from `xaiosctl version`, and a released image is named for it —
so a support case, an advisory and a file on disk cannot disagree about what
is running.

There was a `MAJOR.MINOR.PATCH` version here, `0.1.0`. It was invented rather
than earned: nothing had shipped, so the three numbers recorded no history and
implied compatibility rules nobody had agreed to. A build number states the one
thing that is true — which build this is — and implies nothing further.

Nothing here is production supported, and the syscall surface is not frozen.
That remains the case until physical qualification is accepted rather than
deferred; see the [project tracker](./wiki/Project-Tracker.md).

Entries record what changed for someone *running* XAIOS. The commit history
records how it was built.

## Unreleased

Landed after build 7 and not in any released image.

- **The handshake gate can report its own failure.** When the booted guest
  reported that its handshake had timed out, the gate called
  `read_available(...)` -- a function no version of that file ever defined --
  and died with a `NameError` instead of reading the last lines of the failure
  and the peer's log. It never showed up here because the handshake completes
  on this host; the CI runner is the only place the path has ever run, and it
  reported a Python traceback rather than the reason the handshake failed.

- **The virtio-net packet self-test no longer overruns its stack buffer.**
  `malformed_packet_self_test` built a 54-byte ARP frame in `uint8_t packet[52]`
  -- `build_arp_request` writes `VIRTIO_NET_HDR_SIZE + 42`, and
  `VIRTIO_NET_HDR_SIZE` is 12 -- so every call wrote two bytes past the array.
  macOS clang happened to leave padding there and nothing was ever seen; the
  Linux CI compiler reused those two bytes for the caller's driver pointer, so
  the `virtio_transport_reset` on the next line read a garbage device and the
  RISC-V release image panicked during the kernel-services stage. It was found
  by booting the CI-built image here, where it halted identically, and
  symbolising the fault against the kernel extracted from that ISO:
  `load-page-fault`, `sepc` in `virtio_transport_reset`, `stval` a value no
  pointer in the image could be. The array is now sized by the builder rather
  than by a number, so it cannot drift from what is written into it again.

## Build 7 — 2026-09-17

**No source file is over 500 lines any more.** When this work started, 120
tracked files were, the largest of them a 5,157-line network stack and a
2,121-line build script; today the repository's own ratchet reports zero, and
the longest file is exactly 500. Nothing about the system changed: this is a
size limit met by moving code into modules beside it, verbatim, with the
behaviour checked by the gates rather than assumed from a clean diff.

The limit is enforced, not aspirational. `make docs-check` runs
`check-file-size-budget.py` against a baseline file that listed every offender:
a baselined file may not grow, a new file over the limit fails outright, and a
baselined file that comes back under the limit must be removed from the list
rather than left there. That last rule is what took the list from 120 to zero
entries over the campaign instead of leaving it as a record of past sins.

What made it tractable was the method rather than the effort. Extractions ran in
parallel, one agent per file, none of them building anything: each reported the
wiring its split needed, and the parent applied all of it in one pass and then
ran one verification pass over the result. Every batch ended with `make
compile-check` across all three architectures, a link of all three images, three
QEMU boots, and the area gates.

The gates earned their keep. A move that compiles and links can still panic the
machine: an extraction of `early.c`'s AP startup did exactly that, was reverted,
and landed only a dozen batches later once its seam had been reduced to four
scalars reached through accessors. An extraction of the RISC-V MMU linked
cleanly and then faulted on a null root, because it had renamed and thereby
lost three public entry points; the redo kept the file-scope state whole and
let the parent reach the root by address. Both are the reason every round ends
with a boot gate per architecture touched rather than a link.

Two public headers were split the same way, and the rule there was stricter than
for code: `userspace/include/xaios_control.h` and
`kernel/include/xaios/control_protocol.h` were cut into included sub-headers
with every macro, typedef, wire value and declaration order intact. A header
split that renames or reorders anything is an ABI change wearing a tidy-up's
clothes.

- **A VMware Fusion guest boots again.** Build 6's predecessor work made
  `klog` count the lines it drops when another CPU holds the console lock, and
  report them from the next line that gets through. On Fusion that report ran
  from inside the memory-management transition -- `vmm_init` logs the line
  after it enables translation -- and the first read of the new counter took a
  data abort, so every Fusion boot stopped at the cyan screen while QEMU was
  unaffected. Fusion places the kernel high in RAM; QEMU does not. The counters
  are now armed only once the kernel is on its own page tables
  (`klog_counters_ready`, called after `vmm_init`), which keeps the feature and
  removes the fault: the lines lost during the transition itself are not
  counted, and every drop after it is, exactly as before. Found by bisecting
  the 333 commits since build 6 with an automated build-and-boot test, then
  resolving the panic's `ELR` and `FAR` against the kernel's symbols -- the
  faulting instruction was in `klog` and the address was the counter. The same
  pass made the AArch64 boot mapper stop refining rather than write past its
  L3 table array if a kernel span ever exceeds the 32 MiB the early tables
  cover.

- **The interop peer compiles the vendored runtime with the vendored flag
  set.** With the archiver resolved, the same step failed on the *other*
  vendored tree: `third_party/webtransport-c99/src/core/time.c` wants
  `clock_gettime` and `struct timespec`, which a strict `-std=c99` build on
  glibc does not declare, and the peer compiled every vendored source with this
  repository's `-Werror`. Vendored sources now have their own flag set -- the
  feature macro they need, no `-Werror` -- while this repository's own sources
  keep both. Verified on Linux, not on the runner: an Ubuntu 24.04 container
  with clang 18 runs `make wt-interop-test` through all eight checks,
  `make wt-host-test` and `make wt-host-sanitize` with it.

- **The interop peer finds an archiver anywhere.** With the compile fixed, the
  same step failed on `llvm-ar: not found`: it hard-coded that name, and the
  Linux CI image ships clang and lld without it. The script now prefers
  `llvm-ar` and falls back to the system `ar`, which is the correct tool for a
  host archive. Two defects in one step, both of which had been invisible
  because a job stops at its first failing step.

- **The interop peer builds on Linux.** The host peer compiles the vendored
  BearSSL tree, and it compiled it with `-Werror`; on a Linux runner the POSIX
  entropy seeder calls `getentropy()`, which glibc declares only when
  `_DEFAULT_SOURCE` is set, so the strict `-std=c99` build failed on an implicit
  declaration in *upstream's* code. The vendored sources now compile with the
  same flags minus `-Werror` and with that macro defined, which is the rule the
  host-test runner already followed: a third-party portability warning must not
  read as an XAIOS defect. It was invisible until now because the job stops at
  its first failing step, and the host tests above it were failing first.

- **The WebTransport host tests link, and CI is no longer red because of them.**
  The runner compiles its own small BearSSL subset, and it carried only the
  *verify* half of the signature primitives: from the day the port started
  signing with a loaded key, `wt_xaios_x509.c` wanted four more sources
  (`x509/skey_decoder`, `rsa/rsa_i31_pss_sign`, `rand/hmac_drbg`,
  `ec/ecdsa_i31_sign_asn1`) and the link failed on five symbols. `make
  wt-host-test` is a CI job, so CI had been red ever since -- and a red gate
  hid a second defect behind it: the QUIC packet suite's split module used
  counter names that no longer existed, which nothing compiled until the link
  started working. Both are fixed; the eight suites report 1,572 checks, and
  `make wt-host-sanitize` and `make wt-vectors-check` pass with them.

**The VMware Fusion image builds again, and a stuck build now says so.**

- **`make vmware-fusion-image` no longer hangs.** The chainloader step ran
  GRUB's `grub-mkstandalone` inside a container, and that wrapper -- a compiled
  program that shells out to `tar` and reads the result back through a pipe --
  never returned on this host: a `docker run` of it sat for eighty minutes at
  0.08s of CPU with the release build stopped behind it, no error, and nothing
  printed to say where it was. The chainloader is now built with `grub-mkimage`
  over a memdisk, which is what standalone passes to it anyway -- the same
  modules, the same embedded config, the same output path -- and the container
  is fed through a pipe rather than given bind mounts, because a `--volume` of
  this tree stopped starting the container at all here. A release should not
  depend on the host's file sharing layer behaving, and both docker runs are
  now bounded, for the same reason the image build above them already was.

Three build scripts went the same way as the C: `scripts/build-image.sh` from
2,121 lines to 398, `scripts/build-riscv64-image.sh` from 741 to 63, and
`scripts/build-vm-packages.sh` from 661 to 124, each by extracting verbatim
blocks into `scripts/lib/*.sh` sourced in place. The proof there is mechanical
rather than a diff: replacing each `source` line with the body of the file it
sources reproduces the original byte for byte. The `Makefile` went from 1,656
lines to 91 as eight `mk/*.mk` fragments, verified by comparing all 244 target
definitions and all 315 `make -pn` entries before and after.

Three repository checks read the text of the source they audit, and two of them
had to be updated when the code they read moved: the x86 NUMA gate greps the
IDT trap-gate idiom out of `early_idt.c` now, and the panic-register check reads
the renderer from `panic_render.c`. The assertions are unchanged in both cases,
and that is the point worth recording: those checks pin an implementation
*location* as well as a property, so a split that moves the code must update
them, and a split that does not move it must not.

The wiring was where the mistakes were, not the moves: a `$CFLAGS` that did not
exist in one builder, object lists appended to a compiler's `-o` line three
times, a Makefile pattern that was a substring of another line, and the same
object name meaning different things in different architecture branches. Every
one was caught by a build and none by reading, which is why the campaign never
trusted a diff alone.

- **A real PCI virtio function's DMA is translated by the RISC-V IOMMU.** The
  queue rings a virtio PCI transport hands to a device are given an Sv39
  first-stage context before the device is told where they are: the table
  identity-maps memory, each ring address is resolved back out of it before
  the mapping is claimed, and the entropy source's self-test reads are DMA
  that reached those rings through the walk. Isolation between mediated
  functions and a table that maps to different addresses are what remains,
  and `virtio-mmio` still cannot be mediated at all (B-130).

- **A booted XAIOS guest completes a WebTransport QUIC and TLS 1.3
  handshake.** The port's client is packaged as `/bin/wtqtest` and driven
  by `make qemu-quic-handshake-gate` against the same host peer the interop
  test uses, with the guest pinning the peer's certificate. Two seam
  defects only a guest could find came out of it: every receive was
  rejected for asking the kernel for more bytes than its socket buffer
  holds, and every received datagram was reported with a zero source port,
  so the client discarded the whole server flight as coming from a
  stranger. Both are fixed, and the second is now a documented limit: the
  seam can be a client but not a listener (B-131).

- **The WebTransport C99 port completes a TLS 1.3 handshake with itself.**
  Signing is no longer refused: a DER private key is parsed with BearSSL's
  key decoder and RSA-PSS (fresh salt per signature, from an HMAC-DRBG
  seeded by platform entropy) or ECDSA signs with it. A host handshake
  endpoint drives the vendored runtime session on both sides -- one binary,
  both roles, no OpenSSL anywhere -- and `make wt-interop-test` observes a
  completed QUIC v1 + TLS 1.3 handshake with a pinned certificate, plus the
  negative controls a positive case cannot replace: a wrong fingerprint is
  refused with `trust`, and so is the development bypass asked for off
  loopback. The test runs in CI. It also found that the session driver
  itself had never been compiled by the port's compile check, and that the
  check's object names collided across directories (B-131).

- **The WebTransport C99 port has its crypto backend, and the vendored tree
  is down to one OpenSSL file.** SHA-256 (with the transcript snapshot TLS
  1.3 needs), HMAC, HKDF, HKDF-Expand-Label, AES-128-GCM, ChaCha20 and
  `xaios_random` are bound to BearSSL in `userspace/wt/xaios/`, and X25519
  is the ladder this repository already checks against RFC 7748 -- moved to
  its own source file so the in-tree module and the port link one copy.
  Published vectors for all of it run in `make wt-host-test` (39 checks),
  and the first run found two real defects: an empty AEAD message was
  refused for want of an output buffer, and a second `final` hashed a zeroed
  context instead of reporting `WT_ERR_STATE`. Only `src/tls/trust.c` still
  calls OpenSSL, and it is next (B-131).
- **The WebTransport C99 port no longer has an OpenSSL file.** The trust
  policy (pinned fingerprints, a loopback-only development bypass, named
  refusals for platform store and PEM bundle), the SubjectPublicKeyInfo
  reader, and the RSA-PSS and ECDSA scheme dispatch are now this
  repository's code; the port reaches them through an opaque-key bridge
  because its crypto header and this repository's declare the same names
  for different types. The whole client stack -- `api/`, `webtransport/`
  and `http3/` included -- compiles: 78 sources per architecture with
  nothing missing. The port's host binary checks the trust policy against a
  real ECDSA certificate and signature. A differential test against
  BearSSL's own X.509 decoder found a DER length bug in the new reader on
  its first run (B-131).

- **The WebTransport C99 port has its XAIOS platform seam, and the library's
  remaining surface is four files.** The vendored library keeps every
  operating-system difference behind one private header, and that header is
  a POSIX branch; `userspace/wt/xaios/` supplies the same operations over
  XAIOS's UDP syscalls and clock instead, so the vendored tree stays exactly
  upstream's. `make wt-upstream-compile` builds them against the hosted libc
  sysroot: 37 sources for each of the three architectures, no errors, and it
  names the four that still call OpenSSL -- the crypto primitive backend and
  the three TLS files that use OpenSSL directly. Everything else compiles
  unmodified, which is the integration plan's claim measured rather than
  estimated. The BearSSL backend and the handshake gate are what follow
  (B-131).

- **The completed C99 WebTransport library is vendored, at a pinned commit.**
  `third_party/webtransport-c99/` holds upstream `C99/include` and `C99/src`
  whole -- the QUIC wire core and crypto, the TLS 1.3 handshake over CRYPTO
  frames, the connection runtime, HTTP/3 and QPACK, the draft-16 session layer
  and the public API, 166 files -- copied from
  `46937e29eb734887ca7b739abfedaf68ae565de2` with its MIT licence. Nothing in
  it has been edited: `MANIFEST.sha256` records every file's hash and
  `make docs-check` verifies it, so a local change to vendored code fails the
  build instead of quietly forking upstream. Upstream's `platform/`
  directories were not copied, because they hold build scripts and no C: the
  port's real seams are the socket header, the clock and the crypto
  primitives. The XAIOS platform layer and the handshake gate against this
  code are the work that follows (B-131).

- **A RISC-V machine with a PCI IOMMU attached now mediates PCI DMA, and one
  boot proves translation, refusal and isolation.** A board booted with
  `-device riscv-iommu-pci` and two `iommu-testdev` instances is programmed by
  `kernel/arch/riscv64/iommu.c`: a 1LVL device directory of 64 extended
  contexts, command and fault queues, an `IOFENCE.C` round trip and an
  `IODIR.INVAL_DDT`, with a pass-through context for every enumerated PCI
  function installed in the same step that leaves `Bare`. The device refuses
  all PCI DMA out of reset, so that ordering is what keeps the machine
  booting -- and it still boots to a login prompt with SSH. Sv39 and Sv48
  first-stage tables then translate an `iommu-testdev`'s DMA (`result=0x0
  target=0x12345678`); clearing the mapping and invalidating refuses the same
  transaction with a first-stage fault (`cause=15`), and a second test device
  that was never given a context is refused with `DDT_INVALID` (`cause=258`).
  `make qemu-riscv64-iommu-gate` boots exactly that and requires both refusals
  in the fault total rather than the summary line alone. The plain `virt`
  board still has no IOMMU, and now says so as the result of a probe; this
  board's `virtio-mmio` devices cannot be mediated at all, because the device
  is attached to the PCI bus and to nothing else (B-130).

- **An EL0 process is preempted now, and one boot carries both the proof and
  its control.** The corrected measurement recorded below read a spinner's two
  switches as "EL0 is not preemptible"; the dispatching context had blocked
  itself, so the spinner was the only runnable task and the scheduler was
  right to keep picking it. The dispatcher now stays `RUNNABLE` at the
  process's own priority and is re-queued behind it, so the two alternate, and
  `/bin/spin` -- a process that loops in EL0 for 1.2 seconds, never yields and
  reads the clock once per burst -- is dispatched twice in one boot. With the
  dispatcher runnable the boot records `kernel: /bin/spin preempted pid=7
  switches=86` and requires at least four, because two switches are the
  dispatch and the hand-back and nothing else in that window can add a third.
  With the dispatcher blocked it records `kernel: /bin/spin blocked dispatcher
  pid=8 switches=2` and requires strictly fewer: same process, same span, one
  difference, which is what keeps the first number honest. A port that cannot
  start a task in kernel mode says so and runs neither (B-132).

- **That proof found a scheduler defect, and it was why the first attempt
  stalled.** A task that is picked is removed from its run queue, and the tick
  reschedules every tick while a task's state is `RUNNING` -- so a task
  switched away from before its slice expired was left in no queue at all: it
  could never be chosen again, and the CPU went idle one tick later while the
  abandoned task kept running on a frame the scheduler had stopped saving.
  With one runnable task nothing noticed, because the pick chose the task it
  had just removed and returned without switching; two tasks at the same
  priority lose each other. The tick now puts the running task back before
  choosing, `scheduler_self_test` alternates two equal-priority tasks and
  requires whichever is not current to still be in the queue -- a check that
  fails without the fix -- and the blocked and runnable spinner runs above are
  the behavioural pair (B-132).

- **The EL0 preemption measurement from the last change is corrected: it
  measured the test's own design, not the port.** The spinner ran 1.2 seconds
  in EL0 with two switches, which read as "not preempted" -- but the
  dispatching context was blocked while it waited, so the spinner was the
  only runnable task and the scheduler correctly picked it again instead of
  switching. A measurement of preemption needs a second runnable task (the
  kernel-context test had one, which is why it counted switches); the
  dispatcher staying runnable is the fix, and the blocked case is the
  negative control (B-132).

- **A user process can now be a scheduled task rather than a call that
  returns on the caller's stack, and on RISC-V it is.** The process gets a
  kernel stack of its own and is entered from a task entry that runs on it;
  when it exits, the task hands the CPU back through the scheduler to the
  context that dispatched it instead of unwinding into it. A boot records the
  whole round trip -- dispatcher waiting, the switch into the task, `/bin/hello`
  running in EL0, its exit, the hand-back, the switch back and
  `scheduled dispatch pid=6 switches=2 exit_code=0` -- and the riscv64 smoke
  requires it. The scheduler also re-establishes the per-CPU process binding
  on every switch, without which a preempted process would resume with the
  binding of whatever task displaced it and have its syscalls checked against
  another process's capabilities. A port that cannot start a task in kernel
  mode falls back to the old path and says so (B-132).

- **A user process that exits no longer leaves the kernel with interrupts
  off on RISC-V.** The exit return path leaves through `ret` rather than
  `sret`, so it never restored the interrupt enable that a trap from user mode
  clears: the kernel continuation after every process exit ran with interrupts
  off for the rest of its life. Nothing had noticed, because that continuation
  is normally a few instructions from `timer_disable()` -- and it stopped a
  scheduled user task dead, since the context waiting to be handed the CPU back
  never received another tick. The same path also left the *user* stack pointer
  in `sscratch`, which the next trap entry reads as "this trap came from user
  mode". Both are fixed, and the boot gate records the property, asserting it
  on this port: `kernel: /bin/xaios-worker pid=3 returned to kernel
  exit_code=0 interrupts=1` (B-132).

- **Two preempted tasks no longer share one set of floating-point
  registers.** The RISC-V trap stub saves and restores `f0`-`f31` and
  `fcsr` with the rest of the context, and the frame carries them, so a task
  resumed after a switch finds its own values. The proof is behavioural
  rather than a mapping round-trip: the context that gives the CPU away
  writes a value into `f0`, the task that runs meanwhile writes a different
  one, and the boot requires the first context's value back --
  `... switches=3 fp_kept=1`, asserted. Two port details make it safe: the
  stub switches `sstatus.FS` on for its own duration, because an `fsd` with
  the unit off is an illegal instruction taken inside the trap entry, and it
  skips the restore for a frame whose `FS` says the unit was off, because
  those values are not live (B-132).

- **A kernel context can hand the CPU to another task and get it back,
  which is the piece preemption was missing.** `scheduler_register_kernel_task()`
  builds a task whose frame starts it in kernel mode on a stack of its own,
  `scheduler_adopt_this_context()` registers the context that is running now
  so a tick can save it and hand the CPU over, and the new
  `platform_kernel_preemption_self_test()` uses both: the boot context blocks
  itself, the timer switches to a second kernel task on its own stack, that
  task makes the first runnable again and blocks itself, and the next tick
  brings the first back -- with the runs and switches printed and asserted:
  `switch 30001 -> 30000`, then `switch 30000 -> 30001`, then
  `kernel-context switch registered=1 ran=1 runs=1 switches=3` and the pass
  line. **The ordering is part of the contract, and it was found by getting
  it wrong:** the new task is registered *not* runnable, the caller adopts
  the context that will hand the CPU over, and only then is the task made
  runnable -- the first version made it runnable at registration, a tick
  landed in that window, and the CPU left a context whose frame had never
  been saved and died at program counter zero. RISC-V can build such a frame
  because its trap return loads `sp` from the frame and takes the privilege
  from `sstatus`; AArch64 refuses by name because its exception return keeps
  the CPU's `SP_EL1`, and x86-64 because it does not tick the scheduler from
  a trap at all (B-132).

- **A timer interrupt that arrived before the scheduler existed no longer
  takes the machine down.** The scheduler's current-task accessor read its
  run queues without checking that they had been allocated, and this port's
  timer is armed at 100 Hz for the exception self-test long before
  `scheduler_init()` runs, so a tick in that window loaded from a null run
  queue and the boot ended in `class=load-access-fault stval=0x210` --
  `current_pid`'s offset in that array. Both accessors answer "no task"
  when there is no scheduler yet, which is the same answer (B-135).
- **The RISC-V trap frame now carries the kernel stack its next user-mode
  trap must land on.** The stub records it at entry and the trap return arms
  `sscratch` from the frame rather than from the stack the trap was taken on
  -- the one value a context switch has to carry for the incoming task, and
  the reason a switched-to task's next syscall would otherwise unwind the
  outgoing task's continuation with its own exit code. A machine that never
  switches behaves exactly as before, and the mapping self-test asserts that
  a frame naming no stack cannot move one (B-132, B-129).

- **A timer interrupt inside the scheduler's own self-test could send the
  machine to program counter zero.** `scheduler_self_test` registers three
  tasks whose context frames are a zeroed dummy -- that is what it needs to
  test the pick and the frame write-back -- and a real timer interrupt
  taken in that window ticked the scheduler for real, picked one of them,
  and resumed at its `elr_el1` of 0x1000. AArch64 has applied the frame it
  is handed since it had a tick and so carried the hazard all along; the
  RISC-V tick landing made it reachable and one boot in a handful took it,
  which is how it was found (`scheduler[cpu0]: switch 0 -> 1 ... switch
  1 -> 2` and then `user exception: cause=12 sepc=0x0`). Interrupts are
  masked across the window that registers the fake tasks now, so the
  window is atomic with respect to the mechanism under test (B-134).

- **The RISC-V timer interrupt ticks the scheduler now, and measuring it found
  the reason no EL0 process is preempted on any of the three architectures.**
  The port's trap frame is mapped to the scheduler's context frame in both
  directions, the tick is taken from the timer trap unless that CPU carries the
  network tick, and the answer is written back into the trap frame the return
  resumes; a round-trip self-test covers the mapping and the smoke requires it
  by name (`sched-tick: riscv64 trap-frame mapping self-test passed`). The same
  self-test machinery then counted what the tick actually does, and a boot with
  the worker gate prints `sched-tick: riscv64 user-context tick pid=0 -> pid=0
  ... switches=0`: the tick arrives from EL0 and the scheduler has nothing to
  switch to, because `user_process_run` -- the only path this kernel runs a
  process through -- never registers one, and the single function that does has
  no callers. The worker gate's three processes run to completion one after
  another on the same user stack. **On x86-64 the timer tick that could not
  apply a switch was removed rather than left half-working:** it passed the
  scheduler a context frame nothing filled, saved zeros as the preempted task's
  context and moved the scheduler's idea of the current task without moving the
  CPU, and its self-test now says why by name -- a real switch needs per-task
  kernel context (B-129, B-132).
- **The RISC-V board's IOMMU now has a contract written down rather than an
  assumption.** `docs/RISCV-IOMMU.md` records what QEMU 11.1.1 implements for
  `-device riscv-iommu-pci` -- its requestor id, `CAP`/`DDTP`/queue
  registers, 1LVL device directory and contexts, the Sv39/48/57 tables the
  port already has, its four command opcodes and its fault causes -- and the
  three findings that shape the work. The IOMMU attaches to the PCI bus and
  to nothing else, so the RISC-V runner's virtio-mmio root filesystem cannot
  be mediated on this board at all and only the PCI transports can; the
  moment `DDTP` leaves Bare, every PCI function without a context stops, so
  identity contexts land in the same step that programs it and the driver
  bails out to Bare if the capability read fails; and faults reach the fault
  queue however they are notified, so polling is sufficient evidence on the
  board that has no usable MSI-X. **The first milestone is landed:** the
  port looks for the device over PCI rather than asserting its absence and
  names it and its BAR, with the no-device sentence now the result of that
  look and the evidence that produced it printed beside it, and the device's
  own capability register is read and decoded once its BAR is mapped: QEMU
  places that BAR at 0x400010000, above the window this port identity-maps,
  so mapping the page is what makes the register reachable rather than
  fatal. On the board that carries the device:
  `riscv-iommu: found device=5 base=0x400010000 cap=0x78c2cf4f10 version=0x10
  sv39=1 sv48=1 sv57=1 igs=0` -- version 1.0, every page-table format, and
  MSI-only fault notification. Nothing is programmed -- the device resets
  refusing PCI DMA -- and the look runs in `smmu_self_test()` because
  `smmu_init()` is called before PCI enumeration (B-130).
- **The completed WebTransport C99 library was assessed for integration, and
  the answer is a backend layer rather than a platform directory.**
  `docs/WEBTRANSPORT-C99-INTEGRATION.md` records the seam that matters
  (`C99/src/runtime/udp_platform.h`, `CLOCK_MONOTONIC` in `src/core/time.c`, and
  the twenty crypto primitives), the eleven assumptions to fix, the fact that
  no syscall change and no threads are needed, and the two things that are not
  one-file changes: Picolibc declares `clock_gettime` but implements it only for
  Linux, and the crypto seam does not cover X.509 or X25519, so a backend swap
  touches four TLS files rather than one. One in-tree claim was found false and
  corrected: `userspace/wt/include/wt_crypto.h` said BearSSL has no Poly1305 and
  no RSA-PSS, and the vendored tree has four Poly1305 implementations and six
  PSS files (B-131).
- **The machine no longer stops when a CPU cannot take an interrupt, and the
  NVMe driver no longer invents completions.** Both were defects in the same
  family: a device or a CPU answering a question that had been asked at the
  wrong moment. On x86-64, a CPU spinning with interrupts masked -- which is
  what waiting for the network, service or CPU-AI guard is -- could not take
  the inter-processor interrupt a TLB shootdown waits for, while the CPU it was
  waiting for held that guard and was waiting for its answer; the machine
  panicked after two seconds with `TLB shootdown timeout` (B-123). The spin
  itself now answers the shootdown, so the wait ends when the other CPU lets go
  rather than when a timer gives up. Separately, an idle CPU that asked whether
  there was work and then slept could have its wakeup consumed in the gap and
  sleep with the thread still pending, forever, because only one CPU carries a
  periodic tick (B-120); all three ports now ask once more with interrupts
  masked and sleep and enable them together.
- **A RISC-V machine can be administered over SSH again, and the image said so
  by refusing to build.** The initial filesystem holds a fixed directory of 64
  entries and the RISC-V image used all 64, so adding the SSH authorized-keys
  file -- the difference between a machine that serves SSH and one an operator
  can log in to -- failed the build with `too many initfs files`. The ceiling
  is the format's own (80 records at a 64-byte path are what fit in the 8 KiB
  directory) and is now 80, with the kernel's table and the builder's checked
  against each other by the ABI contract rather than trusted to be edited
  together (B-126).
- **`reboot` on RISC-V restarts the machine instead of stopping it.** The port
  asked SBI's system-reset extension for a *shutdown* and called it a reboot,
  so a guest told to reboot powered off and never came back. It asks for a cold
  reboot now, and `shutdown` still asks for the shutdown it always meant. The
  administrative lifecycle gate found this the first time it ran on RISC-V --
  it boots, is told the previous boot was unclean, reboots over SSH, is driven
  through the control surface and shuts down cleanly (B-127).
- **Storage on RISC-V no longer misreads completions.** The NVMe driver copied
  a completion out of the completion queue and then checked the phase tag, and
  the copy is not a single access: the command identifier and the status share
  one word and the compiler reads them separately. A completion the device was
  still writing was therefore read as a fresh phase with a command identifier
  of zero, which matches no request and looks successful -- and the request
  behind it was then lost, which is why a starved guest saw the stress phase
  fail with `XAIOS_ERR_IO` (B-100). The driver reads that word once and checks
  the phase before reading anything else.
- **The console still drops a line under load, but it now loses fewer and says
  where.** A contended line waits for the console lock, and how long it waits
  was chosen by whether interrupts were masked rather than by whether the CPU
  was inside a handler -- so a line printed from a thread holding a spinlock
  took the short wait meant for a handler and could be lost (B-119, second
  sighting). It asks the right question now, and the report names the context
  so a loss says which budget was wrong.

- **A broken link, rather than a broken machine -- and a split brain found
  underneath it.** Everything the cluster had been tested against was a
  process that stopped: a node killed outright stops answering and stops
  sending, and nobody on the far side of it is deciding anything. A partition
  is the other case, both machines alive, each hearing nothing from the other,
  each deciding on its own. `make qemu-cluster-partition-gate` produces one:
  a fault-injecting relay carries every heartbeat between the three guests,
  one TCP listener per ordered pair, and it can be told to stop carrying in
  one direction or in both while every machine keeps running. Cut every link
  to one node and the cluster does the right thing -- the two that can still
  hear each other keep serving and take over only the cut-off node's experts,
  the cut-off node reports one of three, no quorum, and refuses to answer who
  owns what, and it does that while still alive and still knocking (the relay
  counts the connections it refuses from it, so this is not the node's own
  account of itself). Repair the links and all three converge back on one
  membership and on exactly the ownership map they started with. Cut only
  ONE node's outbound links, though -- heard by nobody, hearing everybody,
  which is what a failed transmit path or a one-way firewall rule looks like
  -- and the cluster splits its brain: the other two write it off and reassign
  its experts while it goes on counting three live nodes and owning them, and
  six of eight experts end up with two owners while both sides pass their own
  quorum test. The arithmetic is right and its input is not: a node judges its
  peers by whether their frames arrive and is never told whether its own are
  arriving anywhere, so liveness is decided alone rather than mutually. That
  is a real defect, it is recorded in D-06, the gate is red on it, and the
  check is not to be relaxed to make the gate green. A node that loses quorum
  now stays running instead of exiting when it is built for this gate, which
  is what makes the repair testable, and it states what it believes every five
  seconds so that two sides of a partition can be compared at one instant
  rather than across two different pasts.
- **A node that stops answering is now noticed, and three of them can decide
  what to do about it.** Cluster membership moved only on frames that said
  what they meant: a node announced a departure and its peers believed it.
  Machines do not usually fail that way -- they lose power, panic, or have a
  cable pulled, and the only evidence anyone gets is that nothing arrives any
  more. Peers now carry a last-heard time and a deadline, and a peer that has
  gone quiet for longer than the deadline is taken offline; a peer that has
  never spoken is left alone, because that is a slow boot rather than a death,
  and a clock that has gone backwards expires nobody. `make
  qemu-cluster-three-node-gate` runs three XAIOS machines heartbeating to each
  other every 500ms, kills one emulator outright, and requires the survivors
  to notice by silence -- they do, four milliseconds past a twenty second
  deadline -- to agree on the membership that is left, and to move only the
  dead node's experts rather than reshuffling all of them. Three machines
  because quorum does not exist at two: kill a second one and the last machine
  reports one of three, no quorum, and refuses to answer who owns what at all,
  since somewhere behind that silence there may be two nodes that can still
  see each other and are entitled to decide. An expert with two owners is not
  an error anybody detects; it is work done twice and a result nobody
  reconciles.

- **RISC-V can lease a core, and its harts come online before the tests that
  need one.** Leasing a hart out of the scheduler answered "unsupported" here,
  and secondaries did not exist until the scheduler rendezvous -- so every
  self-test between bring-up and that point saw a uniprocessor, and the AI
  cell lifecycle skipped itself rather than failing, which read as an absence
  of tests rather than an absence of a feature. Secondaries now come online
  once the address space, allocator, interrupt controller and timer exist,
  and hold at a gate they sleep on until scheduling opens; leasing is
  implemented. RISC-V runs the same boot closure as AArch64: 206 of the 212
  markers are shared, and the six that are not are each machine describing its
  own hardware -- a PLIC is not a GIC, and a gate that demanded ARM's words
  would measure imitation rather than function.

- **An idle machine costs a fifth less.** Waiting for a socket re-derived the
  answer every millisecond: a walk of the whole socket table under its lock,
  then, per socket the waiter owned, the network lock and a walk of the flow
  table. The stack now marks the points where a socket can become readable --
  a frame arriving, a connection queued on a listener -- and a wait re-derives
  readiness only when one of them has happened. The device's interrupt also
  ends the sleep rather than being waited out, so a frame is noticed when it
  arrives instead of at the end of a slice. Measured on an idle guest as host
  CPU over two minutes: AArch64 fell from 4.8% of a core to 3.8%, twice each
  way; x86-64 and RISC-V moved within noise and neither regressed.

## Build 6 — 2026-09-12

One image per architecture, instead of one image for all of them.

Up to build 5 a release was a single ISO carrying an AArch64, an x86-64 and a
RISC-V loader, kernel and initial filesystem, and UEFI made that work: firmware
picks its own loader from the removable-media path and never sees the others.
It was genuinely one deliverable. What it was not was easy to reason about. A
boot that went wrong had three kernels, three initial filesystems and three
loaders on the medium to be wrong about; the file was 220 MB of which about
thirty was payload; and an architecture whose build had quietly not happened
produced an image that still booted on the machine that built it and not on the
machine it was carried to.

So a release is now three images, and every kit built from one is built for one
machine:

| | AArch64 | x86-64 | RISC-V |
|---|---|---|---|
| image | `xaios_b6-aarch64.iso` | `xaios_b6-x86_64.iso` | `xaios_b6-riscv64.iso` |
| USB | yes | yes | yes |
| network boot | yes | yes | yes, untried on hardware |
| QEMU | yes | yes | yes |
| VMware Fusion | yes | — | — |
| Virtualization.framework | yes | — | — |

RISC-V reaches the same shelf as the other two for the first time. It had a
loader in the shipped image and nothing else: no USB kit, no network-boot
binary in the kit anyone downloads, no launcher. It now has all three. The
network-boot binary is the one thing here that has never been fetched by real
firmware -- no RISC-V machine that netboots has been in front of this project
-- so what is unproven is the fetch and the DHCP option-93 selection rather
than the system inside the binary, which boots from a medium in this tree like
the other two. That is stated in the kit's own README rather than left to be
discovered.

Fusion and Virtualization.framework are AArch64 only, and that is a fact about
the host rather than a gap: both run guests on the machine's own cores, so an
x86-64 or RISC-V guest there would be emulation, which is what the QEMU kits
are for.

The two images that no longer have to hold three architectures are much
smaller: 78 MB for x86-64 and 84 MB for RISC-V, against 220 MB before, which
is under the limit that made a zip mandatory rather than merely tidy. The
AArch64 image keeps its 96 MiB EFI System Partition and its size, because that
is the partition VMware Fusion's firmware boots and 96 MiB is the only size it
has ever been given; shrinking it is a Fusion re-qualification rather than an
edit.

**A machine that had run long enough stopped booting, and now does not.** A
file is at most sixteen runs of blocks. The allocator took the first sixteen
free runs it found, in address order -- and the low blocks of a volume are the
most broken up, so on a volume that had been written and rewritten for a while
it collected sixteen fragments out of the rubble at the bottom and never
reached the long runs above them. The write was refused with the volume
two-thirds empty. Because the same path snapshots a file, and because the
update self-test stages a snapshot on every boot and asserts that it worked,
the machine halted in the cyan screen instead of coming up. `fsck` called the
volume sound, and it was: nothing was corrupt, the free space was simply in the
wrong shape. The machine this is developed on had got there after 64 boots.

Blocks are now taken longest run first, which is the best any policy can do
against a sixteen-extent limit -- if the sixteen longest runs cannot cover the
file, no sixteen can. Nothing on disk changes shape; existing volumes read
exactly as before. Sixteen extents is still a ceiling and a volume can still in
principle be aged past it, which is recorded rather than claimed fixed.

Three things that could not fail before now can. The image builder asks
`mformat` what filesystem it actually produced rather than trusting that the
size implies FAT16, which is the property Fusion silently depends on. The
release builder refuses to package an architecture it was asked for and cannot
find, instead of skipping it in a line that scrolls past. And a kernel built to
fault on purpose -- `make qemu-fault-matrix` compiles three of them, into the
same path every packaging script reads -- now says so in its own bytes, and
both packaging scripts refuse it without booting anything.

Released as three images, one per architecture, with eleven kits beside them.
See [the release note](./release/xaios_b6.md), and
[docs/BUILD-PROCESS.md](./docs/BUILD-PROCESS.md) for how a build is produced.

## Build 5 — 2026-09-05

XAIOS on a third architecture, a process monitor that costs almost nothing
to watch, and a machine that is idle when nothing is happening.

Released as `xaios_b5.iso` with the same five kits. See
[the release note](./release/xaios_b5.md).

### Added

- **RISC-V (rv64gc) is a third architecture.** The image carries a RISC-V
  kernel and initial filesystem beside the AArch64 and x86-64 ones, and
  firmware picks among the three. On QEMU's `virt` board it boots to the
  login prompt with sshd answering, runs programs as processes, boots from
  its own signed A/B medium through EDK2, and does so at one, two, four and
  eight harts, with six gates behind it. What it does not have is a
  machine: no RISC-V hardware has run it, and the unified image itself has
  not been booted on RISC-V by any gate — the RISC-V gates boot a RISC-V
  medium built from the same commit.
- **`xtop`, the process monitor, redrawn after mactop.** Renamed from
  `htop`, because it reads XAIOS's own runtime snapshot and a Unix name
  implied a compatibility it does not have. Three layouts (`L`): gauges and
  per-core meters; a Platform panel that says what the machine has (NEON or
  SVE, AVX2/AVX-512/VNNI/AMX, or the RISC-V vector extension and Sstc) beside
  the AI runtime; and history charts with network and disk rates. `-` and
  `+` set the sampling cadence from five seconds down to sixteen
  milliseconds. It runs as one process per session and draws the same
  picture on the framebuffer console as in an SSH client, which a gate holds
  it to on all three architectures. A fresh machine reports no failed tasks:
  the hosted C99 probes that exit non-zero on purpose are recorded as
  exits.
- **A screen framework for the whole system.** A program that draws a
  screen no longer redraws it: what reaches the terminal is only the cells
  that changed, positioned with cursor moves. Every program that uses the
  alternate screen — the editor, the pager, the game, anything to come —
  gets this from the session, over SSH and on the local console, without
  code of its own; `xtop` draws into the framework's cells directly. `pong`
  over SSH, which redraws its whole screen sixty times a second, went from a
  screen clear per frame to about a hundred and forty bytes a second.
- **Two ways for a process to wait.** A sleep, and a wait that blocks until
  console input, activity on a socket the process owns, or data or an exit
  on a child channel is there (syscalls 53 and 54, `XAIOS_CAP_TIME`).
  Nothing in userspace had a way to wait that was not polling a clock.
- **IPv6 reaches beyond the link.** The stack learns the default router
  from router advertisements, sends off-link traffic through it, and answers
  from the address that was asked for; the e1000e driver accepts multicast,
  which is where all of IPv6 lives. F-03's IPv6 leg is qualified on the
  platforms here.
- **Two machines join, partition and recover.** `make
  qemu-cluster-two-node-gate` now runs the membership half of D-06 on top
  of the sealed transport it already had: each phase on its own connection,
  both ends logging the owner of one fixed expert as the other joins,
  leaves and dials back.
- **Snapshot and resume semantics are demonstrated, not described** (F-04):
  data committed before a snapshot survives a revert and data after it does
  not, a revert lands on a volume the guest trusts, and a suspend is not
  counted as a crash.
- **A VMXNET3 driver that brings the device up on VMware Fusion.** Receive
  works; transmit still does not, and F-02 is now bounded by measurement
  rather than suspicion — the two leading theories were ruled out by
  evidence. Fusion's traffic still goes over e1000e.
- **virtio-net asks for every queue pair a device offers, and RSS with
  them.** The driver still services one queue; this is where multiqueue is
  developed (E4).
- **An SVE packed kernel** for the quantized row product, selected ahead of
  NEON where the CPU has SVE and only after reproducing the scalar
  reference (P-07).

### Changed

- **An idle machine is idle.** `sshd`'s loop polled a dozen non-blocking
  calls and went round again, holding a whole core from boot on every
  machine. It now blocks in the kernel until something happens. On four
  emulated cores the machine idles at about two percent with a monitor
  running, where `sshd` alone was a hundred percent of one core; x86-64's
  idle halts the processor rather than spinning on `pause`.
- **The framebuffer console** speaks xterm-256 colours, draws the box, block
  and arrow glyphs, positions its cursor, hides it on request, reports its
  geometry, keeps a cell cache so an unchanged cell costs nothing, and
  presents at most once per sixteen milliseconds. The cursor no longer
  leaves a dark underline wherever it rested on a coloured field.
- **The panic screen** is cyan on every console rather than only over
  serial, its backtrace stops where the kernel ends instead of walking into
  user memory, and the load base is printed on every boot, so a backtrace
  can be resolved from a log alone.
- **The netboot download is a binary that has been booted.** The shipped
  AArch64 binary reaches the login prompt from an EFI System Partition under
  `make boot-media-gate`; before, the only netboot binary any gate booted
  was by construction not the one anybody downloads.
- **Test machines default to four cores** everywhere a test machine is
  started, and every profile says so.
- **Networking, storage and control-plane copies move a word at a time**
  where they were byte loops; the heap zeroes by words. Small under
  emulation, invisible on hardware, and correct.

### Fixed

- **A thread join could lose the context of the process that called it.** A
  process waiting in `xaios_thread_join` runs pending threads on its own
  CPU, so a thread worker could be entered from inside that process's
  syscall and then cleared the CPU to the kernel on its way out. The outer
  syscall carried on with no current process and the kernel's address
  space. It needed a thread still pending when join ran, which is what a
  loaded machine produces. This is the shape of `B-02`, recorded twice and
  explained neither time; the fix is in, the link is inference, and `B-02`
  stays open.
- **An AArch64 sleep could miss its wake-up.** The idle wait unmasked
  interrupts and then executed `wfi`; a timer that fired in the gap was
  taken first, and `wfi` then slept until some unrelated interrupt — on a
  worker CPU, which has no periodic tick, for seconds. The sleep now runs
  masked, which still wakes on a pending interrupt.
- **xaibootFS v6 probed its mirror at the wrong sector, and a rename could
  overflow.** Both found by the crash-recovery gate once a v6 failure was no
  longer hidden behind a v5 pass.
- **Power-loss coverage gained the case a volatile write cache produces.** The
  crash gate constructs a volume whose newest superblock is whole and whose
  catalog was never written, and requires that slot to fail its own hash and
  the volume to come back from the other one.
- **The RISC-V release configuration had never run a program**: no
  per-process address spaces, a global user-access depth, an idle wait that
  slept with nothing armed, and a CPU table sized before the other harts
  were online. All four are fixed and a gate now launches programs there.
- **`B-09`, `B-10`, `B-18`, `B-22` and five older bugs are closed**, each with
  a gate that asserts the exact defect and has been watched passing.

### Known gaps

- No physical hardware for any of the three architectures. Every result is
  from an emulator or a hypervisor.
- The network stack is polled, not interrupt-driven; the kernel's wait for
  events looks at it every one to eight milliseconds.
- `B-02` is fixed by inference only, and the read-only boot path (`B-14`)
  remains written and unexercised.

## Build 4 — 2026-09-01

Build 3 with the fault that should have stopped it from being released, and
cut from a commit whose CI is green.

Released as `xaios_b4.iso` with the same five kits. See
[the release note](./release/xaios_b4.md). **Build 3's artifacts should not be
used**; its note records why.

### Fixed

- **A machine configured with SSH keys and no password account refused every
  key login.** Generalising the username in build 3 turned the public-key
  check from "is this name `admin`" into "is this name in the password
  database", and a key-only machine has no password database by design. What
  authorises a public-key login is the key; the username is the identity it
  claims, and it is now accepted when it names an account the machine has or
  the name the machine's account goes by.
- **Setup ran on machines that were already configured.** It asked whether
  there was a password account, which is not the same question as whether the
  machine has been set up. On a key-only image it stopped the boot at a prompt
  with nobody in front of it, so the SSH server never started. It now runs
  only when there is neither credential.
- **Four dead globals stopped the tree building on current toolchains.**
  Homebrew Clang 23 reports a variable that is assigned and never read, and
  four had accumulated -- a directory counter superseded by the node table, a
  DHCPv6 address recorded and never consulted, a symbol tally nothing
  reported, and the loader hand-off kept only for a self-test that is now
  compiled out. None were reachable behaviour; all four are gone.

### Known gaps

Unchanged from build 3: no physical-hardware evidence, the USB kit has never
been written to a stick and booted, `serve-netboot.sh` has never served a real
machine, real-model inference is not implemented, and the read-only boot path
(`B-14`) remains unexercised. `B-02` has now been seen twice, on two
hypervisors, and is still not understood.

## Build 3 — 2026-08-31

Build 2 could be installed onto a disk by an operator who knew the command.
This one can be set up by a person who does not.

Released as `xaios_b3.iso` with the same five kits. See
[the release note](./release/xaios_b3.md).

### A machine sets itself up

- **A machine with no account now asks for one.** On the first boot of a
  machine nobody has configured, XAIOS offers to run from the medium it booted
  or to install onto a disk, then takes a username and password, an optional
  six digit console PIN, the machine's name, whether it should answer on the
  network, and whether this console should log in automatically. Nothing is
  written until every question has been answered, so an interrupted setup
  leaves the machine as it was.
- **Nothing secret ships in an image any more.** A release image used to be
  forbidden password authentication outright, which meant a released machine
  could never have an account at all. It now carries the code and no
  credential; the account is made on the machine, with a salt from that
  machine's own entropy, and packaging a credential into a release image is
  what the build refuses.
- **A machine can be called something.** The name a person gives it appears on
  the login prompt and in the shell prompt, which read `xaios` and
  `admin@xaios` before, whatever either actually was.
- **An account can be called something.** The username was required to be
  `admin` by the record parser, the console, the SSH path and the kernel's
  command dispatcher. All four now work from the account the machine has.

### Fixed

- **XAIOS could not read a GPT that another tool wrote.** The reader required
  a header to declare exactly 128 partition entries; the specification fixes
  only the array's minimum size and leaves the count to whoever made the
  table. XAIOS's own unified image declares 248, so a machine booted from a
  USB stick could not find the EFI System Partition an install copies from --
  the install path that build 2's USB kit documents had never worked.
- **`xaiosctl storage install` could not be run at all.** Three checks in the
  client each rejected it: one required the caller's identity before the
  caller had been identified, and two disagreed about whether an install may
  carry the confirmation it separately requires. No install could satisfy any
  two at once.
- **A released image installed onto a disk nobody offered it.** A boot-time
  self-test wrote a partition table and a filesystem onto whatever was in
  virtio slot 5, confirming with nobody. It is now behind a build flag that
  only the gates that need it set.
- **A machine booted from read-only media had no writable state**, so it
  locked its console and refused to start its SSH server. It now keeps state
  in memory when it has no disk to keep it on.
- **The initial filesystem could only be mounted once.** A single global held
  the mount prefix, so a second mount silently redirected the first.

### Known gaps

- Still no physical-hardware evidence. The USB kit has never been written to a
  stick and booted on a real machine, and `serve-netboot.sh` has never served
  one.
- **`B-02` recurred.** A thread join under load failed once on VMware Fusion
  during this build's gate runs and did not reproduce on the next. It had been
  seen once before and not since; that is now twice, on two different
  hypervisors, and it remains not understood.
- Real-model inference is not implemented; the model paths are fixtures.
- The read-only boot path (`B-14`) remains written and unexercised.

## Build 2 — 2026-08-31

Build 1 was a system you could boot. This is one you can put on a machine and
leave there.

Released as `xaios_b2.iso`, with five kits beside it — QEMU, VMware Fusion,
Apple Virtualization.framework, a bootable USB stick, and a network boot for a
machine with no disk. See [the release note](./release/xaios_b2.md) for the
exact environments and versions each was tested on, and for what was not.

### Installs

- **XAIOS installs itself onto a disk.** `xaiosctl storage install DISK from
  ESP` writes a partition table, sizes and formats an EFI System Partition from
  what is actually being copied, writes the loader, kernel, initial filesystem
  and entropy seed, and adds a partition for durable state. It refuses to
  install onto the disk the source lives on, and requires the target's own GPT
  identity as confirmation, so a command that destroys a disk is one you have
  to look at the disk to type.
- **A machine with no disk installs the same way.** The network boot image
  carries a plain copy of the loader inside itself, because a running PE cannot
  be copied back out of memory — so a machine that arrived over TFTP can write
  a bootable disk without fetching anything more.
- **The installed machine finds its own storage.** Every gate before this
  attached each volume as a separate device at a known address. An installed
  machine has one disk and has to look: XAIOS now finds xaibootFS on a
  partition of whatever disk it booted from, accepts transitional virtio PCI
  device IDs, and maps above 512 GiB, where firmware puts the 64-bit PCI window.

### Storage

- **Reads and writes no longer cost one device request per sector.** Transfers
  go out in chains of up to 1 MiB, with several in flight at once, and skip the
  bounce buffer when the caller's memory is already reachable by the device.
- **Model bytes are hashed on the CPU's own instructions** where the processor
  has the ARMv8 SHA2 extensions, and on the portable code where it does not.
  The choice is made once at boot and checked against the scalar result.
- **The chunks read most often stay in RAM.** A 256 MiB read cache admits a
  chunk on its second read, and re-reading an admitted chunk skips both the
  device and the hash. Under sustained pressure it now evicts rather than
  freezing full, which is what it did when first measured.
- **XAIOS moves itself into RAM at boot**, in steps of 64, 128 and 256 MiB, and
  says which step it took and why.
- **xaibootFS records extents**, so a volume can be a gigabyte rather than four
  megabytes.

### Survives losing power

- **Power was cut to a machine mid-write, repeatedly**, and what was on the
  volume afterwards was checked rather than assumed. A commit either happened
  or did not; no half-written chunk was ever readable as a whole one.
- **The flushes that safety argument rests on are now checked.** A device with
  a volatile write cache is free to persist a superblock before the catalog it
  points at, which no emulator would ever show. The driver reports every write
  and flush in order, and a gate reads it back and requires a flush between the
  last catalog write and the superblock that publishes it.

### Fixed

- **A userspace write could overflow a static kernel buffer.** The write limit
  was taken from the volume's maximum file size rather than from the buffer
  actually holding the data.
- **The heap lost count of itself**, because a byte-at-a-time copy was replaced
  without the accounting following it.
- **The loader kept memory the kernel needed.** The kernel's `.bss` tail is now
  left to the kernel instead of being claimed by firmware that has finished
  with it.
- **A machine that is not in a cluster dialled one on every boot**, and waited.
- **One slow gate failed the gate after it**, by leaving an emulator running
  when its own timeout killed only the build around it.

### Known gaps

- Still no physical-hardware evidence. Every result is from an emulator or a
  hypervisor and establishes correctness, not performance.
- The USB kit has never been written to a stick and booted on a real machine,
  and `serve-netboot.sh` has never served a real one. The image's EFI System
  Partition and the netboot binaries are both gated; the physical last mile is
  not.
- Real-model inference is not implemented; the model paths are fixtures.
- The read-only boot path (`B-14`) remains written and unexercised.

## Build 1 — 2026-08-27

First released build. XAIOS has been buildable and bootable for some time; what
is new is a single image that boots every environment it claims to support, and
evidence that it does.

Released as `xaios_b1.iso`. See [the release note](./release/xaios_b1.md) for
the exact environments and versions it was tested on, and for what it was not
tested on.

### Runs on

- One image boots QEMU ARM64, QEMU x86_64, VMware Fusion and Apple
  Virtualization.framework — as optical media, as a disk, or from a USB stick —
  at 1, 2 and 4 GiB of memory and four vCPUs. Boot, durable storage, DHCP for
  IPv4 and IPv6, SSH and the userspace applications work on all four.

### Fixed

- **Secondary CPUs took atomics on memory other CPUs could not see the same
  way.** A secondary published itself online while its MMU was still off, so
  the boot CPU began using real atomics against memory those CPUs viewed as
  Device rather than Normal cacheable. VMware Fusion refused the instruction
  and ran one vCPU; the others permitted it and hid the defect.
- **Userspace and the kernel's identity map were the same addresses.** With
  4 GiB of RAM the kernel handed its own memory to userspace and lost it.
  Which machines noticed depended only on how much memory they had.
- **The kernel could only load where it was linked.** A fixed address meant no
  single memory size booted every environment; it is now position-independent
  and the loader places it where the machine actually has memory.
- **DHCP used one fixed transaction id** for every boot of every guest, which a
  server may ignore as a repeat. Roughly one Fusion boot in three got no lease.
- **The applications were never run on two of the four environments**, so the
  syscall suite, the network and SMP tests and the shell's own command surface
  had never executed there.
- **Accumulated unclean boots put the system into rescue mode**, where it
  boots, mounts, takes a lease, listens on SSH — and refuses ordinary commands.
- **A rejected shell command reported no reason**, discarding the explanation
  the kernel had already written.

### Known gaps

- No physical-hardware evidence. Every result is from an emulator or a
  hypervisor and establishes correctness, not performance.
- Real-model inference is not implemented; the model paths are fixtures.
- Two faults have been seen once each and not since, so neither is understood:
  a fatal assertion on VMware Fusion (`B-15`) and a thread join failing under
  load on QEMU (`B-02`). Both now record enough to be diagnosed if they recur.
- The read-only boot path (`B-14`) is written and unexercised, because no
  hypervisor here advertises a read-only block device.

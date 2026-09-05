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

Landed since build 5 and not in any released image.

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

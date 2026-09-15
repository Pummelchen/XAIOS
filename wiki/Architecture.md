# Architecture

XAIOS combines a freestanding operating system with a portable C99 inference
engine. The operating system owns hardware resources, isolation, persistence,
networking, and service lifecycle. The portable engine owns model packages,
architecture plans, backends, sessions, and future inference execution.

The authoritative platform boundary is recorded in
`docs/PLATFORM-SUPPORT.json`. QEMU results prove correctness and ABI behavior;
they do not prove physical performance or production readiness.

This page is the architecture description. The interfaces it names are
specified separately, under
[`docs/`](https://github.com/Pummelchen/XAIOS/tree/main/docs): the syscall and
capability surface in `API.md`, the administration ABI in
`CONTROL-PROTOCOL.md`, the package and filesystem formats in
`MODEL-V2-SPECIFICATION.md` and `MODELFS-FORMAT.md`, and the rule that keeps
the kernel from recognizing a hypervisor in `PLATFORM-NEUTRALITY.md`.

## Boot and runtime flow

1. UEFI firmware loads the XAIOS loader. VMware Fusion uses a generated GRUB
   compatibility chainloader before the same XAIOS loader.
2. `boot/uefi/loader_main.c` validates the ELF, loads its fixed physical
   segments, captures the firmware tables and any boot-image extent, exits boot
   services, and transfers control to the architecture entry. What it hands
   over is version 9 of the boot-information structure in
   `kernel/include/xaios/boot_info.h`: the memory map, the console the firmware
   described, the kernel extent, and an optional initfs and entropy seed. The
   kernel builds its own page tables rather than inheriting the loader's. A
   normal boot displays the colored XAI OS identity and begins the in-place
   progress meter at 0% before loading the system image.
3. Each architecture performs its platform-specific handoff and enters the
   shared `kernel/core/kmain.c` runtime.
4. The kernel initializes architecture services, memory, devices, storage,
   filesystems, security, networking, processes, runtime services, and
   telemetry in dependency order.
5. A normal AArch64, x86_64 or RISC-V image loads `/init`, the service manager, and the
   persistent console/SSH service from initramfs. Before opening TCP port 22, that service
   requires the interface to hold a usable IPv4 address, and deliberately
   probes no external DNS name or TCP endpoint. It then prints the local
   IPv4 address and verified SSH state at 100% and leaves a functional serial
   prompt active beside the SSH event loop. Exact allowlisted diagnostics load in
   separate transient address spaces only when invoked over SSH, then reaped.
   QEMU correctness gates use an explicit profile that runs workers and
   diagnostics during boot to retain deterministic fixture markers.
   AArch64, x86-64 and RISC-V process spaces each provide two adjacent 2 MiB code/data
   page-table spans plus a separate stack span. Switches clear all owned entries
   before installing the next process, preventing stale cross-process mappings.

## Major components

| Component | Main source | Responsibility |
|---|---|---|
| UEFI loader | `boot/uefi/` | Firmware entry, ELF loading, and boot handoff. |
| Architecture ports | `kernel/arch/aarch64/`, `kernel/arch/x86_64/`, `kernel/arch/riscv64/` | Exceptions, timers, interrupts, CPU startup, page tables, and platform discovery. |
| Kernel core | `kernel/core/` | Initialization, logging, telemetry, panic handling, and self-test sequencing. |
| Memory | `kernel/mm/` | Physical and virtual memory, NUMA metadata, heaps, arenas, and ELF ownership. |
| Devices and storage | `kernel/dev/`, `kernel/storage/` | VirtIO, focused NVMe, block devices, GPT, and partitions. |
| Filesystems | `kernel/fs/` | Initramfs, VFS, xaibootFS, and immutable active xaiFS packages. |
| Processes and ABI | `kernel/user/`, `userspace/` | Process ownership, service supervision, syscalls, applications, and SSH/SFTP. |
| Network | `kernel/net/`, `kernel/runtime/network_stack.c` | IPv4/IPv6, TCP/UDP, DNS, routing, and socket state. |
| Administration | `kernel/runtime/admin_control.c`, `kernel/runtime/control_protocol.c` | Typed role-based configuration, key, audit, storage, and model operations. |
| Applications | `userspace/apps/`, `userspace/apps/terminal/` | Standalone ELFs and app-owned terminal modules. The kernel supplies generic capability-gated primitives rather than application implementations. |
| Portable engine | `engine/` | Model-v2 and xaiFS parsing, adapters, backends, model/session ownership, and asynchronous range I/O. |

The engine's cluster layer authenticates bounded peer messages, rejects replay,
and deterministically assigns and reduces expert work. It is no longer hosted
only: sealed frames cross a real network between XAIOS guests, and
`make qemu-cluster-two-node-gate`, `make qemu-cluster-three-node-gate` and
`make qemu-cluster-partition-gate` run join, heartbeat, failure-by-silence and
one-way partition across independent machines. Quorum is mutual rather than
one-sided -- a heartbeat carries the sender's own member bitmap, and a peer
counts only if we hear it and it says it hears us -- because membership decided
from inbound silence alone lets a node whose outbound links are cut go on
counting the whole cluster while the rest have already written it off. See
[`docs/CLUSTER-PROTOCOL.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/CLUSTER-PROTOCOL.md).
What remains hosted-only is distributed activation *execution*, which depends
on real local inference rather than on transport.

## Process and address layout

A normal image starts three processes and stops. `/init` is PID 1 and exits
after its syscalls; `/bin/service-manager` is PID 2 and supervises the service
tree; `/bin/sshd` is PID 3 and stays. Nothing else runs until an administrator
asks for it: an allowlisted diagnostic invoked by its exact name over SSH gets
a transient slot from PID 32 upward, its own address space, and is reaped when
it exits. The `XAIOS_BOOT_TEST_APPS=1` fixture profile is the exception, and
exists so QEMU gates have deterministic markers: it runs bounded workers as
PIDs 3 to 5, the diagnostic applications from PID 6 upward, and `/bin/sshd`
last.

Each architecture links its kernel where its firmware can load it — AArch64 at
`0x90000000`, x86-64 at `0x100000`, RISC-V at `0x80200000` — and userspace
links at `0x3fc0000000` on every one of them, outside the kernel's identity
map. Device addresses are not part of this layout. They come from the
firmware tables the kernel parses at boot, and a hard-coded board value
survives only as a last-resort fallback in the loader's own early console:
assuming one is the defect `docs/PLATFORM-NEUTRALITY.md` exists to prevent.

## What drives the network stack

`network_poll_tick()` in `kernel/runtime/network_stack.c` is the whole of the
network stack's forward motion. It drains the device's receive ring, answers
ARP and NDP, reassembles fragments, feeds DNS and NTP, runs the TCP state
machine, sends the ACKs, retransmits what was not acknowledged, expires dead
flows and drains pending transmissions.

**Two things drive it, and they are not the same thing.** Most of the forward
motion is still the calls a process makes: the network syscalls in
`kernel/user/syscall.c` (connect, accept, send, recv, resolve), the wait loop of
`xaios_wait_events`, and two boot-time loops -- the NTP sync in `kmain.c` and
the SLAAC wait in the stack itself. From userspace only `/bin/sshd` and
`/bin/xtop` call `wait_events`, and the tick inside it runs only for a caller
holding `XAIOS_CAP_NET_SOCKET`.

On top of that, **one CPU carries a network tick** (`OD-011`,
`timer_arm_network_tick()`). `kmain` stops the shared periodic tick immediately
before it starts sshd, so the tick cannot be an ordinary timer callback: it is
*armed* on a secondary CPU afterwards, and on that CPU the timer interrupt does
not tick the scheduler -- it stays masked there exactly as the port left it, so
no CPU gains or loses a preemption. **The tick's whole job is to wake that CPU.**
The poll itself runs from its idle loop, in thread context, through
`network_poll_tick_from_carrier()`, which is the ordinary poll plus a counter.

The tick exists because everything else is a window with no networking in it.
The boot CPU runs kernel code with interrupts masked, so while sshd is inside a
blocking call -- a slow write to the durable volume, a filesystem stall,
anything -- nothing is draining the receive ring: no ACK leaves the machine, no
retransmit fires, no timeout expires, nothing is refused and nothing is closed,
and from a peer it is indistinguishable from the machine having gone away. The
tick does not remove that window, it bounds it: measured by
`make qemu-network-poll-cadence-gate`, the worst gap fell from **55-93 ms idle
and 164-297 ms under load** to **24 ms idle and 29 ms under load**, with several
thousand polls per run now taken from the interrupt rather than from a syscall.

### Why it is arranged this way, and what the alternatives cost

The syscall-driven half is not an oversight: *a machine nobody is talking to
does no network work at all*, and the poll runs at the rate of whatever is
actually using the network. `wait_events` already declines to tick for a caller
that could not receive, and on an interrupt-driven device it ticks only when the
device reports activity or 50 ms of housekeeping have passed. That property is
kept. What was added is a floor under it, not a replacement for it.

**Both objections that made the timer look impossible were real and both were
removed rather than argued with.** The stack's guard is `xaios_reentrant_lock`,
chosen under C-01 because ten of the stack's exported functions call other
exported ones; it identifies its holder by CPU id, so an interrupt landing on a
CPU already inside the guard would be told it holds the lock and would walk into
the critical section it interrupted -- `kernel/include/xaios/spinlock.h` states
that as a property to preserve. **The guard now masks interrupts for as long as
it is held and restores the state on release**, so the condition it guarded
against cannot arise, the same guard may be taken from a handler, and the saved
state is kept per guard because the depth counter already says only the
outermost release undoes the outermost acquire. And the poll being
handler-hostile was true of the wrong function: `operations_tick()` is the part
that flushes block devices and can call `arch_reboot()`, and the interrupt path
simply does not call it.

**That masking has a consequence that had to be answered, and on x86-64 it
stopped the machine.** A CPU waiting for a guard cannot take *any* interrupt,
and one of the machine's interrupts is a wait rather than a notification: the
x86-64 TLB shootdown has the initiating CPU wait until every other CPU has
acknowledged that it invalidated the page. A guard's holder that maps or unmaps
a page inside its critical section is therefore a shootdown, and a CPU spinning
for the same guard is exactly the CPU whose acknowledgement cannot arrive --
neither side can move until the budget runs out, which is `B-123`. The spin
itself now answers the request: `xaios_cpu_relax()` reads the pending shootdown
and invalidates and acknowledges it by hand, so every wait in the kernel that
runs with interrupts masked is still answerable. AArch64 and RISC-V have no such
wait -- hardware broadcasts the invalidation on one and firmware fences every
hart before its call returns on the other -- which is why the self-test that
builds this cycle exists only on x86-64, and why the other two report that the
check does not apply to them rather than passing it in silence.

**The carrier did not exist, and that was the actual problem.** `kmain` switches
the 100 Hz tick off before sshd starts, and that switches off the *global*
period, so no CPU takes a periodic timer interrupt afterwards: a poll placed in
`intid == TIMER_PPI_INTID` is unreachable code. The tick is therefore armed on a
secondary after the fact, and that secondary's timer is the one that outlives
the scheduler's.

**Polling from the loop rather than from the handler is what makes the
mechanism the same on all three architectures.** The obvious design polls from
the timer handler and it was implemented that way first: it works on AArch64 and
x86-64, and on RISC-V it corrupted a trap frame -- `/bin/c99-thread-context`
returned to program counter zero, because that port's trap entry is deliberately
minimal and cannot yet take arbitrary kernel-context traps. Polling from the
loop needs no port to be more interrupt-safe than it already is, so no port has
to be special-cased, and the power path stays out of handlers as a side effect:
`operations_tick()` quiesces storage and can stop the machine, and that is not
handler work when there is an alternative. The CPU has to be idle for the poll
to run, which is exactly when a CPU is free to service the stack.

**A second defect had to be fixed to make it survive, and it was not in the
timer at all.** `vector_entry` masks `DAIF` on every trap, and a secondary's
idle loop could be re-entered with `I` still set -- measured directly, spinning
with a pending timer *visible in its CPU interface* (`hppir1=27`) and
`DAIF=0x3c0`, so it never took another interrupt. A CPU that cannot take an
interrupt cannot be woken by one, which is how the scheduler moves work between
CPUs. The loop now clears `I` every turn rather than once before it.

The same defect had a second face worth knowing about, and it is what made the
first one hard to see from outside: with a pending interrupt the wait-for-event
latch is set, so `wfe` returns immediately instead of sleeping, and the run that
exposed this had turned its idle loop **134 million times** while taking no
interrupts at all. A spinning idle loop and a silent timer were the same fault
seen from two places, not two faults -- clearing `I` settles both, and the
measurement says so: with the tick armed and the loop clearing `I` each turn,
the loop turned once per tick (`n=8000`, `ticks=7970`) instead of millions of
times between them.

**A kernel thread remains the simpler alternative and its cost is unchanged** --
one of three worker CPUs, because `kernel/sched/thread.c` runs one thread to
completion per worker CPU with no preemption. The timer was chosen because it
costs a timer rather than a core, and that is now true in the tree rather than
expected of it.

### What changed: the coupling is measurable, and bounded

The stack measures the gap between consecutive polls whenever a listener is
registered, keeps the longest, prints each new maximum, and prints a distinct
line when a gap is long enough to be an outage rather than a pause:

```
network: longest gap between polls us=24341 polls=612345 tick=2890 listeners=2
network: stack was not polled for ms=1840 outages=1 listeners=2
```

`tick=` is how many of those polls were taken by the CPU carrying the network
tick rather than by a syscall a process made, and it is the field that makes "the tick is armed" and "the
tick fires" different claims: a timer on one CPU is exactly the shape that
silently stops, and it did, twice, before this was right. `make
qemu-network-poll-cadence-gate` fails if a guest announces an armed tick that
never advances this count, and it names the refusals it accepted on the way out.
Measured on this machine: **24 ms idle, 29 ms under load**, several thousand
tick polls per run, zero gaps past a second.

`network_poll_gap_max_ns()` and `network_poll_gap_outage_count()` expose the
same figures. The measurement is deliberately not taken when nothing is
listening: with no listener there is nothing the poll is late for, and a metric
that fires on an idle machine is a metric nobody reads.

`make qemu-network-poll-cadence-gate` is the measurement under load. **Before
the network tick the worst gap was 297 ms**, 55 ms idle on a quiet host rising
to 105 ms when the build machine was busy -- which is the host descheduling the
emulator rather than anything the guest did -- and 164 to 297 ms across three
256 KiB SFTP round trips and ninety rejected connections. **With the tick the
same three phases measured 24, 25 and 29 ms**, because the interrupt floor is
the 100 Hz period rather than sshd's housekeeping interval. No gap crossed the
one-second outage threshold in any run. The gate still records the number rather
than asserting it: on a shared host the spread between runs is the host's, and
what it asserts is that the instrument works, that the poll count advances,
that every transfer came back byte-identical, and now that an armed tick
actually fires.

## Trust boundaries

- EL0 code crosses into the kernel only through validated syscall dispatch.
- Every syscall is associated with a process capability and validates user
  buffers before dereference.
- Direct serial input/output is restricted to the persistent console owner by
  `XAIOS_CAP_CONSOLE`; other applications use the kernel log or SSH channels.
- VFS descriptors and network sockets are process-owned and reclaimed with the
  owning address space.
- Administrative mutations are role- and capability-gated, replay-protected,
  audited, and bounded.
- Active xaiFS packages are immutable. Registration, staging, verification,
  activation, scrub, quarantine, and trim use explicit typed operations.
- QEMU host forwarding and external OpenSSH/SFTP clients cross the network
  trust boundary; FreeBSD is the primary Unix behavioral reference.
- Model-v1 is a deterministic fixture boundary. Production decode must fail
  explicitly until a real architecture plan executes.

Two mitigations sit underneath those boundaries rather than forming one. The
kernel seeds a stack canary before `kmain` and checks it, so a stack buffer
overflow is detected rather than followed; and where the platform provides an
SMMUv3 or equivalent IOMMU, device DMA is translated rather than trusted. Core
leases are a third case and an unfinished one: the topology-aware lease
interface exists and is tested, but production inference dispatch does not use
it yet, so it is not an isolation guarantee.

## Main data flows

### Build

```text
make image
  -> scripts/build-image.sh
  -> Clang/LLD and image tools
  -> UEFI loader, kernel, userspace, initramfs, and QEMU disk images
```

### Boot validation

```text
make qemu-smoke
  -> build the explicit boot-diagnostic fixture image
  -> boot isolated QEMU guest
  -> collect serial markers and telemetry
  -> validate the release-candidate contract
```

### Administrative command

```text
local or SSH xaiosctl
  -> shared command parser
  -> authenticated principal and role
  -> capability-gated syscall
  -> typed query or replay-protected mutation
  -> persistent audit record
  -> shared text or JSON renderer
```

### Model package access

```text
block device
  -> optional GPT partition
  -> xaiFS volume
  -> immutable package extent
  -> verified range read
  -> caller-owned engine buffer or arena
```

## Platform status

The AArch64 QEMU path provides the broadest OS-service coverage. Each discovered
CPU has a private translation root and user directory, preventing concurrent
EL0 workers from replacing another core's mappings. VMware Fusion on Apple
Silicon now reaches public-key SSH through PCI-discovered E1000E networking and
AHCI xaibootFS persistence, public-key SSH/SFTP, recovery, reboot and orderly
shutdown. Fusion runs four vCPUs -- its UEFI answers `PSCI_VERSION` without
advertising PSCI in the FADT, so the kernel asks rather than trusts -- and
`make vmware-fusion-smoke` reads `numvcpus` out of the VMX it is about to boot
and requires the guest to report that many CPUs online (`F-01`).

The x86_64 QEMU image executes the common kernel and complete userspace/service
image. MADT-discovered application processors run EL0 workers with per-CPU user
page-table roots, while runtime-sized XSAVE/FXSAVE state survives live timer
interrupts. The shared filesystems, IPv4/IPv6, SSH/SFTP, security, AI Cell and
telemetry paths run over modern PCI VirtIO block/network, and emulated NVMe
passes identify/write/flush/read. Physical Intel qualification remains open.

## Inference boundary

The portable engine already supplies model-v2 parsing, architecture and backend
registries, scalar packed INT4/INT6 correctness kernels, immutable model
readers, sessions, and a caller-owned service API. It does not yet import or
execute a real Qwen checkpoint. Qwen 3.8 is the next model workstream after
the XAIOS platform completion gate; Kimi K3 and DeepSeek V4 Flash 0731 remain
later roadmap items.

See [[Current Limitations|Current-Limitations]], [[Hardware Support|Hardware-Support]],
and [[Project Tracker|Project-Tracker]].

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

**Nothing schedules it.** There is no timer callback, no interrupt handler and
no kernel thread behind it. It runs only when something calls it, and the
callers are: the network syscalls in `kernel/user/syscall.c` (connect, accept,
send, recv, resolve), the wait loop of `xaios_wait_events`, and two boot-time
loops -- the NTP sync in `kmain.c` and the SLAAC wait in the stack itself. From
userspace only `/bin/sshd` and `/bin/xtop` call `wait_events`, and the tick
inside it runs only for a caller holding `XAIOS_CAP_NET_SOCKET`.

So on a booted machine the network runs while sshd is inside its service loop,
and not otherwise. That is stronger than it sounds, because the kernel's last
act before starting sshd is to disable preemption and the periodic timer
(`kmain.c`): sshd is not merely the only network process, it is the only thing
running on the boot CPU. **Any pause anywhere in that loop -- a slow write to
the durable volume, a filesystem stall, anything -- is a total network
outage.** Nothing comes off the receive ring, no ACK leaves the machine, no
retransmit fires, no timeout expires, nothing is refused and nothing is closed.
From a peer it is indistinguishable from the machine having gone away. B-43 is
the first sighting that is probably this.

### Why it is arranged this way, and what the alternatives cost

The arrangement is not an oversight, and both ways out are more expensive than
they look.

*A timer or interrupt cadence* cannot carry this poll as the kernel stands.
The stack's guard is `xaios_reentrant_lock`, chosen under C-01 because ten of
the stack's exported functions call other exported ones; it identifies its
holder by CPU id, so an interrupt landing on a CPU already inside the guard
would be told it holds the lock and would walk straight into the critical
section it interrupted. `kernel/include/xaios/spinlock.h` states that as a
property to preserve. Nor is the poll interrupt-handler work in the first
place: its first act is `operations_tick()`, which on a pending power action
flushes every block device and calls `arch_reboot()`; it puts a 1520-byte
frame buffer on the stack, and it logs under the kernel log's own lock. And
the carrier does not exist at runtime anyway -- the 100 Hz tick is switched
off before sshd starts, and on RISC-V the timer interrupt never reached
`scheduler_tick()` to begin with. Putting the poll on a timer means restoring
preemption and making the whole stack interrupt-safe, which is a change to the
machine's execution model rather than to its scheduling.

*A kernel thread* is lock-safe -- kernel threads are one of the two sanctioned
contexts for that guard, and an SSH login child on a worker CPU already drives
this poll through `wait_events` today. Its cost is the thread facility:
`kernel/sched/thread.c` runs one thread to completion per worker CPU with no
preemption, so a permanent poll thread permanently removes a CPU from the pool
that hosts kernel threads -- one of three on the four-core default -- and the
only production user of that pool is asynchronous process launch. It also
means a machine that wakes on a cadence whether or not anything is on the
network, which is the cost this project has twice spent work removing.

*What the current arrangement buys* is that a machine nobody is talking to
does no network work at all, and that the poll is driven at the rate of
whatever is actually using the network. `wait_events` already declines to tick
for a caller that could not receive, and on an interrupt-driven device it ticks
only when the device reports activity or 50 ms of housekeeping have passed.

### What changed: the coupling is now measurable

The decision is to keep the arrangement and stop it being invisible, because
invisibility was the part that could not be defended. The stack measures the
gap between consecutive polls whenever a listener is registered, keeps the
longest, prints each new maximum, and prints a distinct line when a gap is long
enough to be an outage rather than a pause:

```
network: longest gap between polls us=55008 polls=752428 listeners=2
network: stack was not polled for ms=1840 outages=1 listeners=2
```

`network_poll_gap_max_ns()` and `network_poll_gap_outage_count()` expose the
same figures. The measurement is deliberately not taken when nothing is
listening: with no listener there is nothing the poll is late for, and a metric
that fires on an idle machine is a metric nobody reads.

`make qemu-network-poll-cadence-gate` is the measurement under load. On QEMU
under TCG the worst gap observed across runs was **297 ms**. Idle it is about
55 ms on a quiet host -- the housekeeping interval of sshd's wait -- rising to
around 105 ms when the build machine is busy, which is the host descheduling
the emulator rather than anything the guest did. Three 256 KiB SFTP round trips
and ninety rejected connections moved it to 164 ms in one run and 297 ms in
another. No gap crossed the one-second outage threshold in any run, which is
consistent with B-43 not reproducing in 1281 QEMU connections. Those are the
figures any future change to this arrangement has to beat, and the reason the
gate records the number rather than asserting it: on a shared host the spread
between runs is the host's.

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

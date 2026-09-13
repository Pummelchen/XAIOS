# Kernel

Where a change belongs, and why the directories are split the way they are.

The organising rule is that **architecture-specific code lives in `arch/` and
nowhere else**. Everything outside `arch/` compiles unchanged for AArch64,
x86-64 and RISC-V, and `make platform-neutrality-check` enforces it: firmware
supplies capabilities, never identity, so nothing here may ask *which machine
am I* in order to decide what to do. When a driver needs something only one
platform provides, the platform offers it through an interface and the driver
asks whether it is present — see [Platform
neutrality](../docs/PLATFORM-NEUTRALITY.md).

| Directory | What belongs here |
|---|---|
| `arch/` | The only architecture-specific code: exception vectors, page tables, timers, interrupt controllers, CPU bring-up, and firmware discovery. One subdirectory each for `aarch64`, `riscv64` and `x86_64`. A file here has a counterpart in the other two, or a stated reason why not. |
| `core/` | Kernel entry and the boot sequence. `kmain.c` is the order in which the system comes up, and reads as a narrative of that order. |
| `mm/` | Physical and virtual memory: the page allocator, NUMA topology and placement, and the device-window arena that hands each driver a mapped range rather than letting drivers pick addresses (two once picked the same one). |
| `sched/` | Scheduling and the CPU domain hierarchy. |
| `user/` | The syscall surface and process loading — the boundary where userspace arguments become kernel actions, and where every capability check happens. |
| `dev/` | Device drivers. `virtio/` holds the transports and the block, network, RNG and GPU devices; the rest are platform devices (NVMe, AHCI, E1000E, VMXNET3, PCI ECAM, USB HID input). A driver here is discovered, never assumed. |
| `net/` | The protocol implementations: IPv4 and IPv6, TCP, UDP, ARP, NDP, DNS and DNSSEC. Protocol logic only. |
| `runtime/` | The largest directory, and the one whose name explains least. It holds the kernel's *services* rather than its mechanisms: the network stack that drives `net/` and `dev/`, remote login, the control and agent protocols, the AI cell and CPU inference runtime, entropy, admin control, and cluster leasing. If a subsystem has state, a lock and a syscall entry point, it lives here. |
| `fs/` | Filesystems: xaibootFS for durable writable state, FAT for the EFI System Partition, and the VFS layer above them. |
| `storage/` | Volumes rather than filesystems: partitioning, the A/B system slot, and installation onto a disk. |
| `lib/` | Freestanding helpers with no subsystem of their own. |
| `include/xaios/` | Every public kernel header. A subsystem's interface lives here; its implementation does not. |

## Three things worth knowing before you choose a directory

**`net/` against `runtime/network_stack.c`.** `net/` builds and parses packets
and knows nothing about sockets, queues or processes. The network stack owns
the state — sockets, flows, the routing table, the guard that serialises it —
and calls into `net/` to do the protocol work. A change to how a header is
parsed goes in `net/`; a change to what happens to a socket goes in `runtime/`.

**What runs the network stack.** Mostly the calls a process makes, and one
timer on one CPU. `network_poll_tick()` in `runtime/network_stack.c` -- which
drains the device ring, runs the TCP state machine, retransmits and expires
flows -- runs inside the network syscalls a process makes and inside
`xaios_wait_events`, and on a booted machine the process making those calls is
`/bin/sshd`, which `core/kmain.c` starts after disabling preemption and the
periodic timer. So a pause anywhere in sshd's loop used to be a total network
outage for its duration.

That window is now bounded on AArch64 and x86-64. One secondary CPU carries a **network tick**
(`timer_arm_network_tick()`, `OD-011`): the shared periodic tick is stopped
before sshd starts, so the tick is armed afterwards on a CPU that takes
kernel-context interrupts, and on that CPU the timer interrupt polls
`network_poll_tick_from_interrupt()` -- the poll without `operations_tick()`,
because the power path quiesces storage and can stop the machine and has no
business in a handler -- instead of ticking the scheduler. No CPU gains or
loses a preemption. Worst gap between polls, measured by
`make qemu-network-poll-cadence-gate`: **24 ms idle, 29 ms under load**, down
from 55-93 ms and 164-297 ms. RISC-V declines the tick -- `timer_arm_network_tick()`
returns 0 there with the reason in the source -- because its trap entry cannot
yet take traps in arbitrary kernel context, and arming it regressed that port's
boot gate at `/bin/c99-thread-context`. Before adding work to any path between a network
syscall and that poll, read the argument in
[Architecture](../wiki/Architecture.md#what-drives-the-network-stack); the
stack measures its own gaps and names how many polls the tick took.

**`fs/` against `storage/`.** `fs/` is about files inside a volume.
`storage/` is about volumes themselves — where they begin on a disk, which of
the two system slots is active, and how a machine installs itself onto
hardware. A bug in reading a directory is `fs/`; a bug in choosing which
kernel to boot is `storage/`.

## Conventions

- **Self-tests run at boot and are load-bearing.** Most subsystems assert
  their own invariants during startup and panic on failure. They are how a
  defect is caught on the machine that has it rather than in a gate that might
  not run there, so a new invariant belongs beside the code that maintains it.
  This includes release images: `kassert` is never compiled out, and a
  self-test that only ran in the test configuration would be testing a
  different binary from the one people install. B-42 measured the price on the
  most expensive one -- the DNSSEC self-test, which carries a committed signed
  chain to walk -- at 7,409 bytes of object content and 4,640 bytes of
  `kernel.elf`, 0.44%, with no change to the boot image or the initfs, and
  kept it. A self-test that needs test *data* should still say in its comment
  what that data costs a shipping image.
- **A refusal is a result.** Where a capability is absent the kernel says so in
  the boot log and degrades in a stated way. Silence is treated as a defect:
  several bugs here were invisible because a subsystem reported nothing rather
  than reporting an absence.
- **Comments explain why.** The surrounding code documents reasoning and
  rejected alternatives, not mechanics. Match that when you add to it.

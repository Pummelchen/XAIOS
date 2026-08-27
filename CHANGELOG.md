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
- Outbound SSH `ProxyJump` fails host key verification on x86_64 (`B-01`).
- The x86_64 guest writes to the medium it booted from (`B-14`), so genuinely
  read-only media would fail one self-test.

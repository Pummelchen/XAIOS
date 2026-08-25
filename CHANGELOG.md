# Changelog

XAIOS versions are `MAJOR.MINOR.PATCH`, single-sourced from
[`VERSION`](./VERSION). A build refuses to proceed if that file is malformed,
and the running system reports the same string on its first boot line and from
`xaiosctl version`, so a support case, an advisory and an image cannot disagree
about what is running.

While the major version is `0`, nothing here is production supported and the
syscall surface is not frozen. A minor bump may change it. That is the whole
meaning of the leading zero, and it will stay `0` until physical qualification
is accepted rather than deferred.

Entries record what changed for someone *running* XAIOS. The commit history
records how it was built.

## 0.1.0 — 2026-08-25

First declared version. XAIOS has been buildable and bootable for some time;
what is new is that it can now say which XAIOS it is.

### Runs on

- QEMU ARM64 and x86_64, VMware Fusion ARM64, and Apple
  Virtualization.framework ARM64. Boot, durable storage, DHCP IPv4, SLAAC IPv6
  and SSH work on all four. Per-function differences are in the
  [project tracker](./wiki/Project-Tracker.md).

### Fixed

- **Secondary CPUs never came online on real hardware.** PSCI starts them with
  translation off, where exclusives are unsupported and stores bypass the
  caches the boot CPU reads, so every boot reported one core of four and most
  panicked. Multiple cores now start and stay up; eleven consecutive four-vCPU
  boots and a sustained eight-core load carry no failure. Emulators could not
  show this: they permit the illegal instruction and model no caches.
- **Any process could halt the kernel by closing a socket twice.** The
  ownership check and the free took the lock separately, so two threads closing
  one descriptor raced and the loser stopped the machine. No privilege and no
  malformed input were required.
- **A transmit that went unanswered stopped the machine**, and one in eighteen
  boots did. The queue is now re-notified while waiting, and a device that
  stays silent leaves the path unvalidated instead of halting.
- **Kernel subsystems were not safe to enter from more than one CPU.** The
  network stack, service records and CPU-AI runtime are now serialised, and
  audit counters that gates measure are atomic.
- **Reaching a guest from the host** on Apple Virtualization.framework now
  works over vmnet, which previously required a console.

### Known gaps

- No physical-hardware evidence. Every result here is from an emulator or
  hypervisor and proves correctness, not performance.
- Real-model inference is not implemented; the model paths are fixtures.
- Outbound SSH `ProxyJump` fails host key verification on x86_64 builds
  (`B-01`).

# System architecture

The architecture description lives on the published Wiki, at
[Architecture](https://github.com/Pummelchen/XAIOS/wiki/Architecture)
(`wiki/Architecture.md` in this repository).

It used to live in both places. The two drifted, as two descriptions of one
thing do: this file still described a single AArch64 port and a boot-info
version the loader had moved past, months after x86-64 and RISC-V were
building and booting. Describing the system is orientation, so it belongs
where the documentation is published and read.

What stayed on this side is the interfaces that description names, because a
specification is read by someone implementing against it and by the checks that
enforce it. See [the reference index](./README.md) for all of them; the ones
closest to the architecture are:

- [API](./API.md) — the syscall table and capability bits
- [Application development](./APPLICATION-DEVELOPMENT.md) — how an application
  is registered and what it is allowed to do
- [Control protocol](./CONTROL-PROTOCOL.md) — the administration ABI
- [Platform neutrality](./PLATFORM-NEUTRALITY.md) — why the kernel discovers
  capabilities and never identifies a hypervisor
- [Hardware portability](./HARDWARE-PORTABILITY.md) — the driver boundary and
  the qualification layers above it

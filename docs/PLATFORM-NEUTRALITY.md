# Platform neutrality

XAIOS behaves the same everywhere it boots. The firmware underneath it is a
source of *capabilities*, never a source of *identity*, and never a source of
behaviour.

This is one rule with three consequences, and it is enforced by
`make platform-neutrality-check` rather than left to good intentions.

## The rule

**Discover capabilities. Never assume a platform.**

A hypervisor is entitled to lack a framebuffer, an interrupt translation
service, a serial port or an entropy protocol. XAIOS is not entitled to notice
*which* hypervisor it is, and must never behave differently because of the
answer.

Concretely:

- **No platform-branded constant may be the initial value of a variable that
  discovery later fills in.** A default is an assumption wearing a disguise: it
  works on the platform it was taken from and fails silently everywhere else.
- **No user-visible behaviour may branch on a platform.** The boot display, the
  login prompt, the shell, the command surface, the SSH server and everything
  they say are XAIOS's, and they read identically on every target that can run
  them.
- **An absent capability degrades one way, everywhere.** If two platforms both
  lack a framebuffer, they must lose exactly the same thing and say exactly the
  same words about it. Degrading differently on different platforms is the same
  defect as behaving differently.

## Why this is a rule and not a preference

It has already cost this project real time twice.

The loader advertised a hard-coded QEMU PL011 at `0x9000000` to every machine
it booted. On Apple's Virtualization.framework, which has no serial hardware at
all, the kernel's first `klog()` wrote to a device that was not there. With the
MMU off that is an external abort, and with no framebuffer it is a silent one.
For a long time this was recorded as "XAIOS does not boot on
Virtualization.framework". The port was fine. The assumption was not.

The interrupt controller carried the same shape: the GIC distributor and
redistributor bases began life as `QEMU_VIRT_*` addresses and were corrected by
ACPI afterwards, so a platform that described something else worked only
because the correction happened to run first.

Both are the same mistake -- treating one platform's layout as the shape of the
world -- and both were invisible until a platform that disagreed showed up.

## What is *not* a violation

Firmware limits are real and may be reported.

- Rendering pixels where a framebuffer exists and text where one does not is
  correct: the *content* is identical, only the transport differs.
- Polling a queue where no interrupt can be delivered is correct.
- Saying `boot-ui: no framebuffer` is correct, because it names an absent
  capability rather than a platform.

The test is whether the sentence could name a *vendor*. "This machine has no
framebuffer" is a capability. "This is Fusion, so draw differently" is an
identity, and identity is what this rule forbids.

## Where platform names are still legitimate

Outside the kernel, naming a platform is often the whole point:

- Harnesses and run scripts in `tools/` and `scripts/` exist to drive one
  specific hypervisor.
- Gates in `tests/` assert what a given platform does.
- Firmware profiles in `contracts/` record evidence per platform by design.

The rule binds `kernel/`, `boot/` and `userspace/` -- everything that ships
inside the operating system.

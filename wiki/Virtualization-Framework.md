# Virtualization Framework

Apple's Virtualization.framework is the fourth way to run XAIOS, alongside
QEMU AArch64, QEMU x86_64 and [[VMware Fusion|VMware-Fusion]]. The guest runs on
the host's own cores with the real interrupt controller and timer rather than a
software model, which makes it a route to correctness and timing behaviour on
Apple Silicon.

It is a **development and verification target, not a qualification profile**.
There is no automated gate for it, so nothing here is qualification evidence;
see [[Firmware Profiles|Firmware-Profiles]] for the profiles that are.

## Status

XAIOS boots to a login. The loader runs, the kernel starts, MutableFS mounts a
durable volume read-write and survives reboots, IPv4 comes up by DHCP, IPv6
configures an address from the router advertisement, and sshd listens on
TCP 22.

```
PCI: enumerated 11 devices (virtio=10 net=1 bridge=1)
virtio-console: modern PCI transport index=2 slot=0
mutable-fs: persistent mounted v5 nodes=256 sectors=8192
kernel: persistent fsck valid=1 v5 files=15 dirs=23
network: DHCP lease ip=c0a84002 mask=ffffff00 gw=c0a84001
IPv4: 192.168.64.2
IPv6: fd4a:250c:3b3c:9412:8c2f:92ff:fe41:4d79
SSH server: up and running (tcp/22)
```

## Running it

Full instructions, including the disk layout this platform needs, are in
[`tools/vz/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/tools/vz/README.md).
Two constraints are easy to trip over:

- The framework takes an exclusive lock on each image, so the same file cannot
  be attached twice; the A/B system volume needs two separate copies.
- The loader prefers the kernel on the A/B system volume over the one on the
  ESP, so a stale copy of that image silently boots a stale kernel. Refresh
  every attached volume from the current build before each run.

## What this platform does differently

Three properties differ from QEMU and each one cost real time to find.

**No PL011.** Firmware publishes no SPCR table because there is no serial
hardware, so the compiled-in QEMU UART address must not be used. The kernel
logs over a virtio console instead.

**No linear framebuffer.** The GOP reports `PixelBltOnly` at 1280x800 across 37
modes, with `FrameBufferBase` and `FrameBufferSize` both zero after a successful
`SetMode`. That is legal UEFI: drawing goes through `GOP->Blt()`, a boot service
that does not outlive `ExitBootServices`. The kernel therefore renders its
terminal to the virtio console and reports `boot-ui: no framebuffer`.

**No interrupt translation service.** Firmware describes no GIC ITS, so
message-signalled interrupts cannot be delivered and every virtio queue runs
polled. Each driver supports that, and a missing interrupt no longer costs a
device. See [[Current Limitations|Current-Limitations]].

virtio is presented entirely on PCI, with no MMIO window, so the kernel probes
MMIO first and falls back to PCI. Real ARM PCIe hardware needs that fallback as
much as this platform does.

## Reaching it from the host

You cannot, with the NAT attachment this harness uses. Guest-initiated traffic
works in both directions -- DHCP completes, the router solicitation is answered,
and an ICMP round trip to the gateway returns in well under a millisecond -- but
host-initiated frames are not delivered to the guest at all: an ARP request for
its address never arrives. sshd therefore listens on TCP 22 without being
reachable from the Mac, which is a property of the attachment rather than of
XAIOS.

A bridged attachment would expose the guest, and needs the
`com.apple.vm.networking` entitlement that Apple issues only with a provisioning
profile; ad-hoc signing cannot provide it. Until then, use the QEMU targets for
anything that has to be connected to.

The console is output-only for the same practical effect: the virtio console
driver posts a receive buffer to keep the device from stalling, but nothing
reads it, so there is no interactive login here yet.

## Running the Intel build here

Not possible. Virtualization.framework does not emulate a guest CPU
architecture: the guest executes on the host's actual cores, so on Apple
Silicon the guest is AArch64 and an x86_64 kernel cannot boot, in any macOS
release.

Rosetta in this framework is narrower than it sounds. It translates x86_64
**Linux userspace** binaries inside an **AArch64 Linux** guest, and needs
`binfmt_misc`, a virtiofs share and the Linux syscall ABI. It does not run a
foreign kernel. Use QEMU or an Intel host for the x86_64 image; see
[[Testing XAIOS|Testing-XAIOS]].

## Debugging on a platform with no console

Two instruments work here and several obvious ones do not.

- The EFI console is not a witness. Firmware renders it by `Blt` into the
  virtio GPU, so it can stop updating while the CPU runs on perfectly well.
  Output that stops mid-way reads exactly like a hang and usually is not one.
- Process liveness distinguishes nothing: the framework exits only when the
  guest powers off, so a wedged guest and a running one look identical.
- Host CPU percentage is useless; a guest spinning in a tight loop reports 0.0%.

What does work is a trace file written to the ESP by the loader, which survives
console death, and PSCI `SYSTEM_OFF` as a one-bit probe after
`ExitBootServices`, where no output channel exists at all: place the call at the
point of interest and a guest that powers off reached it.

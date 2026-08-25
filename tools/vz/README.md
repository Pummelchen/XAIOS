# Virtualization.framework — the fourth way to run XAIOS

XAIOS runs under QEMU on aarch64, QEMU on x86_64, and VMware Fusion. This is
the fourth target: Apple's Virtualization.framework, where the guest executes
on the host's own cores with the real interrupt controller and timer rather
than a software model.

**Status: XAIOS boots and runs.** The loader runs, the kernel starts,
initialisation completes, the kernel log streams to this program's stdout over
the virtio console, MutableFS mounts a durable volume read-write, IPv4 comes
up by DHCP, sshd listens on port 22, and over vmnet you can ssh into it from
the Mac. IPv6 configures an address from the
router advertisement this platform sends; see *IPv6* below.

## Why this target exists

QEMU cannot run XAIOS under HVF. It aborts while emulating MMIO whose trap
carries no instruction syndrome, in both the xHCI and GIC paths. That is
QEMU's limitation rather than ours: the same assertion reproduces from other
guests on QEMU 8.2 and 9.0 (qemu-project/qemu issue 2312) and is still present
in 11.1. What remains is TCG, which models no cache or timing behaviour and so
cannot answer a performance question.

Virtualization.framework avoids that class of failure entirely, because the
interrupt controller and timer are hardware. It offers the host's core count
and no control over interrupt affinity, so it is a route to correctness and
timing behaviour on real silicon, not to many-core scaling work.

## Usage

```sh
./scripts/build-image.sh                       # kernel, loader, initfs
xcrun swiftc -O -o build/vz/xaios-vz tools/vz/xaios_vz.swift
codesign --force --sign - --entitlements tools/vz/xaios-vz.entitlements \
  build/vz/xaios-vz
cc -O2 -o build/vz/vmnet-helper tools/vz/vmnet-helper.c -framework vmnet
./tools/vz/build-vz-disk.sh                    # ESP + GPT boot disk
./build/vz/xaios-vz build/vz/xaios-vz-disk.img --memory-mib 4096 --gui
```

Every path after the boot image is attached as a further volume, in order,
because the kernel identifies its volumes by position on the bus: the
deterministic test volume, the persistent MutableFS volume, the model volume,
the storage administration scratch volume, then the A/B system volume twice.
That is the order `run-qemu-x86_64.sh` uses and the one the slot mapping in
the PCI transport expects.

```sh
./build/vz/xaios-vz build/vz/xaios-vz-disk.img \
  build/xaios-virtio-test.img build/vz/persistent.img \
  build/xaios-model-volume.img build/vz/scratch.img \
  build/vz/system-a.img build/vz/system-b.img --memory-mib 4096
```

Two cautions, both of which cost a while to find. The framework takes an
exclusive lock on each image, so the same file cannot be attached twice: the
system volume needs two separate copies. And the loader prefers the kernel on
the A/B system volume over the one on the ESP, so a stale copy of that image
silently boots a stale kernel; refresh every attached volume from the current
build before each run.

Signing uses an ad-hoc identity; no developer account is involved. `--gui`
opens a window, which is the only way to observe the guest: this platform has
no PL011, so the kernel's serial log has nowhere to go, and Apple's firmware
does not route EFI console output to the virtio console. Silence on the
serial port is not evidence of failure here.

## Checking it

```sh
make vz-gate
```

Boots the current image and requires the kernel, the virtio console, a mounted
and checked durable volume, a DHCP lease, an IPv6 address and a listening SSH
server, failing on a panic or any missing check. The report lands in
`build/vz-gate.json`. It refreshes every attached volume from the current build
first, for the stale-kernel reason below.

It runs only on macOS with a signed harness, so it is not part of CI and its
result is not qualification evidence.

## Reaching it from the host

Yes, over vmnet, with one privileged helper and a choice of network mode:

```sh
sudo ./build/vz/vmnet-helper --socket "$PWD/build/vz/vmnet.sock" --mode host
./build/vz/xaios-vz ... --vmnet "$PWD/build/vz/vmnet.sock"
```

```
$ ssh admin@192.168.18.2 ifconfig
vtnet0: flags=UP,RUNNING mtu 1500
  inet 192.168.18.2 netmask 255.255.255.0
  ether 8a:66:71:6e:fd:5a
```

Not with the NAT attachment the harness uses by default. Guest-initiated
traffic works in both directions there -- DHCP completes, the router
solicitation is answered, an ICMP round trip to the gateway returns in well
under a millisecond -- but host-initiated frames are not delivered at all: an
ARP request for the guest's address never arrives. sshd listens on TCP 22
without being reachable, which is a property of the attachment rather than of
XAIOS.

A bridged attachment would expose the guest directly but needs the
`com.apple.vm.networking` entitlement, which Apple issues only with a
provisioning profile against a paid membership. vmnet itself needs no
entitlement, only root, so `vmnet-helper.c` starts a vmnet interface as root
and relays Ethernet frames over a socket that the harness hands to
Virtualization.framework. Only the helper runs privileged; the virtual machine
does not. This is the arrangement `socket_vmnet` uses for rootless QEMU.

### Which mode to ask for

`--mode host` is `VMNET_HOST_MODE`, a private network between this Mac and its
guests: the host reaches the guest and the guest reaches the host, with no
route off the machine. `--mode shared` is `VMNET_SHARED_MODE`, which is NAT
with internet access and, like the built-in attachment, carries only what the
guest itself starts.

So: host mode to log in, shared mode to fetch something. Neither does both,
and XAIOS drives one interface at a time.

### What it took

The helper is eighty lines of vmnet calls and rather more lifecycle care, and
almost everything that went wrong was in the second part.

**The socket must be a `socketpair`, not a bound pair of paths.** Both are
`AF_UNIX SOCK_DGRAM` and both look right. With two bound paths,
Virtualization.framework delivered four frames to the guest and then stopped
reading, with buffers free on both sides -- which is what "inbound is broken"
meant for most of the time it was broken. With a `socketpair`, the same guest
took 3159. The helper therefore creates the pair itself and passes one end to
the harness over `SCM_RIGHTS`, which is also what makes the privilege split
work: the harness never opens anything, it receives an already-connected
descriptor from a process that had root and dropped nothing to get it.

**The guest's MAC must be the interface's MAC.** vmnet assigns a hardware
address when the interface starts and drops frames addressed to anything else,
so a guest with a different address is invisible inbound while looking fine
outbound. The helper sends its MAC as the first payload on the socket and the
harness sets it on the virtio device before starting the machine.

**`SO_RCVBUF` must be at least twice `SO_SNDBUF`,** which the attachment
documents and which was wrong here for a while. It was not the cause of
anything, but it is a real requirement.

Four further bugs were all in the helper's own lifecycle and all mine: it
accepted a single connection and exited, it never noticed a client leaving
because `SOCK_DGRAM` reports no EOF, `poll` with `events = 0` never reports
`POLLHUP`, and a backlog of one refused the second run. The helper now accepts
in a loop, polls both descriptors for `POLLIN`, and logs to
`<socket>.log` so a privileged process started in another terminal can still
be diagnosed from here.

## Why the disk differs from the QEMU image

The QEMU boot image cannot be used directly, for two reasons:

- It is a bare FAT filesystem with no partition table. EDK2 under QEMU boots
  it because it probes the whole device; Apple's firmware wants an EFI System
  Partition in a GPT. `make_vz_disk.py` wraps the filesystem in one.
- It carries no initfs. Under QEMU the initramfs arrives on a second
  virtio-mmio device, a transport this platform does not offer, so
  `build-vz-disk.sh` places `initfs.img` on the ESP where the loader looks for
  it, the same arrangement the Fusion bundle uses.

Two constraints worth knowing, both of which cost real time to find: the disk
image length must be a whole number of 4 KiB pages, which the framework
reports only as "the disk image format is not recognized"; and the entropy
seed must be exactly 64 bytes, because a short one makes the loader return
EFI_LOAD_ERROR and the machine powers off having printed nothing.

## How far it gets

All the way. Storage, entropy, the initial filesystem, a writable persistent
volume, the network and the userspace services all come up, and the boot log
arrives on stdout:

```
PCI: enumerated 11 devices (virtio=10 net=1 bridge=1)
virtio-console: modern PCI transport index=2 slot=0 common=0x180010000
virtio-blk-h: slot=1 capacity_sectors=32768 event_idx=0
mutable-fs: persistent mounted v5 nodes=256 sectors=8192
kernel: persistent fsck valid=1 v5 files=15 dirs=22
virtio-net: guest offload negotiated; receive buffers hold 65550 bytes
network: DHCP lease ip=c0a84002 mask=ffffff00 gw=c0a84001 dns=c0a84001
IPv4: 192.168.64.2
SSH server: up and running (tcp/22)
```

## What had to be fixed

Five defects, none of which show under QEMU, because EDK2 and the virt
machine happen to accommodate each one:

- The loader validated `FrameBufferBase` before calling `SetMode`. Firmware
  need not publish a framebuffer until a mode is set, and Apple's does not.
- The loader advertised a hard-coded QEMU PL011 at `0x9000000` on a machine
  with no serial hardware. The kernel's first `klog()` then wrote to a device
  that is not there, which with the MMU off is an external abort and with no
  framebuffer is a silent one. That, and nothing else, is what "does not
  boot" meant for a long time.
- aarch64 spoke virtio-MMIO only, scanning a window this platform does not
  have. Both transports are now built and a dispatcher picks between them:
  MMIO first, so the QEMU path is unchanged, then PCI. Real ARM PCIe hardware
  needs this as much as this platform does.
- The PCI transport rejected any device with no device-specific config
  capability. The virtio specification makes that region optional and
  virtio-rng has none at all; QEMU publishes one regardless.
- The network self-test asserted on feature negotiation, so a device that
  declined the driver's feature set halted the kernel outright. Negotiation
  is the device's decision, so it now degrades exactly as an absent device
  already did.
- Both the block and network drivers treated a missing interrupt as fatal.
  There is no message-signalled interrupt support for PCI on aarch64 here, so
  a machine that could have served requests had neither storage nor network.
  Completion is polled on every submission path in both drivers, so neither
  needs the notification.
- This network device runs only on the full feature set it offers, which
  includes both guest segmentation offload bits. Taking those obliges the
  driver to post receive buffers of at least 65550 bytes, and it silently
  wedged *both* queues when given smaller ones: one frame went out, then
  nothing moved and no receive buffer was ever used. A buffer that size spans
  seventeen pages and a descriptor covers one contiguous run, which the kernel
  heap cannot promise, so each receive buffer is now an indirect descriptor
  chain of one page per entry.
- The MutableFS self-test formats whichever block device is currently
  selected, which before any volume is bound is the boot device. QEMU attaches
  that with snapshot=on so formatting it costs nothing; here it is read-only
  removable media, and the test failed on it. It now runs only where a
  throwaway write is safe, and never against the durable volume.
- DHCP was attempted only for the Intel NIC, so a virtio guest kept the
  compiled-in QEMU address of 10.0.2.15 and was simply off-net. Every device
  now asks the network first and falls back to that address.

## IPv6

Working, on both this platform and QEMU:

```
IPv4: 192.168.64.7
IPv6: fd4a:250c:3b3c:9412:8c2f:92ff:fe41:4d79
```

Three defects stood between the stack and a usable address, all of them in
XAIOS rather than in either hypervisor.

`ndp_send_router_solicitation` built a correct solicitation, discarded the
frame, logged that it had sent one and returned success, so no router was ever
asked. Its own self-test asserted on that fabricated success, which is what
kept it looking healthy. Construction is now separate from transmission: the
self-test checks the frame that gets built, and the boot path puts it on the
wire.

Nothing then read the interface between bringing it up and starting services,
so an advertisement that did arrive sat unread in the receive ring. The boot
path now polls for the reply, re-soliciting up to three times the way RFC 4861
does.

Finally, only globally routable prefixes were accepted. Neither of these
networks offers one -- Virtualization.framework's router advertises
`fd4a:25c::/64` and QEMU's slirp advertises `fec0::/64` -- so a machine that
had a perfectly usable prefix on offer ended up with a link-local address and
nothing else. A unique-local prefix is a real address within its network, so it
is now configured and used as the source address for outbound IPv6. Whether an
address is *globally* routable remains a separate question, and
`network_stack_local_public_ipv6` still answers only that one; what changed is
that the address the host sends from, and reports, is the one it actually has.

Before this, outbound IPv6 to a non-link-local destination invented a source
address by copying the destination's prefix and appending our own interface
identifier -- right only when the peer happened to share our link. That guess
now applies only when no advertisement has been accepted.

## Why interrupts are polled here

Message-signalled interrupts on aarch64 are delivered through the GIC's
interrupt translation service, and this platform has none: its firmware
describes no ITS in ACPI, and nothing answers at the address QEMU's virt
machine uses. So every virtio queue here runs polled, which each driver
supports and which is why a missing interrupt no longer costs a device.

The kernel does now configure MSI-X over the ITS for virtio on PCI where one
exists, alongside the NVMe driver that already did, and it finds the ITS from
ACPI rather than assuming QEMU's address. That path cannot be exercised in
either environment available here: this platform has no ITS, and QEMU's virt
machine puts virtio on MMIO, where interrupts arrive through the distributor
instead. It matters for ARM server hardware, where virtio and NVMe both sit on
PCIe behind an ITS, and it is unverified until it meets one.

## Why the kernel has no framebuffer here

Apple's GOP reports `PixelBltOnly`, at 1280x800 across 37 modes, with
`FrameBufferBase` and `FrameBufferSize` both zero after a successful
`SetMode`. That is legal UEFI and it means there is no linear framebuffer:
drawing goes through `GOP->Blt()`, a boot service that ceases to exist at
`ExitBootServices`. The kernel therefore renders its terminal to the virtio
console instead, and reports `boot-ui: no framebuffer` on the way past.

## A note on instruments

Several signals that look reasonable here are not, and each cost real time.

- **The EFI console is not a witness.** Firmware renders it by `Blt` into the
  virtio GPU, and it can stop updating while the CPU runs on perfectly well.
  Output that stops mid-way reads exactly like a hang and usually is not one.
- **Process liveness distinguishes nothing.** Virtualization.framework exits
  only when the guest powers off, so a wedged guest and a running one look
  identical from the host.
- **Host CPU percentage is useless**: a guest spinning in a tight loop still
  reports 0.0%, which a control test confirms.

Two instruments do work, and both were needed:

- **A trace file on the ESP.** Attach the boot disk read-write, extend
  `efi_file_protocol` with `Write`/`Flush`, and have the loader append a line
  per step. It survives console death, and it is what showed the loader
  reaching `ExitBootServices` all along. Read it back afterwards with
  `mtype -i disk.img@@1048576 ::/bootlog.txt`.
- **PSCI `SYSTEM_OFF` as a one-bit probe.** After `ExitBootServices` there is
  no output channel at all, so place an `hvc` with `0x84000008` at the point
  of interest: if the guest powers off, execution reached it. Moving that
  probe through `kmain` is what located the UART abort and then confirmed a
  full boot.

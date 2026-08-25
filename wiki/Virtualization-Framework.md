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
[`platform/virtualization-framework/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/platform/virtualization-framework/README.md).
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

It is also the only target here that runs XAIOS on more than one real core.
Secondary CPUs start under PSCI with translation off, where exclusives are
architecturally unsupported and stores bypass the caches the boot CPU reads;
both cost this port a defect that QEMU cannot show, since TCG permits the
exclusive and models no caches. Four vCPUs now come online on every boot, and
`make vz-gate` requires it. Interrupt affinity is not offered here, so this
target answers correctness on real cores rather than scaling.

## Reaching it from the host

Over vmnet, with a privileged helper:

```sh
sudo ./build/vz/vmnet-helper --socket "$PWD/build/vz/vmnet.sock" --mode host
./build/vz/xaios-vz ... --vmnet "$PWD/build/vz/vmnet.sock"
ssh admin@192.168.18.2
```

Not with the NAT attachment the harness uses by default. Guest-initiated
traffic works in both directions there -- DHCP completes, the router
solicitation is answered, and an ICMP round trip to the gateway returns in well
under a millisecond -- but host-initiated frames are not delivered to the guest
at all: an ARP request for its address never arrives. sshd listens on TCP 22
without being reachable, which is a property of the attachment rather than of
XAIOS.

A bridged attachment would expose the guest directly, and needs the
`com.apple.vm.networking` entitlement that Apple issues only with a provisioning
profile; ad-hoc signing cannot provide it. vmnet needs no entitlement, only
root, so `platform/virtualization-framework/vmnet-helper` runs a vmnet interface privileged and relays
frames to the machine over a socket -- the arrangement `socket_vmnet` uses for
rootless QEMU. Its host mode carries host/guest traffic and reaches no further;
its shared mode reaches the internet and carries only what the guest starts.
Pick the one that matches the errand. `platform/virtualization-framework/README.md` records what the
relay had to get right, none of which is obvious.

The console is interactive too, and needs no helper. Log in on it and the usual
shell is there:

```
xaios login: admin
Password:
XAIOS local console session opened
admin@xaios:/$ ifconfig
vtnet0: flags=UP,RUNNING mtu 1500
  inet 192.168.64.21 netmask 255.255.255.0
  ether 8a:40:8a:1e:fa:e3
```

## Processors

The firmware reports every configured CPU in its MADT but leaves the FADT's
PSCI flag clear, so a kernel that trusts that flag brings up none of them. It
answers `PSCI_VERSION` with 1.1 regardless, so XAIOS asks rather than trusts,
and four vCPUs come online.

DHCP failed twice at four vCPUs early in that work and has not recurred in
later runs, so no cause is attributed to it. The harness defaults to one vCPU.

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

Several obvious instruments mislead here and two work. That is development
detail rather than a property of XAIOS, so it lives with the harness in
[`platform/virtualization-framework/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/platform/virtualization-framework/README.md).

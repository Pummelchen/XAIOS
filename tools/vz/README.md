# Virtualization.framework — the fourth way to run XAIOS

XAIOS runs under QEMU on aarch64, QEMU on x86_64, and VMware Fusion. This is
the fourth target: Apple's Virtualization.framework, where the guest executes
on the host's own cores with the real interrupt controller and timer rather
than a software model.

**Status: XAIOS boots, with a working console.** The loader runs, the kernel
starts, initialisation completes, and the kernel log streams to this
program's stdout over the virtio console. Networking does not come up yet:
the device refuses the feature set the driver asks for, and the machine
carries on without it.

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
./tools/vz/build-vz-disk.sh                    # ESP + GPT boot disk
./build/vz/xaios-vz build/vz/xaios-vz-disk.img --memory-mib 4096 --gui
```

Signing uses an ad-hoc identity; no developer account is involved. `--gui`
opens a window, which is the only way to observe the guest: this platform has
no PL011, so the kernel's serial log has nowhere to go, and Apple's firmware
does not route EFI console output to the virtio console. Silence on the
serial port is not evidence of failure here.

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

Everything except networking. Storage, entropy, the initial filesystem, the
VFS, the scheduler and the userspace services all come up, and the boot log
arrives on stdout:

```
PCI: enumerated 5 devices (virtio=4 net=1 bridge=1)
virtio-console: modern PCI transport index=2 slot=0 common=0x180010000
virtio-rng: secure entropy source initialized
initramfs: mounted rofs version=2 files=52 source=virtio-blk
vfs: MutableFS mounted at /
kernel: preemptive scheduler infrastructure enabled
```

Networking stops at feature negotiation: the device declines the set the
driver requires, so the driver reports it and the machine boots without a
network, which is why sshd is withheld at the end.

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

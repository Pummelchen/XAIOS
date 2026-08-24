# Virtualization.framework — the fourth way to run XAIOS

XAIOS runs under QEMU on aarch64, QEMU on x86_64, and VMware Fusion. This is
the fourth target: Apple's Virtualization.framework, where the guest executes
on the host's own cores with the real interrupt controller and timer rather
than a software model.

**Status: the loader runs; the kernel does not start yet.** The blocker is
identified precisely and is a portability limit in XAIOS, not a defect in the
tooling here. See *Where it stops* below.

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

## Where it stops

The firmware boots the removable-media path, and the loader runs and renders
its progress screen. It stops while loading the third kernel segment:

```
[alloc-ok-zeroed-copied]   segment 1, RX
[alloc-ok-zeroed-copied]   segment 2, RO
[alloc-ok                  segment 3, BSS: allocated, then faults on write
```

The kernel is linked at a fixed physical address of `0x90000000`, and its BSS
runs to roughly `0x90634000`. `AllocateAddress` there reports success and the
write then faults, and it is still faulted after seventy-five seconds, so this
is not slowness. QEMU's EDK2 has memory free at that address and honours the
request; Apple's firmware does not, whatever it reports.

This is a portability limit rather than a bug in this harness. A kernel that
must land at one hard-coded physical address can only boot on firmware whose
memory map happens to suit it, which is a constraint that will apply to
physical hardware too, where the map is whatever the vendor chose.

Resolving it means one of:

- **Make the kernel relocatable**, so the loader can take whatever the
  firmware offers. This is the general answer and the one that also serves
  physical hardware, and it is the larger change.
- **Choose a link address the firmware does offer.** Cheaper, but it trades
  one hard-coded assumption for another and needs revisiting per platform.

## A note on instruments

Two signals that look reasonable here are not. Whether the machine keeps
running distinguishes nothing once the guest stops exiting, because a faulted
jump and a deliberate spin both leave it alive. Host CPU percentage is also
useless: a guest spinning in a tight loop still reports 0.0%, which a control
test confirms. What works is the framebuffer — print, then freeze, and read
the window.

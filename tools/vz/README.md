# Virtualization.framework spike

Boots XAIOS on Apple's Virtualization.framework instead of QEMU, so the guest
runs on the host's own cores with the real interrupt controller and timer.

**Status: the guest does not boot yet.** Apple's EFI firmware starts and writes
its variable store, then halts without launching the loader; the VM sits at 0%
CPU and no DHCP lease appears. Everything on the XAIOS side checks out, so the
remaining unknown is what Apple's firmware wants that ours does not provide.

## Why this exists

QEMU's HVF backend cannot run XAIOS. It aborts emulating MMIO whose trap
carries no instruction syndrome, in both the xHCI and GIC paths. That is a
QEMU limitation, not ours: the same assertion reproduces from U-Boot on QEMU
8.2 and 9.0 (qemu-project/qemu issue 2312), and it is still present in 11.1.
TCG works but models no cache or timing behaviour, so it cannot answer any
performance question.

## What has been ruled out

- The disk is a GPT with a correctly typed EFI System Partition, primary and
  backup headers both valid, and the file length is a whole number of 4 KiB
  pages, which Virtualization.framework requires and reports only as
  "format is not recognized".
- The ESP holds `/EFI/BOOT/BOOTAA64.EFI`, the removable-media path firmware
  is required to try.
- That binary is a well-formed EFI application: PE32+, machine 0xAA64,
  subsystem 10, with a relocation directory.
- The firmware itself does run, which the 128 KiB variable store it writes
  confirms.

## What to try next

- Attach a graphics device and a window. XAIOS renders its boot progress
  through the UEFI GOP framebuffer, which is how the Fusion path is observed,
  and would show whether the loader runs at all. Apple's firmware appears not
  to route EFI console output to the virtio console, so the serial port stays
  silent either way and is not evidence of failure.
- Compare against a known-bootable ESP, to separate "firmware rejects this
  disk" from "firmware rejects this binary".
- Check whether the firmware expects a boot entry in its variable store
  rather than falling back to the removable-media path.

## Usage

```sh
xcrun swiftc -O -o build/vz/xaios-vz tools/vz/xaios_vz.swift
codesign --force --sign - --entitlements tools/vz/xaios-vz.entitlements \
  build/vz/xaios-vz
python3 tools/vz/make_vz_disk.py build/xaios-aarch64.img \
  build/vz/xaios-vz-disk.img
./build/vz/xaios-vz build/vz/xaios-vz-disk.img build/vz/persistent.img \
  --cpus 1 --memory-mib 2048
```

Signing uses an ad-hoc identity; no developer account is involved.

## Scope

Virtualization.framework offers the host's core count and no control over
interrupt affinity or core isolation. It is a route to correctness and timing
behaviour on real silicon, not to the many-core scaling work.

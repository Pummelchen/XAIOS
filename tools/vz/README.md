# Virtualization.framework — the fourth way to run XAIOS

XAIOS runs under QEMU on aarch64, QEMU on x86_64, and VMware Fusion. This is
the fourth target: Apple's Virtualization.framework, where the guest executes
on the host's own cores with the real interrupt controller and timer rather
than a software model.

**Status: XAIOS boots.** The loader runs, the kernel starts, and
initialisation completes. There is no console yet, because this platform
offers the kernel neither a linear framebuffer nor a PL011; see *Where it
stops* below.

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

The firmware boots the removable-media path, the loader runs to completion,
and the kernel completes its whole initialisation sequence: MMU, PCI, devices,
storage, entropy, runtime services and userspace applications all come up.

It does so **silently**, because this platform gives the kernel no console at
all, and that silence was for a long time mistaken for a failure to boot.

Two XAIOS bugs had to be fixed to get here, both of which only appear on
firmware that differs from QEMU's EDK2:

- The loader validated `FrameBufferBase` *before* calling `SetMode`. Firmware
  is not required to publish a framebuffer until a mode is set, and Apple's
  does not, so a working GOP was rejected. EDK2 sets a mode during startup,
  which is why this never showed under QEMU.
- The loader advertised a hard-coded QEMU PL011 at `0x9000000` on a platform
  with no serial hardware. `discover_uart` returns early when ACPI carries no
  SPCR table, leaving the compiled-in default in place, so the kernel's first
  `klog()` wrote to a device that is not there. With the MMU still off that is
  an external abort, and with no framebuffer it is a silent one. The loader
  now reports no UART when firmware publishes ACPI tables but no SPCR.

## Why the kernel has no console here

Apple's GOP reports `PixelBltOnly`, at 1280x800 across 37 modes, with
`FrameBufferBase` and `FrameBufferSize` both zero after a successful
`SetMode`. That is legal UEFI and it means there is no linear framebuffer:
drawing goes through `GOP->Blt()`, a boot service that ceases to exist at
`ExitBootServices`. There is also no PL011. So a kernel console on this
platform needs a **virtio-console driver**, which the harness already wires to
stdout; that is the next piece of work.

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

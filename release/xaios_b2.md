# XAIOS build 2

Six downloads. One of them is the image; the other five are the image with the
launcher, writer or server for a particular way of starting it, and a README
that says exactly what to run.

| Download | Bytes | SHA-256 |
|---|---|---|
| `xaios_b2.iso` | 228,929,536 | `82346fbf29df5b04fa28ac07b029a8bb938a04280ea49a068bcdab4c3d24609b` |
| `xaios_b2.iso.zip` | 19,690,469 | `66486d7c160e8c81d359b4c17a7b1a37485b14c8ff90e6fdb7b207aafb3888fa` |
| `xaios_b2-qemu.zip` | 19,694,734 | `837978642315f95f31c42486d0d82003a9bd109e0d0aa3a5a259e4a293830abc` |
| `xaios_b2-vmware-fusion.zip` | 19,694,447 | `9557eac2e631dbae2290f621b35efd5a66af337c32124956538589b54b6b2449` |
| `xaios_b2-virtualization-framework.zip` | 19,698,984 | `af2068b90499406dae13a3b2d8c5463a1bbe6db7a6a9fd44454eda3492840382` |
| `xaios_b2-usb.zip` | 19,694,392 | `a375d836384ed8280290fa36ed37b0923acab2e1c63e5c6d17a91f6c2522deb3` |
| `xaios_b2-netboot.zip` | 4,312,845 | `9123bc0f7e3779a70ac9ef5e957629e7f1cc6d09f821805825863d98bc8744dc` |

Everything is zipped because the ISO is larger than GitHub will accept as a
file and compressed it is not, so the release can travel with the repository.

One image, five kits. The image already boots every environment below — that is
what makes it unified — so each kit carries it once rather than carrying a
variant. Five copies of one file that differ would be five chances for them to
disagree, not five products. The netboot kit is the exception and is not the
image at all: see below.

## What changed since build 1

Build 1 shipped the image and three kits for running it as a guest. What it did
not ship was a way onto hardware. Two kits are new:

- **`-usb`** — the image and a writer, for a stick that either runs XAIOS
  without touching the machine's disks or installs onto one of them.
- **`-netboot`** — a different artifact: two binaries, one per architecture,
  each carrying a kernel and an initial filesystem inside itself, for a machine
  with no disk that asks the network what to boot.

The installer both of them document is not new code in this build; what is new
is that it is now packaged and written down as a thing a person uses, rather
than a command that existed and was only ever exercised by a gate.

## Where this was tested

Every environment below booted **this exact file** — the one with the SHA-256
above — under `make unified-image-gate`. Nothing in this table is inferred from
a similar configuration, from a rebuild, or from a copy: the checksum was taken
before the gate ran and again after it, and is the same both times.

That distinction matters here, because the image is deliberately not
reproducible: each build embeds a fresh boot entropy seed, so rebuilding this
commit produces a working image with a different checksum. The checksum above
identifies one artifact, not the commit. Verify a download against it; do not
expect a rebuild to match it.

| Environment | Version tested | Attached as | Firmware |
|---|---|---|---|
| QEMU (AArch64) | 11.1.0, `-machine virt`, `-cpu cortex-a72`, `accel=tcg` | virtio-blk disk | EDK2 `edk2-stable202408-prebuilt.qemu.org` |
| QEMU (x86-64) | 11.1.0, `-machine q35`, `-cpu max`, `accel=tcg` | virtio-blk disk | OVMF (Homebrew QEMU 11.1.0) |
| VMware Fusion | 26.0.0 (build 25388279) | SATA CD-ROM | Fusion ARM64 UEFI, GRUB chainloader |
| Apple Virtualization.framework | macOS 26.6.2 (25G83) | virtio-blk disk | Virtualization.framework UEFI |

Host for all four: Apple M3, macOS 26.6.2 (25G83). Each reached a kernel, a
working shell command surface and an SSH server listening, with no panic, no
assertion failure and no fall back to rescue mode.

### The installer

`make qemu-installed-disk-gate` passed. That gate is the evidence behind every
install instruction in the USB and netboot kits, and it is worth being precise
about what it does: a running XAIOS is given a blank disk, and it writes a GPT,
sizes and formats an EFI System Partition, copies the five boot files onto it,
and adds a state partition. Then the emulator is pointed at **that disk** and
nothing else, and it boots — twice.

Twice is the part that matters. A single boot would pass equally well against a
system that silently reformatted its disk on every start, so the second boot
checks that state written by the first one is still there.

### Network boot

`tests/scripts/qemu-netboot-gate.py` passed against binaries byte-identical to
the two in `xaios_b2-netboot.zip`:

| File | SHA-256 |
|---|---|
| `BOOTAA64.EFI` | `3aea06cff0f000342366a573d33d6a0e7aa2a9fed42f03bcf846ccb3a07c6e50` |
| `BOOTX64.EFI` | `746a854493d9391ddebff8279f2289b276e13ca172d46cefec3da0b7a717bb61` |

The x86-64 half is a real network boot: firmware chose PXE, fetched the file
over DHCP and TFTP, and the loader then found its kernel and initial filesystem
inside the image it had been handed rather than asking for a second file. The
AArch64 half was booted from a medium holding only the loader, which exercises
the same "everything is in this one binary" path without a TFTP server.

## Where this is not tested

Read this as the boundary of the claim above, not as a list of things believed
to be broken.

- **No physical hardware.** Every result is from an emulator or a hypervisor.
  This establishes that the system is correct on those platforms; it
  establishes nothing about performance, and nothing about any real machine.
- **The USB kit has never been booted from a USB stick.** The image contains a
  GPT with an EFI System Partition, which is what firmware boots from a stick,
  and that same partition is what QEMU and Virtualization.framework booted here
  — so the path is exercised, but not through a physical USB controller on a
  physical machine. `write-usb.sh` itself has not been run against a real
  device. Treat the USB kit as the least-tested thing in this release.
- **`serve-netboot.sh` has not been run.** The netboot *binaries* are gated, and
  the x86-64 one was fetched over a real DHCP and TFTP exchange — but by QEMU's
  built-in server, not by dnsmasq under this script, and never by a physical
  machine's firmware.
- **No hypervisor other than the three named.** VirtualBox, Parallels, Hyper-V,
  KVM on Linux, cloud instances and UTM are all untried. They are not known to
  fail — they have not been run.
- **No version other than those named.** QEMU 11.1.0 is what was tested, not
  "QEMU 11 or later". This image depends on firmware behaviour that differs
  between products and has already differed between them during development, so
  treat a different version as untested until it has been run.
- **x86-64 was tested only under emulation.** It ran on an ARM host through
  QEMU's interpreter, never on an Intel or AMD processor executing natively.
- **The read-only boot path is written and unexercised** (`B-14`). No
  hypervisor here advertises a read-only block device, so a machine booting a
  CD or a write-protected stick takes a path nothing has run.
- **Two faults have been seen once each and never since**, so neither is
  understood: a fatal assertion on VMware Fusion (`B-15`) and a thread join
  failing under load on QEMU (`B-02`). Neither recurred in this build's runs.

## Which download

| You have | Take |
|---|---|
| QEMU, either architecture | `xaios_b2-qemu.zip` |
| VMware Fusion on Apple Silicon | `xaios_b2-vmware-fusion.zip` |
| A Mac, and want the host's own cores | `xaios_b2-virtualization-framework.zip` |
| A machine and a USB stick | `xaios_b2-usb.zip` |
| A machine with no disk, and a network | `xaios_b2-netboot.zip` |
| Your own tooling | `xaios_b2.iso.zip` |

The USB kit covers two cases with one stick: boot it and run XAIOS without
writing to any disk in the machine, or boot it and install onto one. The
netboot kit installs the same way, sourcing the files from the binary it booted
rather than from a partition.

Every kit's README documents the install, and the command is the same in all of
them:

    xaiosctl storage install DISK from ESP \
      --principal KEY --confirm-device DISK_GUID --operation-id N

`DISK_GUID` comes from `xaiosctl storage partition verify DISK`. It is required
and cannot be guessed, which is what makes a command that destroys a disk one
you have to look at the disk to type.

## Identifying a running build

    XAIOS Build 2 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string. There is no separate `MAJOR.MINOR.PATCH` version: XAIOS is identified
by build number and nothing else.

## What is in it

Both kernels, both initial filesystems, the UEFI loader for each architecture,
and a GRUB chainloader used on VMware Fusion, whose firmware does not launch
the XAIOS loader directly from optical media.

The image is read-only. XAIOS keeps its durable state on a writable xaibootFS
volume, which is a separate disk the platform attaches; each kit's launcher
creates one. Booting without one is supported — the system comes up and reports
the volume as missing rather than pretending otherwise.

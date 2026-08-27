# XAIOS build 1

`xaios_b1.iso` — 227,880,960 bytes
SHA-256 `d09aeaa82b05890bc8d0728f297728f652b1c59a3d4c8f6bf3d6448b09f7cc76`

`xaios_b1.iso.zip` — 19,361,032 bytes
SHA-256 `0cbd037b595fdef8780dfdbbc0f82ef5b228d304f0500513b65d4ea832bc7f73`

The zip contains the image and nothing else. It exists because the ISO is larger than
GitHub will accept as a file, and compressed it is not — so the release can travel
with the repository. Unzip it and check the image against the checksum above.

One file. It carries both an AArch64 and an x86-64 kernel, and firmware selects
the right one. It is an ISO 9660 filesystem and a GPT-partitioned disk at the
same time, so the same file boots as optical media, boots as a disk, and mounts
for reading.

## Where this was tested

Every environment below booted **this exact file** — the one with the SHA-256
above — to a login prompt with the SSH server listening, under
`make unified-image-gate`. Nothing in this table is inferred from a similar
configuration, from a rebuild, or from a copy: the checksum above was
taken before the gate ran and again after it, and is the same both times.

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

Host for all four: Apple M3, macOS 26.6.2 (25G83).

Guest configurations exercised: **4 vCPUs**, and **1 GiB, 2 GiB and 4 GiB** of
memory. All twelve combinations boot.

## Where this is not tested

Read this as the boundary of the claim above, not as a list of things believed
to be broken.

- **No physical hardware.** Every result is from an emulator or a hypervisor.
  This establishes that the system is correct on those platforms; it
  establishes nothing about performance, and nothing about any real machine.
- **No hypervisor other than the three named.** VirtualBox, Parallels, Hyper-V,
  KVM on Linux, cloud instances and UTM are all untried. They are not known to
  fail — they have not been run.
- **No version other than those named.** QEMU 11.1.0 is what was tested, not
  "QEMU 11 or later". VMware Fusion 26.0.0 is what was tested. This image
  depends on firmware behaviour that differs between products and has already
  differed between them during development, so treat a different version as
  untested until it has been run.
- **x86-64 was tested only under emulation.** It ran on an ARM host through
  QEMU's interpreter, never on an Intel or AMD processor executing natively.
- **Not tested from a USB stick.** The image contains a GPT with an EFI System
  Partition, which is what firmware boots from a stick, and the same partition
  is what QEMU and Virtualization.framework booted here. Writing it to a stick
  and booting a physical machine has not been done.

## Using it

Boot as a disk, or attach as a CD-ROM. On VMware Fusion, attach as a CD-ROM.

Write to a USB stick — replace `N`, and note the warning above:

    dd if=xaios_b1.iso of=/dev/rdiskN bs=4m

Mount to read the contents:

    hdiutil attach xaios_b1.iso

The image is read-only. XAIOS keeps its durable state on a writable MutableFS
volume, which is a separate disk the platform attaches; the three hypervisor
configurations above each provide one. Booting without one is supported — the
system comes up and reports the volume as missing rather than pretending
otherwise.

## Identifying a running build

    XAIOS Build 1 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string. There is no separate `MAJOR.MINOR.PATCH` version: XAIOS is identified
by build number and nothing else.

## What is in it

Both kernels, both initial filesystems, the UEFI loader for each architecture,
and a GRUB chainloader used on VMware Fusion, whose firmware does not launch
the XAIOS loader directly from optical media.

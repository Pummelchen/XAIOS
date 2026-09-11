# XAIOS build 6

One image per architecture, instead of one image for all of them.

Up to build 5 a release was a single ISO carrying an AArch64, an x86-64 and a
RISC-V loader, kernel and initial filesystem. UEFI makes that work -- firmware
picks its own loader from the removable-media path and never sees the others --
and it was genuinely one deliverable. What it was not was easy to reason about.
A boot that went wrong had three kernels, three initial filesystems and three
loaders on the medium to be wrong about; the file was 220 MB of which about
thirty was payload; and an architecture whose build had quietly not happened
produced an image that still booted on the machine that built it and not on the
machine it was carried to.

So this build is three images, and every kit is built for one machine.

**This build has not been published.** The files below exist and are checksummed
here; what has and has not been run against them is set out under *Where this
was tested*, and two of the five environments a release claims have not been
run on it at all yet.

## Start here: which file do I download?

First decide which machine you are running it on, then what you are running it
with. The architecture is the first choice now, and it is not reversible by
downloading a different kit -- an AArch64 image will not boot an x86-64 machine.

| To run XAIOS on | AArch64 | x86-64 | RISC-V 64-bit |
|---|---|---|---|
| QEMU | `xaios_b6-aarch64-qemu.zip` | `xaios_b6-x86_64-qemu.zip` | `xaios_b6-riscv64-qemu.zip` |
| VMware Fusion | `xaios_b6-aarch64-vmware-fusion.zip` | — | — |
| Apple Virtualization.framework | `xaios_b6-aarch64-virtualization-framework.zip` | — | — |
| a real machine, from a USB stick | `xaios_b6-aarch64-usb.zip` | `xaios_b6-x86_64-usb.zip` | `xaios_b6-riscv64-usb.zip` |
| a real machine with no disk, over the network | `xaios_b6-aarch64-netboot.zip` | `xaios_b6-x86_64-netboot.zip` | `xaios_b6-riscv64-netboot.zip` |
| your own tooling | `xaios_b6-aarch64.iso.zip` | `xaios_b6-x86_64.iso.zip` | `xaios_b6-riscv64.iso.zip` |

Unzip before use.

### Why there is no Fusion or Virtualization.framework column for the other two

Both run guests on the host Mac's own cores. An x86-64 or RISC-V guest there
would be emulation, which is what the QEMU kits are for. This is a fact about
the host rather than a gap in the release.

### What the image itself is

Each `.iso` is one file that is an ISO 9660 filesystem, a GPT-partitioned disk
and a bootable USB image at the same time, which is why one download covers
CD-ROM, hard disk and stick. It carries one loader, one kernel and one initial
filesystem, and the loader is at the removable-media path that architecture's
firmware looks for: `\EFI\BOOT\BOOTAA64.EFI`, `\EFI\BOOT\BOOTX64.EFI` or
`\EFI\BOOT\BOOTRISCV64.EFI`.

On the AArch64 image that path holds a GRUB chainloader rather than the XAIOS
loader directly. VMware Fusion's firmware will not launch the XAIOS loader from
optical media and will launch GRUB, whose only job is to find `XAIOS.EFI` and
hand over; the other three environments launch GRUB perfectly well.

The two images that no longer have to hold three architectures are much
smaller -- 78 MB and 84 MB against 220 MB -- which is under the size that made
compressing them mandatory rather than merely tidy. The AArch64 image keeps its
96 MiB EFI System Partition and its size: that is the partition Fusion's
firmware boots, it must be FAT16, and 96 MiB is the only size it has ever been
given here.

### Once it boots

There is no default password, because there is no account. The machine asks how
to set itself up on its first boot.

## Checksums

| File | Bytes | SHA-256 |
|---|---|---|
| `xaios_b6-aarch64-netboot.zip` | 2,375,537 | `9faa68a309f7b7c5f12088880b3e56a58cdb839b91bbc8b43cf9ac9cef126866` |
| `xaios_b6-aarch64-qemu.zip` | 13,904,457 | `5707fbd1b7222dd836fb0f9a816c31adb2cbbf968c25fa62e332538aeab067c1` |
| `xaios_b6-aarch64-usb.zip` | 13,905,437 | `ef5158ad74f4ca554574416adf4793da5e8f36384f27a28bbf7c8c17dbfc8598` |
| `xaios_b6-aarch64-virtualization-framework.zip` | 13,912,498 | `fd317ec8779307ad2b5600b6535deb0918dc2b70d2b7a01d1da3d23268dac23b` |
| `xaios_b6-aarch64-vmware-fusion.zip` | 13,905,807 | `a48103db377c0dc6e94ab1b5f44a5f029b81fcd39fb978eaa53ac98d41a8b249` |
| `xaios_b6-aarch64.iso` | 219,492,352 | `6e70d935e9f54bd34022db7a12d5c82bc6a2c50a4482beeac7de371e0de12aff` |
| `xaios_b6-aarch64.iso.zip` | 13,901,155 | `ca108b66e469d15c3e619d372e7e3f9f5493702f3b84feb09dcd09c89f3900d0` |
| `xaios_b6-riscv64-netboot.zip` | 4,270,592 | `50538432d2cb1271026945481be5ce39a4165c33ae255e51cdee65772dd7fbbb` |
| `xaios_b6-riscv64-qemu.zip` | 13,079,076 | `c4a97acbe25236f9ded0da3d30c602a4c6ed0c940f681ce82e8baba84e64a7a1` |
| `xaios_b6-riscv64-usb.zip` | 13,079,432 | `f924db21bd4bd92e32a1f9f0a2724c24722a515eb58c0897761463d09038434d` |
| `xaios_b6-riscv64.iso` | 84,226,048 | `562ad49f33e89b0e609012dfede39a5902f89181004af2220473fc96a4895799` |
| `xaios_b6-riscv64.iso.zip` | 13,075,130 | `2af83e7fdf5c93f0f971a01c0bf2f5bc3c7bd7afa4e22db01dcc2e40702231ff` |
| `xaios_b6-x86_64-netboot.zip` | 2,202,876 | `551b9cebee7dc9427f3b148a27a1a88b40acedb7158cbbe20833d2a567f32401` |
| `xaios_b6-x86_64-qemu.zip` | 6,750,556 | `e1a1c03296dc54c57f9fc4fdfce5e9b6f5073dff121b5d35afaee51e2898b125` |
| `xaios_b6-x86_64-usb.zip` | 6,751,672 | `b4a30a2a52b1fe642519fae2431fe499a129d57fb1bc3429399b336802504af4` |
| `xaios_b6-x86_64.iso` | 77,934,592 | `03bffb26b2069a98703b7f815b28b4fd1600998fb455a561529fa5f00c3720c1` |
| `xaios_b6-x86_64.iso.zip` | 6,747,395 | `7ae766026d8f7ea094468679aed79721f2bf7b57221126cb92c6aa64ac0fa75a` |

## Where this was tested

Every result below is from **this build's own files**, unzipped and booted the
way a recipient would.

| Kit | Booted to a login with SSH listening | Under |
|---|---|---|
| `xaios_b6-aarch64-qemu.zip` | yes | QEMU 11.1.1, `virt`, `gic-version=3`, TCG |
| `xaios_b6-x86_64-qemu.zip` | yes | QEMU 11.1.1, `q35`, `cpu max`, TCG |
| `xaios_b6-riscv64-qemu.zip` | yes | QEMU 11.1.1, `virt,acpi=off`, `rv64`, EDK2 RISC-V |
| `xaios_b6-aarch64-vmware-fusion.zip` | yes | VMware Fusion, SATA CD-ROM, GRUB chainloader |
| `xaios_b6-aarch64-virtualization-framework.zip` | yes | Apple Virtualization.framework |
| `xaios_b6-aarch64-netboot.zip` | yes | the binary on an EFI System Partition |
| `xaios_b6-x86_64-netboot.zip` | yes | the binary on an EFI System Partition |
| `xaios_b6-riscv64-netboot.zip` | yes | the binary on an EFI System Partition |

Host for all of it: Apple M2, macOS 26.6.2. Only AArch64 runs on the host's own
instruction set; the other two go through QEMU's interpreter.

The RISC-V rows are the new ones. Before this build RISC-V had a loader inside
the shipped image and nothing else -- no launcher anyone downloads, no USB kit,
no network-boot binary -- so neither of those two files had ever been started.

**The gates.** `make boot-media-gate` unzips each kit, checks it carries what
its README names, and boots each architecture's shipped netboot binary from an
EFI System Partition: 72 checks. `make vm-package-gate` boots each VM kit out
of its own archive: five kits, all five up. Those two are what caught this
build's packaging faults, and there were three: a Fusion `.vmx` that still held an unsubstituted template
placeholder and so could not be built at all; a netboot binary built out of a
kernel compiled to fault on purpose, which looked like a release binary in
every respect a person can check; and a checksum helper whose fallback was
attached to a pipeline and so would have shipped a file of blank checksums on
any host without `shasum`.

**What has NOT been run on these files, and it is why this build is not
published:**

- **`make local-gates` has not been run since the split.** The table above says
  both hypervisors booted the AArch64 kit, which is true and is the shallower
  claim; the Fusion smoke, the Virtualization.framework gate and its stress gate
  are deeper and separate, and `make release-check` refuses to tag a build
  without a record of them against its commit.
- **`make release-image-gate` has not been run on these three images.** It boots
  each shipped `.iso` on every environment available, and it was rewritten for
  per-architecture images in this build. The kits carry the same three files and
  those booted, so this is a gap in coverage rather than an untested artifact --
  but it is the gate whose whole job is that distinction, and it has not run.

## Where this is not tested

- **No physical hardware, on any of the three architectures.** Every result is
  from an emulator or a hypervisor. This establishes correctness on those
  platforms; it establishes nothing about performance, and nothing about any
  real machine.
- **The USB downloads have never been written to a stick and booted on a real
  machine.** `write-usb.sh` has not been run against a real device. Treat these
  as the least-tested thing in this release.
- **`serve-netboot.sh` has never served a real machine**, on any architecture.
  All three binaries boot here from a partition rather than being fetched by
  firmware, so what is unproven is the fetch and the DHCP option-93 selection
  rather than the system inside the binary.
- **RISC-V network boot has never been exercised at all beyond that.** No RISC-V
  machine that netboots has been in front of this project, and the option-93
  value in `serve-netboot.sh` -- 27, `0x001b`, "RISC-V 64-bit UEFI" -- is taken
  from the IANA registry rather than from a machine that asked for it.
- **No hypervisor or version other than those named.**
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter, never on an Intel or AMD processor executing natively.
- **The network stack is polled**, not interrupt-driven.
- **`B-02`**, **`B-14`**, and the open rows in the
  [project tracker](https://github.com/Pummelchen/XAIOS/blob/main/wiki/Project-Tracker.md)
  stand as written.

## Identifying a running build

    XAIOS Build 6 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in each image

One kernel, one initial filesystem, that architecture's UEFI loader, and an
entropy seed. The AArch64 image additionally carries the GRUB chainloader
VMware Fusion's firmware needs, and the XAIOS loader behind it as `XAIOS.EFI`.

A kernel built to fault on purpose cannot be in any of them: `make
qemu-fault-matrix` compiles three such kernels into the same path the packaging
scripts read, and both `build-arch-image.sh` and `build-netboot-image.sh` now
refuse a kernel that carries the marker such a build writes into itself.

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
| `xaios_b6-aarch64-netboot.zip` | 2,376,019 | `83285a50cfe2b5c3b8061e2ae7255b0d6e198809209bb716d0a692cf4a2e5967` |
| `xaios_b6-aarch64-qemu.zip` | 13,904,265 | `47bcff4b81bc124b1edb1a9a99281e0accab02f1c5d6da337f47c3a6392a364e` |
| `xaios_b6-aarch64-usb.zip` | 13,905,242 | `15c6d87d8e625963f2071d844c966c0fd72069e349e5549127e3d866d3776d75` |
| `xaios_b6-aarch64-virtualization-framework.zip` | 13,912,304 | `729039fd8c49c35261701ed2eb34f8dc4024b66b6a7d98ae521255f7328856a0` |
| `xaios_b6-aarch64-vmware-fusion.zip` | 13,905,612 | `8f949eae4621a653218a69f02124036ae846ef46a25b80ffd6c3e07d39a1a2a1` |
| `xaios_b6-aarch64.iso` | 219,492,352 | `b21f2a61ab6a1c28710e0e2d3979cdc05771d6d346ab80855ce66f55a5827f98` |
| `xaios_b6-aarch64.iso.zip` | 13,900,958 | `48b3bf3068afab21a8e4016cc20241c847d0f4bc496dc2e0e2f223aecda6b51c` |
| `xaios_b6-riscv64-netboot.zip` | 4,266,986 | `bba4e911ea28f2d1b7afaf766451cac5d4e781f119ac6cb69c651a7e06514288` |
| `xaios_b6-riscv64-qemu.zip` | 13,076,247 | `1043fa9c2a80faa58109043b0e44a86d85cc3f5d2c1399696dcb5b888b944036` |
| `xaios_b6-riscv64-usb.zip` | 13,076,607 | `e9689fe63207853604a302d7042d4730db100c0d2f2b7637412e2d632272f476` |
| `xaios_b6-riscv64.iso` | 84,226,048 | `ae6e175cf7c7342e2f02933fddfa152d97ba26ce24a5d35afb9605e54e5b3a7e` |
| `xaios_b6-riscv64.iso.zip` | 13,072,305 | `0ab19eb746adaf8c6752f8f83675eac693881525e6c082147b3adf36213f34b9` |
| `xaios_b6-x86_64-netboot.zip` | 2,202,871 | `e58f4e9e431705bb6961e32709562cd8d848ede1a1c8f0c385e9c43c3aee7ca1` |
| `xaios_b6-x86_64-qemu.zip` | 6,750,490 | `f318e45151c00c7243b5ad41ef1f75a8572d9fbddfa70c5d6fef834de2e6e84a` |
| `xaios_b6-x86_64-usb.zip` | 6,751,604 | `c8caeef078aa64a1f7bcf753b72247b55623b538677639bb2715a93a99b204ff` |
| `xaios_b6-x86_64.iso` | 77,934,592 | `468a487e0f35333e2d3b39901e6313643ec6d4e8ebdfc28acb45310bcc5fb916` |
| `xaios_b6-x86_64.iso.zip` | 6,747,330 | `2e313955f2029dfcd063247fbec616ce741d2e8c577663d4a3d55673bb732d6a` |

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

The three `.iso` files themselves boot on all five environments under `make
release-image-gate`, each guest reporting this build's number and confirming it
took its kernel from the medium.

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

**`make release-image-gate` passes on all five environments**, after two defects
in the gate itself were fixed. Each guest reports `XAIOS Build 6 kernel
starting` and `system-slot: unavailable`, meaning it ran the kernel on the
medium rather than one from an A/B system volume. That second marker is there
because the Virtualization.framework row had been doing the opposite: it booted
a build 5 kernel out of the tree's own system volume while the gate reported
success, and the marker it checked was `XAIOS Build \d+`, which any build
satisfies. Both are fixed and recorded as `B-54`.

**`make local-gates` recorded the two hypervisors against this commit**, which
`make release-check` requires before a build can be tagged. That covers the
Fusion smoke, the Virtualization.framework gate and its stress gate, which are
deeper than the kit boots in the table above and separate from them.

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

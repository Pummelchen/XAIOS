# XAIOS build 3

A machine you can hand to somebody. Build 2 could be installed onto a disk by
an operator who already knew the command; this one asks.

| Download | Bytes | SHA-256 |
|---|---|---|
| `xaios_b3.iso` | 228,929,536 | `486b7b366c5c7d145560a8709e3e544062c798065e4f18d2c73f1c185308753a` |
| `xaios_b3.iso.zip` | 20,014,841 | `6e077dd3aa4ffc1f394e0b30a686b6765d3a077c208384408ee8f1bd939ff2c5` |
| `xaios_b3-qemu.zip` | 20,019,110 | `bb267150d73d0d80eb6c8c79f6f0b0039155e7815708a814e2d0ea96728ac6bf` |
| `xaios_b3-vmware-fusion.zip` | 20,018,820 | `151e9b10672f7c22a91f7b3c6cba723afac521a03e7a47f8b3bfd9838454fdfd` |
| `xaios_b3-virtualization-framework.zip` | 20,023,359 | `49f2d3a75e6302d513397964ddaaf19d34c718ba5b574ac2dcac02c648be0564` |
| `xaios_b3-usb.zip` | 20,018,767 | `d46ba6efba84dafe8b7e70292ec9f9ee76b0fa77777dfb76bc2fb6d76b0a1a5d` |
| `xaios_b3-netboot.zip` | 4,421,596 | `df18a6deb04eda19ba267fdfd8c92bc33c3d4c77cb95b8db50bbc3a09f5a8c8a` |

Everything is zipped because the ISO is larger than GitHub will accept as a
file and compressed it is not. One image, five kits; the netboot kit is the
exception and is not the image at all.

## What is new

**The first boot of a machine nobody has configured now asks how to set it
up.** It offers running from the medium it booted or installing onto a disk,
then takes an account and password, an optional six digit console PIN, the
machine's name, whether the machine should answer on the network, and whether
this console should log in without asking. Nothing is written until every
question has been answered, so a setup that is interrupted leaves the machine
exactly as it was.

This exists because of something build 2 got wrong. A release image must not
carry a credential every copy of the download shares — build 2 enforced that
by refusing password authentication in release builds outright, which meant a
released machine could never have an account at all. The code is now always
compiled and the *credential* is what a release image may not package. The
account is made on the machine, salted from that machine's own entropy.

**A machine can be called something, and so can its account.** The login
prompt and the shell prompt read `xaios` and `admin@xaios` whatever either
actually was. The username was required to be `admin` by four separate places
— the record parser, the console, the SSH path, and the kernel's command
dispatcher — and all four now work from the account the machine has.

## Where this was tested

Every environment below booted **this exact file** under
`make unified-image-gate`.

| Environment | Version tested | Attached as | Firmware |
|---|---|---|---|
| QEMU (AArch64) | 11.1.0, `-machine virt`, `-cpu cortex-a72`, `accel=tcg` | virtio-blk disk | EDK2 `edk2-stable202408-prebuilt.qemu.org` |
| QEMU (x86-64) | 11.1.0, `-machine q35`, `-cpu max`, `accel=tcg` | virtio-blk disk | OVMF (Homebrew QEMU 11.1.0) |
| VMware Fusion | 26.0.0 (build 25388279) | SATA CD-ROM | Fusion ARM64 UEFI, GRUB chainloader |
| Apple Virtualization.framework | macOS 26.6.2 (25G83) | virtio-blk disk | Virtualization.framework UEFI |

Host for all four: Apple M3, macOS 26.6.2 (25G83).

The image is deliberately not reproducible: each build embeds a fresh boot
entropy seed. The checksum above identifies one artifact, not the commit.

### Setup

`make qemu-setup-gate` passed, all fourteen checks. It builds an image that
packages no account — which is what a release image is — answers what setup
asks by watching for each prompt rather than by sleeping, and then checks the
machine that results rather than setup's own output: the name on its login
prompt, the password opening a shell, a command in that shell being accepted,
and finally the same menu installing onto a blank disk.

The command check earned its place. The kernel caches which account a machine
has; boot self-tests filled that cache before the account existed, and every
command typed by the person who had just set the machine up was refused.
Setup itself looked perfect.

### Network boot

`make qemu-netboot-gate` passed. `BOOTX64.EFI` in the kit is byte-identical to
the binary the gate fetched over a real DHCP and TFTP exchange:

| File | SHA-256 |
|---|---|
| `BOOTAA64.EFI` | `b15d79eb82cc29f190e9691550b4732fc074d01154ced1902aaa4bcf75c7e191` |
| `BOOTX64.EFI` | `2777b5c86c48afc68a5a514edc50a126e8cef629e29f03dc9d0cea71c9d41194` |

`BOOTAA64.EFI` is from the same commit but is **not** the binary the gate
booted, and the difference is deliberate: the gate's AArch64 stages watch a
machine install itself onto a disk unasked, which needs a boot-time self-test
that no shipped image may contain. The binary here is built without it. What
that costs is honesty about the claim — the AArch64 netboot binary in this kit
has not itself been booted.

### Installing

`make qemu-installed-disk-gate` passed: a running XAIOS partitions and formats
a blank disk, and that disk then boots on its own, twice, so a system that
silently reformatted itself on every start would fail.

## Where this is not tested

- **No physical hardware.** Every result is from an emulator or a hypervisor.
- **The USB kit has never been written to a stick and booted**, and
  `serve-netboot.sh` has never served a real machine. The image's EFI System
  Partition and the netboot binaries are gated; the physical last mile is not.
- **No hypervisor or version other than those named.**
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter.
- **`B-02` recurred.** A thread join under load failed once on VMware Fusion
  during this build's gate runs, and did not reproduce on the next. It had
  been seen once before, on QEMU, and not since. That is twice, on two
  hypervisors, and it is still not understood. Everything else in this build's
  gate history passed first time.
- **The read-only boot path** (`B-14`) remains written and unexercised.

## Which download

| You have | Take |
|---|---|
| QEMU, either architecture | `xaios_b3-qemu.zip` |
| VMware Fusion on Apple Silicon | `xaios_b3-vmware-fusion.zip` |
| A Mac, and want the host's own cores | `xaios_b3-virtualization-framework.zip` |
| A machine and a USB stick | `xaios_b3-usb.zip` |
| A machine with no disk, and a network | `xaios_b3-netboot.zip` |
| Your own tooling | `xaios_b3.iso.zip` |

On first boot the machine asks how to set itself up. There is nothing to type
beforehand and no default password to change afterwards, because there is no
default password.

## Identifying a running build

    XAIOS Build 3 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in it

Both kernels, both initial filesystems, the UEFI loader for each architecture,
and a GRUB chainloader used on VMware Fusion, whose firmware does not launch
the XAIOS loader directly from optical media.

The image is read-only. A machine with a writable volume keeps its
configuration there; a machine without one keeps it in memory and loses it at
power-off, which is what running from a stick means.

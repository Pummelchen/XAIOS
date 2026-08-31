# XAIOS build 4

A machine you can hand to somebody. On its first boot it asks how to set
itself up; there is no default password to change afterwards, because there is
no default password.

Build 3 is superseded and its artifacts should not be used — a machine
configured with SSH keys and no password account refused every key login. See
[its note](./xaios_b3.md) for what happened.

## Start here: which file do I download?

**Five of the six downloads contain exactly the same image.** What differs is
what is packaged *around* it — a launcher, a writer, a README. So pick by how
you intend to start XAIOS, not by the file name.

| I want to… | Download | What is inside | What you do with it |
|---|---|---|---|
| Try XAIOS in a virtual machine, using **QEMU** | `xaios_b4-qemu.zip` | the image, `run-aarch64.sh`, `run-x86_64.sh`, README | unzip, run one script — it creates the disk it needs and starts the VM |
| Try it in a virtual machine, using **VMware Fusion** | `xaios_b4-vmware-fusion.zip` | the image, `XAIOS.vmx`, README | unzip, open the `.vmx` in Fusion |
| Try it in a virtual machine, using **Apple's Virtualization.framework** | `xaios_b4-virtualization-framework.zip` | the image, Swift harness source, entitlements, README | unzip, build and sign the harness on your Mac, run it |
| Boot a **real machine from a USB stick** | `xaios_b4-usb.zip` | the image, `write-usb.sh`, README | unzip, run the writer against your stick, boot the machine from it |
| Boot a **real machine that has no disk**, over the network | `xaios_b4-netboot.zip` | two boot binaries, `serve-netboot.sh`, README | serve them on your network; the machine fetches one and boots |
| Use the image with **your own tooling** | `xaios_b4.iso.zip` | the image, and nothing else | whatever you had in mind |

### "What is the difference between the ISO and the USB download?"

For what ends up on the stick: **nothing.** `xaios_b4-usb.zip` contains the
same `xaios_b4.iso` as `xaios_b4.iso.zip`.

The USB download adds two things around it: a script that writes the image to
a stick — it names the disk back to you and refuses to write until you type
the device, because writing to the wrong one destroys it — and a README
explaining the two things you can do once the machine boots from it.

If you already know how to `dd` an image to a stick, take `xaios_b4.iso.zip`
and do that. If you would rather be walked through it, take the USB download.
They will produce the same stick.

### "What is the difference between the QEMU download and the ISO?"

Again the image is the same. The QEMU download adds the two launch scripts,
which matter more than they sound: the flags are not optional. Without
`gic-version=3` the machine faults before printing anything, and without
`virtio-mmio.force-legacy=false` the disk driver finds a device it will not
talk to. Both failures look like a broken image rather than a missing flag.
The README records why each flag is there.

### What the image itself is

`xaios_b4.iso` is one file that is three things at once: an ISO 9660
filesystem, a GPT-partitioned disk with an EFI System Partition, and a
bootable USB image. That is why the same file can be

- attached to a VM as a CD-ROM, and boot;
- attached to a VM as a hard disk, and boot;
- written raw to a USB stick, and boot a physical machine;
- mounted on your own computer, and read.

It carries both an AArch64 and an x86-64 kernel; firmware picks the one for
the machine in front of it. You do not choose an architecture when
downloading.

### Once it boots

The machine has no account yet, so it asks. It offers to run from the medium
you booted — writing to no disk, losing everything at power-off — or to
install onto a disk, which erases the disk you pick. Then it takes an account
name and password, an optional six digit console PIN, the machine's name,
whether it should answer on the network, and whether this console should log
in without asking.

Everything is unzipped first: none of these files are meant to be given to a
hypervisor while still in a `.zip`.

## Checksums

| Download | Bytes | SHA-256 |
|---|---|---|
| `xaios_b4.iso` | 228,929,536 | `58c320e19ffb7ee57788e65945a3e9e7ad4cb4ab23e2dbf7ee4a2f6c043e1a98` |
| `xaios_b4.iso.zip` | 19,986,018 | `286e5db0d103eeb1c59ab0385edb32dd6c81e8a98509252290efe62d70d2ce60` |
| `xaios_b4-qemu.zip` | 19,990,282 | `eec76ab6b3afa5191ea76f9ef00824ef8df400f76d275d36226dc04ffe66b84d` |
| `xaios_b4-vmware-fusion.zip` | 19,989,992 | `d0cf32b14f01762d4393c6a7626e12410dfa7b3829653fea153c497bc87bb4be` |
| `xaios_b4-virtualization-framework.zip` | 19,994,531 | `68f99dfe6272896aaa6ef85dffcd1f80fef8b7042ebee46b4d18dc269bb9ff40` |
| `xaios_b4-usb.zip` | 19,989,944 | `9ad2d060771e55a2ddf1af66c421a0b2a628345b0be92eabe7ad248e3b8fc81d` |
| `xaios_b4-netboot.zip` | 4,411,867 | `f4aa2a2d1234d0e777047a7972dc3eab10abbff2d18ae0a4e66294ef10bbd510` |

The `.iso` itself is not attached here — GitHub will not take a file that
size, which is why everything is zipped. Every download except the netboot one
unzips to that same image, and each kit carries its own `SHA256SUMS`.

The image embeds a fresh boot entropy seed on every build, so rebuilding this
commit produces a working image with a *different* checksum. The checksum
above identifies this artifact, not the commit: check a download against it,
and do not expect a rebuild to match.

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

**Setup:** `make qemu-setup-gate`, fourteen checks. It builds an image with no
account, answers what setup asks, and then tests the machine that results —
the name on its login prompt, the password opening a shell, a command in that
shell being accepted, and the same menu installing onto a blank disk.

**Network boot:** `make qemu-netboot-gate`. `BOOTX64.EFI` in the kit is
byte-identical to the binary the gate fetched over a real DHCP and TFTP
exchange:

| File | SHA-256 |
|---|---|
| `BOOTAA64.EFI` | `bc7b90ea1805fa4b2e7ee7bddb0de476c61d02c59ea2bd7c7bc3380fd810da7f` |
| `BOOTX64.EFI` | `4176ede6efac32130c41838fa53aac8b7d3bc250b1350b5f4d16277d137fe985` |

`BOOTAA64.EFI` is from the same commit but is **not** the binary the gate
booted, deliberately: the gate's AArch64 stages watch a machine install itself
unasked, which needs a boot-time self-test no shipped image may carry. The
binary here is built without it, and so has not itself been booted.

**Installing:** `make qemu-installed-disk-gate` — a running XAIOS partitions
and formats a blank disk, and that disk then boots on its own, twice.

**Interoperability:** `make qemu-docker-network-suite` and
`make qemu-freebsd-bidirectional-suite`, which are what caught build 3's
key-login fault.

## Where this is not tested

- **No physical hardware.** Every result is from an emulator or a hypervisor.
  This establishes correctness on those platforms; it establishes nothing
  about performance, and nothing about any real machine.
- **The USB download has never been written to a stick and booted on a real
  machine.** The partition layout it relies on is the one four hypervisors
  booted here, and `write-usb.sh` itself has not been run against a real
  device. Treat it as the least-tested thing in this release.
- **`serve-netboot.sh` has never served a real machine.** The binaries are
  gated and the x86-64 one was fetched over a real DHCP and TFTP exchange —
  but by QEMU's built-in server, not by dnsmasq under this script.
- **No hypervisor or version other than those named.**
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter, never on an Intel or AMD processor executing natively.
- **`B-02` has been seen twice**, on two hypervisors — a thread join failing
  under load — and is still not understood. It did not appear in this build's
  gate runs.
- **The read-only boot path** (`B-14`) remains written and unexercised.

## Identifying a running build

    XAIOS Build 4 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in the image

Both kernels, both initial filesystems, the UEFI loader for each architecture,
and a GRUB chainloader used on VMware Fusion, whose firmware does not launch
the XAIOS loader directly from optical media.

The image is read-only. A machine with a writable volume keeps its
configuration there; a machine without one keeps it in memory and loses it at
power-off, which is what running from a stick means.

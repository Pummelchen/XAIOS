# XAIOS build 5

A machine you can hand to somebody, now on three architectures. On its first
boot it asks how to set itself up; there is no default password to change
afterwards, because there is no default password.

What is new since build 4, for someone running it: a RISC-V kernel in the
same image beside the AArch64 and x86-64 ones; `xtop`, a process monitor
redrawn after mactop that sends only the cells that changed and draws the
same picture on the console and over SSH; a screen framework that gives every
full-screen program the same economy; and a machine that is idle when nothing
is happening, where build 4's SSH server held a whole core from boot. The
[changelog](https://github.com/Pummelchen/XAIOS/blob/main/CHANGELOG.md#build-5--2026-09-05) has the full list.

## Start here: which file do I download?

**Five of the six downloads contain exactly the same image.** What differs is
what is packaged *around* it — a launcher, a writer, a README. So pick by how
you intend to start XAIOS, not by the file name.

| I want to… | Download | What is inside | What you do with it |
|---|---|---|---|
| Try XAIOS in a virtual machine, using **QEMU** | `xaios_b5-qemu.zip` | the image, `run-aarch64.sh`, `run-x86_64.sh`, README | unzip, run one script — it creates the disk it needs and starts the VM |
| Try it in a virtual machine, using **VMware Fusion** | `xaios_b5-vmware-fusion.zip` | the image, `XAIOS.vmx`, README | unzip, open the `.vmx` in Fusion |
| Try it in a virtual machine, using **Apple's Virtualization.framework** | `xaios_b5-virtualization-framework.zip` | the image, Swift harness source, entitlements, README | unzip, build and sign the harness on your Mac, run it |
| Boot a **real machine from a USB stick** | `xaios_b5-usb.zip` | the image, `write-usb.sh`, README | unzip, run the writer against your stick, boot the machine from it |
| Boot a **real machine that has no disk**, over the network | `xaios_b5-netboot.zip` | two boot binaries, `serve-netboot.sh`, README | serve them on your network; the machine fetches one and boots |
| Use the image with **your own tooling** | `xaios_b5.iso.zip` | the image, and nothing else | whatever you had in mind |

### "What is the difference between the ISO and the USB download?"

For what ends up on the stick: **nothing.** `xaios_b5-usb.zip` contains the
same `xaios_b5.iso` as `xaios_b5.iso.zip`.

The USB download adds two things around it: a script that writes the image to
a stick — it names the disk back to you and refuses to write until you type
the device, because writing to the wrong one destroys it — and a README
explaining the two things you can do once the machine boots from it.

If you already know how to `dd` an image to a stick, take `xaios_b5.iso.zip`
and do that. If you would rather be walked through it, take the USB download.
They will produce the same stick.

### "What is the difference between the QEMU download and the ISO?"

Again the image is the same. The QEMU download adds the two launch scripts,
which matter more than they sound: the flags are not optional. Without
`gic-version=3` the machine faults before printing anything, and without
`virtio-mmio.force-legacy=false` the disk driver finds a device it will not
talk to. Both failures look like a broken image rather than a missing flag.
The README records why each flag is there.

There is no RISC-V launch script in the kit. The image carries the RISC-V
kernel, but the only RISC-V machine that has booted anything here is QEMU's
`virt` board through `platform/qemu/run-qemu-riscv64.sh` in the repository,
booting a RISC-V medium built from this commit rather than this file. See
"Where this is not tested".

### What the image itself is

`xaios_b5.iso` is one file that is three things at once: an ISO 9660
filesystem, a GPT-partitioned disk with an EFI System Partition, and a
bootable USB image. That is why the same file can be

- attached to a VM as a CD-ROM, and boot;
- attached to a VM as a hard disk, and boot;
- written raw to a USB stick, and boot a physical machine;
- mounted on your own computer, and read.

It carries an AArch64, an x86-64 and a RISC-V kernel; firmware picks the one
for the machine in front of it. You do not choose an architecture when
downloading.

### Once it boots

The machine has no account yet, so it asks. It offers to run from the medium
you booted — writing to no disk, losing everything at power-off — or to
install onto a disk, which erases the disk you pick. Then it takes an account
name and password, an optional six digit console PIN, the machine's name,
whether it should answer on the network, and whether this console should log
in without asking.

Once you are in, `xtop` is the process monitor: `L` cycles its three layouts,
`F1` lists the keys, `-` and `+` set how often it samples. It runs at the
same cost whether you watch it on the machine's own screen or over SSH.

Everything is unzipped first: none of these files are meant to be given to a
hypervisor while still in a `.zip`.

## Checksums

| Download | Bytes | SHA-256 |
|---|---|---|
| `xaios_b5.iso` | 237,318,144 | `e6ba85080ed01aa1f2e045987164acb63deefd5f9cdda3ce0ff4bbc84e6ba0c1` |
| `xaios_b5.iso.zip` | 26,077,833 | `81c58744c51e0e51dcc12989b55be217e7edd8548187a0ab2b23bf9d8a3b851d` |
| `xaios_b5-qemu.zip` | 26,082,097 | `16a2463617fbc06b99a92397cf1733b626bd33a0b640fd377905680f3811605a` |
| `xaios_b5-vmware-fusion.zip` | 26,081,808 | `7bfb9e4fd8fb763469c973416ee98ca99879ca5b6c04264389ee9582a5cefa4c` |
| `xaios_b5-virtualization-framework.zip` | 26,086,550 | `bd3c6517cbf73d4acebe5a7a75833f3406909812466cf53978fec4b4fd4a92a4` |
| `xaios_b5-usb.zip` | 26,081,756 | `0ed4b48476fc6798af687886b42f9d906c5aaf65f3aaebee3eb2bb6bf0f5db74` |
| `xaios_b5-netboot.zip` | 4,503,878 | `2b445d6b58684b35d1fff66855686e8c12fe577853dd0f2dbcf07b45abd5c1f0` |

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
| QEMU (AArch64) | 11.1.1, `-machine virt`, `-cpu cortex-a72`, `accel=tcg` | virtio-blk disk | EDK2 `edk2-stable202408-prebuilt.qemu.org` |
| QEMU (x86-64) | 11.1.1, `-machine q35`, `-cpu max`, `accel=tcg` | virtio-blk disk | OVMF (Homebrew QEMU 11.1.1) |
| VMware Fusion | 26.0.0 (build 25388279) | SATA CD-ROM | Fusion ARM64 UEFI, GRUB chainloader |
| Apple Virtualization.framework | macOS 26.6.2 (25G83) | virtio-blk disk | Virtualization.framework UEFI |

Host for all four: Apple M2, macOS 26.6.2 (25G83).

**The hypervisors, at length:** `make local-gates` — the Fusion smoke, the
Virtualization.framework gate and its stress gate — recorded against the
commit this build is cut from, which `make release-check` requires before a
build can be tagged.

**The downloads themselves:** `make vm-package-gate` and `make
boot-media-gate` unzip the kits as a recipient would and boot what comes
out — the QEMU, Fusion and Virtualization.framework kits from their own
archives, and the netboot kit's AArch64 binary from an EFI System
Partition. That is what caught this build's one packaging fault: the
Fusion profile in the kit still held a template placeholder for its
network device, which Fusion refuses to power on at all. Fixed before
this build was cut, and the kit builder now refuses to emit a profile
with a placeholder left in it.

**Setup:** `make qemu-setup-gate`, fourteen checks. It builds an image with no
account, answers what setup asks, and then tests the machine that results —
the name on its login prompt, the password opening a shell, a command in that
shell being accepted, and the same menu installing onto a blank disk.

**Installing:** `make qemu-installed-disk-gate` — a running XAIOS partitions
and formats a blank disk, and that disk then boots on its own, twice.

**Network boot:** `make qemu-netboot-gate` fetches an x86-64 binary over a
real DHCP and TFTP exchange and boots it; `make boot-media-gate` puts the
shipped AArch64 binary on an EFI System Partition and boots it to the login
prompt with SSH listening. The binaries in the kit:

| File | SHA-256 |
|---|---|
| `BOOTAA64.EFI` | `f73d16b07a9abd4a939608a62e1c683ac38f481a62d3c597ca05b157a6567d0d` |
| `BOOTX64.EFI` | `de5959517bde896c4a5c25f095124091804ab2387192ee9fe5e76e8091f1b02b` |

**RISC-V:** `make qemu-riscv64-release-gate` — the release configuration
booting on QEMU's `virt` board at four harts, a login by password, `hello`,
`sysinfo` and `xtop` run as processes — plus the boot-media gate, which boots
the signed A/B medium through EDK2, and the matrix gate at one, two, four
and eight harts.

**The screen, on all three architectures:** `make qemu-console-xtop-gate`
(and `-x86_64`, `-riscv64`) reads the framebuffer back out of QEMU as pixels,
decodes it through the kernel's own font tables, compares it with the frame
an SSH client received at the same size, and requires that `pong` over SSH —
a program that redraws its whole screen sixty times a second — reaches the
client with no screen clears and under thirty kilobytes a second. It measured
about a hundred and forty bytes a second.

## Where this is not tested

- **No physical hardware, on any of the three architectures.** Every result
  is from an emulator or a hypervisor. This establishes correctness on those
  platforms; it establishes nothing about performance, and nothing about any
  real machine.
- **The RISC-V half of this image has not been booted from this image.** The
  RISC-V gates boot a RISC-V medium built from the same commit; the unified
  image gate has no RISC-V environment. The kernel and initial filesystem in
  this file are the same bytes that medium carries, and that is the whole
  claim.
- **The USB download has never been written to a stick and booted on a real
  machine.** The partition layout it relies on is the one four hypervisors
  booted here, and `write-usb.sh` itself has not been run against a real
  device. Treat it as the least-tested thing in this release.
- **`serve-netboot.sh` has never served a real machine.** The binaries are
  gated — the x86-64 one fetched over a real DHCP and TFTP exchange, the
  AArch64 one booted from a partition — but by QEMU, not by dnsmasq under this
  script on a real network.
- **No hypervisor or version other than those named.**
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter, never on an Intel or AMD processor executing natively.
- **The network stack is polled**, not interrupt-driven. The kernel's wait for
  events looks at it every one to eight milliseconds, which is why an idle
  server still shows a few percent of a core under emulation.
- **`B-02`** — a thread join failing under load, seen twice on two
  hypervisors — has a fix in this build whose link to those sightings is
  inference, not a reproduction. It did not appear in this build's gate runs
  and stays open.
- **The read-only boot path** (`B-14`) remains written and unexercised.

## Identifying a running build

    XAIOS Build 5 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in the image

Three kernels, three initial filesystems, the UEFI loader for each
architecture, and a GRUB chainloader used on VMware Fusion, whose firmware
does not launch the XAIOS loader directly from optical media.

The image is read-only. A machine with a writable volume keeps its
configuration there; a machine without one keeps it in memory and loses it at
power-off, which is what running from a stick means.

# XAIOS build 8

Build 8 is the build where the gates went quiet: every defect the previous
build's cut and the CI runner turned up is fixed here, and CI is green end to
end for the commits that carry them.

Two of those defects were in the repository rather than in the operating
system, and both had been hiding behind something in front of them. The host
WebTransport tests linked only the *verify* half of the signature primitives,
so the link had failed since the day the port started signing with a loaded
key; behind that failure, the QUIC packet suite's split module used counter
names a rename had retired, which nothing had compiled. The interop peer
compiled the vendored trees with this repository's `-Werror` and a hard-coded
`llvm-ar`, neither of which survives a Linux runner. And the booted-guest
handshake gate had been read as a network fault for a day: its host peer waited
a fixed twenty seconds for a client that takes longer than that to boot.

One was a memory-safety defect the runner found by building the same sources
with a different compiler. `malformed_packet_self_test` built a 54-byte ARP
frame in a 52-byte array -- two bytes past the end, every call. macOS clang left
padding there; Linux clang reused those two bytes for the caller's pointer, and
the RISC-V release image panicked in the kernel-services stage. It was found by
booting the runner's own artifact on this machine, where it halted identically,
and reading the fault out of the kernel inside that ISO.

## Start here: which file do I download?

First decide which machine you are running it on. The architecture is the first
choice, and it is not reversible by downloading a different kit -- an AArch64
image will not boot an x86-64 machine.

| To run XAIOS on | AArch64 | x86-64 | RISC-V 64-bit |
|---|---|---|---|
| QEMU | `xaios_b8-aarch64-qemu.zip` | `xaios_b8-x86_64-qemu.zip` | `xaios_b8-riscv64-qemu.zip` |
| VMware Fusion | `xaios_b8-aarch64-vmware-fusion.zip` | — | — |
| Apple Virtualization.framework | `xaios_b8-aarch64-virtualization-framework.zip` | — | — |
| a real machine, from a USB stick | `xaios_b8-aarch64-usb.zip` | `xaios_b8-x86_64-usb.zip` | `xaios_b8-riscv64-usb.zip` |
| a real machine with no disk, over the network | `xaios_b8-aarch64-netboot.zip` | `xaios_b8-x86_64-netboot.zip` | `xaios_b8-riscv64-netboot.zip` |
| your own tooling | `xaios_b8-aarch64.iso.zip` | `xaios_b8-x86_64.iso.zip` | `xaios_b8-riscv64.iso.zip` |

### What the image itself is

One bootable file per architecture: hybrid ISO 9660 and GPT, bootable as
optical media, as a disk, or written to a USB stick. It carries one kernel, one
initial filesystem, that architecture's UEFI loader and an entropy seed.

### Once it boots

There is no account and no password. The machine asks how to set itself up on
first boot, and a key can be added instead of a password. `sshd` is running
from that first boot, so the machine is reachable as soon as it has an address.

## What changed in this build

- **A two-byte stack overrun in the virtio-net self-test is fixed** -- the
  defect that panicked the RISC-V release image built anywhere other than this
  machine.
- **The WebTransport host tests, the sanitizer run and the interop handshake
  pass on Linux**, and the booted-guest handshake gate passes in CI on an Apple
  Silicon runner, with the peer's wait now the caller's budget rather than a
  fixed twenty seconds.
- **The RISC-V release-image row has a budget a shared runner can meet**, and
  the Fusion version check is a version line rather than one exact build.
- **The DNS probe in the core OS aggregate reports the session's return code
  and stderr** instead of leaving "produced no output" to be guessed at.
- **`make docs-check` still holds the 500-line limit**: no file in the
  repository is over it, and a new one that crosses it fails the check.

## Checksums

| File | Bytes | SHA-256 |
|---|---|---|
| `xaios_b8-aarch64-netboot.zip` | 2,418,338 | `24731bf0226e8c2c6b5a79975840c76fadef7914d1287215c163ff073149f6cc` |
| `xaios_b8-aarch64-qemu.zip` | 14,033,129 | `581af57c889196f277cc9d98a9217e807fa474db1c79b53e7861af7ec27b3c72` |
| `xaios_b8-aarch64-usb.zip` | 14,034,109 | `161f53ed0601e0b74a724d8af4b82b839f065f58176119aa68348beac39beee4` |
| `xaios_b8-aarch64-virtualization-framework.zip` | 14,041,170 | `c21eb9bb134961749b6d47d9a5abeec3e83598d1c4e6f8c535cf7fc49ebf71f3` |
| `xaios_b8-aarch64-vmware-fusion.zip` | 14,034,478 | `2a56002cce003037f0e5dc20e5975e521b3adbf3992f3c34f7efe171b6a2eabe` |
| `xaios_b8-aarch64.iso` | 219,492,352 | `ebaf9f62522cf8e74e8d00a49300d88a681e263f95d52cfa9ec1970fb8a709d7` |
| `xaios_b8-aarch64.iso.zip` | 14,029,824 | `519a134cd4b4b538351061049bfa344c00cc706d4a725a80cb5fec98b290c0b3` |
| `xaios_b8-riscv64-netboot.zip` | 4,236,751 | `44e3b3e66cf8b220b664fbc4f1726013d87729806790df165b4455daabb33415` |
| `xaios_b8-riscv64-qemu.zip` | 12,985,619 | `fdfc0d2e9bbfe22e5dc008536d670ac0ff860f5ca064f306f82bb143c9ce05c6` |
| `xaios_b8-riscv64-usb.zip` | 12,985,975 | `c57b693734f7bba14c50313c40d2bcdc85d2a9cf0f9d7cd5116e983913c1fcd1` |
| `xaios_b8-riscv64.iso` | 84,226,048 | `ccd58fc255c71ff38aa11d46217662c80bf9cc34de026099c4f08ef9d8867329` |
| `xaios_b8-riscv64.iso.zip` | 12,981,671 | `89b6bc3454ebf833735eeb787ab10c4092da36f0e997a2b50e756cf35c6fa092` |
| `xaios_b8-x86_64-netboot.zip` | 2,209,863 | `2759c67d6630a2e4fbce85e5875a2641d1051513311cecfeca6dec987efa58c9` |
| `xaios_b8-x86_64-qemu.zip` | 6,771,504 | `5ab8f7ec20b419d0252a30949f12013b2175053aae5508c30545d8566171478b` |
| `xaios_b8-x86_64-usb.zip` | 6,772,620 | `81046c16ecfa0919be462170560811d050f475facadb9ac9e3f2e6a1b2a96f52` |
| `xaios_b8-x86_64.iso` | 77,934,592 | `75eac24b4a840dd52efe7be45f9391e947ecb83a08d3522a6d17d6c1d595c9df` |
| `xaios_b8-x86_64.iso.zip` | 6,768,345 | `bbbd69c92f59128f9fd6c423924f3eb08860a7379f6fab9254850094cf16e140` |

## Where this was tested

Every result below is from **this build's own files**, booted the way a
recipient would.

| Environment | Image | Booted to a login with SSH listening |
|---|---|---|
| QEMU, `virt`, `gic-version=3`, TCG | `xaios_b8-aarch64.iso` | yes |
| QEMU, `q35`, `cpu max`, TCG | `xaios_b8-x86_64.iso` | yes |
| QEMU, `virt,acpi=off`, `rv64`, EDK2 RISC-V | `xaios_b8-riscv64.iso` | yes |
| VMware Fusion | `xaios_b8-aarch64.iso` | yes |
| Apple Virtualization.framework | `xaios_b8-aarch64.iso` | **not checked** -- the guest console never attached on this host |

`make release-image-gate` boots each released image on every environment that
can run it: four of the five boot the released files to a login prompt with SSH
listening, and each guest reports this build's number.

`make boot-media-gate` passes 72 checks over the USB and network-boot kits, and
`make vm-package-gate` brings four of the five kits up as their READMEs say --
the Virtualization.framework kit is the one that does not, for the host reason
below.

**`make vmware-fusion-smoke`** -- deeper than the Fusion row above -- runs on
this host now, because the version check accepts a patch release inside the
`26.0` line the smoke was written for. It reports the version it found beside
the result.

The Virtualization.framework row is **not checked**, which is a different
sentence from "checked and passing": the harness runs, and the guest produces
no output at all after the firmware hands control to the loader -- no kernel
line, no framebuffer console, no serial. The released build 6 image behaves the
same way on this host, so it is the host (macOS 27.0) rather than the build,
and it is recorded here rather than counted as a pass.

## Where this is not tested

- **No physical hardware, on any of the three architectures.** Every result is
  from an emulator or a hypervisor.
- **The USB downloads have never been written to a stick and booted on a real
  machine.**
- **`serve-netboot.sh` has never served a real machine**, on any architecture.
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter, never on an Intel or AMD processor executing natively.
- **Apple Virtualization.framework is not checked on this host**, for the
  reason above.
- The open rows in the
  [project tracker](https://github.com/Pummelchen/XAIOS/blob/main/wiki/Project-Tracker.md)
  stand as written.

## Identifying a running build

    XAIOS Build 8 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in each image

One kernel, one initial filesystem, that architecture's UEFI loader, and an
entropy seed.

A kernel built to fault on purpose cannot be in any of them: `make
qemu-fault-matrix` compiles three such kernels into the same path the packaging
scripts read, and both `build-arch-image.sh` and `build-netboot-image.sh` refuse
a kernel that carries the marker such a build writes into itself.

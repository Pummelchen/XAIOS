# Getting Started

This guide builds and starts the AArch64 XAIOS image under QEMU. See
[[Hardware Support|Hardware-Support]] for x86_64, VMware Fusion and Apple
Virtualization.framework boundaries.

If you only want to *run* XAIOS, you do not need any of this — take a released
build instead.

## Download a build

Released builds are on the
[releases page](https://github.com/Pummelchen/XAIOS/releases), the current one
being **build 4**. Six downloads, of which five contain the same image; what
differs is what is packaged around it.

| To run XAIOS | Take |
|---|---|
| in QEMU | `xaios_b4-qemu.zip` — image plus a launch script per architecture |
| in VMware Fusion | `xaios_b4-vmware-fusion.zip` — image plus a `.vmx` |
| in Apple Virtualization.framework | `xaios_b4-virtualization-framework.zip` — image plus a harness you build and sign |
| on a real machine, from a USB stick | `xaios_b4-usb.zip` — image plus a writer that names the target disk back before it writes |
| on a real machine with no disk, over the network | `xaios_b4-netboot.zip` — two boot binaries plus a DHCP/TFTP server script |
| with your own tooling | `xaios_b4.iso.zip` — the image alone |

Unzip before use; none of these are meant to be handed to a hypervisor while
still zipped. The image is simultaneously an ISO 9660 filesystem, a
GPT-partitioned disk with an EFI System Partition, and a bootable USB image,
which is why one file covers CD-ROM, hard disk and stick, and why the ISO and
USB downloads differ only by the writer script and its instructions. It carries
both an AArch64 and an x86-64 kernel and firmware picks the right one, so there
is no architecture to choose when downloading.

On first boot the machine has no account and asks how to set itself up — run
from the medium, or install onto a disk — then takes an account name and
password, an optional six digit console PIN, the machine's name, and whether it
should answer on the network. There is no default password to change
afterwards.

Each release note records the hypervisors and firmware that build was booted
on, and what was not tested. No release has been booted on physical hardware.

The rest of this page builds an image from source instead.

## Prerequisites

On macOS:

```sh
brew install llvm lld qemu mtools python3 xorriso
```

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 mtools python3
```

Homebrew LLVM is required on macOS because the Apple system compiler does not
provide the complete freestanding cross-target toolchain used by the build.

## Build

From the repository root:

```sh
make bootstrap
make image
```

The generated AArch64 boot image is `build/xaios-aarch64.img`. Other generated
EFI, kernel, initramfs, persistent-storage, and test artifacts remain under the
ignored `build/` directory.

For x86_64:

```sh
make image-x86_64
```

## Boot in QEMU

```sh
make qemu
```

`make qemu` is the AArch64 alias. It defaults to TCG, including on Apple
Silicon. Press `Ctrl-A X` to exit QEMU. Set `XAIOS_BOOT_VERBOSE=1` only when a
boot failure requires scrolling diagnostics.

The launcher forwards host TCP port 7788 to guest SSH port 22 by default. The
development image includes the public development account `admin` / `xaios`.
Use it only on isolated development networks; release images reject password
authentication. For a key-only development image, pass
`XAIOS_SSH_PASSWORD_AUTH=0` when building. To provision key-based access:

```sh
mkdir -p build/local-ssh
ssh-keygen -t ed25519 -N '' -f build/local-ssh/admin
XAIOS_AUTHORIZED_KEYS_FILE=build/local-ssh/admin.pub make image
make qemu
```

From another terminal:

```sh
ssh -p 7788 -i build/local-ssh/admin admin@127.0.0.1
```

OpenSSH also accepts `ssh ssh://admin@127.0.0.1:7788`. The form
`admin@127.0.0.1:7788` is not valid OpenSSH destination syntax.

The repository helper keeps host-key verification enabled and accepts a remote
command after `--`:

```sh
platform/qemu/ssh-xaios-qemu.sh
platform/qemu/ssh-xaios-qemu.sh -- htop
```

## First commands

```text
pwd
ls -la /
mkdir -p /home/admin/demo
echo hello > /home/admin/demo/message.txt
cat /home/admin/demo/message.txt
htop
```

See [[Commands|Commands]] for the complete shell surface and
[[Applications|Applications]] for executable programs.

## Validate the image

```sh
make compile-check
make qemu-smoke
```

The complete reproducible validation inventory, including Docker rebuilds, is
documented in [[Testing XAIOS|Testing-XAIOS]].

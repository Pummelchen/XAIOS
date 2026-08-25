# Getting Started

This guide builds and starts the AArch64 XAIOS image under QEMU. See
[[Hardware Support|Hardware-Support]] for x86_64, VMware Fusion and Apple
Virtualization.framework boundaries.

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

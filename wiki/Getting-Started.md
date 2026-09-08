# Getting Started

This page takes you from nothing to a XAIOS login prompt. There are two routes
and they are independent: download a released image and boot it, or build one
from source. The build route defaults to AArch64 under QEMU; see
[[Hardware Support|Hardware-Support]] for x86_64, VMware Fusion and Apple
Virtualization.framework boundaries, and [[RISC-V|RISC-V]] for the rv64gc port,
which builds and runs the same way through its own scripts.

## Download a build

Released builds are on the
[releases page](https://github.com/Pummelchen/XAIOS/releases), the current one
being **build 5**. Six downloads, of which five contain the same image; what
differs is what is packaged around it.

| To run XAIOS | Take |
|---|---|
| in QEMU | `xaios_b5-qemu.zip` — image plus `run-aarch64.sh` and `run-x86_64.sh`. There is no RISC-V script in the kit; the image carries the RISC-V kernel, but the only RISC-V machine anything here has booted on is QEMU's `virt` board through `platform/qemu/run-qemu-riscv64.sh` in the repository |
| in VMware Fusion | `xaios_b5-vmware-fusion.zip` — image plus a `.vmx` |
| in Apple Virtualization.framework | `xaios_b5-virtualization-framework.zip` — image plus a harness you build and sign |
| on a real machine, from a USB stick | `xaios_b5-usb.zip` — image plus a writer that names the target disk back before it writes |
| on a real machine with no disk, over the network | `xaios_b5-netboot.zip` — two boot binaries plus a DHCP/TFTP server script |
| with your own tooling | `xaios_b5.iso.zip` — the image alone |

Unzip before use; none of these are meant to be handed to a hypervisor while
still zipped. The image is simultaneously an ISO 9660 filesystem, a
GPT-partitioned disk with an EFI System Partition, and a bootable USB image,
which is why one file covers CD-ROM, hard disk and stick, and why the ISO and
USB downloads differ only by the writer script and its instructions. It carries
an AArch64, an x86-64 and a RISC-V kernel and firmware picks the one for the
machine in front of it, so there is no architecture to choose when
downloading.

On first boot the machine has no account and asks how to set itself up — run
from the medium, or install onto a disk — then takes an account name and
password, an optional six digit console PIN, the machine's name, and whether it
should answer on the network. There is no default password to change
afterwards.

Each release note records the hypervisors and firmware that build was booted
on, and what was not tested. No release has been booted on physical hardware.

The rest of this page builds an image from source instead.

## Get the source

```sh
git clone --recurse-submodules https://github.com/Pummelchen/XAIOS.git
cd XAIOS
```

The submodule is not optional. The hosted C99 library is built from Picolibc
under `third_party/`, and `make image` builds that library on the way to the
image, so a plain `git clone` stops with:

```text
error: Picolibc submodule is missing; run git submodule update --init --recursive
```

If you already cloned without it, run that command.

## Prerequisites

On macOS:

```sh
brew install llvm lld qemu mtools python3 meson ninja xorriso
```

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y clang lld llvm qemu-system-arm qemu-efi-aarch64 \
    mtools python3 meson ninja-build
```

Homebrew LLVM is required on macOS because the Apple system compiler does not
provide the complete freestanding cross-target toolchain used by the build.
`meson` and `ninja` are needed because the libc build uses them, not because
XAIOS itself does.

### The one PATH entry that matters

```sh
export PATH="$(brew --prefix llvm)/bin:$PATH"
```

`scripts/build-image.sh` and the QEMU launchers find `clang`, `ld.lld`, `mtools`
and `qemu-system-aarch64` through `brew --prefix`, so they work whatever your
`PATH` says. `scripts/build-libc.sh` does not: it looks for `llvm-ar` — along
with `meson`, `ninja` and `python3` — on `PATH` and nowhere else, and refuses to
start when it is missing. Since `make image` calls it, the export above is the
difference between a build and `error: required tool not found: llvm-ar`.

### Check the toolchain

```sh
make bootstrap
```

`make bootstrap` is a macOS check and nothing else: it locates each tool, tests
that QEMU has HVF, TCG and the `virt` machine, and finds the AArch64 UEFI
firmware, then reports `ok:` and `fail:` lines. It installs nothing and changes
nothing. On Linux it fails immediately with `fail: host OS is Linux, expected
macOS/Darwin`; skip it there and rely on the package list above.

## Build

From the repository root:

```sh
make image
```

The generated AArch64 boot image is `build/xaios-aarch64.img`. Alongside it the
build writes the VirtIO scratch disk, the persistent xaibootFS volume, the
signed xaiFS model volume and the signed A/B system volume; all of them, and
every EFI, kernel, initramfs and test artifact, stay under the ignored `build/`
directory. The last lines of a successful build name them, with the repository
root elided from the paths:

```text
check-user-elf-base: 57 user binaries link at 0x3fc0000000
Creating FAT boot image: build/xaios-aarch64.img
Created build/xaios-aarch64.img
Creating VirtIO block test image: build/xaios-virtio-test.img
Creating persistent disk image: build/xaios-persistent.img
Created build/xaios-persistent.img (16 MB, 32768 sectors)
Creating signed xaiFS fixture: build/xaios-xaifs.img
Creating signed A/B system volume: build/xaios-system.img
system-volume: verified active=0 pending=4294967295 attempted=0 sequence=1 metadata=primary
```

For x86_64:

```sh
make image-x86_64
```

## Boot in QEMU

```sh
make qemu
```

`make qemu` is the AArch64 alias. It defaults to TCG, including on Apple
Silicon, and to four vCPUs and 2 GiB of memory. Press `Ctrl-A X` to exit QEMU.
`make qemu-dry-run` prints the exact `qemu-system-aarch64` command line without
running it, which is the quickest way to see what the launcher decided. Set
`XAIOS_BOOT_VERBOSE=1` only when a boot failure requires scrolling diagnostics.

### What success looks like

The firmware speaks first, and its complaints are not XAIOS's — EDK2 prints
`ArmTrngLib could not be correctly initialized`, several `Error: Image at ...
start failed` lines and `Image type X64 can't be loaded on AARCH64 UEFI system`
on a perfectly good boot. Then the XAIOS boot display takes the screen and
redraws in place, `XAI` in purple and `OS` in cyan:

```text
XAI OS

[########################################] 100%

Loaded: system services
Loading: complete
Remaining: 0 components

IPv4: 10.0.2.15
IPv6: fe80::5054:ff:fe12:3457
SSH server: up and running (tcp/22)

xaios login:
```

Three things in that tail are the ones to check. The bar reaching 100% means
every component reported in; `SSH server: up and running (tcp/22)` is printed
only after the listener is actually open, so a numeric startup error in its
place is a real failure and not a timing artefact; and `xaios login:` means
userspace is alive. The address comes from QEMU's user-mode networking, which
hands out `10.0.2.15` by default. See [[Boot and Console|Boot-and-Console]] for
the login policy and for what a failed boot looks like.

### Connect over SSH

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
platform/qemu/ssh-xaios-qemu.sh -- xtop
```

## First commands

The prompt names the account and the machine. The shell runs one command per
line: there is no `;` separator, and a line containing one is reported as a
command that does not exist.

```text
admin@xaios:/$ ls -la /
d 0 etc
d 0 bin
d 0 state
d 0 config
d 0 logs
d 0 workspaces
d 0 models
d 0 tmp
d 0 home
d 0 var
d 0 update
d 0 apps

admin@xaios:/$ mkdir -p /home/admin/demo
admin@xaios:/$ echo hello > /home/admin/demo/message.txt
admin@xaios:/$ cat /home/admin/demo/message.txt
hello

admin@xaios:/$ df
Filesystem Size Used Avail Capacity Mounted on
xaibootFS 2048K 29K 2018K 2% /
xaiFS 65536K 10312K 55224K 16% /models
```

`xaiosctl status` is the one command worth running early, because it answers
what this machine can currently do rather than what it is:

```text
admin@xaios:/$ xaiosctl status
uptime_ns=67288432992
init_service=stopped
service_manager=stopped
ssh=running
network=stopped
storage=ready
model=fixture-only
cluster=unsupported
readiness=degraded
readiness_reasons=58
online_cpus=4
worker_count=0
production_models_loaded=0
queue_depth=unknown
active_requests=unknown
physical_pages=512898
managed_pages=512898
free_pages=505846
```

`model=fixture-only` and `readiness=degraded` are accurate, not transitional: no
transformer executes here. For a live screen rather than a snapshot, run
`xtop`, the full-screen sampled process monitor.

See [[Commands|Commands]] for the complete shell surface,
[[Applications|Applications]] for executable programs, and
[[Administration|Administration]] for the full `xaiosctl` surface.

## Validate the image

```sh
make compile-check
make qemu-smoke
```

`make qemu-smoke` builds the `XAIOS_BOOT_TEST_APPS=1` fixture profile, boots it,
runs its self-tests and userspace fixtures and validates JSON telemetry. It is
correctness evidence and not hardware evidence. The complete reproducible
validation inventory, including Docker rebuilds, is documented in
[[Testing XAIOS|Testing-XAIOS]].

## Where to go next

- [[Boot and Console|Boot-and-Console]] — the boot display, login policy, console PIN, and how to read a boot failure.
- [[Networking and SSH|Networking-and-SSH]] — addressing, SFTP, outbound SSH.
- [[Filesystem and Storage|Filesystem-and-Storage]] — xaibootFS and xaiFS, and what persists across a reboot.
- [[Architecture|Architecture]] — how the loader, kernel, userspace and engine fit together.
- [[Current Limitations|Current-Limitations]] — the explicit non-claims, before you rely on anything here.
- [[Project Tracker|Project-Tracker]] — everything still open, in one place.

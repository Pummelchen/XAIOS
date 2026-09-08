# Build scripts

The programs that turn this source tree into something a machine can boot.

## `scripts/` or `tools/`?

Both directories hold host programs, and the split is by role rather than by
language:

- **`scripts/` produces artefacts.** It compiles the kernel and userspace and
  assembles them into images, boot media and distributable kits. Almost every
  file here is reached through a `make` target rather than run directly.
- **[`tools/`](../tools/README.md) reads and writes artefacts.** It builds a
  system volume, inspects a model package, or stands in for hardware — usually
  called *by* a script or a gate, occasionally by a maintainer.

The short version: if it produces the thing you boot, it is a script; if it
manipulates or inspects a file that already exists, it is a tool.

## The ones to know first

| Script | What it builds |
|---|---|
| `build-image.sh` | The AArch64 image, and the x86-64 one with `XAIOS_TARGET_ARCH=x86_64`. The single most-used script here and the one most environment switches reach. |
| `build-riscv64.sh`, `build-riscv64-image.sh`, `build-riscv64-boot-media.sh` | The RISC-V equivalents. Separate because that port boots through OpenSBI or EDK2 rather than the path the other two share. |
| `build-unified-image.sh` | One ISO that boots all three architectures and both hypervisors, which is what a release actually ships. |
| `build-boot-media.sh`, `build-netboot-image.sh` | Bootable media for real machines, and the network-boot kit for a blank one. |
| `build-libc.sh` | The hosted C99 library, its sysroot and compiler-rt. Runs before anything that links a hosted application. |
| `build-release.sh`, `build-vm-packages.sh` | A numbered build and the per-hypervisor kits published beside it. |
| `macos-bootstrap.sh` | Checks a macOS host for the toolchain and reports what is missing and how to install it. It installs nothing itself, so it is safe to run first when nothing builds yet. |

The remaining scripts create fixtures and volumes (`create-initfs.py`,
`create-persistent-image.sh`), convert artefacts (`elf-to-efi.py`,
`prepare-libc-sysroot.py`), or run a host-side helper for a gate
(`xaios-ssh-bridge.py`, `publish-xapt-repository.sh`).

## Environment switches

Build behaviour is set by environment variables rather than by flags, so a
`make` target and a direct invocation behave identically. Two matter more than
the rest and are a common source of confusion:

- **`XAIOS_TARGET_ARCH`** selects the architecture for `build-image.sh`
  (`aarch64` by default, or `x86_64`). RISC-V has its own scripts.
- **`XAIOS_BOOT_TEST_APPS`** selects the *configuration*, not the
  architecture. With it set, the image runs the test applications and the
  kernel log stays on the console. Without it — which is what `make image`
  produces — the boot UI owns the console and the kernel log is suppressed.
  A gate that reads kernel markers must build the test configuration; more
  than one gate has reported a perfectly healthy release image as a machine
  that produced no output.

Each script documents its own switches in a comment at the top. Where a switch
exists only to make something testable, the comment says so.

## Conventions

- **Failures stop the build.** A script that cannot produce a correct artefact
  exits non-zero rather than producing an incomplete one; a partial image that
  boots is worse than no image.
- **Checks run at pack time.** `build-image.sh` and `build-riscv64-image.sh`
  call `tools/check_user_elf_base.py` before assembling, so a binary linked
  where the kernel will not map it fails the build instead of panicking the
  kernel a full boot later.
- **Artefacts land in `build/`**, which is not tracked. Nothing here writes
  into the source tree.

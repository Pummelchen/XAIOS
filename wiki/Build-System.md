# Build System

XAIOS uses Make, shell scripts, Clang/LLD, Python, QEMU, and filesystem image
tools. Kernel and userspace targets are freestanding C99 plus architecture
assembly. Host tools and tests are ordinary native C or Python programs.

## Host prerequisites

macOS:

```sh
brew install llvm lld qemu mtools python3 xorriso
```

Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 mtools python3
```

Run `make bootstrap` after installing dependencies. Optional hosted Python
dependencies are listed in `requirements-dev.txt`.

## Build targets

| Target | Result |
|---|---|
| `make all` | Default repository build. |
| `make image` | AArch64 UEFI loader, kernel, userspace, initramfs, and QEMU disk images. |
| `make image-x86_64` | Focused x86_64 UEFI bring-up image. |
| `make engine-cli` | Native portable-engine command-line tool. |
| `make vmware-fusion-image` | Apple Silicon Fusion ISO and VM bundle through the ARM64 GRUB compatibility stage. |
| `make clean` | Removes generated `build/`, `out/`, and `dist/` outputs. |

`scripts/build-image.sh` is the primary image orchestrator. It selects the
architecture compiler targets, builds EFI/kernel/userspace objects, creates the
initramfs, and assembles the disk images. Architecture-specific source must be
compiled for its actual target; CI keeps AArch64 and x86_64 gates separate.

## Run targets

| Target | Purpose |
|---|---|
| `make qemu` or `make qemu-aarch64` | Interactive AArch64 QEMU boot. |
| `make qemu-x86_64` | Interactive x86_64 QEMU boot. |
| `make qemu-dry-run` | Prints validated emulator command lines without booting. |
| `make vmware-fusion` | Opens the generated ARM64 VM in Fusion. |
| `make vmware-fusion-smoke` | Validates the bounded Fusion boot path through `/init`. |

AArch64 QEMU defaults to TCG. HVF remains an explicit experimental override.
VMware packaging uses Debian only as a reproducible GRUB build environment; it
does not introduce a Linux ABI or runtime dependency into XAIOS.

## Generated artifacts

Generated images, binaries, maps, logs, packet captures, and JSON evidence live
under ignored output directories, primarily `build/`. Do not commit generated
`.img`, `.iso`, `.efi`, `.elf`, `.bin`, `.map`, `.log`, packet capture, or QEMU
report files unless a release or benchmark process explicitly defines an
immutable evidence location.

## CI

`.github/workflows/ci.yml` runs independent compile, hosted, documentation,
ABI, AArch64, x86_64, storage, network, and interoperability jobs. Later jobs
remain visible even when an unrelated job fails. The workflow uploads evidence
from long QEMU gates and pins the special upstream QEMU revision required for
translated SMMUv3 testing.

See [[Developer Guide|Developer-Guide]] and
[[Testing and Benchmarking|Testing-and-Benchmarking]].

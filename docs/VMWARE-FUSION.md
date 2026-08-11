# VMware Fusion ARM64

Status: limited virtual-platform correctness path.

Platform progress is tracked only in
[`wiki/Project-Tracker.md`](../wiki/Project-Tracker.md). VMware Fusion does not
replace the QEMU release gates and does not provide physical-hardware or
performance evidence.

## Verified Scope

On 2026-08-10, VMware Fusion 25.0.1 on an Apple M3 Mac passed:

```sh
make vmware-fusion-smoke
```

The gate builds the standard AArch64 image, builds an ARM64 GRUB UEFI
compatibility executable in a Debian 13 container, creates a UEFI El Torito ISO
and generated `.vmwarevm`, boots it with `vmrun`, checks serial markers, writes
`build/vmware-fusion/fusion-smoke-evidence.json`, and stops the VM in all normal
pass/fail paths.

Verified markers cover:

- XAIOS UEFI loader and kernel entry.
- ACPI SPCR discovery for the Fusion virtual UART.
- The versioned boot ABI and a firmware-loaded deterministic initfs image.
- RAM-backed read, write, asynchronous completion and flush behavior for that
  boot image.
- Kernel, filesystem, software IPv4/IPv6/UDP/TCP and control self-tests reached
  before userspace.
- ARM PAN-safe syscall access to validated EL0 buffers.
- A complete `/init` run and return to the kernel.

## Commands

Prerequisites are Apple Silicon macOS, VMware Fusion, Docker, Clang/LLD,
Python 3, mtools and `xorriso`.

```sh
make image
make vmware-fusion-image
make vmware-fusion-dry-run
make vmware-fusion-smoke
make vmware-fusion
```

`make vmware-fusion` opens the generated VM in the Fusion GUI. The bundle is
`build/vmware-fusion/XAIOS.vmwarevm` and is regenerated from source; do not edit
it as a source file.

## Boot Design

Fusion firmware did not load the repository's minimal XAIOS EFI application
directly from a raw FAT disk or El Torito image. The generated ISO therefore
uses standard Debian GRUB for ARM64 as a compatibility stage. GRUB does not
load the kernel or interpret XAIOS formats; it chainloads `XAIOS.EFI`, which
continues to validate and load `kernel.elf`.

Fusion does not expose the QEMU VirtIO-MMIO test disk. The EFI loader may load
`EFI/XAIOS/initfs.img` into `EfiLoaderData` pages and passes its 64-bit extent
through boot-info ABI v6. XAIOS registers that image as `boot-memory` for the
current boot. Writes are volatile and are never represented as persistent
storage or as a VMware/VirtIO hardware driver. Normal QEMU boots omit the image
and retain the existing VirtIO path.

## Open Boundaries

- Apple Silicon Fusion supports ARM64 guests, not the x86_64 XAIOS image.
- XAIOS currently discovers one CPU under Fusion; ACPI MADT CPU/GIC discovery
  and multi-vCPU startup are not integrated into the AArch64 platform path.
- The fixed QEMU GIC and PL031 addresses are rejected when they read all ones.
  ACPI-described interrupt-controller and clock support remains required.
- The generated VM has no virtual NIC. vmxnet3/e1000 support is absent, so
  external networking, SSH and SFTP are not claimed under Fusion.
- No VMware persistent block driver is present. The initfs boot image is
  volatile and A/B system, ModelFS and MutableFS persistence are not attached.
- The smoke stops after `/init`; preemptive interrupt scheduling, all later
  applications and the freestanding SSH daemon remain QEMU-only gates.
- No VMware Tools integration, suspend/resume, snapshot consistency or hostile
  device-input testing has been completed.

Use QEMU TCG for the complete reproducible ARM64 correctness suite and the
x86_64 QEMU/VPS path for Intel architecture validation.

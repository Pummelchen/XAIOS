# VMware Fusion ARM64

Status: experimental boot-compatibility target. The firmware boot path is
verified; XAIOS is not yet a usable VMware Fusion guest.

Fusion is a separate virtual-hardware target, not a QEMU mode. QEMU remains the
reproducible AArch64 and x86_64 correctness environment; neither environment
provides physical-hardware or performance evidence.

## Current Groundwork

The generated ARM64 Fusion bundle uses Debian 13 ARM64 GRUB only as a UEFI
compatibility chainloader. GRUB chainloads `XAIOS.EFI`; the XAIOS loader still
validates and loads `kernel.elf` itself.

The common ARM64 kernel now validates ACPI RSDP/XSDT/RSDT checksums and uses
MADT GICC/GICD/GICR and MCFG records for CPU discovery, GIC resource selection
and PCI ECAM selection. It rejects malformed, incomplete or unsupported GIC
descriptions without falling back to QEMU MMIO addresses. This path is covered
by hosted parser tests and the AArch64 QEMU smoke gate.

MutableFS now consumes the generic block-device interface rather than raw
VirtIO calls. NVMe or a future VMware storage driver must register a writable,
flush-capable 512-byte block device before it can be mounted. This preserves the
same storage contract for QEMU, Fusion and physical machines.

On 2026-08-14, `make vmware-fusion-smoke` passed on VMware Fusion 26.0.0 on
Apple Silicon in 8.31 seconds. It proves boot completion through the normal
service boundary with the safe ACPI bootstrap-only CPU policy and explicit
no-network/no-storage capability errors. It does not prove a usable service,
network, storage or multi-vCPU guest.

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

`make vmware-fusion-image` generates
`build/vmware-fusion/XAIOS.vmwarevm`; do not edit that generated bundle. The
smoke gate is authoritative only when it writes passing evidence from the
current host. It is not currently a release gate.

## Required Gates Before Fusion Support

- A reproducible Fusion boot with serial evidence through the normal kernel
  service boundary, not only a firmware handoff.
- Firmware-described timer and UART support, including ACPI GTDT/SPCR where
  Fusion exposes them.
- Confirmed multi-vCPU startup using the firmware CPU-start method supported by
  Fusion. The current ARM64 secondary path uses PSCI and is QEMU-proven only.
- A capability-gated VMware NIC driver with IPv4/IPv6, SSH and SFTP
  interoperability gates. No VMXNET3 or e1000 driver exists today.
- A writable VMware storage path that registers a generic block device, then
  passes MutableFS persistence, update and crash-recovery tests. No such driver
  exists today.
- Clean shutdown, reset, snapshot/recovery and hostile-device-input tests.

Apple Silicon Fusion hosts ARM64 guests only. It is not an x86_64 validation
environment. See `wiki/Hardware-Support.md` and `wiki/Project-Tracker.md` for
the current cross-platform qualification boundary.

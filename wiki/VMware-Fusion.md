# VMware Fusion

XAIOS has experimental ARM64 firmware-portability groundwork for VMware Fusion
on Apple Silicon. It does not replace QEMU and does not prove physical Apple
performance.

## Verified groundwork

The generated UEFI ISO uses Debian 13 ARM64 GRUB only as a compatibility
chainloader. XAIOS then owns ELF validation, kernel loading and boot-info ABI
handoff. The common ARM64 code validates ACPI MADT GICC/GICD/GICR and MCFG
records, then uses them for CPU discovery, GIC resource selection and PCI ECAM
selection. Hosted tests and AArch64 QEMU validate that parser path.

On 2026-08-14, `make vmware-fusion-smoke` passed on VMware Fusion 26.0.0 on
Apple Silicon. The evidence covers safe single-core boot completion through the
service boundary and expected no-network/no-storage capability errors. It does
not establish a usable VMware network, storage or multi-vCPU guest.

Use `make vmware-fusion-image` to generate the VM bundle and
`make vmware-fusion` to open it in Fusion.

## Not Yet Supported

- x86_64 guests on Apple Silicon Fusion.
- VMware virtual NICs, external networking, SSH or SFTP.
- VMware persistent disks and persistent XAIOS filesystems.
- Fusion firmware timer/UART discovery and verified multiple online vCPUs.
- The complete later application and preemptive-scheduler suite.
- Physical-hardware or performance conclusions.

The detailed implementation and current limitations are in
[`docs/VMWARE-FUSION.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/VMWARE-FUSION.md).

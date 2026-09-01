# Hardware Portability Contract

XAIOS targets multiple virtual and physical platforms without encoding a
hypervisor or board identity into core services.

## Kernel Boundary

- Firmware discovery validates only data the kernel consumes. On ARM64 this is
  currently ACPI MADT GICC/GICD/GICR and MCFG for CPU, GIC and PCI resources.
- Architecture code turns validated records into CPU topology, interrupt and
  PCI configuration. Invalid firmware leaves the corresponding capability
  unavailable; it must never select QEMU addresses on another platform.
- Drivers register capability-described devices. Filesystems consume generic
  block devices, network services consume a network-device interface, and
  applications do not bind to hypervisor names.
- Platform-specific drivers are selected by discovered hardware IDs and must
  expose the same generic contracts as VirtIO or NVMe.

## Qualification Layers

1. Hosted parser and contract tests validate malformed firmware and driver
   inputs.
2. QEMU validates architecture and ABI correctness; it does not prove physical
   speed, durability, NUMA locality or device behavior.
3. Each hypervisor requires a boot, multi-vCPU, storage, network and shutdown
   evidence gate using its actual devices.
4. Physical hardware additionally requires immutable device inventory,
   sustained-load and recovery artifacts.

## Current Status

QEMU is the broadest operating-system correctness environment. VMware Fusion
ARM64 is a qualified four-vCPU guest path tested only on VMware Fusion 26H1
(26.0.0), with PCI-discovered E1000E DHCP, AHCI xaibootFS, public-key SSH/SFTP,
recovery, reboot and shutdown evidence on the current Apple Silicon host. It
remains incomplete for multi-vCPU, VMXNET3, live DNSSEC interoperability and
physical qualification. Future Fusion and physical drivers must be
capability-gated; no platform is supported merely because it reports a CPU
family or firmware table.

The canonical three-profile contract and immutable evidence format are in
[Firmware Platform Profiles](./FIRMWARE-PLATFORM-PROFILES.md). It keeps macOS
QEMU ARM64, macOS VMware Fusion ARM64, and Intel VPS QEMU x86_64 evidence
separate and rejects an aggregate with missing or mismatched reports.

# Firmware Profiles

XAIOS uses three distinct firmware/platform profiles. A result for one profile
does not validate a different firmware, hypervisor or CPU architecture.

| Profile | Platform contract | Required device inventory | Evidence scope |
|---|---|---|---|
| macOS QEMU ARM64 | AAVMF/EDK2, ARM ACPI, GICv3, PSCI, PL011 and VirtIO-MMIO | VirtIO-MMIO block/net/RNG and xHCI USB HID keyboard | QEMU ARM64 correctness only |
| macOS VMware Fusion ARM64 | Fusion 26H1 (26.0.0) UEFI through generated GRUB chainload, four-vCPU ARM ACPI and PCI ECAM | E1000E, AHCI and PL011-compatible serial | Fusion 26H1 full supported lifecycle |
| Intel VPS QEMU x86_64 | OVMF/EDK2, q35, x86 ACPI MADT/SRAT/SLIT/HMAT, xAPIC/IOAPIC and PCI configuration I/O | VirtIO-PCI block/net, QEMU NVMe/MSI-X and xHCI USB HID keyboard | immutable designated Intel VPS QEMU evidence |

The contract records a required table and device inventory plus separate gates
for boot, CPU, storage, network/SSH, shutdown and repeat boot. It also records
unavailable capability outcomes. The Fusion profile qualifies its explicit
four-vCPU boot, SSH/SFTP, persistence/recovery, reboot and shutdown lifecycle.
It does not claim VMXNET3 merely because it can boot an ARM64 guest.

## Evidence

The profile runner writes a JSON report containing the source commit, contract,
firmware and emulator SHA-256 hashes, effective machine/CPU arguments, host
identity, gate log hashes and capability outcomes. Fusion reports additionally
hash the GRUB chainloader, boot ISO and VMX configuration. The exact command set
is in [Firmware Platform Profiles](../docs/FIRMWARE-PLATFORM-PROFILES.md). It
rejects a tracked dirty worktree so the recorded source commit is authoritative.
Gate logs live outside the disposable build tree under
`/var/tmp/xaios-firmware-profiles` by default and are SHA-256 hashed in the
evidence report.

```sh
make firmware-profiles-check
```

Run the ARM QEMU and Fusion commands on Apple Silicon macOS. Run the x86_64
profile only on the designated Intel VPS with
`XAIOS_FIRMWARE_PROFILE_HOST_CLASS=intel-vps`; copy its JSON report unchanged
for aggregation. The aggregate refuses a missing, mismatched or non-passing
profile report.

The Intel evidence profile reserves QEMU-forwarded port `17788`; it does not
take over a host's existing service port `7788`.

The shared architecture boundary is UEFI loader -> architecture firmware parser
-> generic capability consumers. The x86-specific early boot and ACPI code in
`kernel/arch/x86_64/` remains separate from ARM firmware discovery in
`kernel/arch/aarch64/`.

On both QEMU profiles, `vblk0` is the immutable initramfs/test volume and the
separately discovered durable xaibootFS volume is mounted as `vblk1`. This
prevents fixture writes from being mistaken for durable lifecycle state.
An NVMe namespace added for controller validation or model data is preserved
when it is not a valid xaibootFS volume; the kernel continues to the dedicated
durable volume. A valid NVMe xaibootFS namespace remains eligible for root
persistence.

The 128- and 256-vCPU x86 QEMU topology scenarios have a 480-second TCG
correctness budget for AP startup and complete services. It does not represent
a physical-hardware performance target.

QEMU evidence proves the named virtual correctness gates only. It never proves
physical hardware performance, durability, NUMA locality, thermal behavior or
PMU results.

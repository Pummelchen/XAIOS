# Firmware Platform Profiles

XAIOS qualifies firmware and virtual-platform behavior through three separate
profiles. They are not interchangeable firmware binaries, and passing one
profile does not validate another.

| Profile | Firmware and machine | Required inventory | Evidence host |
|---|---|---|---|
| macOS QEMU ARM64 | AAVMF/EDK2; `qemu-system-aarch64 -machine virt,gic-version=3 -cpu cortex-a72 -accel tcg` | ARM ACPI, GICv3, PSCI, PL011, VirtIO-MMIO block/net/RNG | Apple Silicon macOS |
| macOS VMware Fusion ARM64 | VMware Fusion 26H1 (26.0.0) UEFI through generated GRUB chainload | ARM ACPI, PCI ECAM, E1000E, AHCI, PL011-compatible serial | Apple Silicon macOS |
| Intel VPS QEMU x86_64 | OVMF/EDK2; `qemu-system-x86_64 -machine q35 -cpu max -accel tcg` unless recorded otherwise | x86 ACPI MADT/SRAT/SLIT/HMAT, xAPIC/IOAPIC, PCI config I/O, VirtIO-PCI, QEMU NVMe/MSI-X | designated Intel VPS |

The machine-readable contract is
[`contracts/firmware-platform-profiles-v1.json`](../contracts/firmware-platform-profiles-v1.json).
It specifies the required firmware tables, device inventory, capability outcome,
gate commands, and timeout for each profile. The evidence runner records the
source commit, contract SHA-256, host identity, firmware and emulator paths and
SHA-256 hashes, effective machine/CPU/accelerator arguments, gate logs and their
hashes. Fusion evidence also hashes the generated GRUB chainloader, boot ISO and
VMX configuration after the smoke gate builds them. It refuses a tracked dirty
worktree, so every report is tied to its stated commit. Gate logs are written
outside the disposable `build/` tree to
`${XAIOS_FIRMWARE_PROFILE_LOG_DIR:-/var/tmp/xaios-firmware-profiles}` and their
SHA-256 hashes are included in the JSON report.

## Boundary

The shared boot boundary remains deliberately narrow:

1. The UEFI loader supplies validated boot data.
2. Architecture code parses the firmware tables it consumes.
3. Generic drivers and services consume the resulting capabilities.

`kernel/arch/x86_64/early.c` and `kernel/arch/x86_64/acpi.c` own x86-specific
early boot and ACPI parsing. They are not ARM firmware-discovery code. ARM64
firmware parsing remains under `kernel/arch/aarch64/`. Generic storage, network,
filesystem and SSH services must not select a platform by hypervisor name.

For the QEMU profiles, `vblk0` remains the immutable initramfs/test volume.
The kernel opens the separately discovered durable VirtIO volume as `vblk1`
before mounting MutableFS. This keeps fixture self-tests out of the persistence
and lifecycle-recovery path on both ARM VirtIO-MMIO and x86 VirtIO-PCI.

## Running Profile Evidence

Use each command only on its matching host. Firmware inputs are explicit so a
report cannot silently hash a host-default firmware image.

```sh
# Apple Silicon macOS, with the AAVMF code file selected explicitly.
export XAIOS_AAVMF_CODE=/absolute/path/to/edk2-aarch64-code.fd
make firmware-profile-macos-qemu-aarch64

# Apple Silicon macOS running VMware Fusion 26H1 (26.0.0).
make firmware-profile-macos-vmware-fusion-aarch64

# Designated Intel VPS. The host-class value prevents an arbitrary Linux host
# from being mislabeled as the immutable Intel qualification environment.
export XAIOS_FIRMWARE_PROFILE_HOST_CLASS=intel-vps
export XAIOS_OVMF_CODE=/absolute/path/to/OVMF_CODE.fd
make firmware-profile-intel-vps-qemu-x86_64
sha256sum build/firmware-profiles/intel-vps-qemu-x86_64.json
```

The Intel VPS contract reserves loopback-forwarded port `17788` for its QEMU
gates, leaving unrelated services such as the VPS's public port `7788` intact.

Copy the Intel JSON evidence without editing it to the macOS checkout, preserve
its SHA-256 with the qualification record, then aggregate only matching commits:

```sh
export XAIOS_AAVMF_CODE=/absolute/path/to/edk2-aarch64-code.fd
export XAIOS_INTEL_VPS_PROFILE_EVIDENCE=/absolute/path/to/intel-vps-qemu-x86_64.json
make firmware-profiles
```

The aggregate rejects missing profiles, duplicate profiles, mismatched contracts,
different source commits, and any non-passing gate. The local check is:

```sh
make firmware-profiles-check
```

## Capability Interpretation

Every profile checks boot, CPU, storage, network/SSH, shutdown and repeat-boot
status. An unavailable capability is a result, not a pass: Fusion 26H1 currently
records CPU, shutdown and repeat boot as not qualified beyond its bootstrap
policy, and VMXNET3 as not implemented. QEMU reports are correctness and ABI
evidence only. They never authorize physical performance, durability, NUMA
locality, thermal, PMU or hardware-support claims.

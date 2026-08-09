# VMware Fusion

XAIOS has a limited ARM64 correctness path for VMware Fusion on Apple Silicon.
It does not replace QEMU and does not prove physical Apple performance.

## Verified

VMware Fusion 25.0.1 on an M3 Mac passes:

```sh
make vmware-fusion-smoke
```

The generated UEFI ISO uses Debian 13 ARM64 GRUB only as a compatibility
chainloader. XAIOS then owns ELF validation, kernel loading and boot-info ABI
handoff. The gate verifies ACPI SPCR serial, the RAM-backed deterministic
initfs, ARM PAN-safe syscalls and a successful `/init` return.

Use `make vmware-fusion-image` to generate the VM bundle and
`make vmware-fusion` to open it in Fusion.

## Not Yet Supported

- x86_64 guests on Apple Silicon Fusion.
- VMware virtual NICs, external networking, SSH or SFTP.
- VMware persistent disks and persistent XAIOS filesystems.
- ACPI GIC/CPU/clock discovery and multiple online vCPUs.
- The complete later application and preemptive-scheduler suite.
- Physical-hardware or performance conclusions.

The detailed implementation and current limitations are in
[`docs/VMWARE-FUSION.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/VMWARE-FUSION.md).

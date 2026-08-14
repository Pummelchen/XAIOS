# VMware Fusion

XAIOS has an experimental functional ARM64 guest path for VMware Fusion 26H1
(26.0.0) on Apple Silicon. It remains virtual-platform correctness evidence,
not a compatibility claim for other Fusion releases, physical Apple Silicon
performance, or production certification.

The generated VM uses the Debian 13 ARM64 GRUB chainloader to launch the same
XAIOS UEFI loader used by the common firmware path. The kernel discovers its
devices through ACPI/PCI rather than selecting a Fusion-specific core path.

## Verified On Fusion 26H1 (26.0.0) ARM64

- PCI bridge traversal and Intel 82574L/E1000E-compatible NIC discovery.
- Bridged DHCP IPv4 configuration and the boot-screen lease address.
- Standard AHCI SATA discovery, ATA identify, writable MutableFS format, and
  reload of the same VMDK after reboot.
- Public-key SSH command execution from macOS to the bridged guest.

Build the bundle with:

```sh
make vmware-fusion-image
make vmware-fusion-smoke
```

For SSH, package a disposable key when building and connect to the address
shown by the guest:

```sh
XAIOS_AUTHORIZED_KEYS_FILE=/path/to/test-key.pub make vmware-fusion-image
ssh -i /path/to/test-key admin@guest-address
```

The generated bundle and its 256 MiB VMDK live under
`build/vmware-fusion/XAIOS.vmwarevm`. Rebuilding the bundle creates a new VMDK;
ordinary reboots preserve it.

## Remaining Boundary

- Fusion multi-vCPU startup remains bootstrap-only.
- VMXNET3 is not implemented; the qualified device is E1000E.
- Live recursive DNSSEC, IPv6/SFTP/outbound client, clean shutdown and
  long-duration Fusion service gates are not complete.
- Fusion on Apple Silicon does not validate x86_64 guests or physical hardware.

See the repository [Fusion detail document](https://github.com/Pummelchen/XAIOS/blob/main/docs/VMWARE-FUSION.md),
[[Hardware Support|Hardware-Support]], and the [[Project Tracker|Project-Tracker]].

# VMware Fusion ARM64

Status: qualified virtual ARM64 guest profile, tested only with VMware Fusion
26H1 (26.0.0) on Apple Silicon. The qualified VM uses one vCPU, E1000E and
AHCI. VMware Fusion is a distinct virtual-hardware target, not a QEMU mode.
No virtual result establishes physical hardware performance or support.

## Verified Scope

The generated ARM64 bundle uses Debian 13 ARM64 GRUB only as a UEFI
compatibility chainloader. GRUB chainloads `XAIOS.EFI`; the XAIOS loader still
validates and loads `kernel.elf` itself.

The common ARM64 kernel validates ACPI RSDP/XSDT/RSDT checksums and consumes
MADT GICC/GICD/GICR and MCFG records for CPU discovery, GIC selection and PCI
ECAM discovery. The Fusion VM uses a standard Intel 82574L/E1000E-compatible
NIC and a standard AHCI SATA controller, selected from PCI identifiers rather
than a Fusion-specific kernel path.

The generated VM is bridged by default. It obtains its IPv4 configuration by
DHCP, prints the lease address without padding between address components at
boot, and starts SSH only after the kernel
has initialized the selected network device and IPv4 configuration. A
per-build 64-byte development seed is provisioned into the UEFI image because
the tested Fusion firmware exposes neither `EFI_RNG_PROTOCOL` nor AArch64
RNDR. This seed is unique to the local generated bundle and is not a
hardware-backed entropy claim.

The UEFI loader passes an optional validated Graphics Output Protocol (GOP)
framebuffer to the kernel. Where firmware provides an RGBX/BGRX framebuffer,
the kernel continues a compact, sharp 8x16 console-style boot display after `ExitBootServices`;
this prevents Fusion from leaving the final UEFI 20% frame visible while the
kernel finishes booting on its serial console. At 100%, the display shows the
IPv4 address, verified SSH state and the current local-authentication prompt.
When a checksum-valid Router Advertisement supplies an autonomous global
unicast `/64` prefix, it also shows the resulting `PUBLIC IPV6` SLAAC address.
Link-local and unique-local IPv6 addresses are intentionally not presented as
public addresses.
The screen leaves a terminal row below the SSH status and mirrors the serial
login state with a blinking cursor. Fusion's graphics device is status-only:
the authoritative interactive local console is the PL011 serial device. The
screen cannot receive keyboard input until XAIOS has a Fusion input driver.
Serial remains the headless-console path when no usable framebuffer is present.

The bundle includes a 256 MiB SATA VMDK. The AHCI driver registers
`/dev/ahci0p0` through the generic block-device interface; MutableFS formats a
new disk and loads the existing volume on later boots. No filesystem behavior
is special-cased for Fusion.

On the current Apple Silicon host, Fusion 26H1 (26.0.0) ARM64 evidence covers:

- UEFI-to-kernel boot through normal services.
- PCI bridge traversal, E1000E discovery, DHCP lease acquisition and IPv4
  stack initialization.
- AHCI ATA identify, writable MutableFS format, and subsequent persistent
  volume reload.
- Mac-local public-key SSH command execution and SFTP upload/download to the
  bridged guest.
- A persistent file written through SSH, hard-stop recovery, guest-initiated
  reboot, orderly shutdown with storage quiescing, and a clean repeat boot.

## Commands

Prerequisites are Apple Silicon macOS, VMware Fusion, Docker, Clang/LLD,
Python 3, mtools and `xorriso`.

```sh
make image
make vmware-fusion-image
make vmware-fusion-smoke
make vmware-fusion
```

`make vmware-fusion-image` generates
`build/vmware-fusion/XAIOS.vmwarevm`; do not edit that generated bundle. The
boot screen prints the DHCP address and enables the default development account
`admin` / `xaios`. This credential is public and is unsuitable for an exposed
bridged network. For a usable key-based SSH test, package a disposable public
key at build time and use that address:

```sh
XAIOS_AUTHORIZED_KEYS_FILE=/path/to/test-key.pub make vmware-fusion-image
ssh -i /path/to/test-key admin@guest-address
```

The build VMDK is recreated when `make vmware-fusion-image` rebuilds the
bundle. Reboots and recovery of the same generated bundle preserve MutableFS
state. `make vmware-fusion-smoke` builds a disposable public-key image and
proves SSH, SFTP, crash recovery, reboot, clean shutdown and repeat boot.

`make vmware-fusion-smoke` is authoritative only when it writes passing
evidence from the current host. It is not a release or physical-performance
gate.

## Remaining Qualification Work

- Fusion multi-vCPU startup is deliberately outside this profile. Fusion UEFI
  does not expose PSCI `CPU_ON` after `ExitBootServices`; supporting additional
  CPUs requires a separate UEFI MP Services handoff design and gate.
- The current NIC path covers E1000E. VMXNET3 is not implemented.
- Live recursive DNSSEC interoperability needs resolver-response compatibility
  work. DNSSEC callers remain fail-closed; SSH startup is intentionally not
  tied to a third-party DNS or TCP endpoint.
- IPv6, outbound SSH/SCP, VM snapshot semantics and long-duration
  network/storage soak need separate Fusion-specific qualification.
- Apple Silicon Fusion hosts ARM64 guests only. It is not an x86_64 or physical
  Apple Silicon qualification environment.

See `wiki/Hardware-Support.md` and `wiki/Project-Tracker.md` for the current
cross-platform boundary.

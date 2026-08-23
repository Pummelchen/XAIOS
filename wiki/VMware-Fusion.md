# VMware Fusion

XAIOS has a qualified virtual ARM64 guest profile for VMware Fusion 26H1
(26.0.0) on Apple Silicon. The supported profile is one vCPU with E1000E and
AHCI. It remains virtual-platform correctness evidence, not a compatibility
claim for other Fusion releases, physical Apple Silicon performance, or
production certification.

The generated VM uses the Debian 13 ARM64 GRUB chainloader to launch the same
XAIOS UEFI loader used by the common firmware path. The kernel discovers its
devices through ACPI/PCI rather than selecting a Fusion-specific core path.

Fusion's UEFI Graphics Output Protocol framebuffer is passed to the kernel
when valid. The kernel continues a compact 8x16 console-style progress display
after UEFI hands off at 20%, then renders the IPv4 address, an assigned public
IPv6 SLAAC address when a validated Router Advertisement provides one, verified SSH state
and the current local-authentication prompt with a blinking cursor at 100%.
The common input path includes a USB HID boot-keyboard driver for QEMU xHCI.
The Fusion bundle provisions xHCI so the same driver is available to the guest;
interactive Fusion-window qualification remains separate from the QEMU input
gates. PL011 serial remains the headless-console fallback.

## Verified On Fusion 26H1 (26.0.0) ARM64

- PCI bridge traversal and Intel 82574L/E1000E-compatible NIC discovery.
- Bridged DHCP IPv4 configuration and the boot-screen lease address.
- Standard AHCI SATA discovery, ATA identify, writable MutableFS format, and
  reload of the same VMDK after reboot.
- Mac-local public-key SSH command execution and SFTP upload/download.
- Persistent SSH writes across hard-stop recovery, guest reboot, orderly
  shutdown with storage quiescing, and a clean repeat boot.

Build the bundle with:

```sh
make vmware-fusion-image
make vmware-fusion-smoke
```

## Typing at the Fusion console

The generated profile wires the serial port to `fusion-serial.log`, which is
write-only: the guest prints to it but nothing can be typed back. The Fusion
window itself shows the boot status screen — progress bar, address, SSH state
and a `XAIOS LOGIN:` prompt with a blinking cursor — but that screen is a
status display, not a terminal. It never echoes typed characters or renders
command output, so it cannot be used to operate the system.

There are two ways to get an interactive session:

**SSH**, which is the intended administration path. The guest takes a bridged
address, printed on the boot screen, and accepts `admin` / `xaios`:

```sh
ssh admin@<address printed on the boot screen>
```

**A bidirectional serial pipe**, for console-level access such as recovery or
watching early boot. Build with the serial port as a pipe, then attach a
terminal to the socket VMware creates:

```sh
XAIOS_FUSION_SERIAL=pipe ./scripts/build-vmware-fusion.sh
./scripts/run-vmware-fusion.sh
nc -U /tmp/xaios-fusion-console
```

Set `XAIOS_FUSION_SERIAL_PIPE` to move the socket. The default stays `file`
so the automated Fusion smoke gate keeps reading `fusion-serial.log`.

The default development account is `admin` / `xaios`; it is public and must
only be used on an isolated development network. For key-based SSH, package a
disposable key when building and connect to the address shown by the guest:

```sh
XAIOS_AUTHORIZED_KEYS_FILE=/path/to/test-key.pub make vmware-fusion-image
ssh -i /path/to/test-key admin@guest-address
```

The generated bundle and its 256 MiB VMDK live under
`build/vmware-fusion/XAIOS.vmwarevm`. Rebuilding the bundle creates a new VMDK;
ordinary reboots preserve it.

`make vmware-fusion-smoke` builds a disposable public-key image and performs
the complete lifecycle above. It leaves no VM running when it succeeds or
fails.

## Remaining Boundary

- Fusion multi-vCPU startup remains bootstrap-only.
- VMXNET3 is not implemented; the qualified device is E1000E.
- IPv6, outbound SSH/SCP, VM snapshot semantics and long-duration Fusion
  service gates remain separate work.
- Fusion on Apple Silicon does not validate x86_64 guests or physical hardware.

See the repository [Fusion detail document](https://github.com/Pummelchen/XAIOS/blob/main/docs/VMWARE-FUSION.md),
[[Hardware Support|Hardware-Support]], and the [[Project Tracker|Project-Tracker]].

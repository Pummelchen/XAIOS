# VMware Fusion

XAIOS has a qualified virtual ARM64 guest profile for VMware Fusion 26H1
(26.0.0) on Apple Silicon. The supported profile is four vCPUs with E1000E and
AHCI. It remains virtual-platform correctness evidence, not a compatibility
claim for other Fusion releases, physical Apple Silicon performance, or
production certification.

The generated VM uses a Debian 13 ARM64 GRUB build purely as a UEFI
compatibility chainloader: GRUB chainloads `XAIOS.EFI`, and the XAIOS loader
still validates and loads `kernel.elf` itself. Nothing about the boot is
Fusion-specific after that point. The common ARM64 kernel validates the ACPI
RSDP, XSDT and RSDT checksums and takes CPU discovery, GIC selection and PCI
ECAM placement from MADT and MCFG records. The NIC is a standard Intel
82574L/E1000E-compatible part and the disk controller a standard AHCI SATA
controller, both selected from PCI identifiers rather than from knowing which
hypervisor is underneath. The AHCI driver registers `/dev/ahci0p0` through the
generic block interface, and xaibootFS formats a new disk and reloads the
existing volume on later boots with no filesystem behavior special-cased for
Fusion.

Fusion's UEFI Graphics Output Protocol framebuffer is passed to the kernel
when valid. The kernel continues a compact 8x16 console-style progress display
after UEFI hands off at 20%, then renders the IPv4 address, an assigned public
IPv6 SLAAC address when a validated Router Advertisement provides one, verified SSH state
and the current local-authentication prompt with a blinking cursor at 100%.
Only a globally routable SLAAC address is shown there: link-local and
unique-local addresses are deliberately not presented as public ones, because
an address printed on a boot screen is an invitation to connect to it.
The common input path includes a USB HID boot-keyboard driver for QEMU xHCI.
The Fusion bundle provisions xHCI so the same driver is available to the guest;
interactive Fusion-window qualification remains separate from the QEMU input
gates. PL011 serial remains the headless-console fallback.

The bundle also carries a per-build 64-byte development entropy seed inside the
UEFI image, because the tested Fusion firmware exposes neither
`EFI_RNG_PROTOCOL` nor AArch64 RNDR and a guest with no entropy source cannot
start its SSH service at all. The seed is unique to the locally generated
bundle and is a development convenience, not a hardware-backed entropy claim.

## Verified On Fusion 26H1 (26.0.0) ARM64

- PCI bridge traversal and Intel 82574L/E1000E-compatible NIC discovery.
- Bridged DHCP IPv4 configuration and the boot-screen lease address.
- Standard AHCI SATA discovery, ATA identify, writable xaibootFS format, and
  reload of the same VMDK after reboot.
- Mac-local public-key SSH command execution and SFTP upload/download.
- Persistent SSH writes across hard-stop recovery, guest reboot, orderly
  shutdown with storage quiescing, and a clean repeat boot.

## Building and running it

The host needs Apple Silicon macOS, VMware Fusion, Docker (which builds the
reproducible GRUB stage), Clang/LLD, Python 3, mtools and `xorriso`.

```sh
make image
make vmware-fusion-image
make vmware-fusion-smoke
make vmware-fusion
```

`make vmware-fusion-image` generates `build/vmware-fusion/XAIOS.vmwarevm`.
Treat that bundle as output and do not edit it; the next rebuild replaces it,
along with its VMDK. Ordinary reboots and recovery of the same bundle preserve
xaibootFS state.

`make vmware-fusion-smoke` is authoritative only when it writes passing
evidence from the host in front of you. It is not a release gate and it is not
physical-performance evidence.

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
XAIOS_FUSION_SERIAL=pipe ./platform/vmware-fusion/build-vmware-fusion.sh
./platform/vmware-fusion/run-vmware-fusion.sh
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

The bundle's disk is a 256 MiB SATA VMDK. `make vmware-fusion-smoke` builds a
disposable public-key image, performs the complete lifecycle above, and leaves
no VM running whether it succeeds or fails.

## Remaining Boundary

- Fusion multi-vCPU startup is no longer a boundary: four vCPUs come online,
  and `make vmware-fusion-smoke` reads `numvcpus` out of the VMX it is about
  to boot and requires the guest to report that many online, so a guest that
  quietly started one fails rather than passes. See `F-01`.
- VMXNET3 carries traffic end to end on Fusion 26.0.0: build with
  `XAIOS_FUSION_NIC=vmxnet3` and the guest takes a real DHCP lease from the
  bridged LAN, answers ICMPv6, SSH on both families and SFTP. The qualified
  device remains E1000E by choice -- `XAIOS_FUSION_NIC` defaults to it -- so
  the qualified profile cannot drift onto the card. See `F-02`.
- IPv6 works on a bridged guest whose network offers it: a globally routable
  SLAAC address, inbound SSH/SFTP/UDP and outbound SSH/SCP. It did not until
  the E1000E receive filter stopped discarding all multicast, which is where
  router advertisements arrive.
- Snapshot and resume semantics are defined and gated -- see
  `make vmware-fusion-snapshot-gate`. A snapshot taken powered off is a point
  in time; a revert boots onto a filesystem the guest trusts; a suspend is not
  counted as an unclean boot. A revert used to leave the guest refusing shell
  commands while SFTP still worked (`B-25`); that was sshd leaking one of the
  kernel's sixty-four session contexts per connection whose command failed,
  and it is fixed and gated -- see `make qemu-ssh-session-exhaustion-gate`.
- Long-duration Fusion service load is no longer untested, and what it found is
  a defect rather than a clean bill. `make vmware-fusion-load-soak` holds one
  boot under continuous 256 KiB SFTP round trips -- one boot rather than many,
  because a leak of a page per operation is invisible in a boot and obvious
  over a thousand. It gave `B-28` a rate for the first time: round 61 of 586
  failed with `sftp exited 255 ('Connection closed')` and rounds 62 through 586
  succeeded. Repeat-boot at volume has its own harness in
  `make vmware-fusion-boot-soak`, which is a reproduction harness for `B-15`
  and not a gate -- it exits non-zero only if it reproduces. Crash recovery
  against generated VMDKs remains separate work.
- What the Fusion window shows cannot be read back from the host, and
  `make vmware-fusion-framebuffer-gate` exists to say so by name rather than
  leave the question looking open. `vmrun captureScreen` is classified as a
  *guest* operation: it needs VMware Tools running inside the machine and a
  login to it, and XAIOS ships no VMware Tools. There is no flag for it and
  nothing an operator can enable. The gate boots the guest, asks, and reports
  the refusal; the two questions it would ask -- nothing left of the progress
  bar, and something on the screen -- are already written and will start
  answering if a guest agent ever exists. This is the half of `V-06` that
  Virtualization.framework has closed and Fusion has not.
- Both hypervisor gates had only ever run at 2048 MiB, the one memory size at
  which `B-06` cannot occur and the only Fusion size where the framebuffer
  lands inside the identity map. `make hypervisor-memory-matrix` runs Fusion
  and Virtualization.framework at 1, 2 and 4 GiB, which is what
  `make qemu-memory-matrix` does for the three QEMU architectures.
- Live recursive DNSSEC interoperability still needs resolver-response
  compatibility work, and the shape of that work is now named: the whole
  root-DNSKEY to DS to child-DNSKEY to answer walk shares one deadline, because
  `g_pending.started_ns` is set once per resolution and never reset per query
  (`B-35`). A longer chain spends the budget and returns a cancellation that a
  caller cannot tell from a validation refusal (`B-36`). Callers are **not**
  fail-closed, which this page previously said: on a bridged guest a correctly
  signed name resolved to an address while a mis-signed one was refused. That
  observation is not gated, for the two reasons above. SSH startup is
  deliberately not tied to a DNS or TCP endpoint, so none of this affects
  whether the guest comes up reachable.
- Fusion on Apple Silicon does not validate x86_64 guests or physical hardware.

See [[Hardware Support|Hardware-Support]] for where this profile sits against
the others, and the [[Project Tracker|Project-Tracker]] for the open items
named above. The firmware evidence contract this profile reports under is
[`docs/FIRMWARE-PLATFORM-PROFILES.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/FIRMWARE-PLATFORM-PROFILES.md).

<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/d1170b39-84b0-40c3-8f3e-c2de85ae9c94" />


# XAIOS

XAIOS is an experimental freestanding Unix-like operating system and portable
inference-engine foundation being developed as an SSH-administered distributed
CPU AI model server. The current OS boots under QEMU, VMware Fusion and Apple
Virtualization.framework, and exercises deterministic kernel/runtime contracts. Real-model inference and the dedicated inference
network service are under development and are not production supported.

Human-facing project documentation is maintained in the
[XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki). The repository keeps
the complete curated Wiki page set under [`wiki/`](./wiki/) so operating,
architecture, testing, security, and status claims can be checked with source.

## Unix compatibility boundary

FreeBSD is the primary external behavioral reference for portable command,
SSH/SFTP and network interoperability work. XAIOS is not FreeBSD-derived and
does not provide a FreeBSD or Linux binary ABI: guest programs use native XAIOS
syscalls, and passing host-client tests proves wire behavior only. The official
FreeBSD 15.1 AArch64 QEMU gate covers public-key acceptance/rejection,
`xaiosctl`, SFTP, PTY ANSI `htop`, and UDP echo. The Debian 13 client remains an
independent Linux/OpenSSH cross-family gate with broader administration and
load coverage. See [Unix compatibility](./wiki/Unix-Compatibility.md).

XAIOS provides a statically linked hosted ISO C99 library for AArch64 and
x86_64 without a public POSIX API or new syscall identifiers. Standard images
ship the on-demand `helloworldc99` demonstration; custom hosted applications
remain an explicit build choice. The project conformance boundary and evidence
are documented in the [C99 libc Wiki page](./wiki/C99-Libc.md).

The native [`xapt` updater](./wiki/Xapt-Package-Updates.md) installs and updates
independently signed XAIOS applications without rebooting and stages signed OS
images into the inactive A/B slot. Its current trust root is for development
and QEMU use; production key custody and an operator-approved rotation process
remain explicit gates.

ModelFS can repair a quarantined package from an administrator-selected,
unmounted signed replica after complete identity and payload verification. This
offline recovery path does not establish production replica enrollment or
private signing-key custody; see [ModelFS recovery](./docs/MODELFS-RECOVERY.md).

## Model support status

The deterministic QEMU model-v1 path is **Fixture only**, and model-v2 is a
format/interface foundation; neither executes a transformer. Qwen 3.8 is
the next real-model correctness target. Kimi K3 text, Kimi K3 multimodal,
and DeepSeek V4 Flash 0731 remain later targets, and no listed model is
production supported. K3 text and multimodal support are separate milestones.

XAIOS is designed around official architecture adapters rather than a
hard-coded Qwen graph. Exact target-model semantics are the default;
approximate modes, if introduced, will be explicit and opt-in. The single
authoritative delivery order, progress code, support boundary, acceptance gate,
open-decision list, and risk register are in the
[Project Tracker](./wiki/Project-Tracker.md). The machine-readable model catalog
at [`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json) contains identifiers,
not an independent status mirror.

The consolidated QEMU qualification-readiness gate is documented in
[`docs/PHYSICAL-QUALIFICATION-READINESS.md`](./docs/PHYSICAL-QUALIFICATION-READINESS.md).
It collects the strongest emulated SSH/network, NVMe, diagnostics, topology,
and sustained-soak evidence without treating QEMU as physical hardware.

VMware Fusion has a qualified one-vCPU ARM64 virtual guest profile, tested
only on Apple Silicon with **VMware Fusion 26H1 (26.0.0)**. It is not a
compatibility claim for other Fusion versions, x86_64 guests, multi-vCPU
Fusion guests, or physical Apple hardware; see
[`docs/VMWARE-FUSION.md`](./docs/VMWARE-FUSION.md).

Apple Virtualization.framework runs XAIOS to a login on Apple Silicon, with
MutableFS on a durable volume, DHCP IPv4, SLAAC IPv6 and SSH. It is a
development and verification target rather than a qualification profile: there
is no automated gate for it, so none of that is qualification evidence. The
platform provides no PL011, no linear framebuffer and no GIC interrupt
translation service, so the kernel logs over a virtio console and every virtio
queue runs polled; see
[`tools/vz/README.md`](./tools/vz/README.md).

## Firmware profiles

XAIOS keeps **macOS QEMU ARM64**, **macOS VMware Fusion ARM64**, and
**Intel VPS QEMU x86_64** as separate qualification profiles. Each records its
own firmware and emulator hashes, device inventory, lifecycle gates and explicit
unavailable capabilities; a passing ARM result cannot stand in for Intel VPS
evidence. See [Firmware Platform Profiles](./docs/FIRMWARE-PLATFORM-PROFILES.md).

## License

XAIOS is source-available under the
[PolyForm Noncommercial License 1.0.0](./LICENSE). The license permits private,
personal, educational and noncommercial research use, including use by
universities and public research organizations. It does not grant commercial
use.

Commercial use requires a separate written commercial license obtained before
use. See [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md) for the licensing
route. XAIOS is not MIT-licensed because the MIT License permits unrestricted
commercial use.

<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/d1170b39-84b0-40c3-8f3e-c2de85ae9c94" />


# XAIOS

An experimental freestanding Unix-like operating system, written in C99, built
towards an SSH-administered distributed CPU inference server. It boots to a
login with durable storage, dual-stack networking and SSH. Real-model inference
is not implemented.

Everything about *what XAIOS does* lives in the
[XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki), mirrored under
[`wiki/`](./wiki/) so every claim can be checked against source. Everything
about *what remains* lives in one place, the
[Project Tracker](./wiki/Project-Tracker.md).

## Get a build

Released builds are on the
[releases page](https://github.com/Pummelchen/XAIOS/releases); the current one
is [**build 4**](https://github.com/Pummelchen/XAIOS/releases/tag/b4). You do
not need to compile anything to try XAIOS.

Six downloads, and **five of them contain the same image** — what differs is
what is packaged around it:

| To run XAIOS | Take |
|---|---|
| in QEMU | `xaios_b4-qemu.zip` — image plus a launch script per architecture |
| in VMware Fusion | `xaios_b4-vmware-fusion.zip` — image plus a `.vmx` |
| in Apple Virtualization.framework | `xaios_b4-virtualization-framework.zip` — image plus a harness you build and sign |
| on a real machine, from a USB stick | `xaios_b4-usb.zip` — image plus a writer that names the target disk back before it writes |
| on a real machine with no disk, over the network | `xaios_b4-netboot.zip` — two boot binaries plus a DHCP/TFTP server script |
| with your own tooling | `xaios_b4.iso.zip` — the image, and nothing else |

Unzip before use. The image is one file that is an ISO 9660 filesystem, a
GPT-partitioned disk and a bootable USB image at once, which is why one
download covers CD-ROM, hard disk and stick. On first boot there is no account
and no default password; the machine asks how to set itself up.

Each release note records exactly which hypervisors and firmware that build was
booted on, and what was *not* tested — see the
[build 4 note](./release/xaios_b4.md). To build from source instead, see
[Getting Started](./wiki/Getting-Started.md).

## Where it runs

| Hypervisor | Qualification profile | Gate | Evidence class |
|---|---|---|---|
| QEMU ARM64 | macOS QEMU ARM64 | full CI | correctness and ABI only |
| QEMU x86_64 | Intel VPS QEMU x86_64 | full CI | correctness and ABI only |
| VMware Fusion | macOS VMware Fusion ARM64 | `make vmware-fusion-smoke` | Fusion 26H1 four-vCPU lifecycle |
| Apple Virtualization.framework | none; development target | `make vz-gate`, `make vz-stress-gate` | not qualification evidence |

XAIOS behaves the same on all of them. Firmware supplies capabilities, never
identity and never behaviour, and `make platform-neutrality-check` enforces it.
Where a capability is absent the system degrades the same way everywhere. The
per-environment feature matrix is in the
[Project Tracker](./wiki/Project-Tracker.md); no ARM result stands in for Intel
evidence, and each profile records its own firmware hashes, device inventory
and gates — see
[Firmware Platform Profiles](./docs/FIRMWARE-PLATFORM-PROFILES.md).

No result here is physical-hardware evidence. Emulators prove correctness, not
performance or firmware behaviour.

## Boundaries worth knowing before you read further

**Unix compatibility.** FreeBSD is the behavioural reference for commands,
SSH/SFTP and network interoperability. XAIOS is not FreeBSD-derived and offers
no FreeBSD or Linux binary ABI — guest programs use native syscalls, so passing
host-client tests proves wire behaviour only. See
[Unix compatibility](./wiki/Unix-Compatibility.md).

**Architectures.** AArch64, x86_64 and RISC-V (rv64gc). AArch64 and x86_64 run
on real machines and hypervisors; RISC-V runs the same shared kernel on the
QEMU `virt` board, booting to 100% across four harts with a login prompt, a
working SSH server and the hosted C99 library, either from a kernel handed to
QEMU or from its own disk through UEFI firmware. What it does not have is hardware qualification: no
RISC-V machine or hypervisor is in the test set, so its evidence is one board.
See [RISC-V](./wiki/RISC-V.md).

**C99 libc.** A statically linked hosted ISO C99 library for AArch64 and
x86_64, with no public POSIX API and no new syscall identifiers. See
[C99 libc](./wiki/C99-Libc.md).

**Model support status.** Neither the deterministic model-v1 path nor the
model-v2 format foundation executes a transformer. Qwen 3.8 is the next
correctness target, Kimi K3 and DeepSeek V4 later; nothing is production
supported. XAIOS is built around official architecture adapters rather than a
hard-coded graph. See [Model support](./wiki/Applications.md).

**Updates.** The native [`xapt` updater](./wiki/Xapt-Package-Updates.md)
installs signed applications without rebooting and stages OS images into the
inactive A/B slot. Its trust root is for development use; production key
custody and rotation remain open gates.

## License

Source-available under the
[PolyForm Noncommercial License 1.0.0](./LICENSE): private, personal,
educational and noncommercial research use, including by universities and
public research organisations. It does not grant commercial use, which requires
a separate written licence obtained beforehand — see
[`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).

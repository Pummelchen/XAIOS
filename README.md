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

## Where it runs

| Hypervisor | Qualification profile | Gate | Evidence class |
|---|---|---|---|
| QEMU ARM64 | macOS QEMU ARM64 | full CI | correctness and ABI only |
| QEMU x86_64 | Intel VPS QEMU x86_64 | full CI | correctness and ABI only |
| VMware Fusion | macOS VMware Fusion ARM64 | `make vmware-fusion-smoke` | Fusion 26H1 one-vCPU lifecycle |
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

**C99 libc.** A statically linked hosted ISO C99 library for AArch64 and
x86_64, with no public POSIX API and no new syscall identifiers. See
[C99 libc](./wiki/C99-Libc.md).

**Model support status.** The deterministic model-v1 path is fixture only and
model-v2 is a format foundation; neither executes a transformer. Qwen 3.8 is
the next correctness target, with Kimi K3 and DeepSeek V4 later. Nothing listed
is production supported. XAIOS is built around official architecture adapters
rather than a hard-coded graph, and exact target-model semantics are the
default. See [Model support](./wiki/Applications.md) and the
[Project Tracker](./wiki/Project-Tracker.md).

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

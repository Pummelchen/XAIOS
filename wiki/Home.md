# XAIOS

XAIOS is a freestanding Unix-like operating system for dedicated AI and
high-performance server workloads, written in C99. It boots from UEFI on
AArch64, x86_64 and RISC-V under QEMU, and on two macOS hypervisors — VMware
Fusion and Apple Virtualization.framework — and provides a native
kernel/userspace ABI, persistent filesystems, IPv4/IPv6, OpenSSH-compatible
SSH/SFTP, local and remote shells, administration controls, and a portable
inference-engine foundation.

The target it is built towards is an SSH-administered distributed CPU inference
server in which the operating system and the model runtime are one system
rather than an application on a distribution: the kernel owns hardware,
isolation, persistence, networking and service lifecycle, the engine owns model
packages, architecture adapters, backends and sessions, and the two are built
and gated together. No transformer executes yet, which is why the evidence
boundary below is stated rather than implied.

XAIOS is not Linux or FreeBSD and does not run their binaries. FreeBSD is the
primary Unix behavior reference for commands and network interoperability.

New here? [[Getting Started|Getting-Started]] goes from a clone to a login
prompt; [[Current Limitations|Current-Limitations]] says what is not claimed.

## Use XAIOS

0. Take a released build from the
   [releases page](https://github.com/Pummelchen/XAIOS/releases) — currently
   **build 5** — or build one from source. Which download to take, and what is
   in each, is in [[Getting Started|Getting-Started]].
1. Follow [[Getting Started|Getting-Started]] to build and boot an image.
2. Read [[Boot and Console|Boot-and-Console]] for startup and local login.
3. Connect through [[Networking and SSH|Networking-and-SSH]].
4. Use the shell surface in [[Commands|Commands]] and executable programs in
   [[Applications|Applications]].
5. Manage the system through [[Administration|Administration]].
6. Install signed applications through [[xapt Package Updates|Xapt-Package-Updates]].

## Implemented OS surface

- AArch64, x86_64 and RISC-V UEFI boot under QEMU.
- Runtime-sized CPU, cpuset, scheduler, NUMA, and process metadata.
- EL0 processes and threads with capability-checked syscalls.
- VirtIO block/network/RNG plus focused emulated NVMe and SMMUv3 gates.
- xaibootFS for bounded writable state and xaiFS for immutable model data.
- IPv4, IPv6, TCP, UDP, DNS, reassembly, and SACK-aware transport behavior.
- First-boot setup on a machine that has no account: run from the medium or
  install onto a disk, then an account name and password, an optional six
  digit console PIN, the machine's name, and whether the console logs in
  automatically.
- Concurrent SSH sessions, SFTP, outbound SSH/SCP, and authenticated local
  console sessions — from a credential the machine was set up with, or one a
  development image packaged.
- FreeBSD-style command behavior, archive exchange, `nano`, `less`,
  and terminal Pong.
- Typed `xaiosctl` administration for status, configuration, identity, audit,
  storage, and model-package lifecycle operations.
- Signed `xapt` catalogs, independent application activation and rollback, and
  streamed A/B OS updates.

## Evidence boundary

The ARM, x86_64 and RISC-V QEMU core-OS correctness gates pass. QEMU proves boot,
protocol, ABI, and deterministic behavior; it does not prove physical hardware
performance, production security, or real-model inference. No real Qwen, Kimi,
or DeepSeek checkpoint has passed end-to-end token and logits parity.

See [[Current Limitations|Current-Limitations]] for explicit non-claims and the
single [[Project Tracker|Project-Tracker]] for remaining work.

## Documentation

### Operate the OS

- [[Getting Started|Getting-Started]]
- [[Boot and Console|Boot-and-Console]]
- [[Applications|Applications]]
- [[Commands|Commands]]
- [[Filesystem and Storage|Filesystem-and-Storage]]
- [[Networking and SSH|Networking-and-SSH]]
- [[Administration|Administration]]
- [[xapt Package Updates|Xapt-Package-Updates]]
- [[Operations and Recovery|Operations-and-Recovery]]

### Understand and validate it

- [[Architecture|Architecture]]
- [[Screen Framework|Screen-Framework]]
- [[Security Model|Security-Model]]
- [[Unix Compatibility|Unix-Compatibility]]
- [[ISO C99 Library|C99-Libc]]
- [[Hardware Support|Hardware-Support]]
- [[Firmware Profiles|Firmware-Profiles]]
- [[RISC-V|RISC-V]]
- [[VMware Fusion|VMware-Fusion]]
- [[Virtualization Framework|Virtualization-Framework]]
- [[Testing XAIOS|Testing-XAIOS]]
- [[Current Limitations|Current-Limitations]]
- [[FAQ]]
- [[Project Tracker|Project-Tracker]]

## Where the source lives

A change goes in exactly one of these, and the choice is usually settled by the
directory's purpose rather than by the file's subject.

| Directory | Why it exists |
|---|---|
| [`boot/`](https://github.com/Pummelchen/XAIOS/tree/main/boot) | The UEFI loader: firmware entry, kernel validation, boot handoff. |
| [`kernel/`](https://github.com/Pummelchen/XAIOS/tree/main/kernel) | The kernel. Shared code, with `arch/aarch64/`, `arch/x86_64/` and `arch/riscv64/` for what cannot be shared. |
| [`userspace/`](https://github.com/Pummelchen/XAIOS/tree/main/userspace) | `init`, the shell, `/bin` applications, the hosted C99 library, sshd. |
| [`engine/`](https://github.com/Pummelchen/XAIOS/tree/main/engine) | The portable inference engine: model packages, adapters, backends, sessions. |
| [`platform/`](https://github.com/Pummelchen/XAIOS/tree/main/platform) | One directory per hypervisor, holding its assets and launchers and nothing else. |
| [`tests/`](https://github.com/Pummelchen/XAIOS/tree/main/tests) | Gates that boot XAIOS, checks about the repository itself, fixtures, network harnesses. |
| [`contracts/`](https://github.com/Pummelchen/XAIOS/tree/main/contracts) | Versioned machine-readable contracts: what a gate is allowed to call passing. |
| [`docs/`](https://github.com/Pummelchen/XAIOS/tree/main/docs) | Versioned specifications and formats. |
| [`scripts/`](https://github.com/Pummelchen/XAIOS/tree/main/scripts) / [`tools/`](https://github.com/Pummelchen/XAIOS/tree/main/tools) | If the build calls it, it is a script; if you call it, it is a tool. |
| [`release/`](https://github.com/Pummelchen/XAIOS/tree/main/release) | One note per numbered build: what it was booted on, and what was not tested. |

Naming a hypervisor is `platform/` and `tests/` work. Kernel, boot and
userspace code may not do it at all — see
[Platform neutrality](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-NEUTRALITY.md)
and [CONTRIBUTING](https://github.com/Pummelchen/XAIOS/blob/main/CONTRIBUTING.md).

## Repository reference documents

The Wiki is the human-readable entry point. Detailed versioned specifications
and API contracts remain in the source repository:

- [Reference index](https://github.com/Pummelchen/XAIOS/blob/main/docs/README.md)
- [Application development](https://github.com/Pummelchen/XAIOS/blob/main/docs/APPLICATION-DEVELOPMENT.md)
- [`xaiosctl` reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
- [Control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md)
- [Model-v2 specification](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODEL-V2-SPECIFICATION.md)
- [Architecture adapters](https://github.com/Pummelchen/XAIOS/blob/main/docs/ARCHITECTURE-ADAPTERS.md)
- [Hardware backends](https://github.com/Pummelchen/XAIOS/blob/main/docs/HARDWARE-BACKENDS.md)
- [Portable engine service](https://github.com/Pummelchen/XAIOS/blob/main/docs/ENGINE-SERVICE.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [Syscall and userspace API](https://github.com/Pummelchen/XAIOS/blob/main/docs/API.md)
- [Network and SSH status](https://github.com/Pummelchen/XAIOS/blob/main/docs/NETWORK-SSH-STATUS.md)
- [Storage architecture](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-ARCHITECTURE.md)
- [xaiFS format](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODELFS-FORMAT.md)
- [xaiFS recovery](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODELFS-RECOVERY.md)
- [Storage tools](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-TOOLS.md)
- [Large-model upload](https://github.com/Pummelchen/XAIOS/blob/main/docs/LARGE-MODEL-UPLOAD.md)
- [Storage security](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-SECURITY.md)
- [Storage benchmarking](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-BENCHMARKING.md)
- [Hardware readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
- [Virtualization.framework harness](https://github.com/Pummelchen/XAIOS/blob/main/platform/virtualization-framework/README.md)
- [Complete test inventory](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md)

[Source repository](https://github.com/Pummelchen/XAIOS) | [API reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/API.md) | [License](https://github.com/Pummelchen/XAIOS/blob/main/LICENSE)

# XAIOS

XAIOS is a freestanding Unix-like operating system for dedicated AI and
high-performance server workloads. It boots on AArch64, x86_64 and RISC-V under QEMU,
provides a native kernel/userspace ABI, persistent filesystems, IPv4/IPv6,
OpenSSH-compatible SSH/SFTP, local and remote shells, administration controls,
and a portable inference-engine foundation.

XAIOS is not Linux or FreeBSD and does not run their binaries. FreeBSD is the
primary Unix behavior reference for commands and network interoperability.

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

- AArch64 and x86_64 UEFI boot under QEMU.
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

The ARM and x86_64 QEMU core-OS correctness gates pass. QEMU proves boot,
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

### Understand and validate it

- [[Hardware Support|Hardware-Support]]
- [[RISC-V|RISC-V]]
- [[Architecture|Architecture]]
- [[Security Model|Security-Model]]
- [[Unix Compatibility|Unix-Compatibility]]
- [[ISO C99 Library|C99-Libc]]
- [[Testing XAIOS|Testing-XAIOS]]
- [[VMware Fusion|VMware-Fusion]]
- [[Virtualization Framework|Virtualization-Framework]]
- [[Current Limitations|Current-Limitations]]
- [[FAQ]]
- [[Project Tracker|Project-Tracker]]

## Repository reference documents

The Wiki is the human-readable entry point. Detailed versioned specifications
and API contracts remain in the source repository:

- [Getting started](https://github.com/Pummelchen/XAIOS/blob/main/docs/GETTING-STARTED.md)
- [`xaiosctl` reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
- [Control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md)
- [Model-v2 specification](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODEL-V2-SPECIFICATION.md)
- [Architecture adapters](https://github.com/Pummelchen/XAIOS/blob/main/docs/ARCHITECTURE-ADAPTERS.md)
- [Hardware backends](https://github.com/Pummelchen/XAIOS/blob/main/docs/HARDWARE-BACKENDS.md)
- [Portable engine service](https://github.com/Pummelchen/XAIOS/blob/main/docs/ENGINE-SERVICE.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [OS architecture](https://github.com/Pummelchen/XAIOS/blob/main/docs/ARCHITECTURE.md)
- [Syscall and userspace API](https://github.com/Pummelchen/XAIOS/blob/main/docs/API.md)
- [Network and SSH status](https://github.com/Pummelchen/XAIOS/blob/main/docs/NETWORK-SSH-STATUS.md)
- [Unix compatibility boundary](https://github.com/Pummelchen/XAIOS/blob/main/docs/UNIX-COMPATIBILITY.md)
- [Storage architecture](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-ARCHITECTURE.md)
- [xaiFS format](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODELFS-FORMAT.md)
- [xaiFS recovery](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODELFS-RECOVERY.md)
- [Storage tools](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-TOOLS.md)
- [Large-model upload](https://github.com/Pummelchen/XAIOS/blob/main/docs/LARGE-MODEL-UPLOAD.md)
- [Storage security](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-SECURITY.md)
- [Storage benchmarking](https://github.com/Pummelchen/XAIOS/blob/main/docs/STORAGE-BENCHMARKING.md)
- [Hardware readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
- [VMware Fusion details](https://github.com/Pummelchen/XAIOS/blob/main/docs/VMWARE-FUSION.md)
- [Virtualization.framework harness](https://github.com/Pummelchen/XAIOS/blob/main/platform/virtualization-framework/README.md)
- [Complete test inventory](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md)

[Source repository](https://github.com/Pummelchen/XAIOS) | [API reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/API.md) | [License](https://github.com/Pummelchen/XAIOS/blob/main/LICENSE)

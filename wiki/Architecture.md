# Architecture

XAIOS combines a freestanding operating system with a portable C99 inference
engine. The operating system owns hardware resources, isolation, persistence,
networking, and service lifecycle. The portable engine owns model packages,
architecture plans, backends, sessions, and future inference execution.

The authoritative platform boundary is recorded in
`docs/PLATFORM-SUPPORT.json`. QEMU results prove correctness and ABI behavior;
they do not prove physical performance or production readiness.

## Boot and runtime flow

1. UEFI firmware loads the XAIOS loader. VMware Fusion uses a generated GRUB
   compatibility chainloader before the same XAIOS loader.
2. `boot/uefi/loader_main.c` validates and loads `kernel.elf`, builds the boot
   information structure, and transfers control to the architecture entry. A
   normal boot displays the colored XAI OS identity and begins the in-place
   progress meter at 0% before loading the system image.
3. Each architecture performs its platform-specific handoff and enters the
   shared `kernel/core/kmain.c` runtime.
4. The kernel initializes architecture services, memory, devices, storage,
   filesystems, security, networking, processes, runtime services, and
   telemetry in dependency order.
5. A normal AArch64 or x86_64 image loads `/init`, the service manager, and the
   persistent console/SSH service from initramfs. Before opening TCP port 22, that service
   requires a successful external IPv4 DNS response. It then prints the local
   IPv4 address and verified SSH state at 100% and leaves a functional serial
   prompt active beside the SSH event loop. Exact allowlisted diagnostics load in
   separate transient address spaces only when invoked over SSH, then reaped.
   QEMU correctness gates use an explicit profile that runs workers and
   diagnostics during boot to retain deterministic fixture markers.
   AArch64 and x86-64 process spaces each provide two adjacent 2 MiB code/data
   page-table spans plus a separate stack span. Switches clear all owned entries
   before installing the next process, preventing stale cross-process mappings.

## Major components

| Component | Main source | Responsibility |
|---|---|---|
| UEFI loader | `boot/uefi/` | Firmware entry, ELF loading, and boot handoff. |
| Architecture ports | `kernel/arch/aarch64/`, `kernel/arch/x86_64/` | Exceptions, timers, interrupts, CPU startup, page tables, and platform discovery. |
| Kernel core | `kernel/core/` | Initialization, logging, telemetry, panic handling, and self-test sequencing. |
| Memory | `kernel/mm/` | Physical and virtual memory, NUMA metadata, heaps, arenas, and ELF ownership. |
| Devices and storage | `kernel/dev/`, `kernel/storage/` | VirtIO, focused NVMe, block devices, GPT, and partitions. |
| Filesystems | `kernel/fs/` | Initramfs, VFS, MutableFS, and immutable active ModelFS packages. |
| Processes and ABI | `kernel/user/`, `userspace/` | Process ownership, service supervision, syscalls, applications, and SSH/SFTP. |
| Network | `kernel/net/`, `kernel/runtime/network_stack.c` | IPv4/IPv6, TCP/UDP, DNS, routing, and socket state. |
| Administration | `kernel/runtime/admin_control.c`, `kernel/runtime/control_protocol.c` | Typed role-based configuration, key, audit, storage, and model operations. |
| Applications | `userspace/apps/`, `userspace/apps/terminal/` | Standalone ELFs and app-owned terminal modules. The kernel supplies generic capability-gated primitives rather than application implementations. |
| Portable engine | `engine/` | Model-v2 and ModelFS parsing, adapters, backends, model/session ownership, and asynchronous range I/O. |

## Trust boundaries

- EL0 code crosses into the kernel only through validated syscall dispatch.
- Every syscall is associated with a process capability and validates user
  buffers before dereference.
- Direct serial input/output is restricted to the persistent console owner by
  `XAIOS_CAP_CONSOLE`; other applications use the kernel log or SSH channels.
- VFS descriptors and network sockets are process-owned and reclaimed with the
  owning address space.
- Administrative mutations are role- and capability-gated, replay-protected,
  audited, and bounded.
- Active ModelFS packages are immutable. Registration, staging, verification,
  activation, scrub, quarantine, and trim use explicit typed operations.
- QEMU host forwarding and external OpenSSH/SFTP clients cross the network
  trust boundary; FreeBSD is the primary Unix behavioral reference.
- Model-v1 is a deterministic fixture boundary. Production decode must fail
  explicitly until a real architecture plan executes.

## Main data flows

### Build

```text
make image
  -> scripts/build-image.sh
  -> Clang/LLD and image tools
  -> UEFI loader, kernel, userspace, initramfs, and QEMU disk images
```

### Boot validation

```text
make qemu-smoke
  -> build the explicit boot-diagnostic fixture image
  -> boot isolated QEMU guest
  -> collect serial markers and telemetry
  -> validate the release-candidate contract
```

### Administrative command

```text
local or SSH xaiosctl
  -> shared command parser
  -> authenticated principal and role
  -> capability-gated syscall
  -> typed query or replay-protected mutation
  -> persistent audit record
  -> shared text or JSON renderer
```

### Model package access

```text
block device
  -> optional GPT partition
  -> ModelFS volume
  -> immutable package extent
  -> verified range read
  -> caller-owned engine buffer or arena
```

## Platform status

The AArch64 QEMU path provides the broadest OS-service coverage. Each discovered
CPU has a private translation root and user directory, preventing concurrent
EL0 workers from replacing another core's mappings. VMware Fusion on Apple
Silicon reaches `/init` through a limited ARM64 compatibility path but does not
yet have VMware networking, persistent storage, or multi-vCPU discovery.

The x86_64 QEMU image executes the common kernel and complete userspace/service
image. MADT-discovered application processors run EL0 workers with per-CPU user
page-table roots, while runtime-sized XSAVE/FXSAVE state survives live timer
interrupts. The shared filesystems, IPv4/IPv6, SSH/SFTP, security, AI Cell and
telemetry paths run over modern PCI VirtIO block/network, and emulated NVMe
passes identify/write/flush/read. Physical Intel qualification remains open.

## Inference boundary

The portable engine already supplies model-v2 parsing, architecture and backend
registries, scalar packed INT4/INT6 correctness kernels, immutable model
readers, sessions, and a caller-owned service API. It does not yet import or
execute a real Qwen checkpoint. Qwen 3.8 27B is the next model workstream after
the XAIOS platform completion gate; Kimi K3 and DeepSeek V4 Flash 0731 remain
later roadmap items.

See [[Current Limitations|Current-Limitations]], [[Hardware Support|Hardware-Support]],
and [[Project Tracker|Project-Tracker]].

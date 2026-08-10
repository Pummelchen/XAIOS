# XAIOS System Architecture

## Overview

XAIOS combines a freestanding AArch64 operating-system prototype with a
portable C99 inference-engine foundation. The current complete OS correctness
path boots through UEFI on QEMU virt. A limited VMware Fusion ARM64 path on
Apple Silicon reaches `/init`; `docs/VMWARE-FUSION.md` records its narrower
device/platform boundary. The x86_64 QEMU image executes the common kernel and
complete userspace/service image. It starts MADT-discovered APs, uses per-CPU
user address-space roots, validates ring-3 threads and XSAVE/FXSAVE interrupt
state, parses ACPI topology, and operates modern PCI VirtIO block/network plus
emulated NVMe. Kernel and userspace code are freestanding C99 without libc.
The authoritative 20-item status is `docs/PLATFORM-SUPPORT.json`.

## Boot Flow

```
UEFI firmware (AAVMF or Fusion through GRUB chainload)
  └─ BOOTAA64.EFI (loader_main.c)
       └─ Loads kernel.elf from FAT partition
       └─ Passes boot-info v6 (memory map, UART, kernel and optional initfs)
            └─ kmain(boot_info)
```

**Boot contract**: The UEFI loader validates the ELF, loads its fixed physical
segments, captures firmware tables and optional boot-image extent, exits boot
services, and jumps to `kmain`. The kernel establishes its own page tables.

## Kernel Initialization Order

`kmain()` in `kernel/core/kmain.c` executes subsystems in a strict sequence:

```
 1. exception_init()          — Vector table install (VBAR_EL1)
 2. timer_init()              — ARM generic timer (CNTVCT_EL0)
 3. stack_canary_init()       — Stack protection seed
 4. smp_init_qemu_virt()      — Secondary core discovery
 5. numa_init(boot)           — NUMA topology (single node on QEMU)
 6. pmm_init(boot)            — Physical memory manager (delegates to NUMA)
 7. vmm_init(boot)            — Virtual memory manager (4-level page tables)
 8. smmu_init()               — ARM SMMUv3 IOMMU
 9. pci_init()                — PCIe ECAM enumeration
10. rtc_init()                — PL031 real-time clock
11. watchdog_init()           — Hardware watchdog timer
12. kheap / arena             — Kernel heap and arena allocator
13. rate_limit_init()         — Token bucket quotas
14. security / remote_login   — Security policy and shell engine
15. source_index / git_ws     — AI agent source indexing
16. sandbox / core_lease      — Isolation primitives
17. gic_init()                — GICv3 interrupt controller
18. virtio_blk / persistence  — Generic block devices and MutableFS
19. VFS / ModelFS             — Mutable root, immutable models, bounded staging
20. klog_ring / boot_counter  — Persistent logging and crash recovery
21. update_self_test()        — Package delivery with SHA-256
22. virtio_net / ARP / IPv4   — Network stack
23. initramfs / syscall       — Process loading infrastructure
24. scheduler / worker thread — Preemptive process state and CPU-assigned jobs
25. service_supervisor        — Service tree management
26. model_arena / cpu_ai      — Fixture runtime plus immutable model mappings
27. ai_cell                   — AI cell resource management
28. admin/control_protocol    — Persistent role-based administration service
29. telemetry_emit()          — Boot summary JSON
```

After self-tests, a normal image runs `/init`, `/bin/service-manager`, and the
persistent SSH service. Diagnostic applications are loaded into independent
address spaces only when an administrator invokes their exact allowlisted name
over SSH; the kernel reclaims their pages and process-table slot after exit.
On both AArch64 and x86-64, each process address space owns two adjacent 2 MiB
page-table spans for a bounded 4 MiB ELF code/data window plus an independent
stack span. Address-space switches clear all three owned entries before
installing the next process, and mappings outside those spans fail closed.
QEMU gates use a separate build profile that exercises bounded workers and all
diagnostic applications during boot to preserve deterministic fixture markers.

## Directory Layout

```
XAIOS/
├── boot/uefi/            — UEFI bootloader (PE/COFF, AArch64)
│   ├── loader_main.c     — EFI entry, ELF loader, firmware/boot-image handoff
│   └── linker.ld         — PE section layout
├── kernel/
│   ├── arch/aarch64/     — Architecture-specific code
│   │   ├── entry.S       — EL1 entry, BSS clear, canary seed, jump to kmain
│   │   ├── secondary.S   — Secondary CPU parking
│   │   ├── vectors.S     — Exception vector table
│   │   ├── exception.c   — Exception handlers (sync, IRQ, SError)
│   │   ├── timer.c       — ARM generic timer
│   │   ├── gic.c         — GICv3 distributor/redistributor
│   │   ├── mmu.c         — Page table management (4-level, 4KB pages)
│   │   ├── smp.c         — Multi-core discovery via PSCI
│   │   ├── smmu.c        — SMMUv3 driver
│   │   ├── pci.c         — PCIe ECAM enumeration
│   │   ├── rtc.c         — PL031 RTC
│   │   └── watchdog.c    — Timer-based watchdog
│   ├── core/             — Kernel core
│   │   ├── kmain.c       — Main entry, init sequencing, app launching
│   │   ├── klog.c        — Kernel logging (UART output)
│   │   ├── klog_ring.c   — Persistent ring buffer logging
│   │   ├── telemetry.c   — JSON telemetry emission
│   │   ├── panic.c       — Panic handler (PSCI reset)
│   │   ├── assert.c      — kassert macro support
│   │   └── stack_canary.c — Stack corruption detection
│   ├── mm/               — Memory management
│   │   ├── pmm.c         — Physical memory manager (NUMA-backed)
│   │   ├── numa.c        — NUMA topology and per-node free-stacks
│   │   ├── vmm.c         — Virtual memory manager
│   │   ├── kheap.c       — Kernel heap allocator
│   │   ├── arena.c       — Arena allocator for model weights
│   │   └── elf_loader.c  — ELF64 parser and process loader
│   ├── fs/               — Initramfs, VFS, MutableFS and ModelFS adapters
│   ├── storage/          — GPT and bounded partition devices
│   ├── net/              — Network protocols
│   │   ├── arp.c         — ARP cache and resolution
│   │   ├── ipv4.c        — IPv4 header construction
│   │   └── icmp.c        — ICMP echo reply
│   ├── dev/              — Generic block API and VirtIO device drivers
│   │   ├── virtio_transport.c — MMIO transport layer
│   │   ├── virtio_blk.c  — Block device driver
│   │   └── virtio_net.c  — Network device driver
│   ├── sched/            — Scheduler
│   │   ├── scheduler.c   — Round-robin preemptive scheduler
│   │   └── context.S     — Context switch (AArch64 register save/restore)
│   ├── user/             — Userspace management
│   │   ├── user.c        — Process table, ELF loading, address space
│   │   ├── service.c     — Service supervisor (tree, restart policies)
│   │   └── syscall.c     — Syscall dispatch table (49 syscalls)
│   ├── runtime/          — Kernel runtime services
│   │   ├── ai_cell.c     — AI cell lifecycle and resource management
│   │   ├── cpu_ai_runtime.c — Deterministic fixture runtime; production decode unsupported
│   │   ├── model_arena.c — Fixture-copy arena and no-copy immutable mappings
│   │   ├── network_stack.c — UDP/TCP flow management
│   │   ├── remote_login.c — Per-session shell command interpreter
│   │   ├── admin_control.c — Persistent config, keys, revocation and audit
│   │   ├── control_protocol.c — Typed measured and mutation administration
│   │   ├── security.c    — Capability-based security policy
│   │   ├── sandbox.c     — Process sandbox
│   │   ├── core_lease.c  — CPU core lease management
│   │   ├── rate_limit.c  — Token bucket rate limiter
│   │   ├── source_index.c — Source code indexing agent
│   │   ├── git_workspace.c — Git workspace agent
│   │   ├── persistence.c — Disk persistence layer
│   │   ├── update.c      — Package update/rollback
│   │   └── sha256.c      — FIPS 180-4 SHA-256
│   └── include/xaios/     — Kernel headers
├── userspace/
│   ├── include/          — Userspace SDK header (xaios_user.h)
│   ├── lib/              — Userspace C library (start.S, xaios_user.c)
│   ├── init/             — /init process, service-manager, worker
│   ├── apps/             — User applications (hello, systest, etc.)
│   └── sshd/             — Userspace SSH daemon
├── engine/               — Portable model-v2, ModelFS, adapter and backend APIs
├── tests/storage/        — Hosted block/GPT/VFS/SFTP tests
├── tests/model_volume/   — ModelFS lifecycle and portable reader tests
├── scripts/              — Build, test, and gate scripts
├── platform/vmware-fusion/ — Generated-VM inputs and GRUB build definition
├── contracts/            — ABI contract (qemu-rc-v1.json)
├── docs/                 — Developer documentation
├── Makefile              — Build orchestration
├── LICENSE               — PolyForm Noncommercial 1.0.0
└── COMMERCIAL-LICENSE.md — Commercial licensing route
```

## Memory Layout

| Region | Physical Address | Description |
|--------|-----------------|-------------|
| Kernel ELF | `0x90000000` (loaded by UEFI) | Text, rodata, data, BSS; fits QEMU and Fusion firmware maps |
| UART0 | `0x09000000` | PL011 serial console |
| VirtIO MMIO | `0x0a000000–0x0a003fff` | Block + net devices |
| GICv3 | `0x08000000–0x0801ffff` | Interrupt controller |
| SMMUv3 | `0x09050000–0x0906ffff` | IOMMU (page 0 + page 1) |
| ECAM | `0x4010000000` | PCIe config space |
| PL031 RTC | `0x01010000` | Real-time clock |
| Userspace ELF | `0x100000000` | User processes (per-process L2/L3), outside the first-4-GiB kernel identity map |

## Userspace Lifecycle

1. Kernel loads `/init` from initramfs → PID 1, runs syscalls, exits
2. Kernel loads `/bin/service-manager` → PID 2, supervises child services
3. The service-manager fixture exercises `/svc/source-index` supervision without
   retaining a userspace process-table entry
4. A normal image starts persistent `/bin/sshd` as PID 3; authenticated key roles
   remain the per-request authority
5. Exact allowlisted diagnostic commands run on demand in a transient slot from
   PID 32 upward, in their own address space, and are reaped after exit
6. The `XAIOS_BOOT_TEST_APPS=1` QEMU fixture profile instead runs workers as PIDs
   3-5, apps as PIDs 6-17, and persistent `/bin/sshd` as PID 18
7. The boot CPU remains in the persistent SSH service; secondary CPUs use the
   scheduler's interrupt-backed idle path when no work is assigned

## Security Model

- **Capability-based**: Each process has a bitmask of allowed syscalls
- **Sandbox**: Processes cannot escape their address space (nG bit on user PTEs)
- **Core isolation**: topology-aware lease interfaces exist, but production
  inference dispatch and isolation remain incomplete
- **Stack canaries**: SP-XOR canaries detect stack buffer overflows
- **SMMU**: IOMMU enforcement for device DMA (when available)

## Build Pipeline

```
make bootstrap   — Install toolchain (macOS: brew install llvm lld qemu mtools python)
make image       — Build UEFI loader + kernel ELF + userspace → disk image
make image-qemu-test — Build the deterministic boot-diagnostic fixture image
make qemu        — Boot in QEMU (interactive)
make qemu-smoke  — Automated smoke test (330+ boot markers)
make hosted-test — Portable engine, ModelFS and storage correctness tests
make qemu-core-os-rc — Aggregate cross-architecture core correctness gate
make vmware-fusion-smoke — Limited Apple Silicon Fusion boot through /init
make test        — bootstrap + image + dry-run
```

All C code is compiled with `clang --target=aarch64-none-elf -std=c99 -ffreestanding -Wall -Wextra -Werror`.

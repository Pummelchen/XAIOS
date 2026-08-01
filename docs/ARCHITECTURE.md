# XAIOS System Architecture

## Overview

XAIOS is a freestanding AArch64 operating system designed for CPU-only embedded AI agents. It boots via UEFI, runs on QEMU virt (macOS host), and targets Intel Desktop/Xeon and ARM N1X-class SoCs. The kernel is single-binary, monolithic, and written in C99 with no libc dependency.

## Boot Flow

```
UEFI firmware (AAVMF)
  └─ BOOTAA64.EFI (loader_main.c)
       └─ Loads kernel.elf from FAT partition
       └─ Passes xaios_boot_info_t (memory map, UART base, kernel phys range)
            └─ kmain(boot_info)
```

**Boot contract**: The UEFI loader validates the ELF, sets up page tables for the kernel's identity-mapped region, and jumps to `kmain` at EL1.

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
18. virtio_blk / persistence  — Block device and mutable filesystem
19. klog_ring / boot_counter  — Persistent logging and crash recovery
20. update_self_test()        — Package delivery with SHA-256
21. virtio_net / ARP / IPv4   — Network stack
22. initramfs / syscall       — Process loading infrastructure
23. scheduler / ELF loader    — Preemptive scheduling and process exec
24. service_supervisor        — Service tree management
25. model_arena / cpu_ai      — AI runtime and model loading
26. ai_cell                   — AI cell resource management
27. telemetry_emit()          — Boot summary JSON
```

After initialization, the kernel runs userspace processes sequentially, then enters an infinite `wfe` loop.

## Directory Layout

```
XAIOS/
├── boot/uefi/            — UEFI bootloader (PE/COFF, AArch64)
│   ├── loader_main.c     — EFI entry, ELF loader, page table setup
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
│   ├── fs/               — Filesystems
│   │   ├── initramfs.c   — Read-only init filesystem (FAT-based)
│   │   └── mutable_fs.c  — Writable persistent filesystem (MFS v3)
│   ├── net/              — Network protocols
│   │   ├── arp.c         — ARP cache and resolution
│   │   ├── ipv4.c        — IPv4 header construction
│   │   └── icmp.c        — ICMP echo reply
│   ├── dev/virtio/       — VirtIO device drivers
│   │   ├── virtio_transport.c — MMIO transport layer
│   │   ├── virtio_blk.c  — Block device driver
│   │   └── virtio_net.c  — Network device driver
│   ├── sched/            — Scheduler
│   │   ├── scheduler.c   — Round-robin preemptive scheduler
│   │   └── context.S     — Context switch (AArch64 register save/restore)
│   ├── user/             — Userspace management
│   │   ├── user.c        — Process table, ELF loading, address space
│   │   ├── service.c     — Service supervisor (tree, restart policies)
│   │   └── syscall.c     — Syscall dispatch table (33 syscalls)
│   ├── runtime/          — Kernel runtime services
│   │   ├── ai_cell.c     — AI cell lifecycle and resource management
│   │   ├── cpu_ai_runtime.c — CPU-only ML inference engine
│   │   ├── model_arena.c — Shared read-only model arena
│   │   ├── network_stack.c — UDP/TCP flow management
│   │   ├── remote_login.c — Shell command interpreter
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
├── scripts/              — Build, test, and gate scripts
├── contracts/            — ABI contract (qemu-rc-v1.json)
├── docs/                 — Developer documentation
├── Makefile              — Build orchestration
├── LICENSE               — PolyForm Noncommercial 1.0.0
└── COMMERCIAL-LICENSE.md — Commercial licensing route
```

## Memory Layout

| Region | Physical Address | Description |
|--------|-----------------|-------------|
| Kernel ELF | `0x40100000` (loaded by UEFI) | Text, rodata, data, BSS |
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
3. Service manager loads `/svc/source-index` → PID 3, crash/restart tested
4. Workers (PIDs 3-5) run via scheduler for concurrent execution testing
5. User apps (PIDs 6-15) run sequentially: shell, hello, sysinfo, systest, smptest, nettest, lstm-xor, sshtest, mltest, posix-shell
6. Kernel enters idle loop (`wfe`)

## Security Model

- **Capability-based**: Each process has a bitmask of allowed syscalls
- **Sandbox**: Processes cannot escape their address space (nG bit on user PTEs)
- **Core isolation**: CPUs 1-3 are "leased" to AI workloads, no migration
- **Stack canaries**: SP-XOR canaries detect stack buffer overflows
- **SMMU**: IOMMU enforcement for device DMA (when available)

## Build Pipeline

```
make bootstrap   — Install toolchain (macOS: brew install llvm lld qemu mtools python)
make image       — Build UEFI loader + kernel ELF + userspace → disk image
make qemu        — Boot in QEMU (interactive)
make qemu-smoke  — Automated smoke test (330+ boot markers)
make test        — bootstrap + image + dry-run
```

All C code is compiled with `clang --target=aarch64-none-elf -std=c99 -ffreestanding -Wall -Wextra -Werror`.

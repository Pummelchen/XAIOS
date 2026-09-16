# The RISC-V IOMMU (`B-130`): device contract and driver plan

QEMU's `virt` board can carry a RISC-V IOMMU. `-device riscv-iommu-pci` adds
the PCI device (vendor `0x1b36`, device `0x0014`; PCI function `00:01.0`,
requestor id 8, with the device tree's `iommu-map` deliberately excluding that
id so the IOMMU is not asked to translate itself), and
`-M virt,iommu-sys=on` adds the platform variant at `0x3010000` with four PLIC
sources (36-39). `-device virtio-iommu-pci` is a different thing -- the virtio
paravirtual protocol -- and is **not** what this document describes; it would
test a different contract.

This is the contract a driver must own, gathered from the installed QEMU
11.1.1 (`hw/riscv/riscv-iommu.c`, `riscv-iommu-pci.c`, `riscv-iommu-sys.c`,
`riscv-iommu-bits.h`, `docs/specs/riscv-iommu.rst`) and from a `dumpdtb` of the
board. Where a spec section is cited it is second-hand: the encodings below are
what QEMU implements, which is what the gates can test.

## Registers (one 4 KiB page, 4- or 8-byte aligned accesses)

| Offset | Register | Notes |
|---|---|---|
| `0x000` | `CAP` | version `[7:0]` = `0x10` for 1.0; Sv39/Sv48/Sv57 at bits 9/10/11; Sv39x4-Sv57x4 at 17-19; MSI flags 22/23; `IGS[29:28]` |
| `0x008` | `FCTL` | `BE`, `WSI` (wire-signalled interrupts), `GXL` |
| `0x010` | `DDTP` | mode `[3:0]`: 0 Off, 1 Bare, 2 1LVL, 3 2LVL, 4 3LVL; busy bit 4; PPN `[53:10]` |
| `0x018`/`0x020`/`0x024` | `CQB`/`CQH`/`CQT` | command queue base, head, tail |
| `0x028`/`0x030`/`0x034` | `FQB`/`FQH`/`FQT` | fault queue base, head, tail |
| `0x038`/`0x040`/`0x044` | `PQB`/`PQH`/`PQT` | page-request queue (unused here) |
| `0x048` | `CQCSR` | `cqen` 0, `cie` 1, `cqmf` 8, `cmd_to` 9, `cmd_ill` 10, `cqon` 16, `busy` 17 |
| `0x04c` | `FQCSR` | `fqen` 0, `fie` 1, `fqmf` 8, `fqof` 9, `fqon` 16, `busy` 17 |
| `0x054` | `IPSR` | interrupt-pending status |
| `0x300` | MSI config table | the PCI wrapper overlays MSI-X here; QEMU rejects any access at or above `0x300` |

`off=on` is QEMU's default: **out of reset the DDT mode is Off and every PCI
transaction through the IOMMU is refused**. A guest that attaches the device
and does not program it loses all PCI DMA.

## Device directory and contexts

A DDT entry is `{valid = bit 0, PPN[53:10]}`. In 1LVL mode the device id
indexes a context array directly; a context is 32 bytes (base) or 64 bytes
(extended, when MSI or PD8 is in use), and the supported device-id width is
6/7 bits (1LVL), 15/16 (2LVL) or 24 (3LVL). QEMU refuses a wider id with
`TTYPE_BLOCKED`.

A context is eight qwords: `tc, iohgatp, ta, fsc, msiptp, msi_addr_mask,
msi_addr_pattern, reserved`. `tc.V` must be set; `fsc` selects the first-stage
page table (`iosatp`, mode 8/9/10 = Sv39/Sv48/Sv57) and `iohgatp` the
second-stage one. XAIOS needs one stage only: `iohgatp = Bare`, `fsc` = the
port's Sv48 (or Sv39), with the root table in RAM.

## Page tables

Bit-identical to RISC-V Sv39/Sv48/Sv57: V/R/W/X/U/G/A/D, PPN[53:10], NAPOT via
`PTE.N`. Two traps a hand-built table hits on QEMU: a leaf must have `U=1` when
no `process_id` is involved (accesses are treated as user accesses), and `A`
(plus `D` for writes) must be set because software-managed A/D is the simplest
correct choice unless the hardware-AD feature is enabled in `tc`.

## Queues

Commands are 16 bytes: `opcode[6:0]`, `function[9:7]`. The driver needs
`IOTINVAL.VMA` (1/0) for a page invalidation, `IOTINVAL.GVMA` (1/1),
`IODIR.INVAL_DDT` (3/0) to drop a cached device context, and `IOFENCE.C` (2/0)
as a completion fence. Enqueue is a write of the entry followed by the new
`CQT`; retirement is observed by `CQH` advancing; `cmd_ill`, `cmd_to` and
`cqmf` are write-1-to-clear.

Fault records are 32 bytes: `hdr{cause[11:0], pid[31:12], pv, ttype[39:34],
did[63:40]}, reserved, iotval, iotval2`. The causes that matter for a gate are
5/7 (read/write fault), 13/15 (first-stage read/write fault), 256
(`DMA_DISABLED`), 257/258/259 (`DDT_LOAD_FAULT`, `DDT_INVALID`,
`DDT_MISCONFIGURED`) and 260 (`TTYPE_BLOCKED`). **Faults are written to the
queue regardless of how they are notified**, so a gate that polls `FQH`/`FQT`
loses nothing -- and on the default PLIC board that is the only option, since
the PCI IOMMU's MSI-X is unusable there (`msix_init` returns `-ENOTSUP`) and
only the `iommu-sys` variant has wire interrupts.

## What to reuse, and what must not be copied

`kernel/arch/aarch64/smmu.c` is the model, and it is SMMUv3 throughout: every
register offset, command opcode, STE/CD/PTE encoding and IDR/CR bitfield is
AArch64-specific and must **not** be copied. What is reusable:

- PCI: `pci_find_device`, `pci_enable_device`, `pci_bar_address`,
  `pci_stream_id` (`kernel/dev/pci_ecam.c`). The stream id is `BDF | bus<<8`,
  which is exactly the IOMMU device id on this board, and the BUS is 0 in both
  QEMU variants, so no `iommu-map` parsing is needed.
- MMIO fault containment while probing: `exception_mmio_probe_begin/end/faulted`
  (`kernel/arch/riscv64/exception.c`).
- Barriers: `xaios_cpu_io_barrier()` (`kernel/include/xaios/arch_cpu.h`) is
  `fence iorw, iorw` here -- a copied `dsb sy` would be an AArch64 instruction.
- Table indexing: 9 bits per level over a 39-bit VA is the same arithmetic, and
  the VMM already has Sv48 in `kernel/arch/riscv64/mmu.c`.

A latent mismatch must be fixed rather than preserved: `smmu_init` is declared
as taking `const xaios_boot_info_t *` in `kernel/include/xaios/smmu.h` and
called that way from `kmain`, while `kernel/arch/riscv64/platform.c` defines it
with no parameters. It links only because the argument is ignored.

## Ordering, because the failure mode is a machine with no DMA

As soon as `DDTP` leaves Bare, **every** PCI function without a valid context
stops. The riscv64 runner's entropy (`virtio-rng-pci`) and PCI block devices
would go with it, so the driver must install an identity context for every
enumerated PCI function **in the same step** that it first programs `DDTP`, and
must bail out to Bare with the honest marker if the capability read or the
first command fails. Queue memory must be page-aligned and in RAM; a bad PPN
sets `CQMF`/`FQMF`, stalls the engine and silently drops the fault that a gate
would assert. Every `DDTP`/`CQCSR` write must be preceded by a busy check,
since a write while busy is unspecified, and the fault queue must be drained
every poll or `FQOF` hides the evidence.

Milestones, each independently verifiable:

1. **Probe** -- **landed 2026-09-16.** Find the device over PCI, name it and
   its BAR, and on a board without it say so as the *result of a look*:
   `smmu: riscv64 pci inventory has no 0x1b36:0x0014 and the tree has no
   riscv,iommu node`, followed by the sentence the smoke requires. Safe: with
   the device reset (Bare) no DMA changes. Three things were learned doing it
   and are worth keeping. `smmu_init(boot)` runs *before* `pci_init()`, so the
   look belongs in `smmu_self_test()`, which runs after it -- a probe in
   `smmu_init` reports that a board with the device attached has none.
   `pci_enable_device()` must come before the BAR is read. And **the `CAP`
   read needs the BAR mapped first:** QEMU places this 64-bit BAR at
   `0x400010000`, this port identity-maps its device window below 4 GiB, and
   reading it unmapped faults with `ERROR: controlled page fault reported`,
   `class=load-page-fault cause=13 stval=0x400010000` -- the MMIO probe
   containment does not turn that into a returned value. With
   `vmm_map_page(base, base, XAIOS_VMM_DEVICE)` in front of it the register
   answers, and a guest booted with the device attached reports
   `riscv-iommu: found device=5 base=0x400010000 cap=0x78c2cf4f10 version=0x10
   sv39=1 sv48=1 sv57=1 igs=0`: version 1.0, all three page-table formats
   available, and **`IGS = 0`, which is MSI only** -- so on a board whose PCI
   IOMMU has no usable MSI-X, faults are only ever seen by polling the fault
   queue, and the gate must assert them that way.
2. **Queues and DDT** -- 1LVL, command and fault queues enabled, `IOFENCE.C`
   round trip, `IODIR.INVAL_DDT`; installs the identity contexts in the same
   change (see above).
   **Landed 2026-09-17.** `kernel/arch/riscv64/iommu.c` builds a 1LVL device
   directory of 64 extended (64-byte) contexts -- the format QEMU's `intremap`
   reset selects, which is also what fixes the 1LVL device-id width at six
   bits, one page -- enables 16-entry command and fault queues, round-trips
   `IOFENCE.C` and issues `IODIR.INVAL_DDT`, and installs a pass-through
   context (`tc.V` set, both stages Bare) for every enumerated PCI function
   *before* `DDTP` leaves Bare. Measured: `riscv-iommu: queues and ddt enabled
   commands=2 contexts=7 fence=1 invalidate_ddt=1 faults=0`, and the machine
   boots to the login prompt with SSH afterwards. A function whose stream id is
   wider than the table is named and the device is left in Bare rather than
   having its id truncated into another function's context.
3. **Page tables** -- Sv39 first, then Sv48, identity over RAM, one test page
   mapped and unmapped, software A/D.
   **Landed 2026-09-17.** One tree serves both formats: `l2` is an Sv39 root and
   an Sv48 root sits one level above it pointing at the same `l2`, so the two
   are read at different depths. The low RAM is identity-mapped with 1 GiB
   leaves -- what a driver written for unmediated DMA needs -- and the test IOVA
   gets a 4 KiB page through a full walk, every leaf R/W/U with A and D set by
   software. One encoding had to be measured rather than reasoned about: a
   leaf's physical address is the PPN field at bits 53:10, so writing
   `address & ~0xfff` puts the address where the page number belongs and the
   walk lands at `address >> 2` -- the first version translated the test IOVA to
   `0x20177c000` for a target of `0x805df000`, and the trace showed it before
   the kernel did.
4. **Translation for one device** -- identity context for `iommu-testdev`,
   whose write lands; this also answers whether its `DMA_ATTRS` encoding is
   accepted on RISC-V (`attrs=0` is the fallback).
   **Landed 2026-09-17.** The `DMA_ATTRS` encoding the SMMU gate uses
   (`0x0a`: space valid, non-secure) is accepted here too, and the identity
   control runs first -- with its pass-through context still in place the
   device's own DMA is `result=0x0 target=0x12345678`, which is what separates
   "the engine works" from "the page table works". Then Sv39 and Sv48:
   `riscv-iommu: sv39 translated DMA result=0x0 target=0x12345678
   iova=0x100000000 did=48` and the same under Sv48.
5. **Isolation** -- unmap and invalidate, assert a first-stage fault; abort the
   context, assert `DDT_INVALID` for a device that was never registered.
   **Landed 2026-09-17.** Clearing the leaf and issuing `IOTINVAL.VMA` turns the
   same transaction into `result=0xdead0002 target=0x0` with a fault record
   `cause=15 did=48 ttype=3 iotval=0x100000000` -- the first-stage write fault
   the page table was the only reason for. The second `iommu-testdev` is
   deliberately left out of the directory, and its transaction is
   `result=0xdead0002` with `cause=258` (`DDT_INVALID`), which is the refusal
   rather than a translation of an unregistered id.
6. **Gate and documentation** -- a `make qemu-riscv64-iommu-gate` that boots
   with two `iommu-testdev` instances (one authorized, one deliberately not),
   requires the markers in order, parses the fault total so that "printed the
   summary" cannot pass with zero faults, and records
   `qemu_correctness_only: true`. The closest model is
   `tests/scripts/qemu-smmu-gate.py`, and the capability contract
   (`tests/scripts/qemu-core-os-rc.py`, `tests/repository/check-core-os-status.py`)
   moves only when both files move together.
   **Landed 2026-09-17.** `make qemu-riscv64-iommu-gate` builds the RISC-V
   kernel and image and runs `tests/scripts/qemu-riscv-iommu-gate.py`, which
   boots the runner with `XAIOS_QEMU_IOMMU=riscv-iommu` -- the device and two
   `iommu-testdev` instances at fixed slots, so the stream ids the driver names
   are stable -- requires the markers, and requires at least two refused
   transactions in the fault total so "printed the summary" cannot pass with no
   faults. Its report is `xaios.qemu.riscv-iommu.v1` with
   `qemu_correctness_only: true`. The capability
   `translated_riscv_iommu_isolation` was added to
   `contracts/qemu-rc-v1.json`, `tests/repository/check-core-os-status.py` and
   `tests/scripts/qemu-core-os-rc.py` in the same change.

## What this board cannot prove

Both QEMU variants attach the IOMMU to the PCI bus and to nothing else, so
**virtio-mmio is not mediated and cannot be**: the riscv64 runner's root
filesystem, models volume and persistent disks are all `virtio-blk-device` on
`virtio-mmio-bus`, and no driver can change that.

The PCI transports are a different matter, and the virtio half is now landed.
Every PCI function starts with a pass-through context; when a virtio PCI
transport hands a queue to a device, `setup_queue` calls
`riscv64_iommu_mediate_dma` for the descriptor, available and used rings, and
the driver installs an Sv39 first-stage context whose table identity-maps three
gigabytes with 1 GiB leaves. Identity, because a driver allocates a device's
buffers wherever physical memory is, and the point of this step is that the
walk happens rather than that the addresses move. What it buys is a table this
driver owns: an entry can be taken away, and the table's contents can be read
back from the CPU and asserted. `riscv-iommu: mediated dma stream_id=32
region=0x... pte_ok=1` is that read, and `virtio-rng: entropy delivery
self-test passed` afterwards is two real device reads that could only have
reached their rings through the walk.

**What the virtio half is not yet:** isolation between mediated functions. They
share one identity-mapped table, so the walk happens without keeping them out of
each other's memory, and a transport whose buffers are mapped to *different*
addresses -- a real translation rather than an identity one -- is the step after
that. The isolation proof this gate makes is the one the test device makes:
unmap, invalidate, and the same transaction faults.

Not claimable here either: ATS/PRI behaviour (the capability is advertised and
no device on this board uses it), interrupt-delivered faults on the default
board (polling is the stronger evidence anyway), a board where the
requestor-id mapping is not the identity, a second IOMMU, and any physical
machine.

The plain `virt` board genuinely has no IOMMU, so the smoke's marker stays
true, and it is now the result of a probe that names what it searched for. Only
a board booted with the device attached claims isolation, and
`make qemu-riscv64-iommu-gate` is that board.

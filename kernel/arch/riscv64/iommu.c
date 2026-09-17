/*
 * The RISC-V IOMMU (B-130), from docs/RISCV-IOMMU.md.
 *
 * QEMU's `virt` board can carry one with `-device riscv-iommu-pci`, and this
 * file looks for it, names it, and -- once it is there -- proves it is doing
 * its job. The plain board has none, and that is still the result of a look
 * rather than a compile-time sentence: `smmu: riscv64 has no IOMMU on this
 * board` is printed only after `pci_find_device` came back empty.
 *
 * Three facts about this device shape everything below.
 *
 * **Its reset state refuses all PCI DMA.** `DDTP` comes up Off, so the moment
 * the device is attached every PCI function without a valid context stops.
 * The identity contexts therefore go in *before* `DDTP` leaves Bare, in the
 * same step, and a driver that cannot finish programming writes `Bare` back
 * rather than leaving a half-built table in charge of the machine's DMA.
 *
 * **Its contexts are 64 bytes, and that fixes the device-id width.** The
 * property QEMU resets the device with (`intremap`, MSI translation) selects
 * the extended context format, and in 1LVL that format supports six-bit device
 * ids: 64 contexts, exactly one page. A function whose stream id is wider than
 * that is a machine this table cannot describe, and the driver says so and
 * stays in Bare instead of truncating an id into someone else's context.
 *
 * **Fault evidence is polled.** This PCI variant advertises MSI-only interrupt
 * generation (`IGS = 0`), the board delivers no PCI MSI to this port, and the
 * specification writes the fault record whether or not anything is notified --
 * so the fault queue is drained by reading `FQH`/`FQT`, and that is the
 * stronger evidence rather than a workaround.
 *
 * The register interface and the two queues live in iommu_hw.c, and the device
 * directory table with its identity, translation and mediated first-stage
 * contexts in iommu_ddt.c. This file keeps the first-stage page tables, the
 * QEMU test device and the self-test that reads the machine's behaviour back
 * out. The split is a size split: register offsets, queue layout and
 * translation semantics are unchanged.
 */

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/exception.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/smmu.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

#include "iommu_internal.h"

/* CAP, only the fields this file's log line decides with. */
#define IOMMU_CAP_VERSION UINT64_C(0xff)
#define IOMMU_CAP_SV39    (UINT64_C(1) << 9)
#define IOMMU_CAP_SV48    (UINT64_C(1) << 10)
#define IOMMU_CAP_IGS     (UINT64_C(3) << 28)

/* The generic QEMU test device (Red Hat 0x1b36:0x0005): BAR0 is a
   programmable DMA engine that writes a known word through its translated
   address space and reads it back from a chosen physical address, so a
   translation that lands where it should is observable from the CPU. */
#define ITD_DMA_TRIGGERING UINT32_C(0x00)
#define ITD_DMA_GVA_LO     UINT32_C(0x04)
#define ITD_DMA_GVA_HI     UINT32_C(0x08)
#define ITD_DMA_LEN        UINT32_C(0x0c)
#define ITD_DMA_RESULT     UINT32_C(0x10)
#define ITD_DMA_DBELL      UINT32_C(0x14)
#define ITD_DMA_ATTRS      UINT32_C(0x18)
#define ITD_DMA_GPA_LO     UINT32_C(0x1c)
#define ITD_DMA_GPA_HI     UINT32_C(0x20)
#define ITD_DMA_ARM        UINT32_C(1)
/* space valid, Arm non-secure: the encoding the SMMU gate already uses, and
   the one this device checks for internal consistency. */
#define ITD_ATTRS_VALID_NONSECURE UINT32_C(0x0a)
#define ITD_DMA_WRITE_VALUE UINT32_C(0x12345678)

/* The IOVA the test presents, deliberately above the identity-mapped RAM so a
   translation that is not there cannot be confused with a pass-through. */
#define IOMMU_TEST_IOVA UINT64_C(0x0000000100000000)

/* First-stage tables for the one device this driver translates. One tree
   serves both formats: `l2` is an Sv39 root, and an Sv48 root is one level
   above it pointing at the same `l2`, so the two are read at different depths
   rather than built twice. */
static uint64_t g_iommu_root[512] __attribute__((aligned(4096)));
static uint64_t g_iommu_l2[512] __attribute__((aligned(4096)));
static uint64_t g_iommu_l1[512] __attribute__((aligned(4096)));
static uint64_t g_iommu_l0[512] __attribute__((aligned(4096)));
static uint8_t g_iommu_dma_target[4096] __attribute__((aligned(4096)));

static uint64_t pte_pointer(const void *table) {
  return (((uint64_t)(uintptr_t)table >> 12U) << 10U) | IOMMU_PTE_V;
}

/* The physical address in a leaf is the PPN field at bits 53:10, so it is the
   address's page number and not the address: an address written into the low
   bits -- which is what `address & ~0xfff` produces -- makes the walk land at
   `address >> 2` and the transaction fails somewhere else entirely. That was
   measured, not reasoned about: the first leaf built this way translated the
   test IOVA to 0x20177c000 for a target of 0x805df000.

   Named rather than static because iommu_ddt.c's mediation builds its own
   tree with the same leaf encoding. */
uint64_t riscv64_iommu_pte_leaf(uint64_t address) {
  return ((address >> 12U) << 10U) | IOMMU_PTE_LEAF;
}

uint64_t riscv64_iommu_first_stage_fsc(const void *table, uint64_t mode) {
  return (((uint64_t)(uintptr_t)table >> 12U) & UINT64_C(0xfffffffffff)) | mode;
}

/* Build the first-stage tree: RAM is identity-mapped with 1 GiB leaves --
   which is what a device written for unmediated DMA needs to keep working --
   and the test IOVA gets a 4 KiB page of its own through a full walk. Both
   formats read the same tree, so a mismatch between them is a mismatch in the
   context and not in the tables. */
static void build_first_stage_tables(uint64_t target) {
  for (uint32_t entry = 0U; entry < 512U; ++entry) {
    g_iommu_root[entry] = 0U;
    g_iommu_l2[entry] = 0U;
    g_iommu_l1[entry] = 0U;
    g_iommu_l0[entry] = 0U;
  }
  for (uint32_t gib = 0U; gib < 3U; ++gib) {
    g_iommu_l2[gib] = riscv64_iommu_pte_leaf((uint64_t)gib * IOMMU_GIB);
  }
  g_iommu_l2[(IOMMU_TEST_IOVA >> 30U) & 0x1ffU] = pte_pointer(g_iommu_l1);
  g_iommu_l1[(IOMMU_TEST_IOVA >> 21U) & 0x1ffU] = pte_pointer(g_iommu_l0);
  g_iommu_l0[(IOMMU_TEST_IOVA >> 12U) & 0x1ffU] =
      riscv64_iommu_pte_leaf(target);
  g_iommu_root[0] = pte_pointer(g_iommu_l2);
  xaios_cpu_io_barrier();
}

static void unmap_test_page(void) {
  g_iommu_l0[(IOMMU_TEST_IOVA >> 12U) & 0x1ffU] = 0U;
  xaios_cpu_io_barrier();
}

static void zero_dma_target(void) {
  for (uint32_t byte = 0U; byte < sizeof(g_iommu_dma_target); ++byte) {
    g_iommu_dma_target[byte] = 0U;
  }
  xaios_cpu_io_barrier();
}

static uint32_t dma_target_word(void) {
  return *(volatile const uint32_t *)(const void *)g_iommu_dma_target;
}

static uint32_t find_iommu_testdev(uint32_t ordinal) {
  uint32_t seen = 0U;
  for (uint32_t index = 0U; index < pci_device_count(); ++index) {
    const xaios_pci_device_t *device = pci_device(index);
    if (device == 0) continue;
    if (device->vendor_id != RISCV_IOMMU_PCI_VENDOR ||
        device->device_id != RISCV_IOMMU_TESTDEV_DEVICE) {
      continue;
    }
    if (seen == ordinal) return index;
    ++seen;
  }
  return UINT32_MAX;
}

static volatile uint32_t *map_testdev_bar(uint32_t index) {
  uint64_t address = pci_bar_address(index, 0U);
  if (address == 0U) return 0;
  if (vmm_map_page(address, address,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                       XAIOS_VMM_DEVICE) != XAIOS_OK) {
    return 0;
  }
  return (volatile uint32_t *)(uintptr_t)address;
}

/* Arm the device and let it run: one write through its translated address
   space and a read-back from the physical address it was told to expect. Zero
   is success; 0xdead0002 is a transaction the IOMMU refused. */
static int run_testdev_dma(volatile uint32_t *bar, uint64_t iova,
                           uint64_t target) {
  bar[ITD_DMA_GVA_LO / 4U] = (uint32_t)iova;
  bar[ITD_DMA_GVA_HI / 4U] = (uint32_t)(iova >> 32U);
  bar[ITD_DMA_LEN / 4U] = 4U;
  bar[ITD_DMA_ATTRS / 4U] = ITD_ATTRS_VALID_NONSECURE;
  bar[ITD_DMA_GPA_LO / 4U] = (uint32_t)target;
  bar[ITD_DMA_GPA_HI / 4U] = (uint32_t)(target >> 32U);
  bar[ITD_DMA_DBELL / 4U] = ITD_DMA_ARM;
  xaios_cpu_io_barrier();
  (void)bar[ITD_DMA_TRIGGERING / 4U];
  xaios_cpu_io_barrier();
  return (int)bar[ITD_DMA_RESULT / 4U];
}

void riscv64_iommu_self_test(void) {
  uint32_t index = pci_find_device(RISCV_IOMMU_PCI_VENDOR,
                                   RISCV_IOMMU_PCI_DEVICE);
  if (index == UINT32_C(0xFFFFFFFF)) {
    klog("smmu: riscv64 pci inventory has no 0x%04x:0x%04x and the tree has no "
         "riscv,iommu node\n",
         (unsigned)RISCV_IOMMU_PCI_VENDOR, (unsigned)RISCV_IOMMU_PCI_DEVICE);
    klog("smmu: riscv64 has no IOMMU on this board; DMA is unmediated\n");
    return;
  }
  (void)pci_enable_device(index);
  uint64_t base = pci_bar_address(index, 0U);
  if (base == 0U) {
    klog("smmu: riscv64 riscv-iommu-pci present with no BAR0 assigned; DMA is "
         "unmediated\n");
    return;
  }

  /* QEMU places this 64-bit BAR above the port's identity-mapped device
     window, so the page has to be mapped before a register can be read. It is
     writable as well as present: the first milestone only read `CAP` through a
     read-only mapping, and the first register write through it was a
     store-page-fault at `base + 0x18`, which is `CQB`. */
  if (vmm_map_page(base, base,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                       XAIOS_VMM_DEVICE) != XAIOS_OK) {
    klog("smmu: riscv64 riscv-iommu-pci at 0x%lx could not be mapped; DMA is "
         "unmediated\n",
         (unsigned long)base);
    return;
  }
  riscv64_iommu_bind(base);

  /* A read that faults and a read of all-ones mean the same thing here, and
     neither is fatal. */
  exception_mmio_probe_begin();
  uint64_t cap = riscv64_iommu_read_cap();
  exception_mmio_probe_end();
  if (exception_mmio_probe_faulted() != 0) {
    klog("smmu: riscv64 riscv-iommu-pci at 0x%lx does not answer; DMA is "
         "unmediated\n",
         (unsigned long)base);
    return;
  }

  klog("riscv-iommu: found device=%u base=0x%lx cap=0x%lx version=0x%lx sv39=%u "
       "sv48=%u sv57=%u igs=%u\n",
       (unsigned)index, (unsigned long)base, (unsigned long)cap,
       (unsigned long)(cap & IOMMU_CAP_VERSION),
       (unsigned)((cap & IOMMU_CAP_SV39) != 0U),
       (unsigned)((cap & IOMMU_CAP_SV48) != 0U),
       (unsigned)((cap & (UINT64_C(1) << 11)) != 0U),
       (unsigned)((cap & IOMMU_CAP_IGS) >> 28));

  /* The table the driver builds must be describable by this device, and the
     contexts it fills are Bare on both stages, which every version supports. */
  if (riscv64_iommu_install_identity_contexts() == 0) return;

  if (riscv64_iommu_program_device() == 0) return;

  int fenced = riscv64_iommu_issue_command(IOMMU_CMD_IOFENCE_C, 0U);
  int ddt_invalidated =
      riscv64_iommu_issue_command(IOMMU_CMD_IODIR_INVAL_DDT, 0U);
  if (fenced == 0 || ddt_invalidated == 0) {
    riscv64_iommu_bail_to_bare("a first command did not complete");
    return;
  }
  uint64_t faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: queues and ddt enabled commands=%lu contexts=%u fence=%d "
       "invalidate_ddt=%d faults=%lu\n",
       (unsigned long)riscv64_iommu_command_count(),
       (unsigned)riscv64_iommu_identity_contexts(), fenced, ddt_invalidated,
       (unsigned long)faults);
  kassert(fenced != 0);
  kassert(ddt_invalidated != 0);
  kassert(riscv64_iommu_identity_contexts() != 0U);

  /* Milestones 4 and 5: translation for one device, then its removal and the
     device this table never described. Both need the two test instances the
     runner attaches; a board with the IOMMU but without them stops here with
     the queue and table evidence above and claims nothing further. */
  uint32_t authorized = find_iommu_testdev(0U);
  uint32_t unregistered = find_iommu_testdev(1U);
  if (authorized == UINT32_MAX || unregistered == UINT32_MAX) {
    klog("riscv-iommu: %s; translation and isolation are not claimed\n",
         authorized == UINT32_MAX ? "no iommu-testdev present"
                                  : "only one iommu-testdev present");
    return;
  }
  uint32_t authorized_id = pci_stream_id(authorized);
  uint32_t unregistered_id = pci_stream_id(unregistered);
  if (authorized_id >= IOMMU_DDT_CONTEXTS ||
      unregistered_id >= IOMMU_DDT_CONTEXTS) {
    klog("riscv-iommu: a test device stream_id=%u/%u is wider than the "
         "table's %u device ids; translation and isolation are not claimed\n",
         (unsigned)authorized_id, (unsigned)unregistered_id,
         (unsigned)IOMMU_DDT_CONTEXTS);
    return;
  }
  volatile uint32_t *authorized_bar = map_testdev_bar(authorized);
  volatile uint32_t *unregistered_bar = map_testdev_bar(unregistered);
  if (authorized_bar == 0 || unregistered_bar == 0) {
    klog("riscv-iommu: a test device BAR could not be mapped; translation and "
         "isolation are not claimed\n");
    return;
  }
  (void)pci_enable_device(authorized);
  (void)pci_enable_device(unregistered);

  uint64_t target = (uint64_t)(uintptr_t)g_iommu_dma_target;

  /* The control the rest of this depends on: the engine works at all. While
     the device still has its identity context, its own DMA is the cheapest
     thing that can go wrong for a reason that has nothing to do with page
     tables -- a BAR that cannot be written, a stream id whose context was
     never read -- and separating the two is worth one transaction. */
  zero_dma_target();
  int identity_result = run_testdev_dma(authorized_bar, target, target);
  uint64_t identity_faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: identity DMA result=0x%x target=0x%x faults=%lu\n",
       identity_result, dma_target_word(), (unsigned long)identity_faults);
  kassert(identity_result == 0);
  kassert(dma_target_word() == ITD_DMA_WRITE_VALUE);

  build_first_stage_tables(target);

  /* Sv39 first: the device's context is replaced, and both caches drop what
     they hold -- the context itself through IODIR, the translations through
     IOTINVAL. Without the second the first identity context could still
     answer, which is exactly the stale entry the later test needs to be able
     to flush. */
  riscv64_iommu_install_translation_context(
      authorized_id,
      riscv64_iommu_first_stage_fsc(g_iommu_l2, IOMMU_FSC_MODE_SV39));
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IODIR_INVAL_DDT, 0U);
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IOTINVAL_ALL, 0U);
  zero_dma_target();
  int translated = run_testdev_dma(authorized_bar, IOMMU_TEST_IOVA, target);
  uint64_t translated_faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: sv39 translated DMA result=0x%x target=0x%x iova=0x%lx "
       "did=%u faults=%lu\n",
       translated, dma_target_word(), (unsigned long)IOMMU_TEST_IOVA,
       (unsigned)authorized_id, (unsigned long)translated_faults);
  kassert(translated == 0);
  kassert(dma_target_word() == ITD_DMA_WRITE_VALUE);

  /* Then Sv48 through the same tree one level deeper, because the format is
     part of the context rather than of the tables and a driver that only ever
     built one would report a capability it never used. */
  riscv64_iommu_install_translation_context(
      authorized_id,
      riscv64_iommu_first_stage_fsc(g_iommu_root, IOMMU_FSC_MODE_SV48));
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IODIR_INVAL_DDT, 0U);
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IOTINVAL_ALL, 0U);
  zero_dma_target();
  int translated_sv48 =
      run_testdev_dma(authorized_bar, IOMMU_TEST_IOVA, target);
  uint64_t translated_sv48_faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: sv48 translated DMA result=0x%x target=0x%x did=%u "
       "faults=%lu\n",
       translated_sv48, dma_target_word(), (unsigned)authorized_id,
       (unsigned long)translated_sv48_faults);
  kassert(translated_sv48 == 0);
  kassert(dma_target_word() == ITD_DMA_WRITE_VALUE);

  /* Take the page away, flush, and the identical transaction must fault: the
     mapping is the only reason it worked a line ago. */
  unmap_test_page();
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IOTINVAL_ALL, 0U);
  zero_dma_target();
  int stale = run_testdev_dma(authorized_bar, IOMMU_TEST_IOVA, target);
  uint64_t stale_faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: stale mapping blocked result=0x%x target=0x%x "
       "faults=%lu\n",
       stale, dma_target_word(), (unsigned long)stale_faults);
  kassert(stale != 0);
  kassert(dma_target_word() == 0U);
  kassert(stale_faults >= 1U);

  /* And the device the directory never described: no valid context at all, so
     the walk stops before any page table and the reason is DDT_INVALID. */
  zero_dma_target();
  int refused = run_testdev_dma(unregistered_bar, IOMMU_TEST_IOVA, target);
  uint64_t refused_faults = riscv64_iommu_drain_faults();
  klog("riscv-iommu: unregistered device refused result=0x%x target=0x%x "
       "did=%u faults=%lu\n",
       refused, dma_target_word(), (unsigned)unregistered_id,
       (unsigned long)refused_faults);
  kassert(refused != 0);
  kassert(dma_target_word() == 0U);
  kassert(refused_faults >= 1U);

  klog("riscv-iommu: isolation self-test passed authorized=1 forbidden=1 "
       "stale_mapping=blocked faults=%lu\n",
       (unsigned long)riscv64_iommu_fault_count());
}

/* The RISC-V IOMMU device directory and its first-stage contexts (B-130).
 *
 * This is the table the device walks: an identity context for every PCI
 * function, so a machine whose drivers were written for unmediated DMA keeps
 * booting; the context a translating function is given; and the first-stage
 * mediation a transport asks for when it hands a queue to a device.
 *
 * Moved here from iommu.c, which keeps the first-stage page tables, the QEMU
 * test device and the self-test. The 64-byte extended context, the 1LVL
 * directory and the walk are unchanged: the split is a size split.
 */

#include <xaios/arch_cpu.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/smmu.h>
#include <xaios/types.h>

#include "iommu_internal.h"

typedef struct riscv_iommu_context {
  uint64_t tc;
  uint64_t iohgatp;
  uint64_t ta;
  uint64_t fsc;
  uint64_t msiptp;
  uint64_t msi_addr_mask;
  uint64_t msi_addr_pattern;
  uint64_t reserved;
} riscv_iommu_context_t;

/* tc.V, with both `iohgatp` and `fsc` left Bare: a pass-through context. */
#define IOMMU_TC_V UINT64_C(1)

static riscv_iommu_context_t g_ddt[IOMMU_DDT_CONTEXTS]
    __attribute__((aligned(4096)));
static uint32_t g_identity_contexts;

/* The directory table's physical address, for the one write that programs
   `DDTP`. The register side lives in iommu_hw.c and reaches the table by
   address rather than by pointer. */
uint64_t riscv64_iommu_ddt_base(void) {
  return (uint64_t)(uintptr_t)g_ddt;
}

/* The identity context for one function: first and second stage both Bare, so
   an address a device presents is the address it reaches. That is what keeps
   a machine whose drivers were written against unmediated DMA working while
   the table is in place, and it is the context the isolation test later takes
   away from the device it is proving. */
static void install_identity_context(uint32_t device_id) {
  riscv_iommu_context_t *context = &g_ddt[device_id];
  context->tc = IOMMU_TC_V;
  context->iohgatp = 0U;
  context->ta = 0U;
  context->fsc = 0U;
  context->msiptp = 0U;
  context->msi_addr_mask = 0U;
  context->msi_addr_pattern = 0U;
  context->reserved = 0U;
  xaios_cpu_io_barrier();
}

int riscv64_iommu_install_identity_contexts(void) {
  uint32_t count = pci_device_count();
  uint32_t testdevs = 0U;
  for (uint32_t index = 0U; index < count; ++index) {
    const xaios_pci_device_t *device = pci_device(index);
    if (device == 0) continue;
    uint32_t device_id = pci_stream_id(index);
    if (device->vendor_id == RISCV_IOMMU_PCI_VENDOR &&
        device->device_id == RISCV_IOMMU_TESTDEV_DEVICE) {
      /* The test device does no DMA of its own, so the identity context it
         would otherwise be given is not what keeps the machine booting -- it
         is the device the isolation proof needs to find *unregistered*. Every
         instance after the first is therefore left out of the table on
         purpose, and its first transaction is the `DDT_INVALID` the gate
         asserts. */
      if (testdevs >= 1U) {
        klog("riscv-iommu: leaving iommu-testdev stream_id=%u unregistered for "
             "the isolation proof\n",
             (unsigned)device_id);
        ++testdevs;
        continue;
      }
      ++testdevs;
    }
    if (device_id >= IOMMU_DDT_CONTEXTS) {
      klog("riscv-iommu: stream_id=%u is wider than this table's %u device "
           "ids; leaving the IOMMU in Bare\n",
           (unsigned)device_id, (unsigned)IOMMU_DDT_CONTEXTS);
      return 0;
    }
    install_identity_context(device_id);
    ++g_identity_contexts;
  }
  return 1;
}

uint32_t riscv64_iommu_identity_contexts(void) {
  return g_identity_contexts;
}

void riscv64_iommu_install_translation_context(uint32_t device_id,
                                               uint64_t fsc) {
  riscv_iommu_context_t *context = &g_ddt[device_id];
  context->tc = IOMMU_TC_V;
  context->iohgatp = 0U;
  context->ta = 0U;
  context->fsc = fsc;
  context->msiptp = 0U;
  context->msi_addr_mask = 0U;
  context->msi_addr_pattern = 0U;
  context->reserved = 0U;
  xaios_cpu_io_barrier();
}

/* --- First-stage contexts for the functions that actually do DMA (B-130) ---
 *
 * Every PCI function starts with a pass-through context, which is what keeps a
 * machine whose drivers were written for unmediated DMA booting. That is not a
 * translation: the IOMMU is in the path and there is no table for it to walk.
 * This is the other half -- a PCI function whose DMA is a walk.
 *
 * The table identity-maps three gigabytes with 1 GiB leaves in Sv39. It is
 * identity because a driver allocates a device's buffers wherever physical
 * memory happens to be, and the point of this step is that the walk happens,
 * not that the addresses move. What it buys is the thing a pass-through cannot
 * have: the mapping is a table this driver owns, so an entry can be taken away
 * (that is a revocation) and the table's contents can be read back from the CPU
 * and asserted, rather than inferred from a device that happens to work.
 *
 * The mediation happens when a transport hands a queue to a device, which is
 * the moment the device first has memory to reach; `virtio_transport_pci.c`
 * calls it from `setup_queue`. Passing the rings rather than every buffer is
 * deliberate: they are the memory the transport itself knows about, and the
 * identity mapping is what lets the driver keep allocating its data buffers the
 * way it always did.
 */

#define IOMMU_MEDIATED_MAX 4U

static uint64_t g_mediated_table[IOMMU_MEDIATED_MAX][512]
    __attribute__((aligned(4096)));
static uint32_t g_mediated_stream[IOMMU_MEDIATED_MAX];
static uint32_t g_mediated_count;
static uint64_t g_mediated_pages;
static uint64_t g_mediated_regions;

/* What the table resolves `address` to, read back out of the table. A leaf at
 * this level covers 1 GiB, so the offset within it is the address's low thirty
 * bits; a table that resolved to something else would be one whose context
 * pointed at the wrong root, and asserting the walk is what tells the two
 * apart without a device in the loop. */
static uint64_t mediated_walk(const uint64_t *table, uint64_t address) {
  uint64_t entry = table[(address >> 30U) & 0x1ffU];
  if ((entry & (IOMMU_PTE_V | IOMMU_PTE_R | IOMMU_PTE_W)) !=
      (IOMMU_PTE_V | IOMMU_PTE_R | IOMMU_PTE_W)) {
    return UINT64_MAX;
  }
  return ((entry >> 10U) << 12U) | (address & UINT64_C(0x3fffffff));
}

/* The slot for `stream_id`, building and installing its table the first time.
 * Returns -1 when the slots are full, which is a refusal rather than a
 * fall-back to pass-through: a device this driver cannot mediate is one it
 * must not claim to. */
static int mediated_slot(uint32_t stream_id) {
  for (uint32_t slot = 0U; slot < g_mediated_count; ++slot) {
    if (g_mediated_stream[slot] == stream_id) return (int)slot;
  }
  if (g_mediated_count >= IOMMU_MEDIATED_MAX) return -1;
  uint32_t slot = g_mediated_count;
  g_mediated_stream[slot] = stream_id;
  for (uint32_t entry = 0U; entry < 512U; ++entry) {
    g_mediated_table[slot][entry] = 0U;
  }
  for (uint32_t gib = 0U; gib < 3U; ++gib) {
    g_mediated_table[slot][gib] =
        riscv64_iommu_pte_leaf((uint64_t)gib * IOMMU_GIB);
  }
  xaios_cpu_io_barrier();
  /* One table serves as the Sv39 root: its entries are 1 GiB leaves, which is
   * level two's leaf size in this format, so no second level is needed to
   * describe memory a device can reach. */
  riscv64_iommu_install_translation_context(
      stream_id,
      riscv64_iommu_first_stage_fsc(g_mediated_table[slot],
                                    IOMMU_FSC_MODE_SV39));
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IODIR_INVAL_DDT, 0U);
  (void)riscv64_iommu_issue_command(IOMMU_CMD_IOTINVAL_ALL, 0U);
  ++g_mediated_count;
  klog("riscv-iommu: first-stage context stream_id=%u leaves=3 ram=3GiB "
       "format=sv39\n",
       (unsigned)stream_id);
  return (int)slot;
}

int riscv64_iommu_mediate_dma(uint32_t stream_id, uint64_t physical,
                              uint64_t size) {
  int slot;
  uint64_t page;
  uint64_t resolved;
  uint64_t pages;

  if (riscv64_iommu_ready() == 0U || size == 0U) return 0;
  if (stream_id >= IOMMU_DDT_CONTEXTS) return 0;
  slot = mediated_slot(stream_id);
  if (slot < 0) {
    klog("riscv-iommu: no first-stage slot left for stream_id=%u; its DMA "
         "stays unmediated\n",
         (unsigned)stream_id);
    return 0;
  }
  page = physical & ~UINT64_C(0xfff);
  resolved = mediated_walk(g_mediated_table[slot], page);
  if (resolved != page) {
    klog("riscv-iommu: first-stage walk for stream_id=%u address=0x%lx "
         "resolved=0x%lx; refusing to claim the mapping\n",
         (unsigned)stream_id, (unsigned long)page, (unsigned long)resolved);
    return 0;
  }
  pages = (size + 4095U) / 4096U;
  g_mediated_pages += pages;
  ++g_mediated_regions;
  klog("riscv-iommu: mediated dma stream_id=%u region=0x%lx size=%lu "
       "pages=%lu pte_ok=1\n",
       (unsigned)stream_id, (unsigned long)physical, (unsigned long)size,
       (unsigned long)pages);
  return 1;
}

uint32_t riscv64_iommu_mediated_functions(void) { return g_mediated_count; }

uint64_t riscv64_iommu_mediated_regions(void) { return g_mediated_regions; }

uint64_t riscv64_iommu_mediated_pages(void) { return g_mediated_pages; }

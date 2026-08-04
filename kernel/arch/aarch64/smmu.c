#include <xaios/assert.h>
#include <xaios/boot_info.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/smmu.h>
#include <xaios/vmm.h>

#define SMMU_TEST_DEVICE_ID UINT16_C(0x0005)
#define SMMU_QUEUE_LOG2 4U
#define SMMU_QUEUE_ENTRIES (1U << SMMU_QUEUE_LOG2)
#define SMMU_STREAM_LOG2 8U
#define SMMU_STREAM_ENTRIES (1U << SMMU_STREAM_LOG2)
#define SMMU_TEST_IOVA UINT64_C(0x0000000100000000)
#define SMMU_PTE_ADDR_MASK UINT64_C(0x0000fffffffff000)
#define SMMU_TABLE_DESCRIPTOR UINT64_C(0x8000000000000003)
#define SMMU_PAGE_DESCRIPTOR UINT64_C(0x0400000000000763)

#define ITD_DMA_TRIGGERING UINT32_C(0x00)
#define ITD_DMA_GVA_LO UINT32_C(0x04)
#define ITD_DMA_GVA_HI UINT32_C(0x08)
#define ITD_DMA_LEN UINT32_C(0x0c)
#define ITD_DMA_RESULT UINT32_C(0x10)
#define ITD_DMA_DBELL UINT32_C(0x14)
#define ITD_DMA_ATTRS UINT32_C(0x18)
#define ITD_DMA_GPA_LO UINT32_C(0x1c)
#define ITD_DMA_GPA_HI UINT32_C(0x20)
#define ITD_DMA_TX_FAIL UINT32_C(0xdead0002)
#define ITD_DMA_WRITE_VALUE UINT32_C(0x12345678)

typedef struct smmu_command {
  uint32_t word[4];
} smmu_command_t;

typedef struct smmu_event {
  uint32_t word[8];
} smmu_event_t;

static volatile uint32_t *g_smmu;
static uint32_t g_smmu_present;
static uint32_t g_smmu_ready;
static uint32_t g_smmu_idr0;
static uint32_t g_active_streams;
static uint64_t g_tlb_invalidate_count;
static uint64_t g_fault_count;
static uint32_t g_cmdq_prod;
static uint32_t g_eventq_cons;
static xaios_smmu_stream_t g_streams[SMMU_STREAM_ENTRIES];

static uint8_t g_stream_table[SMMU_STREAM_ENTRIES][64]
    __attribute__((aligned(16384)));
static smmu_command_t g_cmdq[SMMU_QUEUE_ENTRIES]
    __attribute__((aligned(4096)));
static smmu_event_t g_eventq[SMMU_QUEUE_ENTRIES]
    __attribute__((aligned(4096)));
static uint32_t g_context_descriptor[16] __attribute__((aligned(64)));
static uint64_t g_l0[512] __attribute__((aligned(4096)));
static uint64_t g_l1[512] __attribute__((aligned(4096)));
static uint64_t g_l2[512] __attribute__((aligned(4096)));
static uint64_t g_l3[512] __attribute__((aligned(4096)));
static uint8_t g_dma_target[4096] __attribute__((aligned(4096)));

static uint32_t mmio_read32(uint32_t offset) {
  return g_smmu[offset / 4U];
}

static void mmio_write32(uint32_t offset, uint32_t value) {
  g_smmu[offset / 4U] = value;
  __asm__ volatile("dsb sy" ::: "memory");
}

static void mmio_write64(uint32_t offset, uint64_t value) {
  g_smmu[offset / 4U] = (uint32_t)value;
  g_smmu[offset / 4U + 1U] = (uint32_t)(value >> 32U);
  __asm__ volatile("dsb sy" ::: "memory");
}

static void zero_memory(void *dst, uint64_t size) {
  uint8_t *bytes = (uint8_t *)dst;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static int wait_register(uint32_t offset, uint32_t expected) {
  for (uint32_t spin = 0U; spin < UINT32_C(1000000); ++spin) {
    if (mmio_read32(offset) == expected) return 1;
  }
  return 0;
}

static int smmu_issue_command(uint32_t opcode, uint32_t sid) {
  if (g_smmu_ready == 0U) return 0;
  uint32_t mask = (SMMU_QUEUE_ENTRIES << 1U) - 1U;
  uint32_t next = (g_cmdq_prod + 1U) & mask;
  if (next == (mmio_read32(SMMU_CMDQ_CONS) & mask)) return 0;
  smmu_command_t *command = &g_cmdq[g_cmdq_prod & (SMMU_QUEUE_ENTRIES - 1U)];
  zero_memory(command, sizeof(*command));
  command->word[0] = opcode;
  command->word[1] = sid;
  __asm__ volatile("dsb sy" ::: "memory");
  g_cmdq_prod = next;
  mmio_write32(SMMU_CMDQ_PROD, g_cmdq_prod);
  for (uint32_t spin = 0U; spin < UINT32_C(1000000); ++spin) {
    uint32_t consumer = mmio_read32(SMMU_CMDQ_CONS);
    if ((consumer & UINT32_C(0x7f000000)) != 0U) return 0;
    if ((consumer & mask) == g_cmdq_prod) return 1;
  }
  return 0;
}

static void write_ste(uint32_t sid, uint32_t config, uint64_t context) {
  uint32_t *ste = (uint32_t *)(void *)g_stream_table[sid];
  zero_memory(ste, 64U);
  ste[0] = 1U | ((config & 7U) << 1U) |
           (uint32_t)(context & UINT64_C(0xffffffc0));
  ste[1] = (uint32_t)((context >> 32U) & UINT64_C(0x00ffffff));
  __asm__ volatile("dsb sy" ::: "memory");
}

static uint32_t table_index(uint64_t address, uint32_t level) {
  return (uint32_t)((address >> (39U - level * 9U)) & UINT64_C(0x1ff));
}

static void configure_stage1(uint32_t sid, uint64_t target) {
  zero_memory(g_context_descriptor, sizeof(g_context_descriptor));
  zero_memory(g_l0, sizeof(g_l0));
  zero_memory(g_l1, sizeof(g_l1));
  zero_memory(g_l2, sizeof(g_l2));
  zero_memory(g_l3, sizeof(g_l3));

  uint64_t l0 = (uint64_t)(uintptr_t)g_l0;
  uint64_t l1 = (uint64_t)(uintptr_t)g_l1;
  uint64_t l2 = (uint64_t)(uintptr_t)g_l2;
  uint64_t l3 = (uint64_t)(uintptr_t)g_l3;
  g_l0[table_index(SMMU_TEST_IOVA, 0U)] =
      (l1 & SMMU_PTE_ADDR_MASK) | SMMU_TABLE_DESCRIPTOR;
  g_l1[table_index(SMMU_TEST_IOVA, 1U)] =
      (l2 & SMMU_PTE_ADDR_MASK) | SMMU_TABLE_DESCRIPTOR;
  g_l2[table_index(SMMU_TEST_IOVA, 2U)] =
      (l3 & SMMU_PTE_ADDR_MASK) | SMMU_TABLE_DESCRIPTOR;
  g_l3[table_index(SMMU_TEST_IOVA, 3U)] =
      (target & SMMU_PTE_ADDR_MASK) | SMMU_PAGE_DESCRIPTOR;

  g_context_descriptor[0] = UINT32_C(0xc0000010);
  g_context_descriptor[1] = UINT32_C(0x00016204);
  g_context_descriptor[2] =
      UINT32_C(1) | (uint32_t)(l0 & UINT64_C(0xfffffff0));
  g_context_descriptor[3] =
      (uint32_t)((l0 >> 32U) & UINT64_C(0x000fffff));
  __asm__ volatile("dsb sy" ::: "memory");
  write_ste(sid, 5U, (uint64_t)(uintptr_t)g_context_descriptor);
  kassert(smmu_issue_command(SMMU_CMD_CFGI_STE, sid) != 0);
}

static uint32_t consume_events(uint32_t expected_sid) {
  uint32_t mask = (SMMU_QUEUE_ENTRIES << 1U) - 1U;
  uint32_t producer = mmio_read32(SMMU_EVENTQ_PROD) & mask;
  uint32_t matched = 0U;
  while (g_eventq_cons != producer) {
    smmu_event_t *event =
        &g_eventq[g_eventq_cons & (SMMU_QUEUE_ENTRIES - 1U)];
    uint32_t type = event->word[0] & UINT32_C(0xff);
    uint32_t sid = event->word[1];
    if (type != 0U) {
      klog("SMMU: event type=0x%x sid=%u address=0x%lx\n", type, sid,
           ((uint64_t)event->word[5] << 32U) | event->word[4]);
      ++g_fault_count;
      if (sid == expected_sid) ++matched;
    }
    zero_memory(event, sizeof(*event));
    g_eventq_cons = (g_eventq_cons + 1U) & mask;
  }
  mmio_write32(SMMU_EVENTQ_CONS, g_eventq_cons);
  return matched;
}

void smmu_init(const xaios_boot_info_t *boot) {
  g_smmu_present = boot != 0 &&
                   (boot->platform_flags & XAIOS_BOOT_PLATFORM_SMMUV3) != 0U;
  g_smmu_ready = 0U;
  g_smmu_idr0 = 0U;
  g_active_streams = 0U;
  g_tlb_invalidate_count = 0U;
  g_fault_count = 0U;
  g_cmdq_prod = 0U;
  g_eventq_cons = 0U;
  zero_memory(g_streams, sizeof(g_streams));
  zero_memory(g_stream_table, sizeof(g_stream_table));
  zero_memory(g_cmdq, sizeof(g_cmdq));
  zero_memory(g_eventq, sizeof(g_eventq));
  if (g_smmu_present == 0U) {
    klog("SMMU: bypass mode (firmware reported no SMMUv3)\n");
    return;
  }

  g_smmu = (volatile uint32_t *)(uintptr_t)XAIOS_SMMU_MMIO_BASE;
  g_smmu_idr0 = mmio_read32(SMMU_IDR0);
  uint32_t idr1 = mmio_read32(SMMU_IDR1);
  if ((g_smmu_idr0 & UINT32_C(0x2)) == 0U ||
      (idr1 & UINT32_C(0x3f)) < SMMU_STREAM_LOG2) {
    klog("SMMU: required stage-1 or stream width unavailable idr0=0x%x idr1=0x%x\n",
         g_smmu_idr0, idr1);
    return;
  }

  mmio_write32(SMMU_CR0, 0U);
  if (!wait_register(SMMU_CR0ACK, 0U)) return;
  mmio_write32(SMMU_GBPA, SMMU_GBPA_UPDATE);
  mmio_write32(SMMU_CR1, UINT32_C(0x0d75));
  mmio_write64(SMMU_STRTAB_BASE,
               (uint64_t)(uintptr_t)g_stream_table);
  mmio_write32(SMMU_STRTAB_BASE_CFG, SMMU_STREAM_LOG2);
  mmio_write64(SMMU_CMDQ_BASE,
               (uint64_t)(uintptr_t)g_cmdq | SMMU_QUEUE_LOG2);
  mmio_write32(SMMU_CMDQ_PROD, 0U);
  mmio_write32(SMMU_CMDQ_CONS, 0U);
  mmio_write64(SMMU_EVENTQ_BASE,
               (uint64_t)(uintptr_t)g_eventq | SMMU_QUEUE_LOG2);
  mmio_write32(SMMU_EVENTQ_PROD, 0U);
  mmio_write32(SMMU_EVENTQ_CONS, 0U);
  mmio_write32(SMMU_CR0,
               SMMU_CR0_SMMUEN | SMMU_CR0_EVENTQEN | SMMU_CR0_CMDQEN);
  if (!wait_register(SMMU_CR0ACK,
                     SMMU_CR0_SMMUEN | SMMU_CR0_EVENTQEN |
                         SMMU_CR0_CMDQEN)) {
    klog("SMMU: enable acknowledgement timeout\n");
    return;
  }
  g_smmu_ready = 1U;
  klog("SMMU: enabled idr0=0x%x idr1=0x%x streams=%u queues=%u\n",
       g_smmu_idr0, idr1, SMMU_STREAM_ENTRIES, SMMU_QUEUE_ENTRIES);
}

uint32_t smmu_initialized(void) { return g_smmu_ready; }
uint32_t smmu_idr0_value(void) { return g_smmu_idr0; }

xaios_status_t smmu_register_stream(uint32_t stream_id, uint32_t device_type) {
  if (stream_id >= SMMU_STREAM_ENTRIES || g_streams[stream_id].active != 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (g_smmu_ready != 0U) {
    write_ste(stream_id, 4U, 0U);
    if (!smmu_issue_command(SMMU_CMD_CFGI_STE, stream_id)) {
      return XAIOS_ERR_IO;
    }
  }
  g_streams[stream_id].stream_id = stream_id;
  g_streams[stream_id].active = 1U;
  g_streams[stream_id].device_type = device_type;
  ++g_active_streams;
  return XAIOS_OK;
}

xaios_status_t smmu_unregister_stream(uint32_t stream_id) {
  if (stream_id >= SMMU_STREAM_ENTRIES || g_streams[stream_id].active == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (g_smmu_ready != 0U) {
    write_ste(stream_id, 0U, 0U);
    if (!smmu_issue_command(SMMU_CMD_CFGI_STE, stream_id)) {
      return XAIOS_ERR_IO;
    }
  }
  g_streams[stream_id].active = 0U;
  --g_active_streams;
  return XAIOS_OK;
}

xaios_status_t smmu_tlb_invalidate_all(void) {
  if (g_smmu_ready != 0U &&
      !smmu_issue_command(SMMU_CMD_TLBI_NH_ALL, 0U)) {
    return XAIOS_ERR_IO;
  }
  ++g_tlb_invalidate_count;
  return XAIOS_OK;
}

uint64_t smmu_tlb_invalidate_count(void) { return g_tlb_invalidate_count; }
uint64_t smmu_fault_count(void) { return g_fault_count; }
uint64_t smmu_stream_count(void) { return g_active_streams; }

static void iommu_testdev_program(volatile uint32_t *bar, uint64_t iova,
                                  uint64_t target) {
  bar[ITD_DMA_GVA_LO / 4U] = (uint32_t)iova;
  bar[ITD_DMA_GVA_HI / 4U] = (uint32_t)(iova >> 32U);
  bar[ITD_DMA_LEN / 4U] = 4U;
  bar[ITD_DMA_ATTRS / 4U] = UINT32_C(0x0a);
  bar[ITD_DMA_GPA_LO / 4U] = (uint32_t)target;
  bar[ITD_DMA_GPA_HI / 4U] = (uint32_t)(target >> 32U);
  bar[ITD_DMA_DBELL / 4U] = 1U;
  __asm__ volatile("dsb sy" ::: "memory");
  (void)bar[ITD_DMA_TRIGGERING / 4U];
  __asm__ volatile("dsb sy" ::: "memory");
}

void smmu_self_test(void) {
  if (g_smmu_ready == 0U) {
    kassert(smmu_register_stream(0U, UINT32_C(0xaa)) == XAIOS_OK);
    kassert(smmu_unregister_stream(0U) == XAIOS_OK);
    kassert(smmu_tlb_invalidate_all() == XAIOS_OK);
    klog("SMMU: self-test bypass mode streams=0 invalidations=1\n");
    return;
  }

  uint32_t index = pci_find_device(XAIOS_PCI_VENDOR_REDHAT,
                                   SMMU_TEST_DEVICE_ID);
  kassert(index != UINT32_MAX);
  uint32_t sid = pci_stream_id(index);
  uint64_t bar_address = pci_bar_address(index, 0U);
  kassert(sid < SMMU_STREAM_ENTRIES && bar_address != 0U);
  kassert(pci_enable_device(index) == XAIOS_OK);
  kassert(vmm_map_page(bar_address, bar_address,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_DEVICE) == XAIOS_OK);
  volatile uint32_t *bar = (volatile uint32_t *)(uintptr_t)bar_address;
  uint64_t target = (uint64_t)(uintptr_t)g_dma_target;
  zero_memory(g_dma_target, sizeof(g_dma_target));

  configure_stage1(sid, target);
  iommu_testdev_program(bar, SMMU_TEST_IOVA, target);
  klog("SMMU: translated DMA result=0x%x event_prod=0x%x gerror=0x%x cmd_cons=0x%x target=0x%x\n",
       bar[ITD_DMA_RESULT / 4U], mmio_read32(SMMU_EVENTQ_PROD),
       mmio_read32(SMMU_GERROR), mmio_read32(SMMU_CMDQ_CONS),
       *(volatile uint32_t *)(void *)g_dma_target);
  if (bar[ITD_DMA_RESULT / 4U] != 0U) {
    (void)consume_events(sid);
  }
  kassert(bar[ITD_DMA_RESULT / 4U] == 0U);
  kassert(*(volatile uint32_t *)(void *)g_dma_target == ITD_DMA_WRITE_VALUE);

  g_l3[table_index(SMMU_TEST_IOVA, 3U)] = 0U;
  __asm__ volatile("dsb sy" ::: "memory");
  kassert(smmu_tlb_invalidate_all() == XAIOS_OK);
  zero_memory(g_dma_target, sizeof(g_dma_target));
  iommu_testdev_program(bar, SMMU_TEST_IOVA, target);
  kassert(bar[ITD_DMA_RESULT / 4U] == ITD_DMA_TX_FAIL);
  kassert(*(volatile uint32_t *)(void *)g_dma_target == 0U);
  kassert(consume_events(sid) >= 1U);

  write_ste(sid, 0U, 0U);
  kassert(smmu_issue_command(SMMU_CMD_CFGI_STE, sid) != 0);
  iommu_testdev_program(bar, SMMU_TEST_IOVA, target);
  kassert(bar[ITD_DMA_RESULT / 4U] == ITD_DMA_TX_FAIL);
  kassert(*(volatile uint32_t *)(void *)g_dma_target == 0U);
  kassert(smmu_tlb_invalidate_all() == XAIOS_OK);
  klog("SMMU: translated DMA self-test passed sid=%u authorized=1 forbidden=1 stale_mapping=blocked faults=%lu\n",
       sid, g_fault_count);
}

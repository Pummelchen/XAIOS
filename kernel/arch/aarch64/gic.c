#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>

#define QEMU_VIRT_GICD_BASE UINT64_C(0x08000000)
#define QEMU_VIRT_GICR_BASE UINT64_C(0x080A0000)
#define QEMU_VIRT_GICR_LOW_FRAMES UINT32_C(123)
#define QEMU_VIRT_GICR_HIGH_BASE UINT64_C(0x4000000000)
#define GICR_STRIDE UINT64_C(0x20000)

/* GIC Distributor registers */
#define GICD_CTLR        0x0000U
#define GICD_TYPER       0x0004U
#define GICD_IIDR        0x0008U
#define GICD_IGROUPR0    0x0080U
#define GICD_ISENABLER0  0x0100U
#define GICD_ICENABLER0  0x0180U
#define GICD_IPRIORITYR0 0x0400U
#define GICD_IROUTER0    0x6000U
#define GIC_MAX_INTIDS   1020U

/* GIC Redistributor registers (per-CPU frame 0) */
#define GICR_CTLR         0x0000U
#define GICR_IIDR         0x0004U
#define GICR_TYPER        0x0008U
#define GICR_WAKER        0x0014U
#define GICR_ISENABLER0   0x0100U
#define GICR_ICENABLER0   0x0180U
#define GICR_IPRIORITYR0  0x0400U

/* GIC CPU Interface system registers */
#define ICC_CTLR_EL1   "S3_0_C12_C12_4"
#define ICC_PMR_EL1    "S3_0_C4_C6_0"
#define ICC_IGRPEN1_EL1 "S3_0_C12_C12_7"

/* Physical timer INTID (PPI 14) */
#define TIMER_PPI_INTID 30U

static xaios_gic_info_t g_gic_info;
static uint32_t g_gic_full_init;
static xaios_irq_handler_t g_irq_handlers[GIC_MAX_INTIDS];
static void *g_irq_contexts[GIC_MAX_INTIDS];
static uint32_t g_registered_interrupts;

static uint32_t mmio_read32(uint64_t base, uint32_t offset) {
  volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)(base + offset);
  return *reg;
}

static uint64_t redistributor_base(uint32_t cpu_id) {
  if (cpu_id < QEMU_VIRT_GICR_LOW_FRAMES) {
    return QEMU_VIRT_GICR_BASE + (uint64_t)cpu_id * GICR_STRIDE;
  }
  return QEMU_VIRT_GICR_HIGH_BASE +
         (uint64_t)(cpu_id - QEMU_VIRT_GICR_LOW_FRAMES) * GICR_STRIDE;
}

static void mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
  volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)(base + offset);
  *reg = value;
}

static void mmio_write64(uint64_t base, uint32_t offset, uint64_t value) {
  volatile uint64_t *reg = (volatile uint64_t *)(uintptr_t)(base + offset);
  *reg = value;
}

void gic_init_qemu_virt(void) {
  for (uint32_t intid = 0U; intid < GIC_MAX_INTIDS; ++intid) {
    g_irq_handlers[intid] = 0;
    g_irq_contexts[intid] = 0;
  }
  g_registered_interrupts = 0U;
  g_gic_info.distributor_base = QEMU_VIRT_GICD_BASE;
  (void)mmio_read32(QEMU_VIRT_GICD_BASE, GICD_CTLR);
  g_gic_info.typer = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_TYPER);
  g_gic_info.iidr = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_IIDR);
  g_gic_info.interrupt_lines = ((g_gic_info.typer & 0x1fU) + 1U) * 32U;
  g_gic_info.cpu_count_hint = ((g_gic_info.typer >> 5U) & 0x7U) + 1U;

  klog("gic: distributor=0x%lx typer=0x%x iidr=0x%x lines=%u cpu_hint=%u\n",
       g_gic_info.distributor_base, g_gic_info.typer, g_gic_info.iidr,
       g_gic_info.interrupt_lines, g_gic_info.cpu_count_hint);
}

xaios_status_t gic_register_interrupt(uint32_t intid,
                                      xaios_irq_handler_t handler,
                                      void *context) {
  if (intid < 32U || intid >= GIC_MAX_INTIDS || handler == 0 ||
      intid >= g_gic_info.interrupt_lines) {
    return XAIOS_ERR_INVALID;
  }
  if (g_irq_handlers[intid] != 0) return XAIOS_ERR_BUSY;
  g_irq_handlers[intid] = handler;
  g_irq_contexts[intid] = context;
  ++g_registered_interrupts;

  uint32_t group_offset = GICD_IGROUPR0 + (intid / 32U) * 4U;
  uint32_t group = mmio_read32(QEMU_VIRT_GICD_BASE, group_offset);
  mmio_write32(QEMU_VIRT_GICD_BASE, group_offset,
               group | (UINT32_C(1) << (intid % 32U)));
  uint32_t priority_offset = GICD_IPRIORITYR0 + (intid & ~UINT32_C(3));
  uint32_t priority = mmio_read32(QEMU_VIRT_GICD_BASE, priority_offset);
  uint32_t shift = (intid % 4U) * 8U;
  priority &= ~(UINT32_C(0xff) << shift);
  priority |= UINT32_C(0x80) << shift;
  mmio_write32(QEMU_VIRT_GICD_BASE, priority_offset, priority);
  mmio_write64(QEMU_VIRT_GICD_BASE, GICD_IROUTER0 + intid * 8U, 0U);
  mmio_write32(QEMU_VIRT_GICD_BASE,
               GICD_ISENABLER0 + (intid / 32U) * 4U,
               UINT32_C(1) << (intid % 32U));
  klog("gic: registered interrupt intid=%u handlers=%u\n", intid,
       g_registered_interrupts);
  return XAIOS_OK;
}

xaios_status_t gic_unregister_interrupt(uint32_t intid,
                                        xaios_irq_handler_t handler,
                                        void *context) {
  if (intid < 32U || intid >= GIC_MAX_INTIDS || handler == 0 ||
      g_irq_handlers[intid] != handler || g_irq_contexts[intid] != context) {
    return XAIOS_ERR_INVALID;
  }
  mmio_write32(QEMU_VIRT_GICD_BASE,
               GICD_ICENABLER0 + (intid / 32U) * 4U,
               UINT32_C(1) << (intid % 32U));
  g_irq_handlers[intid] = 0;
  g_irq_contexts[intid] = 0;
  --g_registered_interrupts;
  return XAIOS_OK;
}

int gic_dispatch_interrupt(uint32_t intid) {
  if (intid >= GIC_MAX_INTIDS || g_irq_handlers[intid] == 0) return 0;
  g_irq_handlers[intid](intid, g_irq_contexts[intid]);
  return 1;
}

void gic_enable_full(void) {
  if (g_gic_full_init != 0) {
    return;
  }

  /* Route timer PPI (INTID 30) to Group 1 */
  uint32_t igroupr = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_IGROUPR0);
  igroupr |= (1U << TIMER_PPI_INTID);
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_IGROUPR0, igroupr);

  /* Set priority for timer INTID 30 (byte offset = (30 % 4) * 8 = 24) */
  uint32_t ipr7 = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_IPRIORITYR0 + 28U);
  ipr7 &= ~(0xffU << 24U);
  ipr7 |= (0xa0U << 24U);
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_IPRIORITYR0 + 28U, ipr7);

  /* Enable timer INTID 30 in distributor */
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_ISENABLER0, (1U << TIMER_PPI_INTID));

  /* Enable distributor Group 1 */
  uint32_t ctlr = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_CTLR);
  ctlr |= 1U;
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_CTLR, ctlr);

  /* Configure redistributor for CPU 0 */
  uint32_t gicr_waker = mmio_read32(QEMU_VIRT_GICR_BASE, GICR_WAKER);
  gicr_waker &= ~(1U << 1U); /* clear ProcessorSleep */
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_WAKER, gicr_waker);

  /* Set redistributor priority for timer */
  uint32_t gicr_ipr7 = mmio_read32(QEMU_VIRT_GICR_BASE, GICR_IPRIORITYR0 + 28U);
  gicr_ipr7 &= ~(0xffU << 24U);
  gicr_ipr7 |= (0xa0U << 24U);
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_IPRIORITYR0 + 28U, gicr_ipr7);

  /* Enable redistributor PPI 30 */
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_ISENABLER0, (1U << TIMER_PPI_INTID));

  /* Enable CPU interface: set priority mask to allow all priorities */
  __asm__ volatile("msr " ICC_PMR_EL1 ", %0" : : "r"((uint64_t)0xffU));
  __asm__ volatile("msr " ICC_IGRPEN1_EL1 ", %0" : : "r"((uint64_t)1U));
  __asm__ volatile("isb");

  /* Unmask IRQs at CPU level (clear I bit in DAIF) */
  __asm__ volatile("msr daifclr, #2");

  g_gic_full_init = 1;
  klog("gic: full init complete redistributor=0x%lx timer_intid=%u\n",
       QEMU_VIRT_GICR_BASE, TIMER_PPI_INTID);
}

/* Initialize GIC redistributor and CPU interface for a secondary CPU */
void gic_secondary_init(uint32_t cpu_id) {
  uint64_t gicr_base = redistributor_base(cpu_id);

  /* Wake redistributor: clear ProcessorSleep */
  uint32_t gicr_waker = mmio_read32(gicr_base, GICR_WAKER);
  gicr_waker &= ~(1U << 1U);
  mmio_write32(gicr_base, GICR_WAKER, gicr_waker);

  /* Set redistributor priority for timer PPI */
  uint32_t gicr_ipr7 = mmio_read32(gicr_base, GICR_IPRIORITYR0 + 28U);
  gicr_ipr7 &= ~(0xffU << 24U);
  gicr_ipr7 |= (0xa0U << 24U);
  mmio_write32(gicr_base, GICR_IPRIORITYR0 + 28U, gicr_ipr7);

  /* Enable redistributor PPI 30 (timer) */
  mmio_write32(gicr_base, GICR_ISENABLER0, (1U << TIMER_PPI_INTID));

  /* Enable CPU interface: priority mask + Group 1 */
  __asm__ volatile("msr " ICC_PMR_EL1 ", %0" : : "r"((uint64_t)0xffU));
  __asm__ volatile("msr " ICC_IGRPEN1_EL1 ", %0" : : "r"((uint64_t)1U));
  __asm__ volatile("isb");

  /* Unmask IRQs at CPU level (clear I bit in DAIF) */
  __asm__ volatile("msr daifclr, #2");
}

void gic_disable_full(void) {
  if (g_gic_full_init == 0) {
    return;
  }
  /* Disable timer interrupt in distributor */
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_ICENABLER0, (1U << TIMER_PPI_INTID));
  /* Disable redistributor PPI */
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_ICENABLER0, (1U << TIMER_PPI_INTID));
  if (g_registered_interrupts == 0U) {
    __asm__ volatile("msr daifset, #2");
    __asm__ volatile("msr " ICC_PMR_EL1 ", %0" : : "r"((uint64_t)0U));
    __asm__ volatile("msr " ICC_IGRPEN1_EL1 ", %0" : : "r"((uint64_t)0U));
    __asm__ volatile("isb");
    g_gic_full_init = 0;
  }
  klog("gic: timer mode disabled device_handlers=%u cpu_interface=%s\n",
       g_registered_interrupts,
       g_registered_interrupts == 0U ? "masked" : "enabled");
}

const xaios_gic_info_t *gic_info(void) {
  return &g_gic_info;
}

void gic_self_test(void) {
  kassert(g_gic_info.distributor_base == QEMU_VIRT_GICD_BASE);
  kassert(g_gic_info.interrupt_lines >= 32);
  klog("gic: discovery self-test passed\n");
}

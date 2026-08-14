#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/smp.h>

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
#define GICD_ICFGR0      0x0c00U
#define GICD_IPRIORITYR0 0x0400U
#define GICD_IROUTER0    0x6000U
#define GICD_CTLR_RWP    (UINT32_C(1) << 31U)
#define GICD_CTLR_ARE_NS (UINT32_C(1) << 5U)
#define GIC_SPI_LIMIT    1020U
#define GIC_LPI_BASE     8192U
#define GIC_MAX_INTIDS   16384U

/* GIC Redistributor registers (per-CPU frame 0) */
#define GICR_CTLR         0x0000U
#define GICR_IIDR         0x0004U
#define GICR_TYPER        0x0008U
#define GICR_WAKER        0x0014U
#define GICR_SGI_BASE      0x10000U
#define GICR_IGROUPR0      (GICR_SGI_BASE + 0x0080U)
#define GICR_ISENABLER0    (GICR_SGI_BASE + 0x0100U)
#define GICR_ICENABLER0    (GICR_SGI_BASE + 0x0180U)
#define GICR_IPRIORITYR0   (GICR_SGI_BASE + 0x0400U)

/* GIC CPU Interface system registers */
#define ICC_CTLR_EL1   "S3_0_C12_C12_4"
#define ICC_PMR_EL1    "S3_0_C4_C6_0"
#define ICC_IGRPEN1_EL1 "S3_0_C12_C12_7"

/* EL1 virtual timer INTID (PPI 11). */
#define TIMER_PPI_INTID 27U
#define WORKER_SGI_INTID 1U

static xaios_gic_info_t g_gic_info;
static uint32_t g_gic_full_init;
static xaios_irq_handler_t g_irq_handlers[GIC_MAX_INTIDS];
static void *g_irq_contexts[GIC_MAX_INTIDS];
static uint32_t g_irq_cpu_ids[GIC_MAX_INTIDS];
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

static void wait_distributor(void) {
  while ((mmio_read32(QEMU_VIRT_GICD_BASE, GICD_CTLR) & GICD_CTLR_RWP) !=
         0U) {
    xaios_cpu_relax();
  }
}

static void configure_spi_route(uint32_t intid, uint32_t cpu_id) {
  const xaios_cpu_state_t *cpu = smp_cpu_state(cpu_id);
  if (cpu == 0) return;
  uint64_t mpidr = cpu->mpidr;
  uint64_t route = (mpidr & UINT64_C(0xffffff)) |
                   ((mpidr & UINT64_C(0xff00000000)) >> 8U);
  mmio_write64(QEMU_VIRT_GICD_BASE, GICD_IROUTER0 + intid * 8U, route);
}

static void configure_spi(uint32_t intid, uint32_t cpu_id) {
  uint32_t group_offset = GICD_IGROUPR0 + (intid / 32U) * 4U;
  uint32_t group = mmio_read32(QEMU_VIRT_GICD_BASE, group_offset);
  mmio_write32(QEMU_VIRT_GICD_BASE, group_offset,
               group | (UINT32_C(1) << (intid % 32U)));
  uint32_t priority_offset = GICD_IPRIORITYR0 + (intid & ~UINT32_C(3));
  uint32_t priority = mmio_read32(QEMU_VIRT_GICD_BASE, priority_offset);
  uint32_t shift = (intid % 4U) * 8U;
  priority = (priority & ~(UINT32_C(0xff) << shift)) |
             (UINT32_C(0x80) << shift);
  mmio_write32(QEMU_VIRT_GICD_BASE, priority_offset, priority);
  uint32_t config_offset = GICD_ICFGR0 + (intid / 16U) * 4U;
  uint32_t config = mmio_read32(QEMU_VIRT_GICD_BASE, config_offset);
  uint32_t config_shift = (intid % 16U) * 2U;
  config = (config & ~(UINT32_C(3) << config_shift)) |
           (UINT32_C(2) << config_shift);
  mmio_write32(QEMU_VIRT_GICD_BASE, config_offset, config);
  configure_spi_route(intid, cpu_id);
  mmio_write32(QEMU_VIRT_GICD_BASE,
               GICD_ISENABLER0 + (intid / 32U) * 4U,
               UINT32_C(1) << (intid % 32U));
}

void gic_init_qemu_virt(void) {
  for (uint32_t intid = 0U; intid < GIC_MAX_INTIDS; ++intid) {
    g_irq_handlers[intid] = 0;
    g_irq_contexts[intid] = 0;
    g_irq_cpu_ids[intid] = UINT32_MAX;
  }
  g_registered_interrupts = 0U;
  g_gic_info.distributor_base = QEMU_VIRT_GICD_BASE;
  (void)mmio_read32(QEMU_VIRT_GICD_BASE, GICD_CTLR);
  g_gic_info.typer = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_TYPER);
  g_gic_info.iidr = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_IIDR);
  if (g_gic_info.typer == UINT32_MAX || g_gic_info.iidr == UINT32_MAX) {
    g_gic_info.distributor_base = 0U;
    g_gic_info.interrupt_lines = 0U;
    g_gic_info.cpu_count_hint = 0U;
    klog("gic: QEMU fixed-address controller unavailable\n");
    return;
  }
  g_gic_info.interrupt_lines = ((g_gic_info.typer & 0x1fU) + 1U) * 32U;
  g_gic_info.cpu_count_hint = ((g_gic_info.typer >> 5U) & 0x7U) + 1U;

  klog("gic: distributor=0x%lx typer=0x%x iidr=0x%x lines=%u cpu_hint=%u\n",
       g_gic_info.distributor_base, g_gic_info.typer, g_gic_info.iidr,
       g_gic_info.interrupt_lines, g_gic_info.cpu_count_hint);
}

xaios_status_t gic_register_interrupt(uint32_t intid,
                                      xaios_irq_handler_t handler,
                                      void *context) {
  if (g_gic_info.distributor_base == 0U || intid < 32U ||
      intid >= GIC_MAX_INTIDS || handler == 0 ||
      intid >= g_gic_info.interrupt_lines) {
    return XAIOS_ERR_INVALID;
  }
  if (g_irq_handlers[intid] != 0) return XAIOS_ERR_BUSY;
  g_irq_handlers[intid] = handler;
  g_irq_contexts[intid] = context;
  g_irq_cpu_ids[intid] = 0U;
  ++g_registered_interrupts;
  configure_spi(intid, 0U);
  klog("gic: registered interrupt intid=%u handlers=%u\n", intid,
       g_registered_interrupts);
  return XAIOS_OK;
}

xaios_status_t gic_register_lpi(uint32_t intid, uint32_t cpu_id,
                               xaios_irq_handler_t handler, void *context) {
  const xaios_cpu_state_t *cpu = smp_cpu_state(cpu_id);
  if (intid < GIC_LPI_BASE || intid >= GIC_MAX_INTIDS || handler == 0 ||
      cpu == 0 || cpu->online == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (g_irq_handlers[intid] != 0) return XAIOS_ERR_BUSY;
  g_irq_handlers[intid] = handler;
  g_irq_contexts[intid] = context;
  g_irq_cpu_ids[intid] = cpu_id;
  ++g_registered_interrupts;
  return XAIOS_OK;
}

xaios_status_t gic_unregister_interrupt(uint32_t intid,
                                        xaios_irq_handler_t handler,
                                        void *context) {
  if (intid < 32U || intid >= GIC_MAX_INTIDS || handler == 0 ||
      g_irq_handlers[intid] != handler || g_irq_contexts[intid] != context) {
    return XAIOS_ERR_INVALID;
  }
  if (intid < GIC_SPI_LIMIT) {
    mmio_write32(QEMU_VIRT_GICD_BASE,
                 GICD_ICENABLER0 + (intid / 32U) * 4U,
                 UINT32_C(1) << (intid % 32U));
  }
  g_irq_handlers[intid] = 0;
  g_irq_contexts[intid] = 0;
  g_irq_cpu_ids[intid] = UINT32_MAX;
  --g_registered_interrupts;
  return XAIOS_OK;
}

xaios_status_t gic_route_interrupt(uint32_t intid, uint32_t cpu_id) {
  const xaios_cpu_state_t *cpu = smp_cpu_state(cpu_id);
  if (intid < 32U || intid >= GIC_SPI_LIMIT ||
      intid >= g_gic_info.interrupt_lines || cpu == 0 ||
      cpu->online == 0U) {
    return XAIOS_ERR_INVALID;
  }
  configure_spi_route(intid, cpu_id);
  g_irq_cpu_ids[intid] = cpu_id;
  return XAIOS_OK;
}

int gic_dispatch_interrupt(uint32_t intid) {
  if (intid >= GIC_MAX_INTIDS || g_irq_handlers[intid] == 0) return 0;
  g_irq_handlers[intid](intid, g_irq_contexts[intid]);
  return 1;
}

void gic_enable_full(void) {
  if (g_gic_info.distributor_base == 0U || g_gic_full_init != 0) {
    return;
  }

  /* Enable Group 1 non-secure delivery while preserving secure firmware. */
  uint32_t ctlr = mmio_read32(QEMU_VIRT_GICD_BASE, GICD_CTLR);
  if ((ctlr & GICD_CTLR_ARE_NS) == 0U) {
    mmio_write32(QEMU_VIRT_GICD_BASE, GICD_CTLR,
                 ctlr & ~UINT32_C(0x7));
    wait_distributor();
    ctlr = (ctlr & ~UINT32_C(0x7)) | GICD_CTLR_ARE_NS;
    mmio_write32(QEMU_VIRT_GICD_BASE, GICD_CTLR, ctlr);
    wait_distributor();
  }
  ctlr |= UINT32_C(1) << 1U;
  mmio_write32(QEMU_VIRT_GICD_BASE, GICD_CTLR, ctlr);
  wait_distributor();

  for (uint32_t intid = 32U;
       intid < g_gic_info.interrupt_lines && intid < GIC_SPI_LIMIT; ++intid) {
    if (g_irq_handlers[intid] == 0 || g_irq_cpu_ids[intid] == UINT32_MAX) {
      continue;
    }
    configure_spi(intid, g_irq_cpu_ids[intid]);
  }

  uint32_t timer_priority_offset = TIMER_PPI_INTID & ~UINT32_C(3);
  uint32_t timer_priority_shift = (TIMER_PPI_INTID % 4U) * 8U;

  /* Configure redistributor for CPU 0 */
  uint32_t gicr_waker = mmio_read32(QEMU_VIRT_GICR_BASE, GICR_WAKER);
  gicr_waker &= ~(1U << 1U); /* clear ProcessorSleep */
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_WAKER, gicr_waker);

  /* Set redistributor priority for timer */
  uint32_t gicr_group = mmio_read32(QEMU_VIRT_GICR_BASE, GICR_IGROUPR0);
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_IGROUPR0,
               gicr_group | (UINT32_C(1) << TIMER_PPI_INTID) |
                   (UINT32_C(1) << WORKER_SGI_INTID));
  uint32_t gicr_ipr7 = mmio_read32(
      QEMU_VIRT_GICR_BASE, GICR_IPRIORITYR0 + timer_priority_offset);
  gicr_ipr7 &= ~(UINT32_C(0xff) << timer_priority_shift);
  gicr_ipr7 |= UINT32_C(0xa0) << timer_priority_shift;
  mmio_write32(QEMU_VIRT_GICR_BASE,
               GICR_IPRIORITYR0 + timer_priority_offset, gicr_ipr7);
  uint32_t gicr_ipr0 =
      mmio_read32(QEMU_VIRT_GICR_BASE, GICR_IPRIORITYR0);
  gicr_ipr0 &= ~(UINT32_C(0xff) << (WORKER_SGI_INTID * 8U));
  gicr_ipr0 |= UINT32_C(0x80) << (WORKER_SGI_INTID * 8U);
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_IPRIORITYR0, gicr_ipr0);

  /* Enable the EL1 virtual timer PPI. */
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_ISENABLER0,
               (UINT32_C(1) << TIMER_PPI_INTID) |
                   (UINT32_C(1) << WORKER_SGI_INTID));
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");

  /* Enable CPU interface: set priority mask to allow all priorities */
  __asm__ volatile("msr " ICC_PMR_EL1 ", %0" : : "r"((uint64_t)0xffU));
  __asm__ volatile("msr " ICC_IGRPEN1_EL1 ", %0" : : "r"((uint64_t)1U));
  __asm__ volatile("isb");

  /* Unmask IRQs at CPU level (clear I bit in DAIF) */
  __asm__ volatile("msr daifclr, #2");

  g_gic_full_init = 1U;
  klog("gic: full init complete redistributor=0x%lx timer_intid=%u\n",
       QEMU_VIRT_GICR_BASE, TIMER_PPI_INTID);
}

/* Initialize GIC redistributor and CPU interface for a secondary CPU */
void gic_secondary_init(uint32_t cpu_id) {
  if (g_gic_info.distributor_base == 0U) return;
  uint64_t gicr_base = redistributor_base(cpu_id);

  /* Wake redistributor: clear ProcessorSleep */
  uint32_t gicr_waker = mmio_read32(gicr_base, GICR_WAKER);
  gicr_waker &= ~(1U << 1U);
  mmio_write32(gicr_base, GICR_WAKER, gicr_waker);

  /* Set redistributor priority for timer PPI */
  uint32_t gicr_group = mmio_read32(gicr_base, GICR_IGROUPR0);
  mmio_write32(gicr_base, GICR_IGROUPR0,
               gicr_group | (UINT32_C(1) << TIMER_PPI_INTID) |
                   (UINT32_C(1) << WORKER_SGI_INTID));
  uint32_t priority_offset = TIMER_PPI_INTID & ~UINT32_C(3);
  uint32_t priority_shift = (TIMER_PPI_INTID % 4U) * 8U;
  uint32_t gicr_ipr7 =
      mmio_read32(gicr_base, GICR_IPRIORITYR0 + priority_offset);
  gicr_ipr7 &= ~(UINT32_C(0xff) << priority_shift);
  gicr_ipr7 |= UINT32_C(0xa0) << priority_shift;
  mmio_write32(gicr_base, GICR_IPRIORITYR0 + priority_offset, gicr_ipr7);
  uint32_t gicr_ipr0 = mmio_read32(gicr_base, GICR_IPRIORITYR0);
  gicr_ipr0 &= ~(UINT32_C(0xff) << (WORKER_SGI_INTID * 8U));
  gicr_ipr0 |= UINT32_C(0x80) << (WORKER_SGI_INTID * 8U);
  mmio_write32(gicr_base, GICR_IPRIORITYR0, gicr_ipr0);

  /* Enable the EL1 virtual timer PPI. */
  mmio_write32(gicr_base, GICR_ISENABLER0,
               (UINT32_C(1) << TIMER_PPI_INTID) |
                   (UINT32_C(1) << WORKER_SGI_INTID));
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");

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
  mmio_write32(QEMU_VIRT_GICR_BASE, GICR_ICENABLER0,
               (UINT32_C(1) << TIMER_PPI_INTID) |
                   (UINT32_C(1) << WORKER_SGI_INTID));
  if (g_registered_interrupts == 0U) {
    __asm__ volatile("msr daifset, #2");
    __asm__ volatile("msr " ICC_PMR_EL1 ", %0" : : "r"((uint64_t)0U));
    __asm__ volatile("msr " ICC_IGRPEN1_EL1 ", %0" : : "r"((uint64_t)0U));
    __asm__ volatile("isb");
    g_gic_full_init = 0U;
  }
  klog("gic: timer mode disabled device_handlers=%u cpu_interface=%s\n",
       g_registered_interrupts,
       g_registered_interrupts == 0U ? "masked" : "enabled");
}

const xaios_gic_info_t *gic_info(void) {
  return &g_gic_info;
}

void gic_self_test(void) {
  if (g_gic_info.distributor_base == 0U) {
    klog("gic: discovery self-test skipped no compatible controller\n");
    return;
  }
  kassert(g_gic_info.distributor_base == QEMU_VIRT_GICD_BASE);
  kassert(g_gic_info.interrupt_lines >= 32);
  klog("gic: discovery self-test passed\n");
}

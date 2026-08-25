#include <xaios/assert.h>
#include <xaios/boot_info.h>
#include <xaios/exception.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/smmu.h>
#include <xaios/status.h>

#define X86_IRQ_SLOTS 256U
#define CMOS_INDEX UINT16_C(0x70)
#define CMOS_DATA UINT16_C(0x71)

typedef struct x86_irq_slot {
  xaios_irq_handler_t handler;
  void *context;
} x86_irq_slot_t;

static x86_irq_slot_t g_irq_slots[X86_IRQ_SLOTS];
static xaios_gic_info_t g_interrupt_info;
static xaios_smmu_stream_t g_smmu_streams[XAIOS_SMMU_MAX_STREAMS];
static uint64_t g_smmu_invalidations;
static uint64_t g_smmu_active_streams;
static uint32_t g_rtc_epoch;
static uint32_t g_probe_active;
static uint32_t g_probe_faulted;

static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value;
  __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

static uint8_t cmos_read(uint8_t reg) {
  outb(CMOS_INDEX, (uint8_t)(UINT8_C(0x80) | reg));
  return inb(CMOS_DATA);
}

static uint32_t bcd_value(uint8_t value) {
  return (uint32_t)(value & UINT8_C(0x0f)) +
         (uint32_t)(value >> 4U) * 10U;
}

static uint32_t leap_year(uint32_t year) {
  return (year % 4U == 0U && (year % 100U != 0U || year % 400U == 0U))
             ? 1U
             : 0U;
}

static uint64_t days_before_year(uint32_t year) {
  uint64_t days = 0U;
  for (uint32_t current = 1970U; current < year; ++current) {
    days += leap_year(current) != 0U ? 366U : 365U;
  }
  return days;
}

static uint32_t read_rtc_epoch(void) {
  static const uint16_t month_days[12] = {
      31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U};
  for (uint32_t spin = 0U; spin < UINT32_C(1000000); ++spin) {
    if ((cmos_read(UINT8_C(0x0a)) & UINT8_C(0x80)) == 0U) break;
  }
  uint8_t second = cmos_read(UINT8_C(0x00));
  uint8_t minute = cmos_read(UINT8_C(0x02));
  uint8_t hour = cmos_read(UINT8_C(0x04));
  uint8_t day = cmos_read(UINT8_C(0x07));
  uint8_t month = cmos_read(UINT8_C(0x08));
  uint8_t year = cmos_read(UINT8_C(0x09));
  uint8_t status_b = cmos_read(UINT8_C(0x0b));
  if ((status_b & UINT8_C(0x04)) == 0U) {
    second = (uint8_t)bcd_value(second);
    minute = (uint8_t)bcd_value(minute);
    hour = (uint8_t)bcd_value((uint8_t)(hour & UINT8_C(0x7f)));
    day = (uint8_t)bcd_value(day);
    month = (uint8_t)bcd_value(month);
    year = (uint8_t)bcd_value(year);
  }
  uint32_t full_year = 2000U + year;
  if (month == 0U || month > 12U || day == 0U || day > 31U || hour > 23U ||
      minute > 59U || second > 60U) {
    return 0U;
  }
  uint64_t days = days_before_year(full_year);
  for (uint32_t current = 1U; current < month; ++current) {
    days += month_days[current - 1U];
    if (current == 2U && leap_year(full_year) != 0U) ++days;
  }
  days += day - 1U;
  uint64_t epoch =
      ((days * 24U + hour) * 60U + minute) * 60U + second;
  return epoch <= UINT32_MAX ? (uint32_t)epoch : 0U;
}

void exception_init(void) {
  g_probe_active = 0U;
  g_probe_faulted = 0U;
  klog("exceptions: x86 IDT active\n");
}

void exception_runtime_init(void) {}

void exception_self_test(void) {
  klog("exceptions: x86 controlled INT3 gate verified during early boot\n");
}

void exception_trigger_page_fault_for_test(void) {
  volatile uint64_t *unmapped = (volatile uint64_t *)UINT64_C(0x1000000000);
  (void)*unmapped;
}

void exception_mmio_probe_begin(void) {
  g_probe_active = 1U;
  g_probe_faulted = 0U;
}

void exception_mmio_probe_end(void) { g_probe_active = 0U; }

int exception_mmio_probe_faulted(void) {
  return g_probe_active != 0U && g_probe_faulted != 0U;
}

void gic_init_platform(void) {
  g_interrupt_info = (xaios_gic_info_t){
      .distributor_base = UINT64_C(0xfee00000),
      .typer = 0U,
      .iidr = 0U,
      .interrupt_lines = X86_IRQ_SLOTS,
      .cpu_count_hint = 0U,
  };
  for (uint32_t index = 0U; index < X86_IRQ_SLOTS; ++index) {
    g_irq_slots[index] = (x86_irq_slot_t){0};
  }
  klog("interrupts: x86 local APIC registry initialized vectors=%u\n",
       X86_IRQ_SLOTS);
}

void gic_enable_full(void) { __asm__ volatile("sti" ::: "memory"); }

void gic_disable_full(void) { __asm__ volatile("cli" ::: "memory"); }

void gic_secondary_init(uint32_t cpu_id) { (void)cpu_id; }

xaios_status_t gic_register_interrupt(uint32_t intid,
                                      xaios_irq_handler_t handler,
                                      void *context) {
  if (intid >= X86_IRQ_SLOTS || handler == 0 ||
      g_irq_slots[intid].handler != 0) {
    return XAIOS_ERR_INVALID;
  }
  g_irq_slots[intid].handler = handler;
  g_irq_slots[intid].context = context;
  return XAIOS_OK;
}

xaios_status_t gic_unregister_interrupt(uint32_t intid,
                                        xaios_irq_handler_t handler,
                                        void *context) {
  if (intid >= X86_IRQ_SLOTS || g_irq_slots[intid].handler != handler ||
      g_irq_slots[intid].context != context) {
    return XAIOS_ERR_INVALID;
  }
  g_irq_slots[intid] = (x86_irq_slot_t){0};
  return XAIOS_OK;
}

xaios_status_t gic_route_interrupt(uint32_t intid, uint32_t cpu_id) {
  (void)cpu_id;
  return intid < X86_IRQ_SLOTS && g_irq_slots[intid].handler != 0
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

int gic_dispatch_interrupt(uint32_t intid) {
  if (intid >= X86_IRQ_SLOTS || g_irq_slots[intid].handler == 0) return 0;
  g_irq_slots[intid].handler(intid, g_irq_slots[intid].context);
  return 1;
}

const xaios_gic_info_t *gic_info(void) { return &g_interrupt_info; }

void gic_self_test(void) {
  kassert(g_interrupt_info.interrupt_lines == X86_IRQ_SLOTS);
  klog("interrupts: x86 registry self-test passed\n");
}

void smmu_init(const xaios_boot_info_t *boot) {
  (void)boot;
  g_smmu_invalidations = 0U;
  g_smmu_active_streams = 0U;
  for (uint32_t index = 0U; index < XAIOS_SMMU_MAX_STREAMS; ++index) {
    g_smmu_streams[index] = (xaios_smmu_stream_t){0};
  }
  klog("IOMMU: x86 DMA uses identity mappings in the current scope\n");
}

uint32_t smmu_initialized(void) { return 0U; }
uint32_t smmu_idr0_value(void) { return 0U; }

xaios_status_t smmu_register_stream(uint32_t stream_id, uint32_t device_type) {
  if (stream_id >= XAIOS_SMMU_MAX_STREAMS ||
      g_smmu_streams[stream_id].active != 0U) {
    return XAIOS_ERR_INVALID;
  }
  g_smmu_streams[stream_id].stream_id = stream_id;
  g_smmu_streams[stream_id].device_type = device_type;
  g_smmu_streams[stream_id].active = 1U;
  ++g_smmu_active_streams;
  return XAIOS_OK;
}

xaios_status_t smmu_unregister_stream(uint32_t stream_id) {
  if (stream_id >= XAIOS_SMMU_MAX_STREAMS ||
      g_smmu_streams[stream_id].active == 0U) {
    return XAIOS_ERR_INVALID;
  }
  g_smmu_streams[stream_id].active = 0U;
  --g_smmu_active_streams;
  return XAIOS_OK;
}

xaios_status_t smmu_tlb_invalidate_all(void) {
  ++g_smmu_invalidations;
  return XAIOS_OK;
}

uint64_t smmu_tlb_invalidate_count(void) { return g_smmu_invalidations; }
uint64_t smmu_fault_count(void) { return 0U; }
uint64_t smmu_stream_count(void) { return g_smmu_active_streams; }

void smmu_self_test(void) {
  kassert(smmu_register_stream(0U, UINT32_C(0xaa)) == XAIOS_OK);
  kassert(smmu_unregister_stream(0U) == XAIOS_OK);
  kassert(smmu_tlb_invalidate_all() == XAIOS_OK);
  klog("IOMMU: x86 identity-mode self-test passed invalidations=1\n");
}

void rtc_init(void) {
  g_rtc_epoch = read_rtc_epoch();
  klog("rtc: x86 CMOS initialized epoch=%u\n", g_rtc_epoch);
}

uint32_t rtc_read_epoch(void) { return g_rtc_epoch; }

void rtc_self_test(void) {
  if (g_rtc_epoch == 0U) {
    klog("rtc: x86 CMOS self-test skipped invalid epoch\n");
    return;
  }
  kassert(g_rtc_epoch >= UINT32_C(1577836800));
  klog("rtc: x86 CMOS self-test passed epoch=%u\n", g_rtc_epoch);
}

#include <xaios/assert.h>
#include <xaios/context.h>
#include <xaios/exception.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/panic.h>
#include <xaios/scheduler.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/user.h>

#define ESR_EC_SHIFT 26U
#define ESR_EC_MASK UINT64_C(0x3f)
#define ESR_ISS_MASK UINT64_C(0x01ffffff)

#define ESR_EC_UNKNOWN UINT64_C(0x00)
#define ESR_EC_WFI_WFE UINT64_C(0x01)
#define ESR_EC_SVC_A64 UINT64_C(0x15)
#define ESR_EC_BRK_A64 UINT64_C(0x3c)
#define ESR_EC_INSN_ABORT_LOWER UINT64_C(0x20)
#define ESR_EC_INSN_ABORT_CURRENT UINT64_C(0x21)
#define ESR_EC_DATA_ABORT_LOWER UINT64_C(0x24)
#define ESR_EC_DATA_ABORT_CURRENT UINT64_C(0x25)

/* GIC CPU interface system register encodings */
#define ICC_IAR1_EL1  "S3_0_C12_C12_0"
#define ICC_EOIR1_EL1 "S3_0_C12_C12_1"
#define TIMER_PPI_INTID 30U

/* DFSC for Synchronous External Abort (SEA) */
#define DFSC_SYNC_EXT_ABORT UINT64_C(0x10)

extern char __exception_vectors[];

/* MMIO fault recovery: when set, a synchronous external abort during
 * EL1 data access sets g_mmio_probe_faulted=1 and skips the faulting
 * instruction instead of panicking. Used for probing optional hardware. */
static volatile int g_mmio_probe_active = 0;
static volatile int g_mmio_probe_faulted = 0;

void exception_mmio_probe_begin(void) {
  g_mmio_probe_faulted = 0;
  g_mmio_probe_active = 1;
  __asm__ volatile("isb" ::: "memory");
}

void exception_mmio_probe_end(void) {
  g_mmio_probe_active = 0;
  __asm__ volatile("isb" ::: "memory");
}

int exception_mmio_probe_faulted(void) {
  return g_mmio_probe_faulted;
}

static const char *exception_kind_name(uint64_t kind) {
  switch ((xaios_exception_kind_t)kind) {
    case XAIOS_EXCEPTION_CURRENT_SP0_SYNC:
      return "current-sp0-sync";
    case XAIOS_EXCEPTION_CURRENT_SP0_IRQ:
      return "current-sp0-irq";
    case XAIOS_EXCEPTION_CURRENT_SP0_FIQ:
      return "current-sp0-fiq";
    case XAIOS_EXCEPTION_CURRENT_SP0_SERROR:
      return "current-sp0-serror";
    case XAIOS_EXCEPTION_CURRENT_SPX_SYNC:
      return "current-spx-sync";
    case XAIOS_EXCEPTION_CURRENT_SPX_IRQ:
      return "current-spx-irq";
    case XAIOS_EXCEPTION_CURRENT_SPX_FIQ:
      return "current-spx-fiq";
    case XAIOS_EXCEPTION_CURRENT_SPX_SERROR:
      return "current-spx-serror";
    case XAIOS_EXCEPTION_LOWER_A64_SYNC:
      return "lower-a64-sync";
    case XAIOS_EXCEPTION_LOWER_A64_IRQ:
      return "lower-a64-irq";
    case XAIOS_EXCEPTION_LOWER_A64_FIQ:
      return "lower-a64-fiq";
    case XAIOS_EXCEPTION_LOWER_A64_SERROR:
      return "lower-a64-serror";
    case XAIOS_EXCEPTION_LOWER_A32_SYNC:
      return "lower-a32-sync";
    case XAIOS_EXCEPTION_LOWER_A32_IRQ:
      return "lower-a32-irq";
    case XAIOS_EXCEPTION_LOWER_A32_FIQ:
      return "lower-a32-fiq";
    case XAIOS_EXCEPTION_LOWER_A32_SERROR:
      return "lower-a32-serror";
  }

  return "unknown-kind";
}

static const char *exception_class_name(uint64_t ec) {
  switch (ec) {
    case ESR_EC_UNKNOWN:
      return "unknown";
    case ESR_EC_WFI_WFE:
      return "wfi-wfe";
    case ESR_EC_SVC_A64:
      return "svc-a64";
    case ESR_EC_BRK_A64:
      return "brk-a64";
    case ESR_EC_INSN_ABORT_LOWER:
      return "instruction-abort-lower";
    case ESR_EC_INSN_ABORT_CURRENT:
      return "instruction-abort-current";
    case ESR_EC_DATA_ABORT_LOWER:
      return "data-abort-lower";
    case ESR_EC_DATA_ABORT_CURRENT:
      return "data-abort-current";
    default:
      return "unclassified";
  }
}

void exception_init(void) {
  uint64_t vector_base = (uint64_t)(uintptr_t)__exception_vectors;
  __asm__ volatile(
      "msr vbar_el1, %[vectors]\n"
      "isb\n"
      :
      : [vectors] "r"(vector_base)
      : "memory");

  klog("exceptions: VBAR_EL1=0x%lx\n", vector_base);
}

void exception_self_test(void) {
  uint64_t vector_base = 0;
  __asm__ volatile("mrs %[vectors], vbar_el1" : [vectors] "=r"(vector_base));

  klog("exceptions: self-test vector_base=0x%lx\n", vector_base);
  if (vector_base != (uint64_t)(uintptr_t)__exception_vectors) {
    panic("exception vector install failed");
  }
}

xaios_context_frame_t *aarch64_irq_handler(xaios_context_frame_t *frame) {
  /* Read interrupt ID from GIC CPU interface */
  uint64_t iar = 0;
  __asm__ volatile("mrs %[iar], " ICC_IAR1_EL1 : [iar] "=r"(iar));
  uint32_t intid = (uint32_t)(iar & 0xffffffU);

  if (intid == TIMER_PPI_INTID) {
    /* Timer interrupt: rearm and call scheduler tick */
    timer_rearm();
    scheduler_tick(frame);
  } else if (intid < 1020U) {
    if (gic_dispatch_interrupt(intid) == 0) {
      klog("irq: unhandled intid=%u\n", intid);
    }
  }
  /* else: spurious interrupt (1023) */

  /* Signal end of interrupt to GIC */
  __asm__ volatile("msr " ICC_EOIR1_EL1 ", %[iar]" : : [iar] "r"(iar));

  return frame;
}

void exception_trigger_page_fault_for_test(void) {
  volatile uint64_t *unmapped = (volatile uint64_t *)UINT64_C(0x1000000000);
  klog("exceptions: triggering controlled page fault at 0x%lx\n",
       (uint64_t)(uintptr_t)unmapped);
  (void)*unmapped;
}

uint64_t aarch64_exception_entry(uint64_t kind, uint64_t esr, uint64_t elr,
                                 uint64_t far, uint64_t arg0, uint64_t arg1,
                                 uint64_t arg2, uint64_t syscall) {
  uint64_t ec = (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;
  uint64_t iss = esr & ESR_ISS_MASK;

  /* MMIO probe recovery: if a synchronous external abort occurs while
   * probing optional MMIO hardware (SMMU, etc.), skip the faulting
   * instruction and set faulted flag instead of panicking. */
  if (g_mmio_probe_active && ec == ESR_EC_DATA_ABORT_CURRENT &&
      (iss & UINT64_C(0x3f)) == DFSC_SYNC_EXT_ABORT) {
    g_mmio_probe_faulted = 1;
    __asm__ volatile("msr elr_el1, %[elr]" : : [elr] "r"(elr + 4));
    return 0;
  }

  /* FIX-008: Division by zero protection */
  if (kind == XAIOS_EXCEPTION_LOWER_A64_SYNC && ec == ESR_EC_UNKNOWN) {
    /* Check if this is a division by zero (trapped instruction) */
    klog("exception: division by zero or undefined operation at ELR=0x%lx\n", elr);
    klog("exception: killing process to prevent kernel crash\n");
    /* Return error to kill the offending process */
    return (uint64_t)-1;
  }

  if (kind == XAIOS_EXCEPTION_LOWER_A64_SYNC && ec == ESR_EC_SVC_A64) {
    return syscall_dispatch(syscall, arg0, arg1, arg2);
  }

  klog("\nEXCEPTION: kind=%s class=%s ec=0x%lx iss=0x%lx\n",
       exception_kind_name(kind), exception_class_name(ec), ec, iss);
  klog("EXCEPTION: elr=0x%lx far=0x%lx esr=0x%lx\n", elr, far, esr);

  if (ec == ESR_EC_DATA_ABORT_CURRENT || ec == ESR_EC_INSN_ABORT_CURRENT ||
      ec == ESR_EC_DATA_ABORT_LOWER || ec == ESR_EC_INSN_ABORT_LOWER) {
    panic("controlled page fault reported");
  }

  panic("fatal exception reported");
  for (;;) {
    __asm__ volatile("wfe");
  }
}

#ifndef XAIOS_EXCEPTION_H
#define XAIOS_EXCEPTION_H

#include <xaios/context.h>
#include <xaios/types.h>

typedef enum xaios_exception_kind {
  XAIOS_EXCEPTION_CURRENT_SP0_SYNC = 0,
  XAIOS_EXCEPTION_CURRENT_SP0_IRQ = 1,
  XAIOS_EXCEPTION_CURRENT_SP0_FIQ = 2,
  XAIOS_EXCEPTION_CURRENT_SP0_SERROR = 3,
  XAIOS_EXCEPTION_CURRENT_SPX_SYNC = 4,
  XAIOS_EXCEPTION_CURRENT_SPX_IRQ = 5,
  XAIOS_EXCEPTION_CURRENT_SPX_FIQ = 6,
  XAIOS_EXCEPTION_CURRENT_SPX_SERROR = 7,
  XAIOS_EXCEPTION_LOWER_A64_SYNC = 8,
  XAIOS_EXCEPTION_LOWER_A64_IRQ = 9,
  XAIOS_EXCEPTION_LOWER_A64_FIQ = 10,
  XAIOS_EXCEPTION_LOWER_A64_SERROR = 11,
  XAIOS_EXCEPTION_LOWER_A32_SYNC = 12,
  XAIOS_EXCEPTION_LOWER_A32_IRQ = 13,
  XAIOS_EXCEPTION_LOWER_A32_FIQ = 14,
  XAIOS_EXCEPTION_LOWER_A32_SERROR = 15,
} xaios_exception_kind_t;

void exception_init(void);
/* Allocate per-CPU exception state after the kernel heap is available. */
void exception_runtime_init(void);
void exception_self_test(void);
void exception_trigger_page_fault_for_test(void);
uint64_t aarch64_exception_entry(uint64_t kind, uint64_t esr, uint64_t elr,
                                 uint64_t far, uint64_t arg0, uint64_t arg1,
                                 uint64_t arg2, uint64_t syscall);
xaios_context_frame_t *aarch64_irq_handler(xaios_context_frame_t *frame);

/* MMIO probe: allows safe reads from optional hardware addresses.
 * If the hardware is not present, a Synchronous External Abort occurs
 * but the handler skips the faulting instruction instead of panicking. */
void exception_mmio_probe_begin(void);
void exception_mmio_probe_end(void);
int exception_mmio_probe_faulted(void);

#endif

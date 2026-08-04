#ifndef XAIOS_CONTEXT_H
#define XAIOS_CONTEXT_H

#include <xaios/types.h>

/* Full AArch64 context frame. General state occupies the first 288 bytes so
 * the established offsets remain stable. SIMD/FP state follows it:
 * q0-q31 (512 bytes), FPCR and FPSR (16 bytes). */
#define XAIOS_CONTEXT_FRAME_SIZE 816U
#define XAIOS_CONTEXT_FRAME_REGS 35U
#define XAIOS_CONTEXT_SIMD_REGS 32U

typedef struct xaios_context_frame {
  uint64_t regs[31]; /* x0-x30 */
  uint64_t sp_el1;   /* kernel stack pointer */
  uint64_t sp_el0;   /* user stack pointer */
  uint64_t elr_el1;  /* return address */
  uint64_t spsr_el1; /* processor state */
  uint64_t padding;
  uint64_t simd[64]; /* q0-q31, two 64-bit words per register */
  uint64_t fpcr;
  uint64_t fpsr;
} xaios_context_frame_t;

/* Save callee-saved registers (x19-x30, x29=fp, x30=lr) and sp to frame.
 * Returns 0 on initial save, 1 when restored via context_switch. */
uint64_t context_save(xaios_context_frame_t *frame);

/* Restore callee-saved registers and sp from frame. Does not return to caller;
 * instead resumes at the saved lr (x30). */
void context_restore(const xaios_context_frame_t *frame);

/* Atomic context switch: save current to *old, load *new_frame.
 * When the old context is later restored, context_save returns 1. */
void context_switch(xaios_context_frame_t *old,
                    const xaios_context_frame_t *new_frame);

/* Waits for a real timer IRQ and verifies that volatile SIMD/FP state survives
 * the exception round trip. The periodic timer and IRQ interface must be on. */
uint64_t aarch64_simd_irq_self_test(void);

#endif

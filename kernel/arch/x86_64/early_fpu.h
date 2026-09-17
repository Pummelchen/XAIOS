#ifndef XAIOS_X86_64_EARLY_FPU_H
#define XAIOS_X86_64_EARLY_FPU_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_fpu.c. Both files include it and nothing in it is
 * visible outside those two translation units.
 *
 * The CR4/XCR0/XSAVE primitives are the one thing the moved extended-state
 * code cannot carry away with it: early.c still programs CR4/XCR0 for the AVX2
 * packed canary in x86_64_kmain and for an AP's own XCR0 in x86_64_ap_entry, so
 * the eight primitives are defined once here -- `static inline`, so each side
 * inlines them and no external symbol is introduced -- and early.c's own
 * definitions were removed rather than duplicated. The XSAVE/XRSTOR control
 * bits move with them, because both the moved validation and early.c's AP
 * entry spell the same masks.
 *
 * The extended-state entry points are functions with external linkage, so only
 * their declarations live here; they are defined exactly once, in
 * early_fpu.c. `x86_64_irq_state_save`/`_restore` keep those exact names
 * because entry.S calls them from the interrupt entry. */

#include <xaios/types.h>

#define X86_CR4_OSXSAVE UINT64_C(1 << 18)
#define X86_CR4_OSFXSR UINT64_C(1 << 9)
#define X86_CR4_OSXMMEXCPT UINT64_C(1 << 10)
#define X86_XCR0_AVX UINT64_C(1 << 2)
#define X86_XCR0_SSE UINT64_C(1 << 1)
#define X86_XCR0_X87 UINT64_C(1)
#define X86_XSTATE_AVX512 UINT64_C(0xe0)
#define X86_XSTATE_AMX UINT64_C(0x60000)

static inline uint64_t read_cr4(void) {
  uint64_t value = 0U;
  __asm__ volatile("mov %%cr4, %0" : "=r"(value));
  return value;
}

static inline void write_cr4(uint64_t value) {
  __asm__ volatile("mov %0, %%cr4" : : "r"(value) : "memory");
}

static inline void write_xcr0(uint64_t value) {
  uint32_t low = (uint32_t)value;
  uint32_t high = (uint32_t)(value >> 32U);
  __asm__ volatile("xsetbv" : : "a"(low), "d"(high), "c"(0U) : "memory");
}

static inline uint64_t read_xcr0(void) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0U));
  return (uint64_t)low | ((uint64_t)high << 32U);
}

static inline void xsave_state(void *area, uint64_t mask) {
  uint32_t low = (uint32_t)mask;
  uint32_t high = (uint32_t)(mask >> 32U);
  __asm__ volatile("xsave64 (%0)" : : "r"(area), "a"(low), "d"(high)
                   : "memory");
}

static inline void xrstor_state(const void *area, uint64_t mask) {
  uint32_t low = (uint32_t)mask;
  uint32_t high = (uint32_t)(mask >> 32U);
  __asm__ volatile("xrstor64 (%0)" : : "r"(area), "a"(low), "d"(high)
                   : "memory");
}

static inline void fxsave_state(void *area) {
  __asm__ volatile("fxsave64 (%0)" : : "r"(area) : "memory");
}

static inline void fxrstor_state(const void *area) {
  __asm__ volatile("fxrstor64 (%0)" : : "r"(area) : "memory");
}

/* Defined in early_fpu.c. */
void x86_64_irq_state_save(void);
void x86_64_irq_state_restore(void);
void xaios_x86_fpu_validate(uint16_t serial_base);
void xaios_x86_fpu_prepare_irq_areas(uint16_t serial_base);
/* The mask XCR0 was programmed with, for a CPU that must program its own (an
 * AP). A scalar, not a pointer into the file-scope state; zero when extended
 * state is absent and only the FXSAVE fallback is in use. */
uint64_t xaios_x86_fpu_enabled_mask(void);

#endif

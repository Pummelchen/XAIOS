/* The x86-64 extended CPU state: enabling and validating XSAVE/XRSTOR against
 * the CPUID leaves, the FXSAVE fallback, and the per-CPU nested areas the
 * interrupt entry saves that state into.
 *
 * Split out of kernel/arch/x86_64/early.c. The body is that block moved
 * verbatim; the only edits are the seam in early_fpu.h -- the CR4/XCR0/XSAVE
 * primitives both files inline -- the early_module.h seam that hands this file
 * early.c's CPU table and primitives, and the macro block below that keeps the
 * moved code's short names resolving to the exported ones.
 *
 * This runs at one well-defined point in x86_64_kmain: `xaios_x86_fpu_validate`
 * and `xaios_x86_fpu_prepare_irq_areas`, after the page tables are installed
 * and the ACPI CPU records exist, and before any AP is started. An AP reads the
 * XCR0 mask through `xaios_x86_fpu_enabled_mask` from its own entry, but the
 * mask is settled before the INIT-SIPI-SIPI sequence begins, so nothing here
 * reorders the AP bring-up. */

#include "early_fpu.h"
#include "early_module.h"
#include "platform.h"

#define X86_FPU_COM1_PORT UINT16_C(0x3f8)

/* The moved body names these the way early.c did; each expands to the
 * primitive early.c exports through early_module.h. `validate_xsave` and
 * `prepare_irq_state_areas` are renamed to their exported names. */
#define COM1_PORT X86_FPU_COM1_PORT
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt
#define cpuid xaios_x86_early_cpuid
#define early_alloc xaios_x86_mem_alloc
#define validate_xsave xaios_x86_fpu_validate
#define prepare_irq_state_areas xaios_x86_fpu_prepare_irq_areas

/* early.c's CPU table, read once per call rather than through the old
 * file-scope names. */
static x86_64_cpu_record_t *cpu_records(void) {
  return xaios_x86_early_cpu_records();
}

static uint32_t cpu_record_count(void) {
  return xaios_x86_early_cpu_record_count();
}

/* The canary areas the validation round-trips, the mask XCR0 was programmed
 * with, and the size of one saved area. The FXSAVE fallback leaves the mask
 * zero and the area 512 bytes. Only this file reads the size; early.c's AP
 * entry reads the mask through xaios_x86_fpu_enabled_mask. */
static uint8_t g_xsave_original[UINT32_C(65536)] __attribute__((aligned(64)));
static uint8_t g_xsave_test[UINT32_C(65536)] __attribute__((aligned(64)));
static uint64_t g_xsave_enabled;
static uint32_t g_xsave_area_size;

uint64_t xaios_x86_fpu_enabled_mask(void) { return g_xsave_enabled; }

static uint8_t *current_irq_state_area(void) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count || g_xsave_area_size == 0U ||
      g_cpu_records[ordinal].irq_state_area == 0) {
    return 0;
  }
  uint32_t depth = g_cpu_records[ordinal].user_nesting_depth;
  uint32_t slot = depth == 0U ? 0U : depth - 1U;
  if (slot >= X86_USER_NESTING_MAX) {
    panic_halt(COM1_PORT, "IRQ state nesting");
  }
  return g_cpu_records[ordinal].irq_state_area +
         (uint64_t)slot * g_xsave_area_size;
}

void x86_64_irq_state_save(void) {
  uint8_t *area = current_irq_state_area();
  if (area == 0) return;
  if (g_xsave_enabled != 0U) {
    xsave_state(area, g_xsave_enabled);
  } else {
    fxsave_state(area);
  }
}

void x86_64_irq_state_restore(void) {
  uint8_t *area = current_irq_state_area();
  if (area == 0) return;
  if (g_xsave_enabled != 0U) {
    xrstor_state(area, g_xsave_enabled);
  } else {
    fxrstor_state(area);
  }
}

void validate_xsave(uint16_t serial_base) {
  uint32_t eax = 0U;
  uint32_t ebx = 0U;
  uint32_t ecx = 0U;
  uint32_t edx = 0U;
  cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
  if ((ecx & (UINT32_C(1) << 26U)) == 0U) {
    if ((edx & (UINT32_C(1) << 24U)) == 0U) {
      panic_halt(serial_base, "extended state unavailable");
    }
    write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
    fxsave_state(g_xsave_original);
    fxsave_state(g_xsave_test);
    fxrstor_state(g_xsave_test);
    fxrstor_state(g_xsave_original);
    g_xsave_enabled = 0U;
    g_xsave_area_size = UINT32_C(512);
    serial_puts(serial_base,
                "x86_64: FXSAVE/FXRSTOR fallback canary passed bytes=512\n");
    return;
  }
  uint32_t avx_supported = ecx & (UINT32_C(1) << 28U);
  write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT |
            X86_CR4_OSXSAVE);
  cpuid(0x0dU, 0U, &eax, &ebx, &ecx, &edx);
  uint64_t supported = (uint64_t)eax | ((uint64_t)edx << 32U);
  uint64_t enabled = X86_XCR0_X87 | X86_XCR0_SSE;
  if ((supported & X86_XCR0_AVX) != 0U &&
      avx_supported != 0U) {
    enabled |= X86_XCR0_AVX;
  }
  if ((enabled & X86_XCR0_AVX) != 0U &&
      (supported & X86_XSTATE_AVX512) == X86_XSTATE_AVX512) {
    enabled |= X86_XSTATE_AVX512;
  }
  if ((supported & X86_XSTATE_AMX) == X86_XSTATE_AMX) {
    enabled |= X86_XSTATE_AMX;
  }
  write_xcr0(enabled);
  g_xsave_enabled = enabled;
  cpuid(0x0dU, 0U, &eax, &ebx, &ecx, &edx);
  if (ebx == 0U || ebx > sizeof(g_xsave_original) || read_xcr0() != enabled) {
    panic_halt(serial_base, "XSAVE area sizing failed");
  }
  g_xsave_area_size = ebx;
  xsave_state(g_xsave_original, enabled);
  xsave_state(g_xsave_test, enabled);
  xrstor_state(g_xsave_test, enabled);
  xrstor_state(g_xsave_original, enabled);
  serial_puts(serial_base, "x86_64: XSAVE/XRSTOR canary passed bytes=");
  serial_dec(serial_base, ebx);
  serial_puts(serial_base, " enabled=");
  serial_hex64(serial_base, enabled);
  serial_puts(serial_base, " avx512_supported=");
  serial_dec(serial_base,
             (supported & X86_XSTATE_AVX512) == X86_XSTATE_AVX512);
  serial_puts(serial_base, " avx512_preserved=");
  serial_dec(serial_base,
             (enabled & X86_XSTATE_AVX512) == X86_XSTATE_AVX512);
  serial_puts(serial_base, " amx_supported=");
  serial_dec(serial_base, (supported & X86_XSTATE_AMX) == X86_XSTATE_AMX);
  serial_puts(serial_base, " amx_preserved=");
  serial_dec(serial_base, (enabled & X86_XSTATE_AMX) == X86_XSTATE_AMX);
  serial_puts(serial_base, "\n");
}

void prepare_irq_state_areas(uint16_t serial_base) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  if (g_xsave_area_size == 0U ||
      g_xsave_area_size > UINT32_C(65536)) {
    panic_halt(serial_base, "IRQ state area size");
  }
  uint64_t bytes =
      (uint64_t)g_xsave_area_size * X86_USER_NESTING_MAX;
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    g_cpu_records[ordinal].irq_state_area =
        (uint8_t *)early_alloc(bytes, UINT64_C(64));
    if (g_cpu_records[ordinal].irq_state_area == 0) {
      panic_halt(serial_base, "IRQ state allocation");
    }
    for (uint64_t offset = 0U; offset < bytes; ++offset) {
      g_cpu_records[ordinal].irq_state_area[offset] = 0U;
    }
  }
  serial_puts(serial_base, "x86_64: per-CPU nested IRQ state areas ready bytes=");
  serial_dec(serial_base, bytes);
  serial_puts(serial_base, " cpus=");
  serial_dec(serial_base, g_cpu_record_count);
  serial_puts(serial_base, "\n");
}

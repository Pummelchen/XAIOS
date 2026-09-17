/* The x86-64 platform/idle service layer: every hook platform.h declares that
 * the generic kernel calls on this architecture, plus the idle-halt probe the
 * B-120 wakeup self-test sets and the CPU-record reads those hooks need.
 *
 * Split out of kernel/arch/x86_64/early.c. Nothing here is reached by the boot
 * sequence before the handoff: the first callers are the common kernel and the
 * idle path it starts, all of which run after x86_64_kmain has returned from
 * start_application_processors(), so no INIT-SIPI-SIPI, AP-trampoline or IDT
 * ordering is touched. The moved body is early.c's block verbatim; the seam is
 * early_module.h, which hands this file early.c's CPU table and the scalars it
 * reads, and the macros below keep the moved code's short names resolving to
 * the exported ones.
 *
 * early.c still owns the CPU record table, the TSC and LAPIC frequencies, the
 * APIC-ready flag and the worker-release flag. Every one of those crosses as a
 * value through early_module.h, never as a pointer into early.c's storage; the
 * CPU record pointer is the address early.c already publishes there. */

#include "early_module.h"
#include "platform.h"

/* The APIC register offsets the timer hooks below write. They are the same
 * architectural constants early.c's copy uses; early_irq.c already carries its
 * own APIC_EOI for the same reason. */
#define APIC_EOI UINT32_C(0x0b0)
#define APIC_LVT_TIMER UINT32_C(0x320)
#define APIC_TIMER_INITIAL UINT32_C(0x380)
#define APIC_TIMER_DIVIDE UINT32_C(0x3e0)

#define COM1_PORT UINT16_C(0x3f8)

/* The moved body names this the way early.c did; it expands to the primitive
 * early_serial.c exports through early_module.h. */
#define panic_halt xaios_x86_early_panic_halt

/* The idle-wakeup self-test's probe pair. early.c's idle loop reads them
 * through xaios_x86_early_idle_probe_get below, and
 * x86_64_platform_set_idle_halt_probe is the only writer. Zero in production. */
static volatile uint64_t g_idle_halt_probe_gap_cycles;
static volatile uint32_t g_idle_halt_probe_legacy;

uint64_t x86_64_platform_tsc(void) { return xaios_x86_early_rdtsc(); }

uint64_t x86_64_platform_tsc_hz(void) {
  return xaios_x86_early_tsc_hz();
}

void x86_64_platform_set_tsc_hz(uint64_t frequency) {
  xaios_x86_early_set_tsc_hz(frequency);
}

uint64_t x86_64_platform_lapic_hz(void) {
  return xaios_x86_early_lapic_hz();
}

uint32_t x86_64_platform_cpu_count(void) {
  return xaios_x86_early_cpu_record_count();
}

uint32_t x86_64_platform_cpu_apic_id(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  return ordinal < cpu_count ? cpu_table[ordinal].apic_id
                                      : UINT32_MAX;
}

uint32_t x86_64_platform_cpu_online(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  return ordinal < cpu_count
             ? __atomic_load_n(&cpu_table[ordinal].online,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

/* What this CPU is waiting for, published where another CPU can read it. The
 * reader of this note is the TLB shootdown's refusal, which until now could
 * name only the CPU that had not acknowledged: "cpu 1 is silent" is a question
 * and this is the half that answers it (B-123). */
void xaios_cpu_note_wait(const char *reason) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  if (cpu_table == 0) return;
  uint32_t ordinal = xaios_x86_early_current_ordinal_fast();
  if (ordinal < cpu_count) {
    __atomic_store_n(&cpu_table[ordinal].state.waiting_for, reason,
                     __ATOMIC_RELEASE);
  }
}

uint32_t x86_64_platform_workers_ready(void) {
  uint32_t bsp_ordinal = xaios_x86_early_bsp_ordinal();
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t ready = bsp_ordinal < cpu_count ? 1U : 0U;
  for (uint32_t ordinal = 0U; ordinal < cpu_count; ++ordinal) {
    if (ordinal == bsp_ordinal ||
        __atomic_load_n(&cpu_table[ordinal].online, __ATOMIC_ACQUIRE) ==
            0U) {
      continue;
    }
    if (__atomic_load_n(&cpu_table[ordinal].worker_ready,
                        __ATOMIC_ACQUIRE) != 0U) {
      ++ready;
    }
  }
  return ready;
}

struct xaios_cpu_state *x86_64_platform_cpu_state(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  return ordinal < cpu_count ? &cpu_table[ordinal].state : 0;
}

void x86_64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  if (ordinal >= cpu_count) return;
  cpu_table[ordinal].page_table_root = root;
  cpu_table[ordinal].user_page_directory = user_directory;
}

uint64_t *x86_64_platform_page_table_root(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  return ordinal < cpu_count
             ? cpu_table[ordinal].page_table_root
             : 0;
}

uint64_t *x86_64_platform_user_page_directory(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  return ordinal < cpu_count
             ? cpu_table[ordinal].user_page_directory
             : 0;
}

uint32_t x86_64_platform_current_ordinal(void) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t id = xaios_x86_early_lapic_id();
  for (uint32_t ordinal = 0U; ordinal < cpu_count; ++ordinal) {
    if (cpu_table[ordinal].apic_id == id) return ordinal;
  }
  return UINT32_MAX;
}

void x86_64_platform_wake(uint32_t ordinal) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  if (ordinal < cpu_count && cpu_table[ordinal].online != 0U) {
    xaios_x86_early_lapic_send(cpu_table[ordinal].apic_id, 33U);
  }
}

void x86_64_platform_release_workers(void) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  xaios_x86_early_set_worker_release(1U);
  for (uint32_t ordinal = 0U; ordinal < cpu_count; ++ordinal) {
    if (ordinal != x86_64_platform_current_ordinal()) {
      x86_64_platform_wake(ordinal);
    }
  }
}

uint64_t x86_64_platform_bootstrap_start(void) {
  return xaios_x86_mem_bootstrap_start();
}

uint64_t x86_64_platform_bootstrap_end(void) {
  return xaios_x86_mem_bootstrap_end();
}

void x86_64_platform_timer_start(uint32_t initial_count, uint32_t periodic) {
  if (xaios_x86_early_lapic_ready() == 0U) return;
  xaios_x86_early_lapic_write(APIC_LVT_TIMER,
              32U | (periodic != 0U ? UINT32_C(1 << 17) : 0U));
  xaios_x86_early_lapic_write(APIC_TIMER_DIVIDE, UINT32_C(0x0b));
  xaios_x86_early_lapic_write(APIC_TIMER_INITIAL, initial_count);
}

void x86_64_platform_timer_stop(void) {
  if (xaios_x86_early_lapic_ready() != 0U) {
    xaios_x86_early_lapic_write(APIC_LVT_TIMER, UINT32_C(1 << 16) | 32U);
    xaios_x86_early_lapic_write(APIC_TIMER_INITIAL, 0U);
  }
}

uint64_t x86_64_platform_timer_interrupts(void) {
  return g_x86_lapic_timer_interrupts;
}

void x86_64_platform_eoi(void) {
  if (xaios_x86_early_lapic_ready() != 0U) xaios_x86_early_lapic_write(APIC_EOI, 0U);
}

void x86_64_platform_set_idle_halt_probe(uint64_t gap_cycles, uint32_t legacy) {
  __atomic_store_n(&g_idle_halt_probe_legacy, legacy != 0U ? 1U : 0U,
                   __ATOMIC_RELEASE);
  __atomic_store_n(&g_idle_halt_probe_gap_cycles, gap_cycles,
                   __ATOMIC_RELEASE);
}

void xaios_x86_early_idle_probe_get(x86_64_idle_probe_state_t *state) {
  if (state == 0) return;
  state->legacy =
      __atomic_load_n(&g_idle_halt_probe_legacy, __ATOMIC_ACQUIRE);
  state->gap_cycles =
      __atomic_load_n(&g_idle_halt_probe_gap_cycles, __ATOMIC_ACQUIRE);
}

void x86_64_platform_set_user_resume(uint64_t stack) {
  uint32_t bsp_ordinal = xaios_x86_early_bsp_ordinal();
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= cpu_count) panic_halt(COM1_PORT, "user CPU ordinal");
  x86_64_cpu_record_t *record = &cpu_table[ordinal];
  uint32_t depth = record->user_nesting_depth;
  if (depth >= X86_USER_NESTING_MAX) {
    panic_halt(COM1_PORT, "user nesting depth");
  }
  /* The BSP's TSS lives in early_gdt.c now, so its rsp0 is read and written
   * through the scalar accessors rather than a pointer into that state. The
   * two stores and the increment keep the order they had before the split. */
  int bsp = ordinal == bsp_ordinal;
  record->user_resume_rsp[depth] = stack;
  record->user_previous_rsp0[depth] =
      bsp ? xaios_x86_gdt_bsp_rsp0() : record->tss.rsp0;
  ++record->user_nesting_depth;

  uint64_t syscall_stack_low =
      record->syscall_stack_top - X86_KERNEL_STACK_SIZE;
  if (stack > syscall_stack_low && stack < record->syscall_stack_top) {
    uint64_t rsp0 = stack & ~UINT64_C(0xf);
    if (bsp) {
      xaios_x86_gdt_set_bsp_rsp0(rsp0);
    } else {
      record->tss.rsp0 = rsp0;
    }
  }
}

uint64_t x86_64_platform_user_resume(void) {
  uint32_t bsp_ordinal = xaios_x86_early_bsp_ordinal();
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= cpu_count) {
    panic_halt(COM1_PORT, "user resume stack");
  }
  x86_64_cpu_record_t *record = &cpu_table[ordinal];
  uint32_t depth = record->user_nesting_depth;
  if (depth == 0U || record->user_resume_rsp[depth - 1U] == 0U) {
    panic_halt(COM1_PORT, "user resume stack");
  }
  --depth;
  uint64_t stack = record->user_resume_rsp[depth];
  if (ordinal == bsp_ordinal) {
    xaios_x86_gdt_set_bsp_rsp0(record->user_previous_rsp0[depth]);
  } else {
    record->tss.rsp0 = record->user_previous_rsp0[depth];
  }
  record->user_resume_rsp[depth] = 0U;
  record->user_previous_rsp0[depth] = 0U;
  record->user_nesting_depth = depth;
  return stack;
}

void x86_64_platform_set_user_return(uint64_t value) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= cpu_count) panic_halt(COM1_PORT, "user return CPU");
  cpu_table[ordinal].user_return_value = value;
}

uint64_t x86_64_platform_user_return(void) {
  uint32_t cpu_count = xaios_x86_early_cpu_record_count();
  x86_64_cpu_record_t *cpu_table = xaios_x86_early_cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= cpu_count) panic_halt(COM1_PORT, "user result CPU");
  return cpu_table[ordinal].user_return_value;
}

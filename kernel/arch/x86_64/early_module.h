#ifndef XAIOS_X86_64_EARLY_MODULE_H
#define XAIOS_X86_64_EARLY_MODULE_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_tlb.c. Both files include this header and nothing
 * in it is visible outside those two translation units: the x86_64 CPU record,
 * the per-CPU TLB bookkeeping, and the handful of early.c primitives the
 * shootdown needs are shared here, while the globals stay file-scope in
 * whichever file owns them. Declarations and type definitions only -- the
 * functions are defined exactly once, in early.c or early_tlb.c. */

#include <xaios/smp.h>
#include <xaios/types.h>

/* Same nesting bound early.c uses for the per-CPU user-resume stacks; the CPU
 * record's arrays are sized by it. */
#define X86_USER_NESTING_MAX UINT32_C(8)

typedef struct x86_64_tss {
  uint32_t reserved0;
  uint64_t rsp0;
  uint64_t rsp1;
  uint64_t rsp2;
  uint64_t reserved1;
  uint64_t ist[7];
  uint64_t reserved2;
  uint16_t reserved3;
  uint16_t io_map_base;
} __attribute__((packed)) x86_64_tss_t;

typedef struct x86_64_cpu_record {
  uint32_t apic_id;
  volatile uint32_t online;
  volatile uint32_t worker_ready;
  volatile uint32_t requested_generation;
  volatile uint32_t completed_generation;
  volatile uint64_t checksum;
  volatile uint32_t tlb_generation;
  /* What this CPU was doing when somebody asked it for a TLB shootdown, so a
   * refusal can say why it did not answer (B-123). `interrupts_taken` is a
   * liveness count: a CPU that keeps taking timer interrupts is running with
   * interrupts enabled and simply did not receive or handle the request, while
   * one whose count is frozen is not taking interrupts at all. */
  volatile uint64_t interrupts_taken;
  volatile uint32_t last_vector;
  volatile uint64_t shootdowns_handled;
  volatile uint64_t shootdowns_polled;
  volatile uint32_t shootdown_lock_wait;
  /* How many times this CPU reached its halt with a thread pending for it
   * anyway, which is a wakeup that arrived between the idle loop's check and
   * its halt and was consumed by its handler (B-120). Zero after the fix
   * except when it counts one the re-check caught. */
  volatile uint32_t idle_wakeups_raced;
  /* How many times this CPU entered the self-test's widened window, which is
   * how the test knows the wakeup it sends is inside it. */
  volatile uint32_t idle_gap_rounds;
  uint64_t kernel_stack_top;
  uint64_t syscall_stack_top;
  uint64_t user_resume_rsp[X86_USER_NESTING_MAX];
  uint64_t user_previous_rsp0[X86_USER_NESTING_MAX];
  uint32_t user_nesting_depth;
  uint64_t user_return_value;
  uint8_t *irq_state_area;
  uint64_t *page_table_root;
  uint64_t *user_page_directory;
  uint64_t gdt[7];
  x86_64_tss_t tss;
  xaios_cpu_state_t state;
} x86_64_cpu_record_t;

/* Shared read of early.c's CPU table. early.c keeps owning the storage and the
 * pointer; this hands the TLB half the same address it used to reach through
 * the old file-scope names. */
x86_64_cpu_record_t *xaios_x86_early_cpu_records(void);
uint32_t xaios_x86_early_cpu_record_count(void);

/* early.c primitives the shootdown calls but does not own. */
void xaios_x86_early_lapic_send(uint32_t destination, uint32_t command);
uint32_t xaios_x86_early_current_ordinal_fast(void);
void xaios_x86_early_serial_puts(uint16_t base, const char *message);
void xaios_x86_early_serial_dec(uint16_t base, uint64_t value);
void xaios_x86_early_panic_halt(uint16_t serial_base, const char *message);

/* The idle-loop probe globals stay in early.c, which also reads them on the
 * idle path; the self-test's getters live with the rest of the shootdown, so
 * this is the whole of that knob across the seam. */
typedef struct x86_64_idle_probe_state {
  uint64_t gap_cycles;
  uint32_t legacy;
} x86_64_idle_probe_state_t;

void xaios_x86_early_idle_probe_get(x86_64_idle_probe_state_t *state);

/* Defined in early_tlb.c. */
void xaios_x86_early_tlb_note_interrupt(void);
void xaios_x86_early_tlb_acknowledge(x86_64_cpu_record_t *record,
                                     uint32_t generation);

/* The CPU-topology report in early_cpu.c needs two more early.c primitives
 * than the shootdown does; appended here rather than given a second header, so
 * all three early files share one seam. */
void xaios_x86_early_serial_hex64(uint16_t base, uint64_t value);
void xaios_x86_early_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                           uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

/* Defined in early_cpu.c. */
void x86_64_early_cpu_build_placement_policy(uint16_t serial_base);

#endif

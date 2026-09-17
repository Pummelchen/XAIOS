/* The x86-64 TLB shootdown: publishing a page invalidation, waiting for every
 * other online CPU to acknowledge it, answering a request an interrupt cannot
 * carry (B-123), the self-test's probe, and the counters the self-test reads.
 *
 * Split out of early.c. The body is that block moved verbatim; the only edits
 * are the seam in early_module.h, which hands this file early.c's CPU table
 * and primitives, and the macro block below that keeps the moved code's short
 * names resolving to the exported ones. early.c still owns the CPU records and
 * the idle-loop probe globals. */

#include <xaios/arch_cpu.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#include "early_module.h"
#include "platform.h"

#define X86_TLB_COM1_PORT UINT16_C(0x3f8)

/* How long a TLB shootdown waits for every online CPU to acknowledge, and a
 * spin bound for the part of boot where no clock can be read yet. */
#define X86_TLB_SHOOTDOWN_TIMEOUT_NS UINT64_C(2000000000)
#define X86_TLB_SHOOTDOWN_FALLBACK_SPINS UINT64_C(200000000)

/* The moved body names these the way early.c did; each expands to the
 * primitive early.c exports through early_module.h. */
#define COM1_PORT X86_TLB_COM1_PORT
#define lapic_send xaios_x86_early_lapic_send
#define current_ordinal_fast xaios_x86_early_current_ordinal_fast
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define panic_halt xaios_x86_early_panic_halt

/* early.c's CPU table, read once per call rather than through the old
 * file-scope names. */
static x86_64_cpu_record_t *cpu_records(void) {
  return xaios_x86_early_cpu_records();
}

static uint32_t cpu_record_count(void) {
  return xaios_x86_early_cpu_record_count();
}

static volatile uint32_t g_tlb_shootdown_lock;
static volatile uint32_t g_tlb_shootdown_generation;
static volatile uint64_t g_tlb_shootdown_address;
static volatile uint64_t g_tlb_shootdown_count;
/* Non-zero from the moment a shootdown request is published until every other
 * online CPU has acknowledged it. The spin path tests this first, so the cost
 * of answering by hand is one load when nothing is in flight. */
static volatile uint32_t g_tlb_shootdown_in_flight;
/* Set only by the self-test's negative control, which has to run the kernel as
 * it was before the spin path could answer. */
static volatile uint32_t g_tlb_shootdown_poll_suppressed;

static void tlb_acknowledge(x86_64_cpu_record_t *record, uint32_t generation) {
  uint32_t current =
      __atomic_load_n(&record->tlb_generation, __ATOMIC_ACQUIRE);
  if ((int32_t)(generation - current) <= 0) return;
  __atomic_store_n(&record->tlb_generation, generation, __ATOMIC_RELEASE);
}

/* Answer a shootdown request without an interrupt.
 *
 * This is the whole of the fix for B-123. A CPU can be spinning with
 * interrupts masked -- a reentrant guard masks them before it spins, so every
 * CPU waiting for the network, service or CPU AI guard is in that state -- and
 * the CPU it is waiting for can be the CPU waiting for its acknowledgement:
 * the guard's holder maps or unmaps a page inside the critical section, which
 * is a shootdown. Neither side can move, because the answer is meant to arrive
 * as the interrupt the waiting CPU cannot take. The spinning CPU therefore
 * reads the request the interrupt would have carried and answers it directly.
 *
 * `in_flight` is the gate the spin path tests first, so a machine with no
 * shootdown outstanding pays one load per relaxation and no per-CPU lookup.
 * The request is published address-before-generation, so a CPU that sees a
 * generation also sees that generation's address. */
void xaios_cpu_service_shootdown_request(void) __attribute__((weak));
void xaios_cpu_service_shootdown_request(void) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  if (__atomic_load_n(&g_tlb_shootdown_in_flight, __ATOMIC_ACQUIRE) == 0U) {
    return;
  }
  if (__atomic_load_n(&g_tlb_shootdown_poll_suppressed, __ATOMIC_ACQUIRE) !=
      0U) {
    return;
  }
  if (g_cpu_records == 0) return;
  uint32_t ordinal = current_ordinal_fast();
  if (ordinal >= g_cpu_record_count) return;
  uint32_t generation =
      __atomic_load_n(&g_tlb_shootdown_generation, __ATOMIC_ACQUIRE);
  if (generation == 0U) return;
  x86_64_cpu_record_t *record = &g_cpu_records[ordinal];
  if (__atomic_load_n(&record->tlb_generation, __ATOMIC_ACQUIRE) ==
      generation) {
    return;
  }
  uint64_t address =
      __atomic_load_n(&g_tlb_shootdown_address, __ATOMIC_ACQUIRE);
  __asm__ volatile("invlpg (%0)" : : "r"((void *)(uintptr_t)address)
                   : "memory");
  tlb_acknowledge(record, generation);
  __atomic_add_fetch(&record->shootdowns_polled, 1U, __ATOMIC_RELAXED);
}

/* Publish a shootdown request and interrupt every other online CPU. */
static uint32_t tlb_shootdown_begin(uint32_t self, uint64_t virtual_address) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  /* The flag first: a CPU that polls between it and the new generation answers
     whatever was outstanding before this request, which is harmless, and one
     that polls after the generation is published answers this request. */
  __atomic_store_n(&g_tlb_shootdown_in_flight, 1U, __ATOMIC_RELEASE);
  uint32_t generation =
      __atomic_load_n(&g_tlb_shootdown_generation, __ATOMIC_RELAXED) + 1U;
  if (generation == 0U) generation = 1U;
  /* The address before the generation it belongs to, because a polling CPU
     reads the generation and then the address: it must never see a generation
     with the address of the generation before it. */
  __atomic_store_n(&g_tlb_shootdown_address, virtual_address,
                   __ATOMIC_RELEASE);
  __atomic_store_n(&g_tlb_shootdown_generation, generation, __ATOMIC_RELEASE);
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    if (ordinal == self ||
        __atomic_load_n(&g_cpu_records[ordinal].online,
                        __ATOMIC_ACQUIRE) == 0U) {
      continue;
    }
    lapic_send(g_cpu_records[ordinal].apic_id, 35U);
  }
  __asm__ volatile("invlpg (%0)" : : "r"((void *)(uintptr_t)virtual_address)
                   : "memory");
  return generation;
}

/* Wait for every other online CPU to acknowledge `generation`.
 *
 * Returns 1 when every one has, and 0 when the budget runs out with the first
 * CPU that had not answered in `stuck_cpu`. The budget is in nanoseconds and
 * it used to be in TSC ticks: `rdtsc() + 2000000000` is two seconds only on a
 * machine whose TSC runs at 1 GHz, and on the CI runner's 2.4456 GHz it was
 * 0.82 seconds -- the same shape as `B-122`, where a hand-written tick
 * deadline had to become a measured one. A clock that cannot be read yet falls
 * back to a bounded spin, which is what the virtio waits do for the same
 * reason. */
static int tlb_shootdown_wait(uint32_t self, uint32_t generation,
                              uint64_t started_ns, uint64_t budget_ns,
                              uint32_t *stuck_cpu) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  uint64_t spins = 0U;
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    if (ordinal == self ||
        __atomic_load_n(&g_cpu_records[ordinal].online,
                        __ATOMIC_ACQUIRE) == 0U) {
      continue;
    }
    while (__atomic_load_n(&g_cpu_records[ordinal].tlb_generation,
                           __ATOMIC_ACQUIRE) != generation) {
      int expired = started_ns != 0U
                        ? timer_now_ns() - started_ns >= budget_ns
                        : ++spins >= X86_TLB_SHOOTDOWN_FALLBACK_SPINS;
      if (expired != 0) {
        if (stuck_cpu != 0) *stuck_cpu = ordinal;
        return 0;
      }
      __asm__ volatile("pause");
    }
  }
  return 1;
}

/* Name the CPU that did not answer, what it last acknowledged, and what it
 * says it was doing: "the shootdown timed out" says nothing about which CPU is
 * stuck, whether it ever saw the request, or what it was waiting for (B-123).
 * The initiator's own note is printed last, because the CPU that reports the
 * refusal is the one that knows which of the two is holding what. */
static void tlb_shootdown_report_timeout(uint32_t self, uint32_t generation,
                                         uint32_t ordinal, uint64_t started_ns) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  x86_64_cpu_record_t *stuck = &g_cpu_records[ordinal];
  /* Plain reads of a volatile pointer: this is a report, and a pointer that is
     being replaced as it is read is still a pointer. */
  const char *waiting_for = stuck->state.waiting_for;
  const char *own = self < g_cpu_record_count
                        ? g_cpu_records[self].state.waiting_for
                        : 0;
  serial_puts(X86_TLB_COM1_PORT, "x86_64: tlb shootdown timeout waiting for cpu=");
  serial_dec(X86_TLB_COM1_PORT, ordinal);
  serial_puts(X86_TLB_COM1_PORT, " apic_id=");
  serial_dec(X86_TLB_COM1_PORT, stuck->apic_id);
  serial_puts(X86_TLB_COM1_PORT, " generation=");
  serial_dec(X86_TLB_COM1_PORT, generation);
  serial_puts(X86_TLB_COM1_PORT, " acknowledged=");
  serial_dec(X86_TLB_COM1_PORT,
             __atomic_load_n(&stuck->tlb_generation, __ATOMIC_ACQUIRE));
  serial_puts(X86_TLB_COM1_PORT, " online=");
  serial_dec(X86_TLB_COM1_PORT, __atomic_load_n(&stuck->online, __ATOMIC_ACQUIRE));
  serial_puts(X86_TLB_COM1_PORT, " waited_ns=");
  serial_dec(X86_TLB_COM1_PORT, started_ns != 0U ? timer_now_ns() - started_ns : 0U);
  serial_puts(X86_TLB_COM1_PORT, " interrupts=");
  serial_dec(X86_TLB_COM1_PORT,
             __atomic_load_n(&stuck->interrupts_taken, __ATOMIC_ACQUIRE));
  serial_puts(X86_TLB_COM1_PORT, " last_vector=");
  serial_dec(X86_TLB_COM1_PORT, stuck->last_vector);
  serial_puts(X86_TLB_COM1_PORT, " shootdowns_handled=");
  serial_dec(X86_TLB_COM1_PORT,
             __atomic_load_n(&stuck->shootdowns_handled, __ATOMIC_ACQUIRE));
  serial_puts(X86_TLB_COM1_PORT, " shootdowns_polled=");
  serial_dec(X86_TLB_COM1_PORT,
             __atomic_load_n(&stuck->shootdowns_polled, __ATOMIC_ACQUIRE));
  serial_puts(X86_TLB_COM1_PORT, " shootdown_lock_wait=");
  serial_dec(X86_TLB_COM1_PORT, stuck->shootdown_lock_wait);
  serial_puts(X86_TLB_COM1_PORT, " waiting_for=");
  serial_puts(X86_TLB_COM1_PORT, waiting_for != 0 ? waiting_for : "none");
  serial_puts(X86_TLB_COM1_PORT, "\n");
  serial_puts(X86_TLB_COM1_PORT, "x86_64: tlb shootdown initiator cpu=");
  serial_dec(X86_TLB_COM1_PORT, self);
  serial_puts(X86_TLB_COM1_PORT, " waiting_for=");
  serial_puts(X86_TLB_COM1_PORT, own != 0 ? own : "none");
  serial_puts(X86_TLB_COM1_PORT, "\n");
}

void x86_64_platform_invalidate_page_all(uint64_t virtual_address) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  uint32_t self = x86_64_platform_current_ordinal();
  xaios_cpu_note_wait("tlb shootdown lock");
  while (__atomic_exchange_n(&g_tlb_shootdown_lock, 1U,
                             __ATOMIC_ACQUIRE) != 0U) {
    /* A CPU waiting here cannot take the shootdown interrupt either, so record
     * whether it is waiting with interrupts masked -- that is the difference
     * between "spinning and will answer" and "spinning and cannot" -- and
     * answer a shootdown by hand while waiting, for the same reason the guard's
     * spin does (B-123). */
    if (self < g_cpu_record_count) {
      __atomic_store_n(&g_cpu_records[self].shootdown_lock_wait,
                       xaios_interrupts_enabled() != 0 ? 1U : 2U,
                       __ATOMIC_RELEASE);
    }
    xaios_cpu_relax();
  }
  if (self < g_cpu_record_count) {
    __atomic_store_n(&g_cpu_records[self].shootdown_lock_wait, 0U,
                     __ATOMIC_RELEASE);
  }
  xaios_cpu_note_wait("tlb shootdown in progress");
  uint32_t generation = tlb_shootdown_begin(self, virtual_address);
  uint64_t started_ns = timer_now_ns();
  uint32_t stuck = UINT32_MAX;
  if (tlb_shootdown_wait(self, generation, started_ns,
                         X86_TLB_SHOOTDOWN_TIMEOUT_NS, &stuck) == 0) {
    tlb_shootdown_report_timeout(self, generation, stuck, started_ns);
    panic_halt(X86_TLB_COM1_PORT, "TLB shootdown timeout");
  }
  __atomic_store_n(&g_tlb_shootdown_in_flight, 0U, __ATOMIC_RELEASE);
  __atomic_add_fetch(&g_tlb_shootdown_count, 1U, __ATOMIC_RELAXED);
  __atomic_store_n(&g_tlb_shootdown_lock, 0U, __ATOMIC_RELEASE);
  xaios_cpu_note_wait(0);
}

/* One shootdown with a caller-chosen budget, reported rather than fatal.
 *
 * The self-test needs both halves of B-123: the fixed kernel, where a CPU
 * spinning with interrupts masked answers, and the kernel as it was, where it
 * cannot. `suppress_poll` is the second half; the budget is short for that run
 * so the control costs a few tens of milliseconds instead of the production
 * two seconds. Returns 1 when every CPU acknowledged. */
int x86_64_platform_shootdown_probe(uint64_t virtual_address, uint64_t budget_ns,
                                    uint32_t suppress_poll) {
  uint32_t self = x86_64_platform_current_ordinal();
  uint32_t saved = __atomic_exchange_n(
      &g_tlb_shootdown_poll_suppressed, suppress_poll != 0U ? 1U : 0U,
      __ATOMIC_ACQ_REL);
  while (__atomic_exchange_n(&g_tlb_shootdown_lock, 1U,
                             __ATOMIC_ACQUIRE) != 0U) {
    __asm__ volatile("pause");
  }
  uint32_t generation = tlb_shootdown_begin(self, virtual_address);
  uint64_t started_ns = timer_now_ns();
  uint32_t stuck = UINT32_MAX;
  int complete = tlb_shootdown_wait(self, generation, started_ns, budget_ns,
                                    &stuck);
  __atomic_store_n(&g_tlb_shootdown_in_flight, 0U, __ATOMIC_RELEASE);
  if (complete != 0) {
    __atomic_add_fetch(&g_tlb_shootdown_count, 1U, __ATOMIC_RELAXED);
  }
  __atomic_store_n(&g_tlb_shootdown_lock, 0U, __ATOMIC_RELEASE);
  __atomic_store_n(&g_tlb_shootdown_poll_suppressed, saved, __ATOMIC_RELEASE);
  return complete;
}

uint64_t x86_64_platform_tlb_shootdown_count(void) {
  return __atomic_load_n(&g_tlb_shootdown_count, __ATOMIC_ACQUIRE);
}

uint64_t x86_64_platform_shootdown_budget_ns(void) {
  return X86_TLB_SHOOTDOWN_TIMEOUT_NS;
}

/* How each CPU answered, so the self-test can say whether the answer came from
 * the spin or from the interrupt -- a passing test that only ever saw the
 * interrupt would not have built the cycle it claims to test. */
uint64_t x86_64_platform_shootdowns_polled(uint32_t ordinal) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  return ordinal < g_cpu_record_count
             ? __atomic_load_n(&g_cpu_records[ordinal].shootdowns_polled,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

uint64_t x86_64_platform_shootdowns_handled(uint32_t ordinal) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  return ordinal < g_cpu_record_count
             ? __atomic_load_n(&g_cpu_records[ordinal].shootdowns_handled,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

/* The idle-wakeup self-test's setter and the probe globals stay in early.c,
 * which reads them on the idle path (x86_64_platform_set_idle_halt_probe);
 * only the per-CPU counters below are read through the CPU records. */

uint64_t x86_64_platform_idle_gap_rounds(uint32_t ordinal) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  return ordinal < g_cpu_record_count
             ? __atomic_load_n(&g_cpu_records[ordinal].idle_gap_rounds,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

uint64_t x86_64_platform_idle_wakeups_raced(uint32_t ordinal) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  return ordinal < g_cpu_record_count
             ? __atomic_load_n(&g_cpu_records[ordinal].idle_wakeups_raced,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

/* The shootdown interrupt's work, called by early.c's IDT dispatcher for
 * vector 35 where that code used to sit inline. It does exactly what the
 * inline block did, in the same order: read the request, invalidate, account,
 * and leave the end-of-interrupt to the caller's dispatcher. */
void xaios_x86_early_tlb_note_interrupt(void) {
  uint32_t g_cpu_record_count = cpu_record_count();
  x86_64_cpu_record_t *g_cpu_records = cpu_records();
  uint32_t ordinal = x86_64_platform_current_ordinal();
  uint32_t generation =
      __atomic_load_n(&g_tlb_shootdown_generation, __ATOMIC_ACQUIRE);
  uint64_t address =
      __atomic_load_n(&g_tlb_shootdown_address, __ATOMIC_ACQUIRE);
  __asm__ volatile("invlpg (%0)" : : "r"((void *)(uintptr_t)address)
                   : "memory");
  if (ordinal < g_cpu_record_count) {
    tlb_acknowledge(&g_cpu_records[ordinal], generation);
    __atomic_add_fetch(&g_cpu_records[ordinal].shootdowns_handled, 1U,
                       __ATOMIC_RELAXED);
  }
}

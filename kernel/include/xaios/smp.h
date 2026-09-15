#ifndef XAIOS_SMP_H
#define XAIOS_SMP_H

#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/boot_info.h>

typedef enum xaios_cpu_role {
  XAIOS_CPU_ROLE_OFFLINE = 0,
  XAIOS_CPU_ROLE_HOUSEKEEPING = 1,
  XAIOS_CPU_ROLE_SCHEDULING = 2,   /* participates in SMP scheduler */
  XAIOS_CPU_ROLE_AI_HOT = 3,       /* leased to AI Cell, exclusive use */
} xaios_cpu_role_t;

typedef struct __attribute__((aligned(16))) xaios_cpu_state {
  uint32_t cpu_id;
  uint32_t online;
  uint64_t mpidr;
  xaios_cpu_role_t role;
  uint32_t lease_owner_id;
  uint32_t irq_routed_away;
  uint32_t tick_suppressed;
  uint64_t migration_count;
  uint64_t involuntary_context_switch_count;
  /* SMP scheduler fields */
  uint32_t scheduling_enabled; /* 1 when the CPU can accept scheduled work */
  uint32_t steal_count;        /* work-stealing events on this CPU */
  /* What this CPU is waiting for, in the words of the code that waits.
   *
   * A refusal on one CPU that names another ("cpu 1 did not answer") is a
   * question, and the answer is what the other CPU was doing -- which nothing
   * recorded until a TLB shootdown timed out and the report could say only
   * which CPU had not acknowledged (B-123). The waiting CPU writes one word
   * here; whichever CPU reports the refusal reads it. `0` means "not waiting
   * for anything in particular", which is also what a CPU that has not been
   * asked looks like. */
  const char *volatile waiting_for;
  /* How many traps deep this CPU is. `xaios_cpu_in_interrupt()` reads it, and
   * the console lock uses the answer to decide how long it may wait: a CPU
   * inside a handler may be holding that lock in the context the handler
   * interrupted, which cannot run again until the handler returns, so the wait
   * there has to be short rather than long. Interrupts being *masked* is not
   * the same question -- a thread holding a spinlock is masked too, and its
   * holder is another CPU, which will release (B-119). */
  volatile uint32_t interrupt_depth;
  /* Architecture-owned translation root and private user directory. */
  uint64_t *page_table_root;
  uint64_t *user_page_directory;
} xaios_cpu_state_t;

uint32_t smp_cpu_id(void);

/* Record what this CPU is waiting for, so another CPU's refusal can name it.
 *
 * `reason` is a string literal; `0` clears it. The write is one word and the
 * reader only ever prints it, so the note is a report and never a decision. */
void xaios_cpu_note_wait(const char *reason);

xaios_status_t smp_wake_cpu(uint32_t cpu_id);

void smp_init_platform(const xaios_boot_info_t *boot);
/* Secondaries exist and can be leased, but do not schedule yet.
 *
 * The three architectures used to disagree about when a secondary was
 * online. AArch64 and x86-64 bring theirs up in smp_init_platform and only
 * enable scheduling at the rendezvous; RISC-V could not, because starting a
 * hart needs an address space and an allocator that do not exist that early,
 * so it did both at the rendezvous -- and every self-test between the two
 * points saw a uniprocessor. One of them, the AI cell lifecycle, needs a
 * leasable core and skipped itself on RISC-V for that reason alone.
 *
 * This is the point where "the address space, the allocator, the interrupt
 * controller and the timer all exist" is true, which is what a secondary
 * needs. A platform whose secondaries are already online answers OK and does
 * nothing. */
xaios_status_t smp_bring_secondaries_online(void);
xaios_status_t smp_release_secondary_schedulers(void);
const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id);
xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled);
uint32_t smp_online_count(void);
uint32_t smp_locking_active(void);
uint32_t smp_capacity(void);
xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end);
xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id);
uint32_t smp_hot_core_mask(void);
uint64_t smp_total_migration_count(void);
uint64_t smp_total_involuntary_context_switch_count(void);
uint32_t smp_irq_isolated_mask(void);
xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id);
xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id);
xaios_status_t smp_run_user_task_set(uint64_t requested_workers,
                                    uint64_t iterations,
                                    uint64_t *ran_workers,
                                    uint64_t *checksum);
xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                        uint64_t iterations,
                                        uint64_t *ran_threads,
                                        uint64_t *checksum);
void smp_self_test(void);
/* Prove that a CPU which cannot take an interrupt still answers a TLB
 * shootdown.
 *
 * The cycle is real and was hit in the operations closure: a CPU holds a
 * reentrant guard, which masks interrupts before it spins; inside that
 * critical section it maps or unmaps a page, which shoots down; another CPU
 * spins for the same guard with interrupts masked; and the first CPU waits for
 * the second CPU's acknowledgement, which is meant to arrive as the interrupt
 * the second CPU cannot take (B-123).
 *
 * x86-64 has the only shootdown that waits for an acknowledgement -- AArch64's
 * `tlbi vaae1is` is broadcast by hardware and RISC-V's remote fence is a
 * firmware call that returns when every named hart has fenced -- so the other
 * architectures report that the check does not apply to them rather than
 * passing a test they did not run. */
void smp_shootdown_ack_self_test(void);
/* Prove that a wakeup is not lost between an idle CPU's check for work and its
 * wait: an interrupt consumed in that gap used to leave the CPU sleeping with
 * its thread still pending (B-120). x86-64 widens the window and builds both
 * halves of it; AArch64 and RISC-V have no such gap -- `sev` sets the
 * wait-for-event latch the `wfe` waits on, and the `wfi` port asks the queue
 * once more with interrupts masked -- so they report that the check does not
 * apply to them rather than passing one they did not run. */
void smp_idle_wakeup_self_test(void);
void smp_secondary_main(uint64_t cpu_id);

#endif

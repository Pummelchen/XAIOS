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
  /* Architecture-owned translation root and private user directory. */
  uint64_t *page_table_root;
  uint64_t *user_page_directory;
} xaios_cpu_state_t;

uint32_t smp_cpu_id(void);
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
void smp_secondary_main(uint64_t cpu_id);

#endif

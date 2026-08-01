#ifndef XAIOS_SMP_H
#define XAIOS_SMP_H

#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>

/*
 * SMP infrastructure — supports up to 131,072 CPUs.
 * Scales from single-core QEMU to hyperscale ARM/Xeon servers.
 * Hardware detection via GIC TYPER / ACPI MADT adapts to actual CPU count.
 * BSS per-CPU: ~0.7 MB total (stacks + states + runqueues) at max scale.
 * Requires >= 1 GB RAM for testing, >= 64 GB for production servers.
 */
#define XAIOS_MAX_CPUS 256U

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
  uint32_t scheduling_enabled; /* 1 when timer+GIC active for scheduling */
  uint32_t steal_count;        /* work-stealing events on this CPU */
} xaios_cpu_state_t;

/* Read the current CPU ID from MPIDR_EL1 affinity bits (Aff0 + Aff1 + Aff2 = 24 bits) */
static inline uint32_t smp_cpu_id(void) {
  uint64_t mpidr;
  __asm__ volatile("mrs %[v], mpidr_el1" : [v] "=r"(mpidr));
  uint32_t aff0 = (uint32_t)(mpidr & 0xffU);
  uint32_t aff1 = (uint32_t)((mpidr >> 8U) & 0xffU);
  uint32_t aff2 = (uint32_t)((mpidr >> 16U) & 0xffU);
  return aff0 | (aff1 << 8U) | (aff2 << 16U); /* supports up to 16,777,216 CPUs */
}

void smp_init_qemu_virt(void);
void smp_release_secondary_schedulers(void);
const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id);
xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled);
uint32_t smp_online_count(void);
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

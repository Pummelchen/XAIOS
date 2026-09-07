#ifndef XAIOS_CORE_LEASE_H
#define XAIOS_CORE_LEASE_H

#include <xaios/status.h>
#include <xaios/types.h>

void core_lease_init(void);
xaios_status_t core_lease_acquire_cpus(uint32_t owner_id,
                                       const uint32_t *cpu_ids,
                                       uint32_t cpu_count);
xaios_status_t core_lease_acquire(uint32_t owner_id, uint32_t core_mask);
/* Lease `cpu_count` CPUs chosen by topology rather than named by the caller:
   every leasable CPU on `node_id` first, then the nearest nodes by SLIT
   distance until the count is met. `selected_cpu_ids` receives the chosen ids
   in that order and must have room for `cpu_count`; it is written only when
   the whole lease is granted, since a partial lease of a machine's CPUs is
   never what an owner asked for. */
xaios_status_t core_lease_acquire_on_node(uint32_t owner_id, uint32_t node_id,
                                          uint32_t cpu_count,
                                          uint32_t *selected_cpu_ids);
xaios_status_t core_lease_release(uint32_t owner_id);
uint32_t core_lease_cpu_count(void);
int core_lease_cpu_is_used(uint32_t cpu_id);
int core_lease_cpu_is_irq_isolated(uint32_t cpu_id);
uint32_t core_lease_used_mask(void);
uint32_t core_lease_irq_isolated_mask(void);
uint64_t core_lease_migration_count(void);
uint64_t core_lease_involuntary_context_switch_count(void);
void core_lease_self_test(void);

#endif

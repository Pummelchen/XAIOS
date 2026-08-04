#ifndef XAIOS_CORE_LEASE_H
#define XAIOS_CORE_LEASE_H

#include <xaios/status.h>
#include <xaios/types.h>

void core_lease_init(void);
xaios_status_t core_lease_acquire_cpus(uint32_t owner_id,
                                       const uint32_t *cpu_ids,
                                       uint32_t cpu_count);
xaios_status_t core_lease_acquire(uint32_t owner_id, uint32_t core_mask);
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

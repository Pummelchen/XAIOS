/* Private interface of the AArch64 SMP bring-up, shared by smp.c,
 * smp_platform.c and smp_registry.c.
 *
 * smp.c owns the per-CPU registry: it allocates the bootstrap region out of
 * the UEFI memory map, lays the xaios_cpu_state_t array and the secondary
 * stacks inside it, starts the secondaries through PSCI and releases them at
 * the rendezvous. smp_platform.c holds the questions asked of firmware and of
 * the interrupt controller -- the CPU count, the MPIDR of each ordinal and
 * the PSCI CPU_ON call -- and keeps no state of its own. smp_registry.c holds
 * the registry's public surface: the per-CPU query, the AI-cell lease, the
 * reporting counters and the self-tests.
 *
 * The bootstrap region and the registry it contains are smp.c's own
 * file-scope state, so the other two files read and write it through the
 * declarations below; every name here is defined exactly once, in smp.c.
 * The prefix is the module's because these cross a translation unit now,
 * which they never did when the whole port was one file.
 */
#ifndef XAIOS_ARCH_AARCH64_SMP_INTERNAL_H
#define XAIOS_ARCH_AARCH64_SMP_INTERNAL_H

#include <xaios/aarch64_acpi.h>
#include <xaios/boot_info.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* The live registry, its capacity, and the lock the lease paths take. A
   secondary fills its own entry with plain stores before it is online, so
   these are read without the lock on the bring-up path and under it on the
   lease paths, exactly as they always were. */
extern xaios_cpu_state_t *a64smp_cpu_states;
extern uint32_t a64smp_cpu_capacity;
extern xaios_spinlock_t a64smp_lock;

/* The bootstrap range, so the reservation can be reported before the memory
   map is handed to the allocator. */
extern uint64_t a64smp_bootstrap_start;
extern uint64_t a64smp_bootstrap_end;

/* The secondary rendezvous flag: set by the boot CPU, spun on by the
   secondaries while their translation is still off. */
extern uint32_t a64smp_secondary_release;

/* The cached online count, defined once in smp.c and read by the reporting
   entry points in smp_registry.c. */
uint32_t a64smp_count_online(void);

/* Platform discovery, defined once in smp_platform.c. */
uint64_t a64smp_read_mpidr_el1(void);
uint64_t a64smp_psci_cpu_on(uint64_t mpidr, uint64_t entry, uint64_t context,
                            uint32_t use_hvc);
uint32_t a64smp_platform_cpu_capacity(const xaios_boot_info_t *boot,
                                      aarch64_acpi_info_t *acpi_info);
uint64_t a64smp_platform_mpidr(const aarch64_acpi_info_t *acpi_info,
                               uint64_t boot_mpidr, uint32_t ordinal);
int a64smp_acpi_is_qemu_virt(const aarch64_acpi_info_t *info);

#endif /* XAIOS_ARCH_AARCH64_SMP_INTERNAL_H */

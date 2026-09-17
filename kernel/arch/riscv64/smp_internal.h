/* Private interface of the RISC-V SMP module, shared by smp.c, smp_bringup.c
 * and smp_registry.c.
 *
 * smp.c owns the hart registry and the secondary wait loop: the per-CPU state
 * array, the logical-to-hart map, the online count and the flags the shared
 * kernel polls -- whether locking is live and whether the secondary schedulers
 * have been released. smp_bringup.c records the boot hart, discovers which
 * harts firmware has, starts them through SBI once the address space exists
 * and releases them at the rendezvous. smp_registry.c serves the registry's
 * public surface: the per-CPU query, the AI-cell core lease, the reporting
 * counters and the self-tests.
 *
 * The registry is smp.c's own file-scope state, so the other two files read
 * and write it through the declarations below; every name here is defined
 * exactly once, in smp.c. The prefix is the module's because these cross a
 * translation unit now, which they never did when the whole port was one
 * file.
 */
#ifndef XAIOS_ARCH_RISCV64_SMP_INTERNAL_H
#define XAIOS_ARCH_RISCV64_SMP_INTERNAL_H

#include <xaios/smp.h>
#include <xaios/types.h>

/* How many hart identifiers this port tracks. It bounds the per-CPU state and
   the secondary stacks, so it is one number the three files share rather than
   three copies kept in step by hand. It stays private to the module: the
   probe table in exception_frame.c carries its own bound, and putting this
   one into a public header would export a bound on hart identifiers to files
   that do not need it. */
#define RISCV64_MAX_HARTS 8U

/* The live registry and the numbers derived from it. A secondary fills its own
   entry with plain stores before it is online, so these are read without the
   lock on the bring-up path and under the lease lock in smp_registry.c,
   exactly as they always were. */
extern xaios_cpu_state_t riscv64_smp_cpu_states[RISCV64_MAX_HARTS];
/* Logical CPU number to hart id. Index 0 is the boot hart, whichever one
   firmware chose. */
extern uint32_t riscv64_smp_hart_of_cpu[RISCV64_MAX_HARTS];
extern uint32_t riscv64_smp_online;
extern uint32_t riscv64_smp_capacity;
/* How many harts are expected to arrive, which is what the rendezvous loops
   wait for; see the note on it in smp.c. */
extern uint32_t riscv64_smp_online_target;
/* Set by the boot hart before the first hart is started, because a lock that
   is a no-op on one side and an atomic on the other is not a lock. */
extern uint32_t riscv64_smp_locking_active;
/* The secondary rendezvous flag: set by the boot hart, read by the harts
   waiting to enter the scheduler. */
extern uint32_t riscv64_smp_secondary_release;

/* The secondary stacks, allocated and owned by smp.c. */
uint8_t *riscv64_secondary_stack_top(uint32_t cpu);

/* Record which hart firmware handed over on, called from the early boot path
   and defined in smp_bringup.c. It is CPU 0 and the first entry of the
   logical-to-hart map. */
void riscv64_smp_record_boot_hart(uint32_t hart_id);

/* Each hart has its own root, so each hart is handed its own satp. Defined in
   the MMU module; the bring-up path is the only caller. */
uint64_t riscv64_hart_satp(uint32_t cpu_id);

/* The remote half of the TLB shootdown self-test, defined in mmu_shootdown.c
   and called once the first secondaries are online. */
void riscv64_tlb_shootdown_self_test(void);

/* Where a secondary hart lands once SBI has started it, defined by entry_helpers.S. */
extern char riscv64_secondary_entry[];

/* Declared here rather than through a public klog header, which is what the
   other RISC-V internal headers do too. */
void klog(const char *fmt, ...);

#endif /* XAIOS_ARCH_RISCV64_SMP_INTERNAL_H */

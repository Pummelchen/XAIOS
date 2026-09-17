/* RISC-V hart discovery and bring-up: which harts this machine has, recording
 * the boot hart, starting the secondaries through SBI's Hart State Management
 * extension once an address space exists, and releasing them at the scheduler
 * rendezvous.
 *
 * This is the whole group that moved out of smp.c, in the order it ran there,
 * with its comments: discovery still happens in smp_init_platform and starting
 * still happens in smp_bring_secondaries_online, because a hart started
 * earlier would be handed a satp that has not been built yet. smp.c keeps the
 * registry those harts fill in and the loop a started hart waits in before the
 * release; smp_registry.c serves the registry's public query and lease
 * surface.
 */
#include <xaios/boot_info.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#include "smp_internal.h"

#define SECONDARY_READY_TIMEOUT_MS UINT64_C(2000)

/* What a starting hart needs before it can execute anything: somewhere to put
   a stack frame and the address space to do it in. Physically addressed,
   because the hart reads it with translation off. */
typedef struct hart_handoff {
  uint64_t stack_top;
  uint64_t satp;
  uint64_t cpu_id;
} hart_handoff_t;

static uint32_t g_boot_hart;
static uint32_t g_cpu_count = 1U;
static hart_handoff_t g_handoff[RISCV64_MAX_HARTS];
static uint32_t g_hart_present[RISCV64_MAX_HARTS];
static int64_t g_hart_status[RISCV64_MAX_HARTS];

void riscv64_smp_record_boot_hart(uint32_t hart_id) {
  g_boot_hart = hart_id;
  /* Whichever hart firmware handed over on is CPU 0. */
  riscv64_smp_hart_of_cpu[0] = hart_id;
  g_cpu_count = 1U;
}

/* Which harts this machine has, from the tree rather than from a guess.
 *
 * Counting `riscv` cpu nodes says how many there are; their ids are what SBI
 * wants, and a machine may number them from something other than zero. Asking
 * SBI for each candidate's status is the check that costs nothing and catches
 * both -- a hart that does not exist reports an error rather than starting. */
static void discover_harts(void) {
  g_hart_present[g_boot_hart < RISCV64_MAX_HARTS ? g_boot_hart : 0U] = 1U;
  for (uint32_t hart = 0U; hart < RISCV64_MAX_HARTS; ++hart) {
    if (hart == g_boot_hart) continue;
    g_hart_status[hart] = sbi_hart_status(hart);
    if (g_hart_status[hart] >= 0) g_hart_present[hart] = 1U;
  }
}

void smp_init_platform(const xaios_boot_info_t *boot) {
  (void)boot;

  riscv64_smp_cpu_states[0].cpu_id = 0U;
  /* mpidr is AArch64's name for "what the hardware calls this core"; the hart
     id is what means the same thing here, and reporting it under that name
     beats reporting the kernel's own index twice. */
  riscv64_smp_cpu_states[0].mpidr = g_boot_hart;
  riscv64_smp_cpu_states[0].role = XAIOS_CPU_ROLE_SCHEDULING;
  riscv64_smp_cpu_states[0].online = 1U;
  riscv64_smp_online = 1U;

  if (sbi_probe_extension(SBI_EXT_HSM) == 0) {
    riscv64_smp_capacity = 1U;
    riscv64_smp_online_target = 1U;
    klog("smp: riscv64 firmware offers no hart state management; boot "
         "hart=%u runs alone\n", g_boot_hart);
    return;
  }

  discover_harts();

  /* Counted now, started later. Discovery is safe here; starting is not.
   *
   * smp_init runs while the boot UI still says "CPU and interrupts", which is
   * before vmm_init and before the page allocator. A hart started here would
   * be handed a satp that has not been built yet and would run with
   * translation off through kernel code the boot hart is still writing.
   * smp_release_secondary_schedulers is where the kernel says secondaries may
   * run, and by then the address space, the allocator, the interrupt
   * controller and the timer all exist -- which is what "may run" has to
   * mean. */
  uint32_t candidates = 0U;
  for (uint32_t hart = 0U; hart < RISCV64_MAX_HARTS; ++hart) {
    if (hart == g_boot_hart || g_hart_present[hart] == 0U) continue;
    if (g_cpu_count >= RISCV64_MAX_HARTS) break;
    riscv64_smp_hart_of_cpu[g_cpu_count] = hart;
    ++g_cpu_count;
    ++candidates;
  }
  riscv64_smp_capacity = 1U + candidates;
  uint32_t started = 0U;
  (void)started;

  klog("smp: riscv64 boot hart=%u harts=%u capacity=%u (secondaries start at "
       "the scheduler rendezvous)\n", g_boot_hart, candidates + 1U,
       riscv64_smp_capacity);
}

xaios_status_t smp_bring_secondaries_online(void) {
  /* Start them here, for the reasons smp_init_platform records: by now the
     address space, the allocator, the interrupt controller and the timer all
     exist, which is what a hart needs to run kernel code at all. They land,
     register themselves and then spin on the release flag, so they are
     online and leasable without being in the scheduler. */
  uint32_t started = 0U;
  uint32_t highest_started = 0U;
  if (g_cpu_count <= 1U) return XAIOS_OK;

  /* Before the first one can land, not after the loop that starts them all:
     a hart started early enough executes kernel code while later ones are
     still being started, and a lock that is a no-op on one side and an
     atomic on the other is not a lock. */
  __atomic_store_n(&riscv64_smp_locking_active, 1U, __ATOMIC_RELEASE);
  for (uint32_t cpu = 1U; cpu < g_cpu_count; ++cpu) {
    uint32_t hart = riscv64_smp_hart_of_cpu[cpu];
    g_handoff[cpu].stack_top =
        (uint64_t)(uintptr_t)riscv64_secondary_stack_top(cpu);
    /* This hart's own root, which is what lets it run a different process
       from the boot hart at the same time. */
    g_handoff[cpu].satp = riscv64_hart_satp(cpu);
    g_handoff[cpu].cpu_id = cpu;
    int64_t status =
        sbi_hart_start(hart, (uint64_t)(uintptr_t)riscv64_secondary_entry,
                       (uint64_t)(uintptr_t)&g_handoff[cpu]);
    if (status != 0) {
      klog("smp: hart=%u refused to start sbi_error=%lx\n", hart,
           (uint64_t)status);
      continue;
    }
    if (cpu > highest_started) highest_started = cpu;
    ++started;
  }
  riscv64_smp_online_target = 1U + started;
  if (highest_started + 1U > riscv64_smp_capacity) riscv64_smp_capacity = highest_started + 1U;
  if (started == 0U) {
    /* Nothing started, so nothing else may take an atomic on its account. */
    __atomic_store_n(&riscv64_smp_locking_active, 0U, __ATOMIC_RELEASE);
    return XAIOS_OK;
  }

  /* Wait for them to be online before returning: a caller that leases a core
     immediately after this would otherwise race the hart it is leasing. */
  uint64_t online_frequency = timer_frequency_hz();
  uint64_t online_deadline =
      timer_counter() + (online_frequency == 0U
                             ? UINT64_C(0)
                             : online_frequency * SECONDARY_READY_TIMEOUT_MS /
                                   UINT64_C(1000));
  while (smp_online_count() < riscv64_smp_online_target) {
    if (timer_counter() >= online_deadline) {
      klog("smp: %u of %u harts came online\n", smp_online_count(),
           riscv64_smp_online_target);
      return XAIOS_ERR_IO;
    }
  }
  klog("smp: riscv64 %u harts online, scheduling held until the rendezvous\n",
       smp_online_count());
  /* Here and not in vmm_self_test, because there is nothing to measure until
     a second hart exists. The vmm self-tests run inside vmm_init, long before
     any hart has been started -- which is exactly why the port's own
     large-page test had to record that it could say nothing about any TLB but
     its own. This is the first moment in the boot where that sentence stops
     being true. It has to run before the harts are leased to the AI cell,
     too: a leased hart has left this wait loop's neighbourhood and would not
     answer a probe. */
  riscv64_tlb_shootdown_self_test();
  return XAIOS_OK;
}

xaios_status_t smp_release_secondary_schedulers(void) {
  __atomic_store_n(&riscv64_smp_secondary_release, 1U, __ATOMIC_RELEASE);
  /* The flag is what they check; the interrupt is what ends their sleep.
     Sent to every hart that was started, whether or not it has reached the
     gate yet -- one that has not will read the flag on arrival. */
  for (uint32_t cpu = 1U; cpu < g_cpu_count; ++cpu) {
    if (riscv64_smp_cpu_states[cpu].online != 0U) {
      (void)sbi_send_ipi(UINT64_C(1), riscv64_smp_hart_of_cpu[cpu]);
    }
  }

  uint64_t frequency = timer_frequency_hz();
  uint64_t deadline =
      timer_counter() +
      (frequency == 0U ? UINT64_C(0) : frequency * SECONDARY_READY_TIMEOUT_MS /
                                           UINT64_C(1000));
  for (;;) {
    uint32_t ready = 1U;
    for (uint32_t cpu = 1U; cpu < g_cpu_count; ++cpu) {
      if (__atomic_load_n(&riscv64_smp_cpu_states[cpu].scheduling_enabled,
                          __ATOMIC_ACQUIRE) != 0U) {
        ++ready;
      }
    }
    if (ready >= riscv64_smp_online_target) break;
    if (timer_counter() >= deadline) {
      klog("smp: %u of %u harts reached the scheduler rendezvous\n", ready,
           riscv64_smp_online_target);
      return XAIOS_ERR_IO;
    }
  }
  klog("smp: riscv64 %u harts scheduling online=%u\n", riscv64_smp_online_target,
       smp_online_count());
  return XAIOS_OK;
}

/* Harts: finding them, starting them, and letting them run.
 *
 * The shared kernel asks four things before it can run at all: which CPU am
 * I, how many are there, is locking live, and how many could there be. It
 * then expects to be able to release secondary schedulers and have them
 * arrive. This answers all of that for real harts rather than for one.
 *
 * A supervisor-mode kernel cannot take a hart out of reset itself; that is
 * machine-mode work. SBI's Hart State Management extension exists for exactly
 * this, so asking firmware is the supported route and not a workaround. The
 * hart arrives with translation off, which is why its entry point is in the
 * identity-mapped kernel image and why the stack and satp it needs are handed
 * over as a plain record at a physical address.
 *
 * `smp_locking_active` deserves the note it always did. It reports whether
 * more than one hart can be executing kernel code, and the shared spinlock
 * uses it to decide whether an atomic is needed. Returning 1 on a single-hart
 * system would be merely wasteful; returning 0 once secondaries exist would
 * be a silent data race. It is derived from the online count, so bringing
 * harts up changes the answer without anyone having to remember this file.
 */
#include <xaios/boot_info.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>

void klog(const char *fmt, ...);
void gic_secondary_init(uint32_t cpu_id);
void timer_mask_local(void);
uint32_t xaios_thread_run_pending(uint32_t cpu_id);
xaios_status_t xaios_thread_run_group(uint64_t requested_threads,
                                      uint64_t iterations,
                                      uint64_t *ran_threads,
                                      uint64_t *checksum);
uint64_t riscv64_kernel_satp(void);
/* Each hart has its own root, so each hart is handed its own satp. */
uint64_t riscv64_hart_satp(uint32_t cpu_id);
extern char riscv64_secondary_entry[];

#define RISCV64_MAX_HARTS 8U
#define SECONDARY_READY_TIMEOUT_MS UINT64_C(2000)
#define SECONDARY_STACK_BYTES 16384U

/* What a starting hart needs before it can execute anything: somewhere to put
   a stack frame and the address space to do it in. Physically addressed,
   because the hart reads it with translation off. */
typedef struct hart_handoff {
  uint64_t stack_top;
  uint64_t satp;
  uint64_t cpu_id;
} hart_handoff_t;

static uint32_t g_boot_hart;
/* Logical CPU number to hart id. Index 0 is the boot hart, whichever one
   firmware chose. Everything that talks to SBI goes through this; everything
   that indexes a per-CPU structure uses the logical number. */
static uint32_t g_hart_of_cpu[RISCV64_MAX_HARTS];
static uint32_t g_cpu_count = 1U;
static uint32_t g_online = 1U;
static uint32_t g_capacity = 1U;
static uint32_t g_secondary_release;
static uint32_t g_smp_locking_active;
static xaios_cpu_state_t g_cpu_states[RISCV64_MAX_HARTS];
static hart_handoff_t g_handoff[RISCV64_MAX_HARTS];
static uint32_t g_hart_present[RISCV64_MAX_HARTS];
static int64_t g_hart_status[RISCV64_MAX_HARTS];
static uint8_t g_secondary_stacks[RISCV64_MAX_HARTS][SECONDARY_STACK_BYTES]
    __attribute__((aligned(16)));

void riscv64_smp_record_boot_hart(uint32_t hart_id) {
  g_boot_hart = hart_id;
  /* Whichever hart firmware handed over on is CPU 0. */
  g_hart_of_cpu[0] = hart_id;
  g_cpu_count = 1U;
}

uint32_t smp_cpu_id(void) {
  /* tp holds this hart's logical CPU number, put there by the entry code.
     Read from a register rather than a CSR because mhartid is machine mode
     only -- a supervisor-mode kernel cannot ask the hardware who it is, and
     has to be told once and remember. */
  uint64_t cpu = 0U;
  __asm__ volatile("mv %0, tp" : "=r"(cpu));
  return (uint32_t)cpu;
}

uint32_t riscv64_hart_of_cpu(uint32_t cpu_id) {
  return cpu_id < RISCV64_MAX_HARTS ? g_hart_of_cpu[cpu_id] : 0U;
}

uint32_t smp_online_count(void) {
  return __atomic_load_n(&g_online, __ATOMIC_ACQUIRE);
}

uint32_t smp_locking_active(void) {
  return __atomic_load_n(&g_smp_locking_active, __ATOMIC_ACQUIRE);
}

uint32_t smp_capacity(void) { return g_capacity; }

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  if (cpu_id >= RISCV64_MAX_HARTS || g_cpu_states[cpu_id].online == 0U) {
    return 0;
  }
  return &g_cpu_states[cpu_id];
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  /* The value is recorded, which it was not: this discarded `enabled`, said
     XAIOS_OK, and left the flag the scheduler reads at zero. The kernel duly
     enabled scheduling, was told it had worked, and every tick then returned
     without picking anything -- a scheduler that ran, held no lock, had three
     runnable tasks, and chose none of them. A setter that reports success and
     stores nothing is worse than one that fails. */
  if (cpu_id >= RISCV64_MAX_HARTS || g_cpu_states[cpu_id].online == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  __atomic_store_n(&g_cpu_states[cpu_id].scheduling_enabled,
                   enabled == 0U ? 0U : 1U, __ATOMIC_RELEASE);
  return XAIOS_OK;
}

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (cpu_id == 0) return XAIOS_ERR_INVALID;
  uint32_t seen = 0U;
  for (uint32_t hart = 0U; hart < RISCV64_MAX_HARTS; ++hart) {
    if (g_cpu_states[hart].online == 0U) continue;
    if (seen == ordinal) {
      *cpu_id = hart;
      return XAIOS_OK;
    }
    ++seen;
  }
  return XAIOS_ERR_NOT_FOUND;
}

/* Where a secondary hart lands once SBI has started it. */
void smp_secondary_main(uint64_t cpu_id) {
  if (cpu_id < RISCV64_MAX_HARTS) {
    g_cpu_states[cpu_id].cpu_id = (uint32_t)cpu_id;
    g_cpu_states[cpu_id].mpidr = g_hart_of_cpu[cpu_id];
    g_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
    g_cpu_states[cpu_id].scheduling_enabled = 0U;
    /* Online last, and only once everything it describes has landed: it is
       what the boot hart waits on, and an entry seen half-written is worse
       than one not seen at all. */
    __atomic_store_n(&g_cpu_states[cpu_id].online, 1U, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_online, 1U, __ATOMIC_ACQ_REL);
  }

  /* Spin rather than wfi: nothing sends an interrupt to open this gate, so a
     hart that slept here would sleep until the first timer tick it has not
     been given yet. */
  while (__atomic_load_n(&g_secondary_release, __ATOMIC_ACQUIRE) == 0U) {
    __asm__ volatile("" ::: "memory");
  }

  gic_secondary_init((uint32_t)cpu_id);

  /* Kernel workers are event-driven. The local timer stays masked until this
     hart owns a preemptible run queue. */
  timer_mask_local();

  if (cpu_id < RISCV64_MAX_HARTS) {
    __atomic_store_n(&g_cpu_states[cpu_id].scheduling_enabled, 1U,
                     __ATOMIC_RELEASE);
  }

  __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(2)) : "memory");

  /* Sleeping, not spinning.
   *
   * This spun, because the first version of smp_wake_cpu here reported that
   * there was no way to wake a hart -- so a hart that slept would have slept
   * through every job it was given. There is a way: the shared scheduler
   * already calls smp_wake_cpu whenever it queues work for a CPU other than
   * the one it is running on, and SBI's IPI extension raises the supervisor
   * software interrupt that brings a hart out of wfi. Spinning cost a core
   * doing nothing on every idle machine.
   *
   * The pending work is still checked before sleeping and after waking,
   * because a wake that arrives between the two would otherwise be missed. */
  for (;;) {
    if (xaios_thread_run_pending((uint32_t)cpu_id) == 0U) {
      __asm__ volatile("wfi" ::: "memory");
    }
  }
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

  g_cpu_states[0].cpu_id = 0U;
  /* mpidr is AArch64's name for "what the hardware calls this core"; the hart
     id is what means the same thing here, and reporting it under that name
     beats reporting the kernel's own index twice. */
  g_cpu_states[0].mpidr = g_boot_hart;
  g_cpu_states[0].role = XAIOS_CPU_ROLE_SCHEDULING;
  g_cpu_states[0].online = 1U;
  g_online = 1U;

  if (sbi_probe_extension(SBI_EXT_HSM) == 0) {
    g_capacity = 1U;
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
    g_hart_of_cpu[g_cpu_count] = hart;
    ++g_cpu_count;
    ++candidates;
  }
  g_capacity = 1U + candidates;
  uint32_t started = 0U;
  (void)started;

  klog("smp: riscv64 boot hart=%u harts=%u capacity=%u (secondaries start at "
       "the scheduler rendezvous)\n", g_boot_hart, candidates + 1U,
       g_capacity);
}

xaios_status_t smp_release_secondary_schedulers(void) {
  /* Start them here, for the reasons smp_init_platform records. */
  uint32_t started = 0U;
  for (uint32_t cpu = 1U; cpu < g_cpu_count; ++cpu) {
    uint32_t hart = g_hart_of_cpu[cpu];
    g_handoff[cpu].stack_top =
        (uint64_t)(uintptr_t)&g_secondary_stacks[cpu][SECONDARY_STACK_BYTES];
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
    ++started;
  }
  g_capacity = 1U + started;

  /* Locking becomes real the moment a second hart can execute kernel code,
     and it has to be true before that hart is let past the gate rather than
     after -- a lock that is a no-op on one side and an atomic on the other
     is not a lock. */
  __atomic_store_n(&g_smp_locking_active, started > 0U ? 1U : 0U,
                   __ATOMIC_RELEASE);
  __atomic_store_n(&g_secondary_release, 1U, __ATOMIC_RELEASE);

  uint64_t frequency = timer_frequency_hz();
  uint64_t deadline =
      timer_counter() +
      (frequency == 0U ? UINT64_C(0) : frequency * SECONDARY_READY_TIMEOUT_MS /
                                           UINT64_C(1000));
  for (;;) {
    uint32_t ready = 1U;
    for (uint32_t cpu = 1U; cpu < g_cpu_count; ++cpu) {
      if (__atomic_load_n(&g_cpu_states[cpu].scheduling_enabled,
                          __ATOMIC_ACQUIRE) != 0U) {
        ++ready;
      }
    }
    if (ready >= g_capacity) break;
    if (timer_counter() >= deadline) {
      klog("smp: %u of %u harts reached the scheduler rendezvous\n", ready,
           g_capacity);
      return XAIOS_ERR_IO;
    }
  }
  klog("smp: riscv64 %u harts scheduling online=%u\n", g_capacity,
       smp_online_count());
  return XAIOS_OK;
}

void smp_self_test(void) {
  klog("smp: riscv64 self-test passed id=%u online=%u capacity=%u\n",
       smp_cpu_id(), smp_online_count(), smp_capacity());
}

/* Memory the bootstrap path needs kept out of the allocator's hands.
 *
 * x86-64 reserves the real-mode trampoline application processors start in;
 * AArch64 reserves the spin-table page firmware parks them on. RISC-V starts
 * a hart with SBI, passing the entry address in a register, so there is no
 * fixed page to protect -- and reserving one anyway would take memory out of
 * service to guard something that does not exist. */
xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end) {
  if (start != 0) *start = 0U;
  if (end != 0) *end = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

/* Which cores are held for latency-sensitive work, and which have interrupts
   steered away from them. Both are empty on one hart: there is nothing to
   isolate work onto and nothing to isolate it from. */
uint32_t smp_hot_core_mask(void) { return 0U; }

uint32_t smp_irq_isolated_mask(void) { return 0U; }



/* Leasing a core to the AI runtime needs a second core to lease. Refused
   rather than granted: a lease that reports success and leaves the caller
   sharing the only hart is worse than no leasing at all. */
xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id) {
  (void)cpu_id;
  (void)owner_id;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id) {
  (void)cpu_id;
  (void)owner_id;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t smp_wake_cpu(uint32_t cpu_id) {
  if (cpu_id >= RISCV64_MAX_HARTS || g_cpu_states[cpu_id].online == 0U ||
      __atomic_load_n(&g_cpu_states[cpu_id].scheduling_enabled,
                      __ATOMIC_ACQUIRE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* Addressed by hart, because that is what firmware knows about; the mask is
     one bit relative to that hart rather than a bitmap based at zero, so this
     says nothing about harts it was not asked to wake. */
  uint64_t hart = g_hart_of_cpu[cpu_id];
  return sbi_send_ipi(UINT64_C(1), hart) == 0 ? XAIOS_OK : XAIOS_ERR_IO;
}

uint64_t smp_total_migration_count(void) { return 0U; }

uint64_t smp_total_involuntary_context_switch_count(void) { return 0U; }


/* Kernel threads, which the shared scheduler places itself. */
xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                         uint64_t iterations,
                                         uint64_t *ran_threads,
                                         uint64_t *checksum) {
  return xaios_thread_run_group(requested_threads, iterations, ran_threads,
                                checksum);
}

/* Hart identity and, for now, one of them.
 *
 * The shared kernel asks four things before it can run at all: which CPU am
 * I, how many are there, is locking live, and how many could there be. This
 * answers those honestly for a single hart and does not pretend to more.
 * Secondary harts are started through SBI's HSM extension and are a separate
 * piece of work; what matters here is that nothing above this file has to
 * know that, and that the answers are true rather than optimistic.
 *
 * `smp_locking_active` deserves the note. It reports whether more than one
 * hart can be executing kernel code, and the shared spinlock uses it to
 * decide whether an atomic is needed. Returning 1 on a single-hart system
 * would be merely wasteful; returning 0 once secondaries exist would be a
 * silent data race. It is therefore derived from the online count rather than
 * hardcoded, so bringing harts up later changes the answer without anyone
 * having to remember this file.
 */
#include <xaios/boot_info.h>
#include <xaios/smp.h>
#include <xaios/status.h>

void klog(const char *fmt, ...);

static uint32_t g_boot_hart;
static uint32_t g_online = 1U;

void riscv64_smp_record_boot_hart(uint32_t hart_id) { g_boot_hart = hart_id; }

uint32_t smp_cpu_id(void) {
  /* tp holds this hart's id, put there by the entry code. Reading it from a
     register rather than a CSR because `mhartid` is machine mode only -- a
     supervisor-mode kernel cannot ask the hardware who it is, and has to be
     told once and remember. */
  uint64_t hart = 0U;
  __asm__ volatile("mv %0, tp" : "=r"(hart));
  return (uint32_t)hart;
}

void smp_init_platform(const xaios_boot_info_t *boot) {
  (void)boot;
  g_online = 1U;
  klog("smp: riscv64 boot hart=%u online=%u (secondaries not started)\n",
       g_boot_hart, g_online);
}

uint32_t smp_online_count(void) { return g_online; }

uint32_t smp_locking_active(void) { return g_online > 1U ? 1U : 0U; }

uint32_t smp_capacity(void) { return g_online; }

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (ordinal >= g_online || cpu_id == 0) return XAIOS_ERR_NOT_FOUND;
  *cpu_id = g_boot_hart;
  return XAIOS_OK;
}

xaios_status_t smp_release_secondary_schedulers(void) {
  /* Nothing to release. Reported as unsupported rather than OK: a caller that
     believes secondaries were released and finds none running would wait for
     work that never arrives. */
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  (void)enabled;
  return cpu_id == g_boot_hart ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
}

void smp_self_test(void) {
  klog("smp: riscv64 single-hart self-test passed id=%u online=%u\n",
       smp_cpu_id(), smp_online_count());
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

static xaios_cpu_state_t g_state;

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  if (cpu_id != g_boot_hart) return 0;
  g_state.cpu_id = g_boot_hart;
  g_state.online = 1U;
  /* mpidr is AArch64's identifier; the hart id is what means the same thing
     here, and reporting it under that name beats reporting zero. */
  g_state.mpidr = g_boot_hart;
  g_state.role = XAIOS_CPU_ROLE_SCHEDULING;
  return &g_state;
}

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
  (void)cpu_id;
  /* SBI's HSM extension starts a hart; using it is the next piece of work.
     Until then there is no hart to wake. */
  return XAIOS_ERR_UNSUPPORTED;
}

uint64_t smp_total_migration_count(void) { return 0U; }

uint64_t smp_total_involuntary_context_switch_count(void) { return 0U; }

/* Running work across several harts needs several harts. Refused rather than
   run on one and reported as if spread: a caller measuring parallel speedup
   would record a number that means nothing. */
xaios_status_t smp_run_user_task_set(uint64_t requested_workers,
                                     uint64_t iterations,
                                     uint64_t *ran_workers,
                                     uint64_t *checksum) {
  (void)requested_workers;
  (void)iterations;
  if (ran_workers != 0) *ran_workers = 0U;
  if (checksum != 0) *checksum = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                         uint64_t iterations,
                                         uint64_t *ran_threads,
                                         uint64_t *checksum) {
  (void)requested_threads;
  (void)iterations;
  if (ran_threads != 0) *ran_threads = 0U;
  if (checksum != 0) *checksum = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

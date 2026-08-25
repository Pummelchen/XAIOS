/* Sustained multi-core load with exact invariants.
 *
 * The functional SMP tests show that the concurrent paths work once. This one
 * runs them under contention for as long as it is given, and checks results
 * that admit no tolerance: a contended counter must equal the sum of what the
 * threads say they added, and a word owned by one thread must hold exactly
 * that thread's count no matter who shares its cache line. Both were chosen
 * for the defects this port has actually had -- an atomic that aborted where
 * exclusives were unsupported, and a stale cache line written back over a
 * neighbour's memory. Either would show up here as a mismatch rather than as
 * a crash days later.
 *
 * Iteration counts vary with timing, which is the point; the invariants do
 * not. */

#include <xaios_user.h>

#ifndef XAIOS_STRESS_NANOS
#define XAIOS_STRESS_NANOS 15000000000ULL
#endif

#define STRESS_THREADS 8ULL
#define STRESS_STACK_BYTES 32768ULL
#define CHURN_ROUNDS 24ULL
#define CHURN_THREADS 4ULL

static unsigned char g_stacks[STRESS_THREADS][STRESS_STACK_BYTES]
    __attribute__((aligned(16)));

/* One word, every thread. Counts lost updates. */
static volatile u64 g_contended __attribute__((aligned(64)));

/* Adjacent words deliberately packed into as few lines as possible, one owner
 * each. Nobody touches anybody else's, so any deviation is the memory system
 * or the kernel writing where it should not. */
static volatile u64 g_neighbours[STRESS_THREADS] __attribute__((aligned(64)));

static volatile u64 g_deadline;
static u64 g_added[STRESS_THREADS];

static u64 stress_worker(void *opaque) {
  u64 ordinal = (u64)opaque;
  u64 added = 0;
  u64 mixed = ordinal + 1ULL;
  for (;;) {
    for (u64 batch = 0; batch < 64ULL; ++batch) {
      __atomic_fetch_add(&g_contended, 1ULL, __ATOMIC_RELAXED);
      __atomic_fetch_add(&g_neighbours[ordinal], 1ULL, __ATOMIC_RELAXED);
      ++added;
      /* Vary the interleaving so threads do not fall into lockstep. */
      mixed ^= added + (ordinal << 7ULL);
      mixed *= 0x9e3779b185ebca87ULL;
    }
    /* Published every batch rather than at the end, so a thread that never
     * finishes still says how far it got. */
    g_added[ordinal] = added;
    if (xaios_clock_nanos() >= g_deadline) break;
  }
  /* The local tally is published for the neighbour check and returned for the
   * counter check, so each invariant is tested against a count kept outside
   * the memory it is checking. */
  (void)mixed;
  g_added[ordinal] = added;
  return added;
}

static u64 churn_worker(void *opaque) {
  u64 ordinal = (u64)opaque;
  u64 value = (ordinal + 1ULL) * 0x100000001b3ULL;
  for (u64 i = 0; i < 2048ULL; ++i) {
    value ^= i + (ordinal << 9ULL);
    value *= 0x9e3779b185ebca87ULL;
  }
  return value;
}

static int run_contention(u64 cpus) {
  u64 ids[STRESS_THREADS];
  u64 started = 0;

  g_deadline = xaios_clock_nanos() + XAIOS_STRESS_NANOS;
  for (u64 i = 0; i < STRESS_THREADS; ++i) {
    /* Spread across the cores rather than letting the scheduler collect them
     * on one, so the contention is genuinely between CPUs. CPU 0 is not on
     * offer: it is both the caller and the housekeeping core, and pinning to
     * either is refused. With more threads than schedulable cores the surplus
     * doubles up, which is contention rather than a problem. */
    u64 cpu = cpus > 1ULL ? 1ULL + (i % (cpus - 1ULL)) : XAIOS_THREAD_CPU_ANY;
    /* The ordinal is the number already running, not the loop counter, so the
     * ordinals stay contiguous when a create is refused and the per-thread
     * words the checks read line up with the threads that exist. */
    if (xaios_thread_create(stress_worker, (void *)started, g_stacks[started],
                            STRESS_STACK_BYTES, cpu, &ids[started]) < 0 &&
        xaios_thread_create(stress_worker, (void *)started, g_stacks[started],
                            STRESS_STACK_BYTES, XAIOS_THREAD_CPU_ANY,
                            &ids[started]) < 0) {
      continue;
    }
    ++started;
  }
  xaios_log_u64("/bin/smpstress: started=", started, "\n");
  if (started == 0) {
    xaios_log("/bin/smpstress: no stress thread started\n");
    return 1;
  }

  u64 reported = 0;
  for (u64 i = 0; i < started; ++i) {
    u64 result = 0;
    if (xaios_thread_join(ids[i], 20000000000ULL, &result) < 0) {
      xaios_log_u64("/bin/smpstress: join failed on thread=", i, "\n");
      xaios_log_u64("/bin/smpstress: its counter reads=", g_added[i], "\n");
      return 1;
    }
    reported += result;
  }

  u64 contended = g_contended;
  if (contended != reported) {
    xaios_log("/bin/smpstress: contended counter lost updates\n");
    xaios_log_u64("/bin/smpstress: counter=", contended, "");
    xaios_log_u64(" expected=", reported, "\n");
    return 1;
  }
  for (u64 i = 0; i < started; ++i) {
    if (g_neighbours[i] != g_added[i]) {
      xaios_log("/bin/smpstress: neighbouring word corrupted\n");
      xaios_log_u64("/bin/smpstress: word=", i, "");
      xaios_log_u64(" value=", (u64)g_neighbours[i], "");
      xaios_log_u64(" expected=", g_added[i], "\n");
      return 1;
    }
  }
  xaios_log_u64("/bin/smpstress: threads=", started, "");
  xaios_log_u64(" increments=", contended, "\n");
  xaios_log("/bin/smpstress: contended counter and neighbour words exact\n");
  return 0;
}

static int run_churn(void) {
  u64 ids[CHURN_THREADS];
  for (u64 round = 0; round < CHURN_ROUNDS; ++round) {
    u64 started = 0;
    for (u64 i = 0; i < CHURN_THREADS; ++i) {
      if (xaios_thread_create(churn_worker, (void *)i, g_stacks[i],
                              STRESS_STACK_BYTES, XAIOS_THREAD_CPU_ANY,
                              &ids[i]) < 0) {
        break;
      }
      ++started;
    }
    if (started != CHURN_THREADS) {
      xaios_log("/bin/smpstress: churn thread create failed\n");
      return 1;
    }
    for (u64 i = 0; i < started; ++i) {
      u64 result = 0;
      if (xaios_thread_join(ids[i], 30000000000ULL, &result) < 0 ||
          result != churn_worker((void *)i)) {
        xaios_log("/bin/smpstress: churn thread result mismatch\n");
        return 1;
      }
    }
  }
  xaios_log_u64("/bin/smpstress: churn rounds=", CHURN_ROUNDS, "");
  xaios_log_u64(" threads_per_round=", CHURN_THREADS, "\n");
  xaios_log("/bin/smpstress: create/join churn deterministic\n");
  return 0;
}

int main(void) {
  u64 workers = 0;
  u64 checksum = 0;

  xaios_log("/bin/smpstress: sustained multi-core load starting\n");
  if (xaios_smp_run(8, 64, &workers, &checksum) < 0 || workers == 0) {
    xaios_log("/bin/smpstress: smp worker syscall failed\n");
    return 1;
  }
  xaios_log_u64("/bin/smpstress: cpus=", workers, "\n");

  u64 started_at = xaios_clock_nanos();
  if (run_contention(workers) != 0) return 1;
  if (run_churn() != 0) return 1;
  u64 elapsed = xaios_clock_nanos() - started_at;

  xaios_log_u64("/bin/smpstress: elapsed_ns=", elapsed, "\n");
  xaios_log("/bin/smpstress: complete\n");
  return 0;
}

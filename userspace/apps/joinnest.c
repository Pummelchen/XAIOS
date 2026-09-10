/* A join that has to run a thread inside itself, and a check that the CPU
 * came back the way it was found.
 *
 * B-02's shape is a worker entered from *inside* a process's own
 * `xaios_thread_join`. `thread_join_owned` runs pending work on the joining
 * CPU while it waits, so the worker borrows a CPU that already has a current
 * process bound and that process's address space active. A worker that clears
 * the CPU to the kernel on the way out leaves the outer syscall with neither:
 * every later capability check on it is refused and every user pointer it
 * touches resolves in the wrong space. Nothing in the join reports an error,
 * because nothing in the join asked.
 *
 * That window is narrow and no existing test reaches it. `/bin/smpstress`
 * enters the nested path -- it is a loaded machine with more threads than
 * cores -- but every nested run it produces is a kernel-side join with no
 * process bound, so the CPU had nothing to lose and the defect changes
 * nothing. A test of B-02 has to arrange a *user* process to be the one
 * waiting.
 *
 * This does it deliberately, in three moves:
 *
 *   1. The helper thread is pinned to one worker CPU and starts running
 *      there. A worker CPU runs one thread to completion, so for as long as
 *      the helper is on it nothing else on that CPU will run.
 *   2. `main`, on a different CPU, pins the victim thread to the *same* CPU.
 *      It cannot start: the helper is holding the CPU. It sits pending.
 *   3. The helper joins the victim. The only way that join can ever return is
 *      by running the victim itself, nested inside its own syscall -- which
 *      is the window, with a user process bound and its address space live.
 *
 * The helper then checks the two things the defect breaks, in the order it
 * breaks them: a capability-checked syscall (refused outright once the
 * current-process binding is gone) and a syscall that reads and writes
 * through user pointers (resolved against the kernel's address space instead
 * of the process's). It reports what it found; `main` reports what the helper
 * returned.
 *
 * A process pinning both threads to its own CPU would be simpler and does not
 * work: `select_user_cpu` refuses `preferred_cpu == current_cpu`, so a thread
 * can never be placed on the CPU asking for it. The nesting has to come from
 * a thread already running on the target, which is what the helper is for.
 *
 * Every step that can fail names itself, because "the join went wrong" is
 * exactly the report B-02 has twice been filed as.
 */

#include <xaios_user.h>

#define JOIN_STACK_BYTES 16384ULL
#define VICTIM_MAGIC 0x5ec0ffee5ec0ffeeULL
#define HELPER_MAGIC 0x600d600d600d600dULL
#define WAIT_NANOS 10000000000ULL
#define JOIN_TIMEOUT_NANOS 20000000000ULL

/* Which step failed, reported as a number so the message is one line and the
 * gate can pin it. Zero is "nothing failed yet". */
#define HELPER_FAIL_NO_VICTIM_ID 1ULL
#define HELPER_FAIL_VICTIM_ALREADY_RAN 2ULL
#define HELPER_FAIL_JOIN_REFUSED 3ULL
#define HELPER_FAIL_WRONG_RESULT 4ULL
#define HELPER_FAIL_VICTIM_NEVER_RAN 5ULL
#define HELPER_FAIL_CONTEXT_LOST 6ULL

static unsigned char g_helper_stack[JOIN_STACK_BYTES]
    __attribute__((aligned(16)));
static unsigned char g_victim_stack[JOIN_STACK_BYTES]
    __attribute__((aligned(16)));

/* The handshake. All four are written by one side and read by the other, so
 * they are touched through the atomic builtins rather than trusted to
 * ordinary loads: the two threads are on different CPUs. */
static volatile u64 g_helper_running;
static volatile u64 g_victim_id;
static volatile u64 g_victim_ran;
static volatile u64 g_helper_failure;

/* What the helper saw after the nested join, for main to print. A helper
 * whose process context has been lost cannot log anything itself -- the log
 * syscall is capability-checked and would be the first thing refused -- so
 * the evidence has to survive in memory for someone else to report. */
static volatile u64 g_helper_post_join_cpus;

static u64 victim_thread(void *opaque) {
  (void)opaque;
  /* Published before anything else: the helper checks this before its join
     and after it, and the pair is what proves the victim ran *during* the
     join rather than beside it. */
  __atomic_store_n(&g_victim_ran, 1ULL, __ATOMIC_RELEASE);
  /* A syscall from inside the nested worker. It only succeeds if the worker
     has the process bound, which is what makes this run a user-owned nested
     run rather than the kernel-side kind smpstress produces. */
  xaios_log("/bin/joinnest: victim thread running nested\n");
  u64 value = VICTIM_MAGIC;
  for (u64 index = 0; index < 256ULL; ++index) {
    value ^= index;
    value = (value << 1ULL) | (value >> 63ULL);
  }
  (void)value;
  return VICTIM_MAGIC;
}

static u64 helper_thread(void *opaque) {
  (void)opaque;
  __atomic_store_n(&g_helper_running, 1ULL, __ATOMIC_RELEASE);

  u64 deadline = xaios_clock_nanos() + WAIT_NANOS;
  u64 victim = 0;
  for (;;) {
    victim = __atomic_load_n(&g_victim_id, __ATOMIC_ACQUIRE);
    if (victim != 0ULL) break;
    if (xaios_clock_nanos() >= deadline) {
      __atomic_store_n(&g_helper_failure, HELPER_FAIL_NO_VICTIM_ID,
                       __ATOMIC_RELEASE);
      return 0ULL;
    }
  }

  /* If the victim has already run, this CPU was not held the way the test
     assumes and the join below will return without nesting anything. That is
     a test that proves nothing, so it is a failure rather than a pass. */
  if (__atomic_load_n(&g_victim_ran, __ATOMIC_ACQUIRE) != 0ULL) {
    __atomic_store_n(&g_helper_failure, HELPER_FAIL_VICTIM_ALREADY_RAN,
                     __ATOMIC_RELEASE);
    return 0ULL;
  }

  u64 result = 0;
  int status = xaios_thread_join(victim, JOIN_TIMEOUT_NANOS, &result);
  if (status < 0) {
    __atomic_store_n(&g_helper_failure, HELPER_FAIL_JOIN_REFUSED,
                     __ATOMIC_RELEASE);
    return 0ULL;
  }
  if (result != VICTIM_MAGIC) {
    __atomic_store_n(&g_helper_failure, HELPER_FAIL_WRONG_RESULT,
                     __ATOMIC_RELEASE);
    return 0ULL;
  }
  if (__atomic_load_n(&g_victim_ran, __ATOMIC_ACQUIRE) == 0ULL) {
    __atomic_store_n(&g_helper_failure, HELPER_FAIL_VICTIM_NEVER_RAN,
                     __ATOMIC_RELEASE);
    return 0ULL;
  }

  /* The two things the defect breaks.
   *
   * The log is capability-checked and hands the kernel a user pointer to
   * read, so it fails both ways at once: an unbound CPU refuses it for
   * missing XAIOS_CAP_LOG, and a CPU left in the kernel's address space
   * cannot resolve the string. The SMP call is checked against a different
   * capability and writes two user pointers, so it says the same thing about
   * the other direction. */
  xaios_log("/bin/joinnest: victim ran inside the join\n");
  u64 cpus = 0;
  u64 checksum = 0;
  if (xaios_smp_run(64, 32, &cpus, &checksum) < 0 || cpus == 0ULL ||
      checksum == 0ULL) {
    __atomic_store_n(&g_helper_failure, HELPER_FAIL_CONTEXT_LOST,
                     __ATOMIC_RELEASE);
    return 0ULL;
  }
  __atomic_store_n(&g_helper_post_join_cpus, cpus, __ATOMIC_RELEASE);
  xaios_log("/bin/joinnest: process context intact after nested join\n");
  return HELPER_MAGIC;
}

static void report_helper_failure(void) {
  u64 failure = __atomic_load_n(&g_helper_failure, __ATOMIC_ACQUIRE);
  xaios_log_u64("/bin/joinnest: helper reported failure step=", failure, "\n");
  switch (failure) {
    case HELPER_FAIL_NO_VICTIM_ID:
      xaios_log("/bin/joinnest: helper never saw a victim to join\n");
      break;
    case HELPER_FAIL_VICTIM_ALREADY_RAN:
      xaios_log("/bin/joinnest: victim ran before the join; not nested\n");
      break;
    case HELPER_FAIL_JOIN_REFUSED:
      xaios_log("/bin/joinnest: nested join returned an error\n");
      break;
    case HELPER_FAIL_WRONG_RESULT:
      xaios_log("/bin/joinnest: nested join returned the wrong value\n");
      break;
    case HELPER_FAIL_VICTIM_NEVER_RAN:
      xaios_log("/bin/joinnest: join returned without running the victim\n");
      break;
    case HELPER_FAIL_CONTEXT_LOST:
      xaios_log("/bin/joinnest: process context lost across nested join\n");
      break;
    default:
      xaios_log("/bin/joinnest: helper stopped without saying why\n");
      break;
  }
}

int main(void) {
  u64 cpus = 0;
  u64 checksum = 0;

  xaios_log("/bin/joinnest: nested thread join starting\n");
  if (xaios_smp_run(64, 64, &cpus, &checksum) < 0 || cpus == 0ULL) {
    xaios_log("/bin/joinnest: smp worker syscall failed\n");
    return 1;
  }
  /* The count the guest was actually given, said by the workload rather than
     assumed by whoever started it. A gate that asked for four CPUs and got
     one would otherwise read a boot that could not reach the window at all as
     a boot that reached it and found nothing. */
  xaios_log_u64("/bin/joinnest: cpus=", cpus, "\n");
  if (cpus < 2ULL) {
    /* One CPU has no second core to pin a thread to, so there is no nested
       path to enter. Nothing failed; there was nothing to test. */
    xaios_log("/bin/joinnest: single cpu, nested join window unreachable\n");
    return 0;
  }

  /* Which CPU will hold both threads.
   *
   * Asked for by trying rather than computed: the current CPU is refused, a
   * housekeeping core is refused, and CPU identifiers are not always dense --
   * RISC-V under UEFI loses a hart to firmware, so "cpus=4" does not mean the
   * identifiers are 0..3. The first identifier that accepts a pinned create
   * is the one that gets used, and the search runs past the count for that
   * reason. */
  u64 helper_id = 0;
  u64 helper_cpu = 0;
  u64 found = 0;
  for (u64 candidate = 0; candidate < cpus + 8ULL; ++candidate) {
    if (xaios_thread_create(helper_thread, 0, g_helper_stack,
                            JOIN_STACK_BYTES, candidate, &helper_id) == 0) {
      helper_cpu = candidate;
      found = 1;
      break;
    }
  }
  if (found == 0ULL) {
    xaios_log("/bin/joinnest: no CPU accepted a pinned thread\n");
    return 1;
  }
  xaios_log_u64("/bin/joinnest: helper_cpu=", helper_cpu, "\n");

  /* Wait for the helper to be running before the victim is created. A victim
     created first could be picked up by that CPU's own dispatch loop, run
     beside the helper rather than inside its join, and leave a green run that
     never entered the window. */
  u64 deadline = xaios_clock_nanos() + WAIT_NANOS;
  while (__atomic_load_n(&g_helper_running, __ATOMIC_ACQUIRE) == 0ULL) {
    if (xaios_clock_nanos() >= deadline) {
      xaios_log("/bin/joinnest: helper thread never started\n");
      return 1;
    }
  }

  /* Same CPU, on purpose. The pinned path does not ask whether the CPU is
     busy -- only the round-robin one does -- so this is accepted and queued
     behind the helper, which is exactly the state the join has to resolve. */
  u64 victim_id = 0;
  if (xaios_thread_create(victim_thread, 0, g_victim_stack, JOIN_STACK_BYTES,
                          helper_cpu, &victim_id) < 0 || victim_id == 0ULL) {
    xaios_log("/bin/joinnest: victim thread create failed\n");
    return 1;
  }
  if (__atomic_load_n(&g_victim_ran, __ATOMIC_ACQUIRE) != 0ULL) {
    xaios_log("/bin/joinnest: victim ran before the join; not nested\n");
    return 1;
  }
  xaios_log_u64("/bin/joinnest: victim pinned to cpu=", helper_cpu, "\n");
  __atomic_store_n(&g_victim_id, victim_id, __ATOMIC_RELEASE);

  u64 helper_result = 0;
  if (xaios_thread_join(helper_id, JOIN_TIMEOUT_NANOS, &helper_result) < 0) {
    xaios_log("/bin/joinnest: helper join failed\n");
    report_helper_failure();
    return 1;
  }
  if (helper_result != HELPER_MAGIC) {
    report_helper_failure();
    return 1;
  }

  /* main's own context, checked the same way after the whole exchange. Its
     CPU was never the one borrowed, so this is the cheap half of the claim
     rather than the point of it. */
  u64 final_cpus = 0;
  u64 final_checksum = 0;
  if (xaios_smp_run(64, 32, &final_cpus, &final_checksum) < 0 ||
      final_cpus != cpus) {
    xaios_log("/bin/joinnest: caller context wrong after the exchange\n");
    return 1;
  }
  if (__atomic_load_n(&g_victim_ran, __ATOMIC_ACQUIRE) == 0ULL ||
      __atomic_load_n(&g_helper_post_join_cpus, __ATOMIC_ACQUIRE) != cpus) {
    xaios_log("/bin/joinnest: the exchange did not happen as reported\n");
    return 1;
  }

  /* Everything the run has to be judged on, on one line and printed with
     every other CPU idle.

     The step markers above are printed while the worker CPU is starting or
     finishing a thread, and the kernel logs that from its own CPU: two CPUs
     writing the console at once, which this boot has already been seen to
     drop a line of. A gate that requires a line printed into that window is
     a gate that goes red for console timing. This one is printed after both
     threads are gone, when nothing else is logging, and it carries the
     figures the claim rests on rather than pointing at them. */
  /* One CPU number, not two. Both threads asked for this one, and a pinned
     create either places the thread on the CPU it named or fails -- so a
     second field saying the victim landed where it was sent would be this
     program agreeing with itself rather than evidence. */
  xaios_log_u64("/bin/joinnest: nested join summary cpus=", cpus, "");
  xaios_log_u64(" pinned_cpu=", helper_cpu, "");
  xaios_log_u64(" helper_thread=", helper_id, "");
  xaios_log_u64(" victim_thread=", victim_id, "");
  xaios_log(" ran_nested=1\n");
  xaios_log("/bin/joinnest: nested join kept its process context\n");
  xaios_log("/bin/joinnest: complete\n");
  return 0;
}

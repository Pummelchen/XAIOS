/*
 * Measure what XAIOS costs to use, on whatever cores it is given.
 *
 * Every performance number this project has is a counter -- syscalls executed,
 * pages free, gates passed -- which says what happened and nothing about what
 * it cost. That was tolerable while nothing measured could be trusted anyway:
 * until secondary CPUs actually came online, a multi-core figure described one
 * core with the others idle.
 *
 * Two questions this answers directly.
 *
 * How expensive is a syscall, and does that change when several cores make
 * them at once? A syscall that costs the same at eight threads as at one is
 * scaling; one that costs eight times as much is serialised somewhere.
 *
 * What did the coarse subsystem guards cost? The network stack, the service
 * records and the CPU-AI runtime were serialised to make them correct under
 * parallelism, and correctness was the right thing to buy first -- but the
 * price has never been measured. The network case is measured here by opening
 * and closing sockets from several threads at once, which is exactly the path
 * that now takes a single guard.
 *
 * Numbers from an emulator mean nothing; numbers from a hypervisor on real
 * cores mean something about those cores and nothing about a datacentre part.
 * Neither is a performance claim under docs/BENCHMARK-CONTRACT.md.
 */

#include <xaios_user.h>

#define BENCH_THREADS 8U
#define BENCH_STACK_BYTES 65536U
#define SYSCALL_ITERATIONS 20000U
#define SOCKET_ITERATIONS 400U
#define CHURN_ITERATIONS 64U

static unsigned char g_stacks[BENCH_THREADS][BENCH_STACK_BYTES];
static u64 g_elapsed[BENCH_THREADS];
static u64 g_operations[BENCH_THREADS];

/* A syscall whose only job is to cross the boundary and come back, so what is
   measured is the crossing rather than the work. */
static u64 syscall_loop(u64 iterations) {
  u64 started = xaios_clock_nanos();
  for (u64 i = 0; i < iterations; ++i) {
    (void)xaios_clock_nanos();
  }
  return xaios_clock_nanos() - started;
}

static u64 syscall_worker(void *argument) {
  u64 ordinal = (u64)argument;
  if (ordinal >= BENCH_THREADS) return 0;
  g_elapsed[ordinal] = syscall_loop(SYSCALL_ITERATIONS);
  g_operations[ordinal] = SYSCALL_ITERATIONS;
  return 0;
}

/* Bind and close a UDP socket repeatedly. Both ends of that pair enter the
   network stack, which since C-01 is serialised behind one guard, so several
   threads doing this at once is the contention that guard actually sees. */
static u64 socket_worker(void *argument) {
  u64 ordinal = (u64)argument;
  if (ordinal >= BENCH_THREADS) return 0;
  u64 started = xaios_clock_nanos();
  u64 completed = 0;
  for (u64 i = 0; i < SOCKET_ITERATIONS; ++i) {
    u64 handle = 0;
    if (xaios_net_bind_udp(20000U + ordinal * 512U + (i & 0x1ffU), &handle) < 0) {
      continue;
    }
    (void)xaios_net_close(handle);
    ++completed;
  }
  g_elapsed[ordinal] = xaios_clock_nanos() - started;
  g_operations[ordinal] = completed;
  return 0;
}

static void report(const char *name, u64 threads) {
  u64 total_ops = 0;
  u64 slowest = 0;
  for (u64 i = 0; i < threads; ++i) {
    total_ops += g_operations[i];
    if (g_elapsed[i] > slowest) slowest = g_elapsed[i];
  }
  if (total_ops == 0 || slowest == 0) {
    xaios_log("/bin/perfbench: ");
    xaios_log(name);
    xaios_log(" produced no completed operations\n");
    return;
  }
  /* Wall clock is the slowest thread: that is how long the work took with all
     of them running, which is the number that reflects serialisation. */
  xaios_log("/bin/perfbench: ");
  xaios_log(name);
  xaios_log_u64(" threads=", threads, "");
  xaios_log_u64(" ops=", total_ops, "");
  xaios_log_u64(" ns_per_op=", slowest / (total_ops / threads), "");
  xaios_log_u64(" wall_ns=", slowest, "\n");
}

static u64 run_parallel(u64 (*worker)(void *), u64 threads, const char *name) {
  u64 ids[BENCH_THREADS];
  u64 started = 0;
  for (u64 i = 0; i < threads && i < BENCH_THREADS; ++i) {
    g_elapsed[i] = 0;
    g_operations[i] = 0;
    if (xaios_thread_create(worker, (void *)started, g_stacks[started],
                            BENCH_STACK_BYTES, XAIOS_THREAD_CPU_ANY,
                            &ids[started]) < 0) {
      continue;
    }
    ++started;
  }
  for (u64 i = 0; i < started; ++i) {
    u64 result = 0;
    (void)xaios_thread_join(ids[i], 0, &result);
  }
  if (started != 0) report(name, started);
  return started;
}

int main(void) {
  xaios_log("/bin/perfbench: measuring syscall and subsystem cost\n");

  /* One thread first, so the parallel figures have something to divide by. */
  g_elapsed[0] = syscall_loop(SYSCALL_ITERATIONS);
  g_operations[0] = SYSCALL_ITERATIONS;
  report("syscall", 1);

  (void)run_parallel(syscall_worker, 4, "syscall");
  (void)run_parallel(syscall_worker, BENCH_THREADS, "syscall");

  g_elapsed[0] = 0;
  g_operations[0] = 0;
  (void)socket_worker((void *)0);
  report("socket_bind_close", 1);

  (void)run_parallel(socket_worker, 4, "socket_bind_close");
  (void)run_parallel(socket_worker, BENCH_THREADS, "socket_bind_close");

  /* Thread creation and teardown, which every parallel workload pays before it
     does anything useful. */
  u64 churn_started = xaios_clock_nanos();
  u64 churned = 0;
  for (u64 i = 0; i < CHURN_ITERATIONS; ++i) {
    u64 id = 0;
    if (xaios_thread_create(syscall_worker, (void *)BENCH_THREADS, g_stacks[0],
                            BENCH_STACK_BYTES, XAIOS_THREAD_CPU_ANY, &id) < 0) {
      continue;
    }
    u64 result = 0;
    (void)xaios_thread_join(id, 0, &result);
    ++churned;
  }
  u64 churn_ns = xaios_clock_nanos() - churn_started;
  if (churned != 0) {
    xaios_log_u64("/bin/perfbench: thread_create_join ops=", churned, "");
    xaios_log_u64(" ns_per_op=", churn_ns / churned, "\n");
  }

  xaios_log("/bin/perfbench: complete\n");
  return 0;
}

/*
 * CPU time accounting, idle waiting and process observation.
 *
 * Split out of kernel/user/user.c, which was 1512 lines. The per-CPU usage
 * records and the per-process statistics are the same accounting; the
 * current-process bindings and the counters that report on them are read
 * through here.
 */

#include "user_internal.h"

typedef struct xaios_cpu_usage_record {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint32_t sequence;
  uint32_t reserved;
  uint64_t busy_ns;
  uint64_t active_since_ns;
} xaios_cpu_usage_record_t;

static xaios_cpu_usage_record_t *g_cpu_usage;
static uint32_t g_cpu_usage_count;
static uint32_t g_cpu_usage_capacity;
static xaios_spinlock_t g_cpu_usage_lock;
static uint64_t g_cpu_usage_started_ns;

/* The records are appended in the order CPUs turn up and searched linearly:
   there are at most as many as the platform has CPUs, and an unsorted
   append is what lets a CPU register after the table exists without a
   reader ever seeing it half-moved. */
static xaios_cpu_usage_record_t *find_cpu_usage(uint32_t cpu_id) {
  uint32_t count = __atomic_load_n(&g_cpu_usage_count, __ATOMIC_ACQUIRE);
  for (uint32_t i = 0U; i < count; ++i) {
    if (g_cpu_usage[i].cpu_id == cpu_id) return &g_cpu_usage[i];
  }
  return 0;
}

/* A CPU's record, made on first use if it has none.
 *
 * The table used to be built once, from the CPUs online when the process
 * table was initialised, and that is every CPU on AArch64 and x86-64 -- their
 * secondaries are up before then. RISC-V starts its secondaries later, at the
 * scheduler rendezvous, so the table held one record and the process monitor
 * reported a four-hart machine as having one CPU. A CPU that runs a process
 * is a CPU, whenever it arrived; it gets its record then. */
static xaios_cpu_usage_record_t *cpu_usage_for(uint32_t cpu_id) {
  xaios_cpu_usage_record_t *usage = find_cpu_usage(cpu_id);
  if (usage != 0 || g_cpu_usage == 0) return usage;
  xaios_spin_lock(&g_cpu_usage_lock);
  usage = find_cpu_usage(cpu_id);
  if (usage == 0 && g_cpu_usage_count < g_cpu_usage_capacity) {
    usage = &g_cpu_usage[g_cpu_usage_count];
    bytes_zero(usage, sizeof(*usage));
    usage->cpu_id = cpu_id;
    __atomic_store_n(&g_cpu_usage_count, g_cpu_usage_count + 1U,
                     __ATOMIC_RELEASE);
  }
  xaios_spin_unlock(&g_cpu_usage_lock);
  return usage;
}

static void process_runtime_write_begin(xaios_user_process_t *process) {
  __sync_fetch_and_add(&process->runtime_sequence, 1U);
  __sync_synchronize();
}

static void process_runtime_write_end(xaios_user_process_t *process) {
  __sync_synchronize();
  __sync_fetch_and_add(&process->runtime_sequence, 1U);
}

static void cpu_usage_write_begin(xaios_cpu_usage_record_t *usage) {
  __sync_fetch_and_add(&usage->sequence, 1U);
  __sync_synchronize();
}

static void cpu_usage_write_end(xaios_cpu_usage_record_t *usage) {
  __sync_synchronize();
  __sync_fetch_and_add(&usage->sequence, 1U);
}

static uint64_t process_runtime_read(const xaios_user_process_t *process,
                                     uint64_t now_ns) {
  uint64_t runtime;
  uint64_t running_since;
  uint32_t before;
  uint32_t after;
  do {
    before = __atomic_load_n(&process->runtime_sequence, __ATOMIC_ACQUIRE);
    if ((before & 1U) != 0U) {
      /* A writer is mid-update. Force the retry through a defined value
         rather than letting the loop test read an unwritten `after`. */
      after = before;
      continue;
    }
    runtime = process->runtime_ns;
    running_since = process->running_since_ns;
    after = __atomic_load_n(&process->runtime_sequence, __ATOMIC_ACQUIRE);
  } while (before != after || (after & 1U) != 0U);
  if (running_since != 0U && now_ns > running_since) {
    runtime += now_ns - running_since;
  }
  return runtime;
}

static uint64_t cpu_usage_read(const xaios_cpu_usage_record_t *usage,
                               uint64_t now_ns, uint32_t *active_pid) {
  uint64_t busy;
  uint64_t active_since;
  uint32_t active;
  uint32_t before;
  uint32_t after;
  do {
    before = __atomic_load_n(&usage->sequence, __ATOMIC_ACQUIRE);
    if ((before & 1U) != 0U) {
      /* Same defined-retry as the runtime reader above. */
      after = before;
      continue;
    }
    busy = usage->busy_ns;
    active_since = usage->active_since_ns;
    active = usage->active_pid;
    after = __atomic_load_n(&usage->sequence, __ATOMIC_ACQUIRE);
  } while (before != after || (after & 1U) != 0U);
  if (active_since != 0U && now_ns > active_since) {
    busy += now_ns - active_since;
  }
  if (active_pid != 0) {
    *active_pid = active;
  }
  return busy;
}

void user_process_runtime_start(uint32_t pid, uint32_t cpu_id,
                                uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || now_ns == 0U) {
    return;
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = cpu_usage_for(cpu_id);
  if (process->pid != pid || usage == 0) {
    return;
  }

  process_runtime_write_begin(process);
  if (process->running_since_ns == 0U) {
    process->running_since_ns = now_ns;
    process->running_cpu_id = cpu_id;
  }
  process_runtime_write_end(process);

  cpu_usage_write_begin(usage);
  if (usage->active_pid == 0U) {
    usage->active_pid = pid;
    usage->active_since_ns = now_ns;
  }
  cpu_usage_write_end(usage);
}

void user_process_runtime_stop(uint32_t pid, uint32_t cpu_id,
                               uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || now_ns == 0U) {
    return;
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = find_cpu_usage(cpu_id);
  if (process->pid != pid || usage == 0) {
    return;
  }

  process_runtime_write_begin(process);
  if (process->running_since_ns != 0U && now_ns > process->running_since_ns) {
    process->runtime_ns += now_ns - process->running_since_ns;
  }
  process->running_since_ns = 0U;
  process->running_cpu_id = cpu_id;
  process_runtime_write_end(process);

  cpu_usage_write_begin(usage);
  if (usage->active_pid == pid) {
    if (usage->active_since_ns != 0U && now_ns > usage->active_since_ns) {
      usage->busy_ns += now_ns - usage->active_since_ns;
    }
    usage->active_pid = 0U;
    usage->active_since_ns = 0U;
  }
  cpu_usage_write_end(usage);
}

void user_thread_runtime_start(uint32_t pid, uint32_t cpu_id,
                               uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || now_ns == 0U) return;
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = cpu_usage_for(cpu_id);
  if (process->pid != pid || usage == 0) return;

  cpu_usage_write_begin(usage);
  if (usage->active_pid == 0U) {
    usage->active_pid = pid;
    usage->active_since_ns = now_ns;
  }
  cpu_usage_write_end(usage);
}

void user_thread_runtime_stop(uint32_t pid, uint32_t cpu_id,
                              uint64_t started_ns, uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || started_ns == 0U ||
      now_ns <= started_ns) {
    return;
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = find_cpu_usage(cpu_id);
  if (process->pid != pid || usage == 0) return;

  __sync_fetch_and_add(&process->runtime_ns, now_ns - started_ns);
  cpu_usage_write_begin(usage);
  if (usage->active_pid == pid) {
    if (usage->active_since_ns != 0U && now_ns > usage->active_since_ns) {
      usage->busy_ns += now_ns - usage->active_since_ns;
    }
    usage->active_pid = 0U;
    usage->active_since_ns = 0U;
  }
  cpu_usage_write_end(usage);
}

/* Every CPU that is online has a record, whether or not it has run a process
   yet. Registering on first use alone left a hart that had not been handed a
   process out of the table, so a four-hart machine reported three CPUs
   depending on what the scheduler had done so far -- an answer that varied
   with timing is not a count. */
static void cpu_usage_sync_online(void) {
  uint32_t online = smp_online_count();
  for (uint32_t ordinal = 0U; ordinal < online; ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK) (void)cpu_usage_for(cpu_id);
  }
}

uint32_t user_cpu_usage_count(void) {
  cpu_usage_sync_online();
  return __atomic_load_n(&g_cpu_usage_count, __ATOMIC_ACQUIRE);
}

xaios_status_t user_cpu_usage_snapshot(
    uint32_t ordinal, uint64_t now_ns,
    xaios_cpu_usage_snapshot_t *snapshot) {
  if (snapshot == 0 || ordinal >= user_cpu_usage_count() || now_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  const xaios_cpu_usage_record_t *usage = &g_cpu_usage[ordinal];
  snapshot->cpu_id = usage->cpu_id;
  snapshot->busy_ns = cpu_usage_read(usage, now_ns, &snapshot->active_pid);
  snapshot->elapsed_ns = now_ns > g_cpu_usage_started_ns
                             ? now_ns - g_cpu_usage_started_ns
                             : 0U;
  return XAIOS_OK;
}

uint64_t user_cpu_busy_total(uint64_t now_ns) {
  uint64_t total = 0U;
  for (uint32_t ordinal = 0; ordinal < g_cpu_usage_count; ++ordinal) {
    uint64_t busy = cpu_usage_read(&g_cpu_usage[ordinal], now_ns, 0);
    if (UINT64_MAX - total < busy) {
      return UINT64_MAX;
    }
    total += busy;
  }
  return total;
}

/* The CPU-usage table, made once at boot from this side of the split.
 *
 * Room for every CPU the platform can have; records for the ones online now,
 * and the rest register themselves when they first run a process. The
 * summary line is logged here because the counts it reports live here. */
void user_cpu_usage_init(void) {
  g_cpu_usage_capacity = smp_capacity();
  if (g_cpu_usage_capacity < smp_online_count()) {
    g_cpu_usage_capacity = smp_online_count();
  }
  g_cpu_usage_count = 0U;
  xaios_spin_init(&g_cpu_usage_lock);
  g_cpu_usage = (xaios_cpu_usage_record_t *)kheap_calloc(
      (uint64_t)g_cpu_usage_capacity * sizeof(xaios_cpu_usage_record_t), 64U);
  kassert(g_cpu_usage_capacity == 0U || g_cpu_usage != 0);
  for (uint32_t ordinal = 0; ordinal < smp_online_count(); ++ordinal) {
    uint32_t cpu_id = 0;
    kassert(smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK);
    kassert(cpu_usage_for(cpu_id) != 0);
  }
  g_cpu_usage_started_ns = timer_now_ns();
  klog("user: process table initialized slots=%u cpu_usage_records=%u "
       "cpu_usage_capacity=%u\n",
       XAIOS_MAX_USER_PROCESSES, g_cpu_usage_count, g_cpu_usage_capacity);
}

static void user_process_idle_common(uint64_t deadline_ns, int wake_on_event) {
  xaios_user_process_t *process = g_current_process;
  uint32_t cpu_id = smp_cpu_id();
  uint64_t started_ns = timer_now_ns();
  if (deadline_ns <= started_ns) return;
  if (process != 0) {
    user_process_runtime_stop(process->pid, cpu_id, started_ns);
  }
  if (wake_on_event != 0) {
    timer_idle_until_event(deadline_ns);
  } else {
    timer_idle_until(deadline_ns);
  }
  if (process != 0) {
    user_process_runtime_start(process->pid, cpu_id, timer_now_ns());
  }
}

void user_process_idle_until(uint64_t deadline_ns) {
  user_process_idle_common(deadline_ns, 0);
}

void user_process_idle_until_event(uint64_t deadline_ns) {
  user_process_idle_common(deadline_ns, 1);
}

const xaios_user_process_t *user_current_process(void) {
  return g_current_process;
}

xaios_status_t user_bind_current_process(uint32_t pid) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->pid != pid || process->state == XAIOS_USER_PROCESS_EMPTY ||
      process->aspace.l3_count == 0U) {
    return XAIOS_ERR_INVALID;
  }
  g_current_process = process;
  return XAIOS_OK;
}

void user_clear_current_process(void) { g_current_process = 0; }

/* Every CPU's binding at once, for the case where one of them is not what the
   running program thinks it is.
   "missing-capability" with pid=0 says the binding on this CPU is empty; it
   does not say whether it was cleared, never set, or is simply not the CPU
   the program is running on -- and on a port where the trap path could get
   the hart id wrong, the third would look exactly like the first two. */
void user_current_process_debug(void) {
  klog("user:   binding table capacity=%u storage=%s cpu_now=%u boot_slot=%u\n",
       g_user_current_process_capacity,
       g_user_current_process_by_cpu != 0 ? "present" : "MISSING", smp_cpu_id(),
       g_user_boot_current_process != 0 ? g_user_boot_current_process->pid
                                        : 0U);
  for (uint32_t cpu = 0U; cpu < g_user_current_process_capacity;
       ++cpu) {
    const xaios_user_process_t *bound =
        g_user_current_process_by_cpu != 0
            ? g_user_current_process_by_cpu[cpu]
            : 0;
    klog("user:   cpu=%u bound_pid=%u name=%s\n", cpu,
         bound != 0 ? bound->pid : 0U,
         bound != 0 && bound->name != 0 ? bound->name : "(none)");
  }
}

xaios_status_t user_process_has_capability(uint64_t capability) {
  if (g_current_process == 0 ||
      (g_current_process->capability_mask & capability) != capability) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

void user_process_note_syscall(uint32_t rejected) {
  if (g_current_process != 0) {
    __sync_fetch_and_add(&g_current_process->syscall_count, 1U);
    if (rejected != 0) {
      __sync_fetch_and_add(&g_current_process->rejected_syscall_count, 1U);
    }
  }
}

uint64_t user_process_note_exit(int exit_code) {
  if (g_current_process != 0) {
    user_process_runtime_stop(g_current_process->pid, smp_cpu_id(),
                              timer_now_ns());
    /* A process that exits the way it was told to has not failed. The
       hosted C99 probes exist to exit 23 and to abort, the kernel asserts
       that they do, and the process table called both of them failures --
       so a machine on which everything had passed reported two failed
       tasks. */
    user_process_transition(g_current_process,
                            exit_code == g_current_process->expected_exit_code
                                ? XAIOS_USER_PROCESS_EXITED
                                : XAIOS_USER_PROCESS_FAILED,
                            exit_code);
  }
  return XAIOS_USER_EXIT_RETURN_MAGIC | ((uint64_t)(uint32_t)exit_code);
}

uint64_t user_process_note_fault(void) {
  if (g_current_process != 0) {
    klog("user: process fault pid=%u image=%s exit=%d\n",
         g_current_process->pid,
         g_current_process->name != 0 ? g_current_process->name : "unknown",
         XAIOS_USER_FAULT_EXIT_CODE);
  }
  return user_process_note_exit(XAIOS_USER_FAULT_EXIT_CODE);
}

xaios_status_t user_process_snapshot_at(uint32_t pid, uint64_t now_ns,
                                        xaios_user_process_t *process) {
  if (process == 0 || pid == 0 || pid > XAIOS_MAX_USER_PROCESSES ||
      now_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }

  const xaios_user_process_t *slot = &g_user_process_table[pid - 1U];
  if (slot->pid != pid || slot->state == XAIOS_USER_PROCESS_EMPTY) {
    return XAIOS_ERR_INVALID;
  }

  copy_process(process, slot);
  process->runtime_ns = process_runtime_read(slot, now_ns);
  return XAIOS_OK;
}

xaios_status_t user_process_snapshot(uint32_t pid,
                                     xaios_user_process_t *process) {
  return user_process_snapshot_at(pid, timer_now_ns(), process);
}

uint64_t user_process_transition_count(void) {
  return g_user_process_transition_count;
}

uint64_t user_process_loaded_count(void) {
  return g_user_process_loaded_count;
}

uint64_t user_process_runnable_count(void) {
  return g_user_process_runnable_count;
}

uint64_t user_process_running_count(void) {
  return g_user_process_running_count;
}

uint64_t user_process_waiting_count(void) {
  return g_user_process_waiting_count;
}

uint64_t user_process_exited_count(void) {
  return g_user_process_exited_count;
}

uint64_t user_process_failed_count(void) {
  return g_user_process_failed_count;
}

uint64_t user_process_current_failed_count(void) {
  uint64_t failed = 0U;
  for (uint32_t i = 0U; i < XAIOS_MAX_USER_PROCESSES; ++i) {
    if (g_user_process_table[i].state == XAIOS_USER_PROCESS_FAILED) ++failed;
  }
  return failed;
}

uint64_t user_process_reclaim_count(void) {
  return g_user_process_reclaim_count;
}

uint64_t user_process_scheduled_count(void) {
  return g_user_process_scheduled_count;
}

uint64_t user_process_wait_count(void) {
  return g_user_process_wait_count;
}

uint64_t user_process_wake_count(void) {
  return g_user_process_wake_count;
}

uint64_t user_process_active_count(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < XAIOS_MAX_USER_PROCESSES; ++i) {
    xaios_user_process_state_t state = g_user_process_table[i].state;
    if (state == XAIOS_USER_PROCESS_LOADED ||
        state == XAIOS_USER_PROCESS_RUNNABLE ||
        state == XAIOS_USER_PROCESS_RUNNING ||
        state == XAIOS_USER_PROCESS_WAITING) {
      ++active;
    }
  }
  return active;
}

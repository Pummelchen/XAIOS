#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/context.h>
#include <xaios/klog.h>
#include <xaios/kheap.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/numa.h>
#include <xaios/topology.h>
#include <xaios/user.h>
#if defined(__aarch64__)
#include <xaios/aarch64_sve.h>
#endif
#include "scheduler_internal.h"

/* Admiral Janeway — “Just enough to bring chaos to order.” */

/*
 * Hierarchical SMP Scheduler
 *
 * Key features:
 * - Per-CPU task tables (eliminates global lock contention)
 * - Hierarchical work-stealing (core → socket → NUMA → system)
 * - O(1) random task placement with NUMA awareness
 * - Periodic load balancing (every 1000 ticks = 10s at 100 Hz)
 * - Per-CPU statistics for telemetry
 */

xaios_cpu_task_table_t *g_cpu_tasks;
xaios_runqueue_t *g_runqueues;
xaios_sched_stats_t *g_sched_stats;
uint32_t g_cpu_capacity;

uint64_t g_tick_count;
uint64_t g_context_switch_count;
uint64_t g_yield_count;
uint64_t g_steal_count;
uint64_t g_load_average_q16[3];
uint64_t g_load_average_last_ns;
uint32_t g_load_average_guard;
uint32_t g_initialized;
static uint32_t *g_lock_depth_per_cpu;

/* Periodic load balancing counter */
uint32_t g_balance_counter;

void sched_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *destination, const void *source, uint64_t size) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (uint64_t i = 0U; i < size; ++i) output[i] = input[i];
}

static uint64_t architecture_state_size(void) {
#if defined(__aarch64__)
  return aarch64_sve_state_size();
#else
  return 0U;
#endif
}

void scheduler_init(void) {
  kassert(sizeof(xaios_context_frame_t) == XAIOS_CONTEXT_FRAME_SIZE);
  /* Initialize per-CPU task tables */
  uint32_t online = smp_online_count();
  g_cpu_capacity = smp_capacity();
  g_cpu_tasks = (xaios_cpu_task_table_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_cpu_tasks), 16U);
  g_runqueues = (xaios_runqueue_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_runqueues), 16U);
  g_sched_stats = (xaios_sched_stats_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_sched_stats), 16U);
  g_lock_depth_per_cpu = (uint32_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_lock_depth_per_cpu), 16U);
  kassert(g_cpu_tasks != 0 && g_runqueues != 0 && g_sched_stats != 0 &&
          g_lock_depth_per_cpu != 0);
  for (uint32_t cpu = 0; cpu < online; ++cpu) {
    sched_bytes_zero(&g_cpu_tasks[cpu], sizeof(xaios_cpu_task_table_t));
    xaios_spin_init(&g_runqueues[cpu].lock);
    g_runqueues[cpu].count = 0;
    g_runqueues[cpu].current_pid = 0;
    g_runqueues[cpu].cpu_id = cpu;
    g_runqueues[cpu].idle_ticks = 0;
    g_runqueues[cpu].busy_ticks = 0;
    sched_bytes_zero(&g_sched_stats[cpu], sizeof(xaios_sched_stats_t));
  }

  g_tick_count = 0;
  g_context_switch_count = 0;
  g_yield_count = 0;
  g_steal_count = 0;
  g_balance_counter = 0;
  for (uint32_t i = 0U; i < 3U; ++i) {
    g_load_average_q16[i] = 0U;
  }
  g_load_average_last_ns = timer_now_ns();
  g_load_average_guard = 0U;
  g_initialized = 1;

  klog("scheduler: hierarchical SMP initialized max_tasks=%u per_cpu_rq=%u "
       "per_cpu_slots=%u tick_hz=%u cpu_capacity=%u\n",
       XAIOS_SCHEDULER_MAX_TASKS, XAIOS_SCHEDULER_PER_CPU_RUNQUEUE,
       XAIOS_TASK_SLOTS_PER_CPU, XAIOS_SCHEDULER_DEFAULT_TICK_HZ,
       g_cpu_capacity);
}

xaios_status_t sched_register_on_cpu(
    uint32_t pid, xaios_task_priority_t priority, uint32_t cpu) {
  if (pid == 0 || pid > XAIOS_SCHEDULER_MAX_TASKS) {
    return XAIOS_ERR_INVALID;
  }
  if (cpu >= smp_online_count() || sched_find_task_global(pid, 0) != 0) {
    return XAIOS_ERR_BUSY;
  }
  xaios_sched_task_t *slot = sched_alloc_task_slot(cpu);
  if (slot == 0) {
    klog("scheduler: task table full on cpu%u, pid=%u\n", cpu, pid);
    return XAIOS_ERR_NO_MEMORY;
  }

  slot->pid = pid;
  slot->active = 1;
  slot->priority = priority;
  slot->state = XAIOS_TASK_STATE_REGISTERED;
  slot->remaining_ticks = sched_priority_slice(priority);
  slot->assigned_cpu = cpu;
  slot->architecture_state_size = architecture_state_size();
  if (slot->architecture_state_size != 0U) {
    slot->architecture_state =
        kheap_calloc(slot->architecture_state_size, 64U);
    if (slot->architecture_state == 0) {
      sched_free_task_slot(cpu, slot);
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  klog("scheduler: registered pid=%u priority=%u cpu=%u\n",
       pid, (unsigned)priority, cpu);
  return XAIOS_OK;
}

xaios_status_t scheduler_register(uint32_t pid) {
  return scheduler_register_with_priority(pid, XAIOS_PRIORITY_NORMAL);
}

xaios_status_t scheduler_register_with_priority(uint32_t pid,
                                                xaios_task_priority_t priority) {
  return sched_register_on_cpu(pid, priority, sched_find_least_loaded_cpu());
}

void scheduler_unregister(uint32_t pid) {
  uint32_t cpu = 0;
  xaios_sched_task_t *task = sched_find_task_global(pid, &cpu);
  if (task == 0) {
    return;
  }

  uint32_t assigned = task->assigned_cpu;
  task->active = 0;
  task->state = XAIOS_TASK_STATE_UNUSED;
  sched_free_task_slot(cpu, task);

  if (assigned < g_cpu_capacity) {
    xaios_spin_lock(&g_runqueues[assigned].lock);
    sched_rq_remove(&g_runqueues[assigned], pid);
    if (g_runqueues[assigned].current_pid == pid) {
      user_process_runtime_stop(pid, assigned, timer_now_ns());
      g_runqueues[assigned].current_pid = 0;
    }
    xaios_spin_unlock(&g_runqueues[assigned].lock);
  }
  klog("scheduler: unregistered pid=%u\n", pid);
}

xaios_status_t scheduler_set_runnable(uint32_t pid) {
  uint32_t cpu = 0;
  xaios_sched_task_t *task = sched_find_task_global(pid, &cpu);
  if (task == 0) {
    return XAIOS_ERR_INVALID;
  }

  task->state = XAIOS_TASK_STATE_RUNNABLE;
  task->remaining_ticks = sched_priority_slice(task->priority);
  uint32_t assigned = task->assigned_cpu;

  if (assigned < g_cpu_capacity) {
    xaios_spin_lock(&g_runqueues[assigned].lock);
    sched_rq_add(&g_runqueues[assigned], pid);
    xaios_spin_unlock(&g_runqueues[assigned].lock);
  }
  return XAIOS_OK;
}

xaios_status_t scheduler_set_blocked(uint32_t pid) {
  uint32_t cpu = 0;
  xaios_sched_task_t *task = sched_find_task_global(pid, &cpu);
  if (task == 0) {
    return XAIOS_ERR_INVALID;
  }

  task->state = XAIOS_TASK_STATE_BLOCKED;
  uint32_t assigned = task->assigned_cpu;

  if (assigned < g_cpu_capacity) {
    xaios_spin_lock(&g_runqueues[assigned].lock);
    sched_rq_remove(&g_runqueues[assigned], pid);
    xaios_spin_unlock(&g_runqueues[assigned].lock);
  }
  return XAIOS_OK;
}

xaios_context_frame_t *scheduler_task_frame(uint32_t pid) {
  xaios_sched_task_t *task = sched_find_task_global(pid, 0);
  if (task == 0) {
    return 0;
  }
  return &task->frame;
}

void scheduler_lock(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu < g_cpu_capacity) { ++g_lock_depth_per_cpu[cpu]; }
}

void scheduler_unlock(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu < g_cpu_capacity && g_lock_depth_per_cpu[cpu] > 0) {
    --g_lock_depth_per_cpu[cpu];
  }
}

void scheduler_tick(xaios_context_frame_t *irq_frame, void *architecture_state) {
  if (g_initialized == 0) {
    return;
  }
  uint32_t cpu = smp_cpu_id();
  if (cpu >= g_cpu_capacity || g_lock_depth_per_cpu[cpu] > 0) {
    return;
  }

  const xaios_cpu_state_t *cpu_state = smp_cpu_state(cpu);
  if (cpu_state != 0 && cpu_state->scheduling_enabled == 0) {
    return;
  }

  uint64_t tick = __sync_add_and_fetch(&g_tick_count, 1U);
  __sync_fetch_and_add(&g_sched_stats[cpu].tick_count, 1);

  uint32_t online = smp_online_count();
  uint64_t load_interval =
      (uint64_t)(online == 0U ? 1U : online) * XAIOS_SCHEDULER_DEFAULT_TICK_HZ;
  if (tick % load_interval == 0U) {
    sched_load_average_update(timer_now_ns());
  }

  xaios_runqueue_t *rq = &g_runqueues[cpu];
  xaios_spin_lock(&rq->lock);

  uint32_t current_pid = rq->current_pid;

  if (current_pid != 0) {
    xaios_sched_task_t *current = sched_find_task_local(cpu, current_pid);
    if (current != 0) {
      current->frame = *irq_frame;
      if (architecture_state != 0 && current->architecture_state != 0) {
        bytes_copy(current->architecture_state, architecture_state,
                   current->architecture_state_size);
      }
      ++current->tick_count;
      if (current->remaining_ticks > 0) {
        --current->remaining_ticks;
      }
    }
  }

  int need_reschedule = 0;

  if (current_pid == 0) {
    need_reschedule = 1;
  } else {
    xaios_sched_task_t *current = sched_find_task_local(cpu, current_pid);
    if (current == 0) {
      need_reschedule = 1;
    } else if (current->state == XAIOS_TASK_STATE_BLOCKED) {
      /* It gave the CPU up of its own accord and is in no queue; there is
         nothing here to switch back to. */
      need_reschedule = 1;
    } else if (current->remaining_ticks == 0) {
      current->state = XAIOS_TASK_STATE_RUNNABLE;
      current->remaining_ticks = sched_priority_slice(current->priority);
      sched_rq_add(rq, current_pid);
      need_reschedule = 1;
    } else if (current->state == XAIOS_TASK_STATE_RUNNING) {
      /* The task that is running is in *no* run queue: `sched_rq_pick_best` removed
         it when it was picked, and RUNNING is the state it was left in. So it
         has to be put back into the queue before the pick, or a switch away
         from it before its slice expires drops it from every queue and it can
         never be chosen again. It is lost rather than delayed, and this CPU
         goes idle one tick later.
       *
       * This is what a dispatching context and the process it dispatched did
       * to each other the first time both were runnable, which is what the
       * queue-order design needs (B-132): every tick switched between them and
       * dropped whichever it left, so after two ticks neither was in a queue
       * and the CPU sat in the idle path while one of them kept running on a
       * frame the scheduler had stopped keeping.
       *
       * The remaining slice is deliberately not re-armed: this task has not
       * used it up, and resetting it on every tick would make the slice
       * meaningless for a task that is switched to often. */
      current->state = XAIOS_TASK_STATE_RUNNABLE;
      sched_rq_add(rq, current_pid);
      need_reschedule = 1;
    }
  }

  if (!need_reschedule) {
    ++rq->busy_ticks;
    __sync_fetch_and_add(&g_sched_stats[cpu].busy_ticks, 1);
    xaios_spin_unlock(&rq->lock);
    return;
  }

  uint32_t next_pid = sched_rq_pick_best(rq, cpu);

  if (next_pid == 0) {
    xaios_spin_unlock(&rq->lock);
    next_pid = sched_try_steal_hierarchical(cpu);
    xaios_spin_lock(&rq->lock);
  }

  if (next_pid == 0) {
    if (current_pid != 0U) {
      user_process_runtime_stop(current_pid, cpu, timer_now_ns());
    }
    ++rq->idle_ticks;
    rq->current_pid = 0;
    __sync_fetch_and_add(&g_sched_stats[cpu].idle_ticks, 1);
    xaios_spin_unlock(&rq->lock);

    /* Periodic load balancing (lightweight, once per second) */
    sched_periodic_load_balance(cpu);
    return;
  }

  if (next_pid == current_pid) {
    ++rq->busy_ticks;
    __sync_fetch_and_add(&g_sched_stats[cpu].busy_ticks, 1);
    xaios_spin_unlock(&rq->lock);
    return;
  }

  xaios_sched_task_t *next_task = sched_find_task_local(cpu, next_pid);
  if (next_task == 0) {
    xaios_spin_unlock(&rq->lock);
    return;
  }
  next_task->state = XAIOS_TASK_STATE_RUNNING;
  ++next_task->switch_count;

  uint64_t switch_ns = timer_now_ns();
  if (current_pid != 0U) {
    user_process_runtime_stop(current_pid, cpu, switch_ns);
  }
  user_process_runtime_start(next_pid, cpu, switch_ns);
  rq->current_pid = next_pid;
  ++rq->busy_ticks;
  __sync_fetch_and_add(&g_context_switch_count, 1);
  __sync_fetch_and_add(&g_sched_stats[cpu].context_switch_count, 1);

  uint32_t old_pid = current_pid;
  xaios_spin_unlock(&rq->lock);

  klog("scheduler[cpu%u]: switch %u -> %u ticks=%lu switches=%lu\n",
       cpu, old_pid, next_pid, g_tick_count, g_context_switch_count);

  user_switch_address_space(next_pid);
  /* The per-CPU process binding follows the address space. A task that is
     not a user process fails this and is left alone, which is why the
     answer is ignored rather than asserted: without it a preempted process
     would resume with the *other* task's binding, and its next syscall
     would be checked against another process's capabilities. */
  (void)user_bind_current_process(next_pid);
  *irq_frame = next_task->frame;
  if (architecture_state != 0 && next_task->architecture_state != 0) {
    bytes_copy(architecture_state, next_task->architecture_state,
               next_task->architecture_state_size);
  }
}

void scheduler_yield(void) {
  if (g_initialized == 0) {
    return;
  }
  ++g_yield_count;

  uint32_t cpu = smp_cpu_id();
  if (cpu >= g_cpu_capacity) {
    return;
  }

  __sync_fetch_and_add(&g_sched_stats[cpu].yield_count, 1);

  xaios_runqueue_t *rq = &g_runqueues[cpu];
  xaios_spin_lock(&rq->lock);
  uint32_t current_pid = rq->current_pid;

  if (current_pid != 0) {
    xaios_sched_task_t *current = sched_find_task_local(cpu, current_pid);
    if (current != 0) {
      current->remaining_ticks = 0;
      current->state = XAIOS_TASK_STATE_RUNNABLE;
      sched_rq_add(rq, current_pid);
    }
  }

  uint32_t next_pid = sched_rq_pick_best(rq, cpu);

  if (next_pid != 0 && next_pid != current_pid) {
    xaios_sched_task_t *next_task = sched_find_task_local(cpu, next_pid);
    if (next_task != 0) {
      next_task->state = XAIOS_TASK_STATE_RUNNING;
      ++next_task->switch_count;
    }
    uint64_t switch_ns = timer_now_ns();
    if (current_pid != 0U) {
      user_process_runtime_stop(current_pid, cpu, switch_ns);
    }
    user_process_runtime_start(next_pid, cpu, switch_ns);
    rq->current_pid = next_pid;
    __sync_fetch_and_add(&g_context_switch_count, 1);
    __sync_fetch_and_add(&g_sched_stats[cpu].context_switch_count, 1);
    user_switch_address_space(next_pid);
  }
  xaios_spin_unlock(&rq->lock);
}

xaios_status_t scheduler_register_kernel_task(uint32_t pid, void (*entry)(void),
                                              uint64_t stack_top,
                                              xaios_task_priority_t priority) {
  if (entry == 0 || stack_top == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = sched_register_on_cpu(pid, priority, smp_cpu_id());
  if (status != XAIOS_OK) {
    return status;
  }
  xaios_context_frame_t *frame = scheduler_task_frame(pid);
  if (frame == 0 || xaios_context_frame_kernel_entry(frame, entry, stack_top) == 0) {
    /* The task record is given back rather than left registered: a task whose
     * port cannot resume it is a task that would hang the CPU the first time it
     * was picked. */
    scheduler_unregister(pid);
    return XAIOS_ERR_UNSUPPORTED;
  }
  /* Registered, and deliberately *not* runnable. The caller has to adopt the
   * context that will hand the CPU over first, and until it has, a runnable
   * task is one a tick may pick -- which would take the CPU from a context
   * whose frame has not been saved yet, and never give it back. That window is
   * not theoretical: the first version of this made the task runnable here and
   * a tick landed inside it. */
  return XAIOS_OK;
}

xaios_status_t scheduler_adopt_this_context(uint32_t pid,
                                            xaios_task_priority_t priority) {
  uint32_t cpu = smp_cpu_id();
  xaios_status_t status = sched_register_on_cpu(pid, priority, cpu);
  if (status != XAIOS_OK) {
    return status;
  }
  /* Runnable and in the queue, so it can be picked again after it is switched
     away from, and current, so the tick saves it before it picks. Its frame is
     deliberately not filled here: the first tick that switches away from it
     saves the context that is running now, which is the only place it exists. */
  status = scheduler_set_runnable(pid);
  if (status != XAIOS_OK) {
    scheduler_unregister(pid);
    return status;
  }
  xaios_spin_lock(&g_runqueues[cpu].lock);
  g_runqueues[cpu].current_pid = pid;
  xaios_spin_unlock(&g_runqueues[cpu].lock);
  return XAIOS_OK;
}

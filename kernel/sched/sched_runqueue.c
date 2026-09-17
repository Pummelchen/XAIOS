/* The scheduler's per-CPU task tables and run queues.
 *
 * Split out of scheduler.c, which was 1202 lines. Everything here answers
 * "where does a task live, and who runs next": the slot bitmap that allocates a
 * task record, the lookup that finds one, the run-queue array and its pick,
 * and the hierarchical walk -- core, socket, NUMA -- that steals work for a CPU
 * whose own queue has run dry, plus the read-only queries that report the
 * current task and the runnable count. The tick, the register calls and the
 * process state transitions stay in scheduler.c and reach this file through
 * scheduler_internal.h.
 *
 * The pick order, the overload test (`count > 2`) and the steal budget are
 * unchanged: they are what the scheduler is, not an implementation detail.
 */

#include "scheduler_internal.h"

#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/types.h>

/* Find task in local CPU's task table (O(128) max, not O(32K)) */
xaios_sched_task_t *sched_find_task_local(uint32_t cpu_id, uint32_t pid) {
  if (cpu_id >= g_cpu_capacity) {
    return 0;
  }

  xaios_cpu_task_table_t *table = &g_cpu_tasks[cpu_id];
  for (uint32_t i = 0; i < XAIOS_TASK_SLOTS_PER_CPU; ++i) {
    if ((table->slot_bitmap[i >> 6U] & (UINT64_C(1) << (i & 63U))) != 0 &&
        table->tasks[i].active != 0 && table->tasks[i].pid == pid) {
      return &table->tasks[i];
    }
  }
  return 0;
}

xaios_sched_task_t *sched_find_task_global(uint32_t pid, uint32_t *cpu_out) {
  uint32_t online = smp_online_count();
  for (uint32_t cpu = 0; cpu < online; ++cpu) {
    xaios_sched_task_t *task = sched_find_task_local(cpu, pid);
    if (task != 0) {
      if (cpu_out != 0) {
        *cpu_out = cpu;
      }
      return task;
    }
  }
  return 0;
}

/* Allocate task slot from local CPU's table using atomic bitmap */
xaios_sched_task_t *sched_alloc_task_slot(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity) {
    return 0;
  }

  xaios_cpu_task_table_t *table = &g_cpu_tasks[cpu_id];
  for (uint32_t word = 0; word < 2; ++word) {
    uint64_t bitmap = table->slot_bitmap[word];
    if (bitmap != UINT64_C(0xffffffffffffffff)) {
      /* Find first free slot */
      for (uint32_t bit = 0; bit < 64; ++bit) {
        uint32_t slot = word * 64 + bit;
        if (slot >= XAIOS_TASK_SLOTS_PER_CPU) {
          break;
        }
        uint64_t mask = UINT64_C(1) << bit;
        if ((bitmap & mask) == 0) {
          /* Atomically claim slot */
          uint64_t old = __sync_val_compare_and_swap(&table->slot_bitmap[word],
                                                      bitmap, bitmap | mask);
          if (old == bitmap) {
            /* Successfully claimed */
            sched_bytes_zero(&table->tasks[slot], sizeof(xaios_sched_task_t));
            return &table->tasks[slot];
          }
          /* Race, retry */
          bitmap = table->slot_bitmap[word];
        }
      }
    }
  }
  return 0; /* table full */
}

/* Free task slot */
void sched_free_task_slot(uint32_t cpu_id, xaios_sched_task_t *task) {
  if (cpu_id >= g_cpu_capacity || task == 0) {
    return;
  }

  xaios_cpu_task_table_t *table = &g_cpu_tasks[cpu_id];
  uint32_t index = (uint32_t)(task - table->tasks);
  if (index >= XAIOS_TASK_SLOTS_PER_CPU) {
    return;
  }

  kheap_free(task->architecture_state);
  task->architecture_state = 0;
  task->architecture_state_size = 0U;

  uint32_t word = index >> 6U;
  uint32_t bit = index & 63U;
  __sync_fetch_and_and(&table->slot_bitmap[word], ~(UINT64_C(1) << bit));
}

uint32_t sched_priority_slice(xaios_task_priority_t prio) {
  switch (prio) {
    case XAIOS_PRIORITY_HIGH:   return XAIOS_PRIORITY_HIGH_SLICE;
    case XAIOS_PRIORITY_NORMAL: return XAIOS_PRIORITY_NORMAL_SLICE;
    case XAIOS_PRIORITY_LOW:    return XAIOS_PRIORITY_LOW_SLICE;
  }
  return XAIOS_PRIORITY_NORMAL_SLICE;
}

uint32_t sched_rq_index(const xaios_runqueue_t *rq, uint32_t pid) {
  for (uint32_t i = 0; i < rq->count; ++i) {
    if (rq->tasks[i] == pid) {
      return i;
    }
  }
  return UINT32_C(0xffffffff);
}

void sched_rq_add(xaios_runqueue_t *rq, uint32_t pid) {
  if (rq->count < XAIOS_SCHEDULER_PER_CPU_RUNQUEUE &&
      sched_rq_index(rq, pid) == UINT32_C(0xffffffff)) {
    rq->tasks[rq->count++] = pid;
  }
}

void sched_rq_remove(xaios_runqueue_t *rq, uint32_t pid) {
  uint32_t idx = sched_rq_index(rq, pid);
  if (idx == UINT32_C(0xffffffff)) {
    return;
  }
  for (uint32_t i = idx; i + 1U < rq->count; ++i) {
    rq->tasks[i] = rq->tasks[i + 1U];
  }
  --rq->count;
}

uint32_t sched_rq_pick_best(xaios_runqueue_t *rq, uint32_t cpu_id) {
  if (rq->count == 0) {
    return 0;
  }

  uint32_t best_pid = rq->tasks[0];
  xaios_task_priority_t best_prio = XAIOS_PRIORITY_LOW;

  for (uint32_t i = 0; i < rq->count; ++i) {
    xaios_sched_task_t *t = sched_find_task_local(cpu_id, rq->tasks[i]);
    if (t != 0 && t->priority < best_prio) {
      best_prio = t->priority;
      best_pid = t->pid;
    }
    if (best_prio == XAIOS_PRIORITY_HIGH) {
      break;
    }
  }

  sched_rq_remove(rq, best_pid);
  return best_pid;
}

static uint32_t rq_pick_stealable(xaios_runqueue_t *victim, uint32_t victim_cpu) {
  if (victim->count == 0) {
    return 0;
  }

  uint32_t best_pid = 0;
  xaios_task_priority_t best_prio = XAIOS_PRIORITY_LOW;

  for (uint32_t i = 0; i < victim->count; ++i) {
    uint32_t pid = victim->tasks[i];
    if (pid == victim->current_pid) {
      continue;
    }
    xaios_sched_task_t *t = sched_find_task_local(victim_cpu, pid);
    if (t != 0 && t->priority <= best_prio) {
      if (t->priority < best_prio || best_pid == 0) {
        best_prio = t->priority;
        best_pid = pid;
      }
    }
  }

  if (best_pid != 0) {
    sched_rq_remove(victim, best_pid);
  }
  return best_pid;
}

/* Hierarchical work-stealing: core → socket → NUMA → stop.
 *
 * Only a level-0 domain lists CPUs. Every other level lists child domains, so
 * this walks down to the leaves rather than reading a domain id as a CPU id,
 * which is what it did before: on a machine with more than one core domain,
 * "steal from the same socket" inspected the runqueue of whatever CPU number
 * a domain id collided with. It looked harmless because on a small
 * single-node machine the ids overlap the CPU ids and the extra levels find
 * nothing to steal anyway. */
static uint32_t try_steal_from_cpu(uint32_t this_cpu, uint32_t victim);

/* `budget` is the number of victims this walk may still look at, kept from
   the original: a steal happens on the path of a CPU that has just run out of
   work, so scanning a whole domain to find nothing costs more than the steal
   was worth. It is spent across the recursion rather than per domain, so a
   deep hierarchy cannot multiply it. */
static uint32_t try_steal_domain_recursive(uint32_t this_cpu,
                                           uint32_t domain_id, uint32_t depth,
                                           uint32_t *budget) {
  if (domain_id == UINT32_MAX || depth > XAIOS_SCHED_DOMAIN_MAX_LEVELS ||
      *budget == 0U) {
    return 0;
  }
  const xaios_sched_domain_t *dom = topology_get_domain(domain_id);
  if (dom == 0 || dom->member_count == 0) {
    return 0;
  }
  for (uint32_t i = 0; i < dom->member_count && *budget != 0U; ++i) {
    uint32_t stolen = 0;
    if (dom->level == 0) {
      --(*budget);
      stolen = try_steal_from_cpu(this_cpu, dom->members[i]);
    } else {
      stolen = try_steal_domain_recursive(this_cpu, dom->members[i], depth + 1,
                                          budget);
    }
    if (stolen != 0) {
      return stolen;
    }
  }
  return 0;
}

static uint32_t try_steal_domain(uint32_t this_cpu, uint32_t domain_id) {
  uint32_t budget = 8U;
  return try_steal_domain_recursive(this_cpu, domain_id, 0, &budget);
}

/* One victim. Returns the pid moved onto this_cpu, or 0 for every reason a
   CPU is not worth stealing from -- it is itself, it is not scheduling, it is
   not overloaded, or another CPU holds its runqueue lock. */
static uint32_t try_steal_from_cpu(uint32_t this_cpu, uint32_t victim) {
  if (victim == this_cpu || victim >= g_cpu_capacity) {
    return 0;
  }

  const xaios_cpu_state_t *state = smp_cpu_state(victim);
  if (state == 0 || state->online == 0 || state->scheduling_enabled == 0) {
    return 0;
  }

  /* Only steal from overloaded CPUs (count > 2) */
  if (g_runqueues[victim].count <= 2) {
    return 0;
  }

  if (!xaios_spin_trylock(&g_runqueues[victim].lock)) {
    return 0;
  }
  uint32_t stolen_pid = rq_pick_stealable(&g_runqueues[victim], victim);
  xaios_spin_unlock(&g_runqueues[victim].lock);
  if (stolen_pid == 0) {
    __sync_fetch_and_add(&g_sched_stats[this_cpu].steal_fail_count, 1);
    return 0;
  }

  xaios_sched_task_t *task = sched_find_task_local(victim, stolen_pid);
  if (task != 0) {
    task->assigned_cpu = this_cpu;
    task->remaining_ticks = sched_priority_slice(task->priority);
  }

  xaios_spin_lock(&g_runqueues[this_cpu].lock);
  sched_rq_add(&g_runqueues[this_cpu], stolen_pid);
  xaios_spin_unlock(&g_runqueues[this_cpu].lock);

  __sync_fetch_and_add(&g_sched_stats[this_cpu].steal_success_count, 1);
  __sync_fetch_and_add(&g_steal_count, 1);
  return stolen_pid;
}

uint32_t sched_try_steal_hierarchical(uint32_t this_cpu) {
  /* Level 0: steal from sibling CPUs in same core domain */
  uint32_t core_domain = topology_get_core_domain(this_cpu);
  uint32_t stolen = try_steal_domain(this_cpu, core_domain);
  if (stolen != 0) {
    return stolen;
  }

  /* Level 1: steal from same socket */
  uint32_t socket_domain = topology_get_socket_domain(this_cpu);
  stolen = try_steal_domain(this_cpu, socket_domain);
  if (stolen != 0) {
    return stolen;
  }

  /* Level 2: steal from same NUMA node */
  uint32_t numa_domain = topology_get_numa_domain(this_cpu);
  if (numa_domain != socket_domain) {
    stolen = try_steal_domain(this_cpu, numa_domain);
    if (stolen != 0) {
      return stolen;
    }
  }

  return 0; /* system-wide steal not worth it */
}

/* O(1) random placement with NUMA awareness */
uint32_t sched_find_least_loaded_cpu(void) {
  uint32_t online = smp_online_count();
  if (online == 0) {
    return 0;
  }

  /* Prefer local NUMA node */
  uint32_t this_cpu = smp_cpu_id();
  uint32_t local_node = topology_get_numa_node_for_cpu(this_cpu);

  /* Use timer counter as simple PRNG */
  uint32_t seed = (uint32_t)timer_counter();
  uint32_t start = seed % online;

  /* Find first scheduling-enabled CPU from random start */
  for (uint32_t i = 0; i < online; ++i) {
    uint32_t cpu = (start + i) % online;
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state == 0 || state->online == 0) {
      continue;
    }
    if (state->role != XAIOS_CPU_ROLE_SCHEDULING &&
        state->role != XAIOS_CPU_ROLE_HOUSEKEEPING) {
      continue;
    }

    /* Prefer local NUMA node */
    if (local_node != UINT32_MAX) {
      uint32_t cpu_node = topology_get_numa_node_for_cpu(cpu);
      if (cpu_node == local_node) {
        return cpu;
      }
    } else {
      return cpu; /* no NUMA info, use first available */
    }
  }

  /* Fallback: any online scheduling CPU */
  for (uint32_t i = 0; i < online; ++i) {
    uint32_t cpu = (start + i) % online;
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0 && state->online != 0 &&
        (state->role == XAIOS_CPU_ROLE_SCHEDULING ||
         state->role == XAIOS_CPU_ROLE_HOUSEKEEPING)) {
      return cpu;
    }
  }

  return 0;
}

/* Periodic load balancing (every 1000 ticks = 10s at 100 Hz) */
void sched_periodic_load_balance(uint32_t this_cpu) {
  /* Only one CPU does load balancing per cycle */
  if ((__sync_fetch_and_add(&g_balance_counter, 1) % 1000) != 0) {
    return;
  }

  /* Find busiest CPU in local domain */
  uint32_t core_domain = topology_get_core_domain(this_cpu);
  if (core_domain == UINT32_MAX) {
    return;
  }

  const xaios_sched_domain_t *dom = topology_get_domain(core_domain);
  if (dom == 0 || dom->member_count == 0) {
    return;
  }

  uint32_t busiest_cpu = UINT32_MAX;
  uint32_t busiest_count = 0;

  for (uint32_t i = 0; i < dom->member_count; ++i) {
    uint32_t cpu = dom->members[i];
    if (g_runqueues[cpu].count > busiest_count) {
      busiest_count = g_runqueues[cpu].count;
      busiest_cpu = cpu;
    }
  }

  /* If busiest has >2× local count and >4 tasks, log imbalance */
  uint32_t local_count = g_runqueues[this_cpu].count;
  if (busiest_count > local_count * 2 && busiest_count > 4 &&
      busiest_cpu != UINT32_MAX && busiest_cpu != this_cpu) {
    klog("scheduler: load imbalance detected cpu%u(%u) vs cpu%u(%u)\n",
         this_cpu, local_count, busiest_cpu, busiest_count);
    __sync_fetch_and_add(&g_sched_stats[this_cpu].load_balance_count, 1);
  }
}

/* "No task" and "no scheduler yet" answer the same thing, and the second is not
 * a corner case: this port's timer is armed at 100 Hz for the exception
 * self-test long before `scheduler_init()` allocates the run queues, and an
 * architecture whose tick asks who is running before it ticks -- RISC-V's does,
 * to tell a tick that switched from one that did not (B-129) -- dereferenced a
 * null `g_runqueues` and took the machine down with
 * `class=load-access-fault stval=0x210`, which is `current_pid`'s offset in that
 * array. The guard is the difference between a tick that arrives early being
 * ignored and being fatal. */
uint32_t scheduler_current_pid(void) {
  uint32_t cpu = smp_cpu_id();
  if (g_runqueues == 0 || cpu >= g_cpu_capacity) {
    return 0;
  }
  return g_runqueues[cpu].current_pid;
}

uint32_t scheduler_current_pid_on_cpu(uint32_t cpu_id) {
  if (g_runqueues == 0 || cpu_id >= g_cpu_capacity) {
    return 0;
  }
  return g_runqueues[cpu_id].current_pid;
}

uint32_t scheduler_runnable_count(void) {
  uint32_t total = 0;
  uint32_t online = smp_online_count();
  for (uint32_t cpu = 0; cpu < online; ++cpu) {
    total += g_runqueues[cpu].count;
  }
  return total;
}


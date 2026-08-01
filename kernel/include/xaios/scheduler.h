#ifndef XAIOS_SCHEDULER_H
#define XAIOS_SCHEDULER_H

#include <xaios/context.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>

/*
 * Preemptive SMP Scheduler
 *
 * - Per-CPU runqueues with spinlock protection
 * - Per-CPU task tables (eliminates global lock contention)
 * - Hierarchical work-stealing (core → socket → NUMA → system)
 * - 3-tier priority system with time-slice accounting
 * - NUMA-aware task placement
 * - Periodic load balancing (every 1000 ticks)
 * - Uses the CPUs admitted by the current SMP platform implementation
 */

#define XAIOS_SCHEDULER_MAX_TASKS 32768U
#define XAIOS_SCHEDULER_PER_CPU_RUNQUEUE 128U
#define XAIOS_SCHEDULER_DEFAULT_TICK_HZ 100U
#define XAIOS_TASK_SLOTS_PER_CPU 128U

typedef enum xaios_task_priority {
  XAIOS_PRIORITY_HIGH = 0,
  XAIOS_PRIORITY_NORMAL = 1,
  XAIOS_PRIORITY_LOW = 2,
} xaios_task_priority_t;

#define XAIOS_PRIORITY_HIGH_SLICE   4U
#define XAIOS_PRIORITY_NORMAL_SLICE 2U
#define XAIOS_PRIORITY_LOW_SLICE    1U

typedef enum xaios_task_state {
  XAIOS_TASK_STATE_UNUSED = 0,
  XAIOS_TASK_STATE_REGISTERED = 1,
  XAIOS_TASK_STATE_RUNNABLE = 2,
  XAIOS_TASK_STATE_RUNNING = 3,
  XAIOS_TASK_STATE_BLOCKED = 4,
} xaios_task_state_t;

typedef struct xaios_sched_task {
  uint32_t pid;
  uint32_t active;
  xaios_context_frame_t frame;
  uint64_t tick_count;
  uint64_t switch_count;
  xaios_task_priority_t priority;
  xaios_task_state_t state;
  uint32_t assigned_cpu;
  uint32_t remaining_ticks;
} xaios_sched_task_t;

typedef struct xaios_runqueue {
  xaios_spinlock_t lock;
  uint32_t tasks[XAIOS_SCHEDULER_PER_CPU_RUNQUEUE];
  uint32_t count;
  uint32_t current_pid;
  uint32_t cpu_id;
  uint64_t idle_ticks;
  uint64_t busy_ticks;
} xaios_runqueue_t;

/* Per-CPU task table (eliminates global lock contention) */
typedef struct xaios_cpu_task_table {
  uint64_t slot_bitmap[2];   /* 128 slots = 2 × 64-bit words */
  xaios_sched_task_t tasks[XAIOS_TASK_SLOTS_PER_CPU];
} xaios_cpu_task_table_t;

/* Per-CPU scheduler statistics */
typedef struct xaios_sched_stats {
  uint64_t tick_count;
  uint64_t context_switch_count;
  uint64_t yield_count;
  uint64_t steal_success_count;
  uint64_t steal_fail_count;
  uint64_t load_balance_count;
  uint64_t migration_count;
  uint64_t idle_ticks;
  uint64_t busy_ticks;
} xaios_sched_stats_t;

void scheduler_init(void);
void scheduler_tick(xaios_context_frame_t *irq_frame);
void scheduler_yield(void);
void scheduler_lock(void);
void scheduler_unlock(void);
xaios_status_t scheduler_register(uint32_t pid);
xaios_status_t scheduler_register_with_priority(uint32_t pid,
                                                xaios_task_priority_t priority);
void scheduler_unregister(uint32_t pid);
xaios_status_t scheduler_set_runnable(uint32_t pid);
xaios_status_t scheduler_set_blocked(uint32_t pid);
xaios_context_frame_t *scheduler_task_frame(uint32_t pid);
uint64_t scheduler_tick_count(void);
uint64_t scheduler_context_switch_count(void);
uint64_t scheduler_yield_count(void);
uint32_t scheduler_current_pid(void);
uint32_t scheduler_current_pid_on_cpu(uint32_t cpu_id);
uint32_t scheduler_runnable_count(void);
void scheduler_self_test(void);

/* Statistics and telemetry */
void scheduler_get_stats(uint32_t cpu_id, xaios_sched_stats_t *stats);
void scheduler_dump_stats(void);

#endif
